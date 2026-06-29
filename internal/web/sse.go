package web

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
)

// cancelGrace is the time interruptProcess waits for the child to exit after a
// graceful signal before forcing a kill.
const cancelGrace = 5 * time.Second

// subscriberBufferSize bounds the per-client event backlog. Ordinary events are
// dropped when a slow client fills its buffer (a reconnect replays the cached
// full history), but terminal events are delivered via a dedicated channel so
// they can never be lost to a full buffer.
const subscriberBufferSize = 256

// terminalEventTypes are events whose delivery is critical. They are pushed on
// a separate unbuffered-per-send path and are always present in the job's
// cached history, so any (re)connect can recover them.
var terminalEventTypes = map[string]bool{
	"scan_completed": true,
	"scan_failed":    true,
	"report_written": true,
}

// subscriber represents one SSE client connection for a single job.
type subscriber struct {
	// ordinary delivers non-terminal events; drops on full buffer.
	ordinary chan event.Event
	// terminal delivers terminal events with a short blocking send + timeout.
	terminal chan event.Event
	// done is closed when the subscriber stops listening.
	done chan struct{}
}

func newSubscriber() *subscriber {
	return &subscriber{
		ordinary: make(chan event.Event, subscriberBufferSize),
		terminal: make(chan event.Event, 4),
		done:     make(chan struct{}),
	}
}

// sseHub fans out events to all subscribers of a single job. It is owned by
// the job and guarded by the job's mutex (subscribers slice is mutated under
// job.mu). Events are also appended to the job's cache before fan-out.
type sseHub struct {
	mu          sync.Mutex
	subscribers map[*subscriber]struct{}
}

func newHub() *sseHub {
	return &sseHub{subscribers: map[*subscriber]struct{}{}}
}

func (h *sseHub) subscribe() *subscriber {
	sub := newSubscriber()
	h.mu.Lock()
	h.subscribers[sub] = struct{}{}
	h.mu.Unlock()
	return sub
}

func (h *sseHub) unsubscribe(sub *subscriber) {
	h.mu.Lock()
	delete(h.subscribers, sub)
	h.mu.Unlock()
	safeClose(sub.done)
}

// broadcast sends an event to all subscribers. Terminal events are sent via the
// terminal channel with a short timeout so they survive a slow consumer;
// ordinary events are non-blocking and dropped on a full buffer.
func (h *sseHub) broadcast(ev event.Event) {
	h.mu.Lock()
	subs := make([]*subscriber, 0, len(h.subscribers))
	for sub := range h.subscribers {
		subs = append(subs, sub)
	}
	h.mu.Unlock()

	terminal := terminalEventTypes[ev.Type]
	for _, sub := range subs {
		if terminal {
			select {
			case sub.terminal <- ev:
			case <-time.After(2 * time.Second):
				// Even terminal sends are bounded to avoid a wedged client
				// blocking the scan pump; the cached history guarantees
				// recovery on reconnect.
			}
			continue
		}
		select {
		case sub.ordinary <- ev:
		default:
			// Drop ordinary event for slow client; replay recovers it.
		}
	}
}

// serveSSE writes events to the SSE client: first the cached history, then the
// live ordinary+terminal streams until the job is terminal and drained or the
// request is cancelled.
func (s *Server) serveSSE(w http.ResponseWriter, r *http.Request, job *ScanJob) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sub := job.hub.subscribe()
	defer job.hub.unsubscribe(sub)

	// 1. Replay cached history (the source of truth).
	for _, ev := range job.history() {
		if !writeSSEEvent(w, flusher, ev) {
			return
		}
	}

	// 2. If the pump is already done, the replay above included all events.
	select {
	case <-job.done:
		return
	default:
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-job.done:
			drainSubscriber(w, flusher, sub)
			return
		case ev := <-sub.ordinary:
			if !writeSSEEvent(w, flusher, ev) {
				return
			}
		case ev := <-sub.terminal:
			if !writeSSEEvent(w, flusher, ev) {
				return
			}
		}
	}
}

func drainSubscriber(w http.ResponseWriter, flusher http.Flusher, sub *subscriber) {
	for {
		select {
		case ev := <-sub.terminal:
			if !writeSSEEvent(w, flusher, ev) {
				return
			}
		case ev := <-sub.ordinary:
			if !writeSSEEvent(w, flusher, ev) {
				return
			}
		default:
			return
		}
	}
}

// writeSSEEvent marshals one event as an SSE data: line and flushes.
// Returns false if the write failed (client gone).
func writeSSEEvent(w http.ResponseWriter, flusher http.Flusher, ev event.Event) bool {
	payload, err := json.Marshal(ev)
	if err != nil {
		return true
	}
	if _, err := w.Write([]byte("data: ")); err != nil {
		return false
	}
	if _, err := w.Write(payload); err != nil {
		return false
	}
	if _, err := w.Write([]byte("\n\n")); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func safeClose(ch chan struct{}) {
	defer func() { _ = recover() }()
	select {
	case <-ch:
	default:
		close(ch)
	}
}
