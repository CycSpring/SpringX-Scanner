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

// sseHub fans out events to all subscribers of a single job. It is owned by the
// job; its subscribers map is guarded by the hub's own mutex (h.mu), NOT the
// job's mutex. The TTL reaper queries count() under h.mu to decide whether a
// terminal job is safe to remove.
type sseHub struct {
	mu          sync.Mutex
	subscribers map[*subscriber]struct{}
}

func newHub() *sseHub {
	return &sseHub{subscribers: map[*subscriber]struct{}{}}
}

// count returns the number of active SSE subscribers, for TTL reaper safety.
func (h *sseHub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
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

	// 1. Replay cached history (the source of truth). Track the seq of every
	// event we have sent so that any event broadcast between subscribe() and
	// this replay (which therefore landed in BOTH the history and the
	// subscriber queue) is not delivered twice — a duplicate would
	// double-count rows/metrics in the live tables.
	//
	// A set (not a high-water mark) is used because the ordinary and terminal
	// queues can deliver out of order; a single lastSeq upper bound would
	// wrongly drop a not-yet-sent event whose seq is below the bound. Events
	// with Seq == 0 (e.g. fake test events that bypass the Emitter) are never
	// deduplicated: real scans always assign Seq >= 1, and the race that
	// produces duplicates only occurs for live events, which always have a
	// real seq.
	sent := make(map[uint64]bool)
	for _, ev := range job.history() {
		if !writeSSEEvent(w, flusher, ev) {
			return
		}
		if ev.Seq != 0 {
			sent[ev.Seq] = true
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
			drainSubscriber(w, flusher, sub, sent)
			return
		case ev := <-sub.ordinary:
			if !shouldSend(sent, ev) {
				continue
			}
			if !writeSSEEvent(w, flusher, ev) {
				return
			}
		case ev := <-sub.terminal:
			if !shouldSend(sent, ev) {
				continue
			}
			if !writeSSEEvent(w, flusher, ev) {
				return
			}
		}
	}
}

// shouldSend reports whether ev should be sent to the client, marking it sent.
// Events with Seq == 0 are always sent (no dedup); events with Seq > 0 are
// sent only if that seq has not been delivered already.
func shouldSend(sent map[uint64]bool, ev event.Event) bool {
	if ev.Seq == 0 {
		return true
	}
	if sent[ev.Seq] {
		return false
	}
	sent[ev.Seq] = true
	return true
}

// drainSubscriber flushes any queued events not yet sent after the pump has
// exited, so terminal events (e.g. report_written arriving after
// scan_completed) are not lost.
func drainSubscriber(w http.ResponseWriter, flusher http.Flusher, sub *subscriber, sent map[uint64]bool) {
	for {
		select {
		case ev := <-sub.terminal:
			if !shouldSend(sent, ev) {
				continue
			}
			if !writeSSEEvent(w, flusher, ev) {
				return
			}
		case ev := <-sub.ordinary:
			if !shouldSend(sent, ev) {
				continue
			}
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
