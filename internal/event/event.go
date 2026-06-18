package event

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Emitter writes line-delimited JSON events for future WebUI consumption.
type Emitter struct {
	w  io.Writer
	mu sync.Mutex
}

type Event struct {
	Type  string         `json:"type"`
	Time  time.Time      `json:"time"`
	Data  map[string]any `json:"data,omitempty"`
	Error string         `json:"error,omitempty"`
}

func NewEmitter(w io.Writer) *Emitter {
	return &Emitter{w: w}
}

func (e *Emitter) Emit(eventType string, data map[string]any) {
	e.write(Event{Type: eventType, Time: time.Now(), Data: data})
}

func (e *Emitter) EmitError(eventType string, err error, data map[string]any) {
	ev := Event{Type: eventType, Time: time.Now(), Data: data}
	if err != nil {
		ev.Error = err.Error()
	}
	e.write(ev)
}

func (e *Emitter) write(ev Event) {
	if e == nil || e.w == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = json.NewEncoder(e.w).Encode(ev)
}
