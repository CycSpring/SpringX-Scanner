package event

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestEmitterAddsProtocolFields(t *testing.T) {
	var buf bytes.Buffer
	emitter := NewEmitter(&buf)
	emitter.SetScanID("scan-123")

	emitter.Emit("scan_started", map[string]any{"target": "https://example.com"})
	emitter.EmitError("scan_failed", errors.New("boom"), nil)

	scanner := bufio.NewScanner(&buf)
	var events []Event
	for scanner.Scan() {
		var ev Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("decode event: %v", err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Version != ProtocolVersion || events[1].Version != ProtocolVersion {
		t.Fatalf("unexpected protocol versions: %#v", events)
	}
	if events[0].ScanID != "scan-123" || events[1].ScanID != "scan-123" {
		t.Fatalf("unexpected scan ids: %#v", events)
	}
	if events[0].Seq != 1 || events[1].Seq != 2 {
		t.Fatalf("unexpected event sequence: %#v", events)
	}
	if events[1].Error != "boom" {
		t.Fatalf("unexpected error: %q", events[1].Error)
	}
}
