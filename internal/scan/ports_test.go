package scan

import "testing"

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("80,443,8000-8002")
	if err != nil {
		t.Fatalf("ParsePorts returned error: %v", err)
	}
	want := []int{80, 443, 8000, 8001, 8002}
	if len(ports) != len(want) {
		t.Fatalf("got %v want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v want %v", ports, want)
		}
	}
}

func TestParseTop100(t *testing.T) {
	ports, err := ParsePorts("TOP100")
	if err != nil {
		t.Fatalf("ParsePorts returned error: %v", err)
	}
	if len(ports) != 100 {
		t.Fatalf("TOP100 length = %d", len(ports))
	}
}
