package scan

import "testing"

func TestNormalizeURL(t *testing.T) {
	got, err := NormalizeURL("example.com")
	if err != nil {
		t.Fatalf("NormalizeURL returned error: %v", err)
	}
	if got != "http://example.com/" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveTargets(t *testing.T) {
	targets, err := ResolveTargets(Config{TargetURL: "https://example.com", TargetIP: "127.0.0.1", Size: 10})
	if err != nil {
		t.Fatalf("ResolveTargets returned error: %v", err)
	}
	if len(targets.URLs) != 1 || len(targets.Hosts) != 1 {
		t.Fatalf("unexpected targets: %+v", targets)
	}
}
