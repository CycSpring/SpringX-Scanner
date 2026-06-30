package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeURLFingerprinting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico":
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write([]byte("springx-icon"))
		default:
			w.Header().Set("Server", "cloudflare")
			w.Header().Set("X-Powered-By", "PHP/8.2")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc"})
			_, _ = w.Write([]byte(`<!doctype html><title>SpringX WP</title><meta name="generator" content="WordPress"><script src="/wp-content/app.js"></script><div id="app" data-vue="1"></div>`))
		}
	}))
	defer server.Close()

	svc := ProbeURL(context.Background(), server.URL, 5*time.Second, "")
	if svc.StatusCode != 200 {
		t.Fatalf("status = %d error=%s", svc.StatusCode, svc.Error)
	}
	for _, want := range []string{"Cloudflare", "PHP", "WordPress", "Vue"} {
		if !containsString(svc.Technologies, want) {
			t.Fatalf("technologies missing %s: %#v sources=%#v", want, svc.Technologies, svc.FingerprintSources)
		}
	}
	if svc.ContentType == "" || !strings.Contains(svc.ContentType, "text/html") {
		t.Fatalf("content type = %q", svc.ContentType)
	}
	if svc.FaviconHash == "" {
		t.Fatalf("expected favicon hash")
	}
}

// TestProbeURLRetryOnTimeout verifies that a retryable network error (the first
// request timing out) is retried once and succeeds on the second attempt.
// retryBackoff is shortened to 1ms so the test does not wait 500ms.
func TestProbeURLRetryOnTimeout(t *testing.T) {
	origBackoff := retryBackoff
	retryBackoff = 1 * time.Millisecond
	defer func() { retryBackoff = origBackoff }()

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			time.Sleep(200 * time.Millisecond) // exceed the 50ms client timeout
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>retry-ok</title>"))
	}))
	defer server.Close()

	// Fresh per-call client (ProbeURL path) with a 50ms timeout so the first
	// request fails with a timeout and the retry succeeds.
	svc := ProbeURL(context.Background(), server.URL, 50*time.Millisecond, "")
	if svc.StatusCode != 200 {
		t.Fatalf("status = %d error=%s; expected retry to succeed", svc.StatusCode, svc.Error)
	}
	if svc.Title != "retry-ok" {
		t.Fatalf("title = %q, want retry-ok", svc.Title)
	}
	if atomic.LoadInt32(&attempts) < 2 {
		t.Fatalf("attempts = %d, want >=2 (retry should have happened)", attempts)
	}
}

// TestProbeURLRetryExhausted verifies that when every attempt times out, the
// probe returns a Service with Error set and no status code.
func TestProbeURLRetryExhausted(t *testing.T) {
	origBackoff := retryBackoff
	retryBackoff = 1 * time.Millisecond
	defer func() { retryBackoff = origBackoff }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // always exceed the 50ms timeout
	}))
	defer server.Close()

	svc := ProbeURL(context.Background(), server.URL, 50*time.Millisecond, "")
	if svc.StatusCode != 0 {
		t.Fatalf("status = %d, want 0 (all attempts timed out)", svc.StatusCode)
	}
	if svc.Error == "" {
		t.Fatal("expected non-empty error after retry exhaustion")
	}
}

// TestProbeURLNormalizeURLFailureCompletesService verifies that a malformed URL
// still produces a structurally complete Service (B.5 fix), not a stub with
// only Host+Error.
func TestProbeURLNormalizeURLFailureCompletesService(t *testing.T) {
	svc := ProbeURL(context.Background(), "not-a-url-with-scheme", 50*time.Millisecond, "")
	if svc.Error == "" {
		t.Fatal("expected an error for a malformed URL")
	}
	if svc.URL == "" || svc.Protocol == "" {
		t.Fatalf("malformed-URL Service incomplete: URL=%q Protocol=%q", svc.URL, svc.Protocol)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
