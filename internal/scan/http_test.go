package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
