package scan

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestGrabBanner verifies that a connection-oriented service greeting (e.g. an
// SSH banner) is captured when the port is open. A small TCP listener sends
// the banner on connect, and isPortOpen should return it.
func TestGrabBanner(t *testing.T) {
	const sshBanner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte(sshBanner + "\r\n"))
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	open, banner := isPortOpen(context.Background(), "127.0.0.1", addr.Port, 2*time.Second)
	if !open {
		t.Fatal("isPortOpen returned false for a listening port")
	}
	if banner == "" {
		t.Fatal("expected a banner, got empty string")
	}
	if !strings.HasPrefix(banner, "SSH-2.0") {
		t.Fatalf("banner = %q, want an SSH greeting prefix", banner)
	}
	// Control characters must be stripped.
	if strings.ContainsAny(banner, "\r\n") {
		t.Fatalf("banner contains raw control chars: %q", banner)
	}
}

// TestGrabBannerSilentService verifies that a service that sends no greeting
// (e.g. an HTTP server waiting for the request first) yields an empty banner
// without hanging beyond the read deadline.
func TestGrabBannerSilentService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read nothing, write nothing; just hold the connection briefly.
			time.Sleep(100 * time.Millisecond)
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	start := time.Now()
	open, banner := isPortOpen(context.Background(), "127.0.0.1", addr.Port, 1*time.Second)
	elapsed := time.Since(start)
	if !open {
		t.Fatal("isPortOpen returned false for a listening port")
	}
	if banner != "" {
		t.Fatalf("expected empty banner for silent service, got %q", banner)
	}
	// Must not hang: the read deadline caps the wait. Allow generous slack for CI.
	if elapsed > 4*time.Second {
		t.Fatalf("isPortOpen took %v on a silent service, deadline should cap it", elapsed)
	}
}
