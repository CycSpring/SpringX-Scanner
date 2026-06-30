package scan

import (
	"runtime"
	"testing"
	"time"
)

func TestConfigParametersIncludeCompatibilityAndTempDir(t *testing.T) {
	tempDir := t.TempDir()
	cfg := Config{
		Web:       true,
		NoBrowser: true,
		NoPOC:     true,
		TempDir:   tempDir,
		AcceptedCompatFlags: map[string]any{
			"dbs":           true,
			"risk":          false,
			"xray-poc-name": "spring-test",
		},
	}
	params := cfg.Parameters()

	if params["web"] != true {
		t.Fatalf("web parameter = %v, want true", params["web"])
	}
	if params["no-browser"] != true {
		t.Fatalf("no-browser parameter = %v, want true", params["no-browser"])
	}
	if params["temp-dir"] != tempDir {
		t.Fatalf("temp-dir parameter = %v, want %s", params["temp-dir"], tempDir)
	}
	compat, ok := params["compat"].(map[string]any)
	if !ok {
		t.Fatalf("compat parameter has type %T", params["compat"])
	}
	if compat["dbs"] != true || compat["xray-poc-name"] != "spring-test" {
		t.Fatalf("unexpected compat parameters: %#v", compat)
	}
}

func TestConfigGetTempDirPrecedence(t *testing.T) {
	explicit := t.TempDir()
	t.Setenv("SPRINGX_TEMP_DIR", t.TempDir())
	if got := (Config{TempDir: explicit}).GetTempDir(); got != explicit {
		t.Fatalf("explicit temp dir = %s, want %s", got, explicit)
	}

	envTemp := t.TempDir()
	t.Setenv("SPRINGX_TEMP_DIR", envTemp)
	if got := (Config{}).GetTempDir(); got != envTemp {
		t.Fatalf("env temp dir = %s, want %s", got, envTemp)
	}
}

func TestConfigGetTempDirWindowsDefaultOrOSFallback(t *testing.T) {
	t.Setenv("SPRINGX_TEMP_DIR", "")
	got := (Config{}).GetTempDir()
	if got == "" {
		t.Fatal("default temp dir is empty")
	}
	if runtime.GOOS == "windows" {
		if got != `D:\Temp` {
			t.Fatalf("windows default temp dir = %s, want D:\\Temp", got)
		}
	}
}

func TestHttpConcurrency(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, 10},    // default
		{-1, 10},   // negative -> default
		{1, 1},     // minimum
		{50, 50},   // mid range
		{100, 100}, // maximum
		{101, 100}, // clamp high
		{500, 100}, // clamp high
	}
	for _, c := range cases {
		if got := (Config{HTTPConcurrency: c.in}).HttpConcurrency(); got != c.want {
			t.Fatalf("HttpConcurrency(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestHTTPTimeout(t *testing.T) {
	if got := (Config{}).HTTPTimeout(); got != 10*time.Second {
		t.Fatalf("default HTTPTimeout = %v, want 10s", got)
	}
	if got := (Config{HTTPTimeoutSec: 20}).HTTPTimeout(); got != 20*time.Second {
		t.Fatalf("HTTPTimeout(20) = %v, want 20s", got)
	}
	if got := (Config{HTTPTimeoutSec: -1}).HTTPTimeout(); got != 10*time.Second {
		t.Fatalf("negative HTTPTimeout = %v, want 10s default", got)
	}
}
