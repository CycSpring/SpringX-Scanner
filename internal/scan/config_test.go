package scan

import (
	"runtime"
	"testing"
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
