package scan

import (
	_ "embed"
	"os"
	"path/filepath"
)

// builtinSmokeTemplate is the embedded springx-smoke template, used only when a
// user explicitly opts in via --use-builtin-smoke-template (for testing). It is
// NOT a real vulnerability template, so it is never used as a silent fallback
// for production scans — a missing template directory still skips POC.
//
//go:embed assets/springx-smoke.yaml
var builtinSmokeTemplate []byte

// writeBuiltinSmokeTemplate writes the embedded smoke template into a temp
// directory and returns that directory path, so nuclei has at least one
// template to run. The caller is responsible for cleanup of tempDir's parent.
func writeBuiltinSmokeTemplate(tempDir string) (string, error) {
	dir := filepath.Join(tempDir, "springx-builtin-templates")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "springx-smoke.yaml"), builtinSmokeTemplate, 0o644); err != nil {
		return "", err
	}
	return dir, nil
}
