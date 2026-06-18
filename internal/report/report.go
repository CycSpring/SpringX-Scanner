package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

// WriteAll renders HTML, Markdown, and JSON from the same structured result.
func WriteAll(result *model.Result, workDir string) (model.ReportPaths, error) {
	base := reportBaseName(result.Scan.StartedAt)
	paths := model.ReportPaths{
		HTML:     filepath.Join(workDir, "reports", "html", base+".html"),
		Markdown: filepath.Join(workDir, "reports", "markdown", base+".md"),
		JSON:     filepath.Join(workDir, "reports", "data", base+".json"),
	}
	if err := ensureDirs(paths); err != nil {
		return paths, err
	}

	result.Reports = paths

	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return paths, err
	}
	if err := os.WriteFile(paths.JSON, append(jsonBytes, '\n'), 0644); err != nil {
		return paths, err
	}
	if err := os.WriteFile(paths.Markdown, []byte(RenderMarkdown(result)), 0644); err != nil {
		return paths, err
	}
	if err := os.WriteFile(paths.HTML, []byte(RenderHTML(result)), 0644); err != nil {
		return paths, err
	}
	return paths, nil
}

func reportBaseName(start time.Time) string {
	if start.IsZero() {
		start = time.Now()
	}
	return fmt.Sprintf("SpringX-Scan-%s", start.Format("20060102-150405"))
}

func ensureDirs(paths model.ReportPaths) error {
	for _, path := range []string{paths.HTML, paths.Markdown, paths.JSON} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
	}
	return nil
}
