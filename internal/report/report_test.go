package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

func sampleResult() *model.Result {
	start := time.Date(2026, 6, 26, 10, 11, 12, 0, time.Local)
	return &model.Result{
		Scan: model.ScanInfo{
			ID:         "scan-report-test",
			Version:    "test",
			Status:     "completed",
			StartedAt:  start,
			FinishedAt: start.Add(3 * time.Second),
			Duration:   "3s",
			POC: model.POCInfo{
				Engine:      "nuclei",
				Executed:    true,
				TemplateDir: `D:\Temp\templates`,
				Targets:     2,
				Findings:    2,
				Duration:    "1s",
				Tags:        []string{"cve", "exposure"},
				Severity:    "critical,high",
				IDs:         []string{"springx-one", "springx-two"},
			},
			POCExecuted: true,
		},
		Parameters: map[string]any{
			"web":        true,
			"no-browser": true,
			"compat": map[string]any{
				"dbs": true,
			},
		},
		Targets: []model.Service{
			{Host: "example.com", Port: 443, Protocol: "WEB应用", Scheme: "https", URL: "https://example.com/", StatusCode: 200, Title: "Example", Server: "nginx", Technologies: []string{"Nginx", "PHP"}, ContentType: "text/html", FaviconHash: "12345"},
			{Host: "127.0.0.1", Port: 8080, Protocol: "http", URL: "http://127.0.0.1:8080/", StatusCode: 200, Title: "Local", Server: "go", Technologies: []string{"Go"}, ContentType: "text/plain"},
		},
		Vulnerabilities: []model.Vulnerability{
			{Engine: "nuclei", TemplateID: "springx-one", Name: "One", Severity: "high", Target: "https://example.com/", MatchedAt: "https://example.com/one", Timestamp: start},
			{Engine: "nuclei", TemplateID: "springx-two", Name: "Two", Severity: "critical", Target: "http://127.0.0.1:8080/", MatchedAt: "http://127.0.0.1:8080/two", Timestamp: start},
		},
		Logs: []string{"log one", "log two"},
	}
}

func TestRenderHTMLStructureAndCounts(t *testing.T) {
	html := RenderHTML(sampleResult())

	if got := strings.Count(html, `<td class="severity-`); got != 2 {
		t.Fatalf("html vulnerability rows = %d, want 2", got)
	}
	if got := strings.Count(html, "<td>example.com</td>") + strings.Count(html, "<td>127.0.0.1</td>"); got != 2 {
		t.Fatalf("html service rows = %d, want 2", got)
	}
	for _, want := range []string{
		"<h1>SpringX 扫描报告</h1>",
		"<h2>POC 状态</h2>",
		"<h2>存活服务</h2>",
		"<h2>POC 发现</h2>",
		"<h2>参数摘要</h2>",
		"springx-one",
		"springx-two",
		"severity-critical",
		"WEB应用",
		"Nginx, PHP",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("html report missing %q", want)
		}
	}
}

func TestRenderMarkdownStructureAndCounts(t *testing.T) {
	md := RenderMarkdown(sampleResult())

	if got := strings.Count(md, "| "); got < 48 {
		t.Fatalf("markdown table cells look too few: %d", got)
	}
	if got := strings.Count(md, "springx-"); got != 4 {
		t.Fatalf("markdown springx template references = %d, want 4", got)
	}
	for _, want := range []string{
		"# SpringX 扫描报告",
		"## 扫描概览",
		"## 存活服务",
		"## POC 发现",
		"| # | 主机 | 端口 | 协议 | 状态 | 标题 | Server | 技术栈 | 内容类型 | Favicon | URL |",
		"| # | 严重级别 | 模板 | 名称 | 目标 | 匹配 |",
		"- `web`: `true`",
		"- `no-browser`: `true`",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown report missing %q", want)
		}
	}
}

func TestWriteAllUsesSameResultForEveryFormat(t *testing.T) {
	result := sampleResult()
	paths, err := WriteAll(result, t.TempDir())
	if err != nil {
		t.Fatalf("WriteAll returned error: %v", err)
	}

	if filepath.Base(paths.HTML) != "SpringX-Scan-20260626-101112.html" {
		t.Fatalf("unexpected html path: %s", paths.HTML)
	}
	for _, path := range []string{paths.HTML, paths.Markdown, paths.JSON} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("report file missing: %s (%v)", path, err)
		}
	}

	var decoded model.Result
	data, err := os.ReadFile(paths.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Targets) != len(result.Targets) || len(decoded.Vulnerabilities) != len(result.Vulnerabilities) {
		t.Fatalf("json counts differ: targets=%d/%d vulns=%d/%d", len(decoded.Targets), len(result.Targets), len(decoded.Vulnerabilities), len(result.Vulnerabilities))
	}

	md, err := os.ReadFile(paths.Markdown)
	if err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(paths.HTML)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(md), "springx-") != 4 {
		t.Fatalf("markdown did not preserve two vulnerability rows and two ID filters")
	}
	if strings.Count(string(html), "springx-") != 4 {
		t.Fatalf("html did not preserve two vulnerability rows and two ID filters")
	}
}
