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
				Engine:          "nuclei",
				Executed:        true,
				TemplateDir:     `D:\Temp\templates`,
				TemplateCount:   100,
				TemplateVersion: "test-v1",
				Targets:         2,
				Findings:        2,
				Duration:        "1s",
				Tags:            []string{"cve", "exposure"},
				Severity:        "critical,high",
				IDs:             []string{"springx-one", "springx-two"},
			},
			POCExecuted: true,
		},
		Parameters: map[string]any{
			"url":        "https://example.com",
			"threads":    5,
			"ports":      "TOP100",
			"nopoc":      false,
			"web":        true,
			"no-browser": true,
			"compat":     map[string]any{"dbs": true},
		},
		Targets: []model.Service{
			{Host: "example.com", Port: 443, Protocol: "WEB应用", Scheme: "https", URL: "https://example.com/", StatusCode: 200, Title: "Example", Server: "nginx", Technologies: []string{"Nginx", "PHP"}, ContentType: "text/html", FaviconHash: "12345"},
			{Host: "127.0.0.1", Port: 8080, Protocol: "http", URL: "http://127.0.0.1:8080/", StatusCode: 200, Title: "Local", Server: "go", Technologies: []string{"Go"}, ContentType: "text/plain", Banner: "SSH-2.0-OpenSSH_8.9"},
		},
		Vulnerabilities: []model.Vulnerability{
			{
				Engine: "nuclei", TemplateID: "springx-one", Name: "SpringX One", Severity: "high",
				Target: "https://example.com/", MatchedAt: "https://example.com/one", Type: "http",
				Description: "Test vulnerability one", Impact: "Data exposure risk",
				Timestamp: start,
				CVE:       []string{"CVE-2026-0001"},
				CWE:       []string{"CWE-552"},
				CVSSScore: 7.5, CVSSMetrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Remediation: "Upgrade to latest version",
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-0001"},
				Tags:        []string{"cve", "exposure"},
				Metadata:    map[string]any{"vendor": "SpringX"},
			},
			{
				Engine: "nuclei", TemplateID: "springx-two", Name: "SpringX Two", Severity: "critical",
				Target: "http://127.0.0.1:8080/", MatchedAt: "http://127.0.0.1:8080/two", Type: "http",
				Description: "Test vulnerability two",
				Timestamp:   start,
				CVE:         []string{"CVE-2026-0002"},
				CVSSScore:   9.8,
				CURLCommand: "curl -X GET http://127.0.0.1:8080/two",
			},
		},
		Logs: []string{"log one", "log two"},
	}
}

func TestRenderHTMLStructureAndCounts(t *testing.T) {
	html := RenderHTML(sampleResult())

	// Vulnerability cards: one per finding.
	if got := strings.Count(html, "vuln-card"); got < 2 {
		t.Fatalf("html vuln-card count = %d, want >=2", got)
	}
	// Service rows: host cells present.
	if got := strings.Count(html, "example.com") + strings.Count(html, "127.0.0.1"); got < 3 {
		t.Fatalf("html service/vuln host mentions = %d, want >=3", got)
	}
	for _, want := range []string{
		"SpringX 安全扫描报告",
		"执行摘要",
		"扫描范围",
		"服务探测结果",
		"漏洞详情",
		"扫描参数",
		"任务日志",
		"springx-one",
		"springx-two",
		"sev-pill high",
		"sev-pill critical",
		"CVSS 7.5",
		"CVSS 9.8",
		"CVE-2026-0001",
		"CWE-552",
		"修复建议",
		"Upgrade to latest version",
		"参考链接",
		"nvd.nist.gov",
		"复现命令",
		"curl",
		"Nginx, PHP",
		"整体风险评级",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("html report missing %q", want)
		}
	}
}

func TestRenderMarkdownStructureAndCounts(t *testing.T) {
	mdOut := RenderMarkdown(sampleResult())

	// Two vulnerability template IDs appear once each in the detail sections.
	if got := strings.Count(mdOut, "springx-"); got < 2 {
		t.Fatalf("markdown springx template references = %d, want >=2", got)
	}
	for _, want := range []string{
		"# SpringX 安全扫描报告",
		"## 执行摘要",
		"## 扫描范围",
		"## 服务探测结果",
		"## 漏洞详情",
		"## 扫描参数",
		"## 任务日志",
		"springx-one",
		"springx-two",
		"CVE-2026-0001",
		"CWE-552",
		"CVSS: 7.5",
		"修复建议",
		"Upgrade to latest version",
		"参考链接",
		"复现命令",
		"整体风险评级",
	} {
		if !strings.Contains(mdOut, want) {
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
	// Verify new structured fields survived JSON round-trip.
	if decoded.Vulnerabilities[0].CVE[0] != "CVE-2026-0001" {
		t.Fatalf("CVE field lost in JSON: %v", decoded.Vulnerabilities[0].CVE)
	}
	if decoded.Vulnerabilities[0].CVSSScore != 7.5 {
		t.Fatalf("CVSSScore field lost in JSON: %v", decoded.Vulnerabilities[0].CVSSScore)
	}

	md, err := os.ReadFile(paths.Markdown)
	if err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(paths.HTML)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(md), "springx-") < 2 {
		t.Fatalf("markdown did not preserve vulnerability template IDs")
	}
	if strings.Count(string(html), "springx-") < 2 {
		t.Fatalf("html did not preserve vulnerability template IDs")
	}
}

func TestCleanURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://127.0.0.1:19999//.env", "http://127.0.0.1:19999/.env"},
		{"https://example.com//double//slash", "https://example.com/double/slash"},
		{"http://example.com/normal", "http://example.com/normal"},
		{"not-a-url", "not-a-url"},
	}
	for _, c := range cases {
		if got := cleanURL(c.in); got != c.want {
			t.Errorf("cleanURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSeverityWeight(t *testing.T) {
	cases := []struct {
		sev  string
		want int
	}{
		{"critical", 5}, {"high", 4}, {"medium", 3}, {"low", 2}, {"info", 1},
		{"CRITICAL", 5}, {"unknown", 0}, {"", 0},
	}
	for _, c := range cases {
		if got := severityWeight(c.sev); got != c.want {
			t.Errorf("severityWeight(%q) = %d, want %d", c.sev, got, c.want)
		}
	}
}

func TestRiskLevel(t *testing.T) {
	if got := riskLevel(nil); got != "无风险" {
		t.Errorf("riskLevel(nil) = %q, want 无风险", got)
	}
	vulns := []model.Vulnerability{{Severity: "medium"}, {Severity: "high"}}
	if got := riskLevel(vulns); got != "高" {
		t.Errorf("riskLevel = %q, want 高", got)
	}
	vulns = []model.Vulnerability{{Severity: "critical"}}
	if got := riskLevel(vulns); got != "极高" {
		t.Errorf("riskLevel = %q, want 极高", got)
	}
}

func TestFilterParams(t *testing.T) {
	params := map[string]any{
		"url":      "http://example.com",
		"threads":  5,
		"nopoc":    false,
		"web":      true,
		"platform": "",
		"dbs":      true,
	}
	fp := filterParams(params)
	if _, ok := fp["nopoc"]; ok {
		t.Error("filterParams should remove false values")
	}
	if _, ok := fp["dbs"]; ok {
		t.Error("filterParams should remove compat flags")
	}
	if _, ok := fp["web"]; ok {
		t.Error("filterParams should remove web compat flag")
	}
	if _, ok := fp["url"]; !ok {
		t.Error("filterParams should keep url")
	}
	if _, ok := fp["threads"]; !ok {
		t.Error("filterParams should keep threads")
	}
}
