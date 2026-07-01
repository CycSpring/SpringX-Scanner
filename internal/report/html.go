package report

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

// sevOrder maps severity names to a sort weight so findings can be ordered by
// descending risk in the report.
var sevOrder = map[string]int{
	"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0, "": 0,
}

func RenderHTML(result *model.Result) string {
	funcs := template.FuncMap{
		"add":            func(a, b int) int { return a + b },
		"formatTime":     formatTime,
		"join":           join,
		"joinNonEmpty":   joinNonEmpty,
		"sortedKeys":     sortedKeys,
		"param":          func(m map[string]any, key string) any { return m[key] },
		"cleanURL":       cleanURL,
		"severityClass":  severityClass,
		"severityLabel":  severityLabel,
		"severityWeight": severityWeight,
		"hasCVSS":        func(v model.Vulnerability) bool { return v.CVSSScore > 0 },
		"cvssText":       cvssText,
		"sevCounts":      sevCounts,
		"riskLevel":      riskLevel,
		"riskClass":      riskClass,
		"filterParams":   filterParams,
		"hasVulnDetail":  hasVulnDetail,
		"isLink":         isLink,
		"zhName":         translateVulnName,
		"remediation":    defaultRemediation,
	}
	tpl := template.Must(template.New("report").Funcs(funcs).Parse(htmlTemplate))
	var b bytes.Buffer
	_ = tpl.Execute(&b, result)
	return b.String()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

func join(values []string) string {
	return strings.Join(values, ", ")
}

func joinNonEmpty(values []string) string {
	var out []string
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, ", ")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// cleanURL collapses accidental double slashes in a URL path while preserving
// the scheme separator (://). This fixes nuclei's habit of appending "/.env"
// to a target already ending with "/".
func cleanURL(s string) string {
	idx := strings.Index(s, "://")
	if idx < 0 {
		return s
	}
	scheme := s[:idx+3]
	rest := s[idx+3:]
	for strings.Contains(rest, "//") {
		rest = strings.ReplaceAll(rest, "//", "/")
	}
	return scheme + rest
}

func severityClass(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		return "unknown"
	}
}

func severityLabel(sev string) string {
	switch severityClass(sev) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "info":
		return "信息"
	default:
		return sev
	}
}

func severityWeight(sev string) int {
	return sevOrder[strings.ToLower(strings.TrimSpace(sev))]
}

func cvssText(score float64) string {
	if score <= 0 {
		return ""
	}
	return fmt.Sprintf("%.1f", score)
}

// sevCounts returns counts per severity level for the executive summary.
func sevCounts(vulns []model.Vulnerability) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, v := range vulns {
		switch severityClass(v.Severity) {
		case "critical":
			counts["critical"]++
		case "high":
			counts["high"]++
		case "medium":
			counts["medium"]++
		case "low":
			counts["low"]++
		case "info":
			counts["info"]++
		}
	}
	return counts
}

// riskLevel computes the overall risk rating from the highest-severity finding.
func riskLevel(vulns []model.Vulnerability) string {
	max := 0
	for _, v := range vulns {
		w := severityWeight(v.Severity)
		if w > max {
			max = w
		}
	}
	switch max {
	case 5:
		return "极高"
	case 4:
		return "高"
	case 3:
		return "中"
	case 2:
		return "低"
	case 1:
		return "信息"
	default:
		return "无风险"
	}
}

func riskClass(level string) string {
	switch level {
	case "极高":
		return "critical"
	case "高":
		return "high"
	case "中":
		return "medium"
	case "低":
		return "low"
	case "信息":
		return "info"
	default:
		return "none"
	}
}

// filterParams removes empty values, compatibility flags, and nested maps
// (like the "compat" summary) that carry no useful information, keeping the
// parameter summary concise.
func filterParams(params map[string]any) map[string]any {
	skip := map[string]bool{
		"":      true,
		"[]":    true,
		"false": true,
		"map[]": true,
	}
	skipKeys := map[string]bool{
		"dbs": true, "risk": true, "deep-scan": true, "nocrack": true,
		"noimg": true, "random": true, "rdp": true, "spy-only": true,
		"xray-poc-name": true, "engines": true, "platform": true,
		"chan": true, "noping": true, "no-browser": true, "web": true,
		"compat": true,
	}
	out := map[string]any{}
	for k, v := range params {
		if skipKeys[k] {
			continue
		}
		// Skip nested maps (e.g. compat summary rendered as map[...]).
		if _, ok := v.(map[string]any); ok {
			continue
		}
		s := fmt.Sprintf("%v", v)
		if s == "" || skip[s] {
			continue
		}
		out[k] = v
	}
	return out
}

// hasVulnDetail returns true if the vulnerability has any of the richer
// fields that warrant a detail card section.
func hasVulnDetail(v model.Vulnerability) bool {
	return v.Description != "" || v.Impact != "" || v.Remediation != "" ||
		len(v.References) > 0 || len(v.CVE) > 0 || len(v.CWE) > 0 ||
		v.CVSSScore > 0 || v.RequestSummary != "" || v.CURLCommand != ""
}

func isLink(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

const htmlTemplate = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SpringX 安全扫描报告</title>
  <style>
    :root { color-scheme: dark; --bg: #0c1218; --panel: #121d29; --panel-2: #18283a; --line: #2d4057; --text: #edf6ff; --muted: #9fb2c7; --blue: #2da8ff; --green: #22c55e; --red: #ef4444; --yellow: #f59e0b; --orange: #f97316; }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", Arial, sans-serif; line-height: 1.6; }
    main { max-width: 1180px; margin: 0 auto; padding: 32px 24px 56px; }
    h1 { margin: 0 0 4px; font-size: 30px; }
    h2 { margin: 36px 0 14px; padding-bottom: 8px; border-bottom: 2px solid var(--blue); font-size: 20px; }
    h3 { margin: 20px 0 8px; font-size: 16px; color: var(--muted); }
    .muted { color: var(--muted); }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-top: 20px; }
    .metric { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px; text-align: center; }
    .metric span { display: block; color: var(--muted); font-size: 12px; margin-bottom: 4px; }
    .metric strong { font-size: 28px; }
    .metric.critical strong { color: var(--red); }
    .metric.high strong { color: var(--orange); }
    .metric.medium strong { color: var(--yellow); }
    .metric.low strong { color: var(--green); }
    .metric.info strong { color: var(--blue); }
    .metric.none strong { color: var(--green); }
    .risk-badge { display: inline-block; border-radius: 999px; padding: 4px 14px; font-size: 14px; font-weight: 700; }
    .risk-badge.critical { background: rgba(239,68,68,.15); color: #f87171; border: 1px solid rgba(239,68,68,.3); }
    .risk-badge.high { background: rgba(249,115,22,.15); color: #fb923c; border: 1px solid rgba(249,115,22,.3); }
    .risk-badge.medium { background: rgba(245,158,11,.15); color: #fbbf24; border: 1px solid rgba(245,158,11,.3); }
    .risk-badge.low { background: rgba(34,197,94,.15); color: #4ade80; border: 1px solid rgba(34,197,94,.3); }
    .risk-badge.info { background: rgba(45,168,255,.15); color: #60a5fa; border: 1px solid rgba(45,168,255,.3); }
    .risk-badge.none { background: rgba(34,197,94,.15); color: #4ade80; border: 1px solid rgba(34,197,94,.3); }
    table { width: 100%; border-collapse: collapse; overflow-wrap: anywhere; }
    th, td { border-bottom: 1px solid var(--line); padding: 10px 12px; text-align: left; vertical-align: top; }
    th { background: var(--panel-2); color: #d9ebff; font-size: 13px; }
    tr:hover td { background: rgba(45, 168, 255, .04); }
    code, pre { font-family: Consolas, "Cascadia Mono", monospace; }
    code { background: var(--panel-2); padding: 2px 6px; border-radius: 4px; font-size: 13px; }
    pre { background: #071017; border: 1px solid var(--line); border-radius: 8px; padding: 14px; overflow: auto; max-height: 400px; font-size: 12px; white-space: pre-wrap; word-break: break-all; }
    details { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; margin: 8px 0; }
    details > summary { padding: 10px 14px; cursor: pointer; font-size: 14px; color: var(--muted); user-select: none; }
    details > summary:hover { color: var(--text); }
    details[open] > summary { border-bottom: 1px solid var(--line); }
    .vuln-card { background: var(--panel); border: 1px solid var(--line); border-left: 4px solid var(--line); border-radius: 10px; padding: 0; margin: 14px 0; overflow: hidden; }
    .vuln-card.critical { border-left-color: var(--red); }
    .vuln-card.high { border-left-color: var(--orange); }
    .vuln-card.medium { border-left-color: var(--yellow); }
    .vuln-card.low { border-left-color: var(--green); }
    .vuln-card.info { border-left-color: var(--blue); }
    .vuln-card.unknown { border-left-color: var(--muted); }
    .vuln-head { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; flex-wrap: wrap; gap: 8px; }
    .vuln-title { font-size: 16px; font-weight: 600; }
    .vuln-title .tid { color: var(--muted); font-weight: 400; font-size: 13px; margin-left: 8px; }
    .vuln-tags { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .sev-pill { display: inline-block; border-radius: 999px; padding: 3px 10px; font-size: 12px; font-weight: 700; }
    .sev-pill.critical { background: rgba(239,68,68,.15); color: #f87171; }
    .sev-pill.high { background: rgba(249,115,22,.15); color: #fb923c; }
    .sev-pill.medium { background: rgba(245,158,11,.15); color: #fbbf24; }
    .sev-pill.low { background: rgba(34,197,94,.15); color: #4ade80; }
    .sev-pill.info { background: rgba(45,168,255,.15); color: #60a5fa; }
    .sev-pill.unknown { background: rgba(159,178,199,.15); color: var(--muted); }
    .cvss-pill { display: inline-block; border-radius: 4px; padding: 3px 8px; font-size: 13px; font-weight: 700; background: var(--panel-2); }
    .vuln-body { padding: 0 18px 16px; }
    .vuln-body .field { margin: 10px 0; }
    .vuln-body .label { color: var(--muted); font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 2px; }
    .vuln-body .value { font-size: 14px; }
    .vuln-body a { color: #60a5fa; word-break: break-all; }
    .ref-list { margin: 4px 0 0; padding-left: 18px; }
    .ref-list li { margin: 2px 0; }
    .toc { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px 18px; margin: 16px 0; }
    .toc a { color: var(--blue); text-decoration: none; }
    .toc a:hover { text-decoration: underline; }
    .toc ol { margin: 0; padding-left: 20px; }
    a { color: #60a5fa; }
  </style>
</head>
<body>
<main>
  <h1>SpringX 安全扫描报告</h1>
  <div class="muted">扫描任务 {{.Scan.ID}} · 引擎版本 {{.Scan.Version}}</div>
  <div class="muted">{{formatTime .Scan.StartedAt}} — {{formatTime .Scan.FinishedAt}}（耗时 {{.Scan.Duration}}）</div>

  {{if gt (len .Vulnerabilities) 0}}
  <div style="margin:16px 0">
    <span class="muted">整体风险评级：</span>
    <span class="risk-badge {{riskClass (riskLevel .Vulnerabilities)}}">{{riskLevel .Vulnerabilities}}</span>
  </div>
  {{else}}
  <div style="margin:16px 0">
    <span class="muted">整体风险评级：</span>
    <span class="risk-badge none">无风险</span>
  </div>
  {{end}}

  {{/* ===== Executive Summary ===== */}}
  <h2>执行摘要</h2>
  {{ $counts := sevCounts .Vulnerabilities }}
  <section class="summary">
    <div class="metric critical"><span>严重</span><strong>{{$counts.critical}}</strong></div>
    <div class="metric high"><span>高危</span><strong>{{$counts.high}}</strong></div>
    <div class="metric medium"><span>中危</span><strong>{{$counts.medium}}</strong></div>
    <div class="metric low"><span>低危</span><strong>{{$counts.low}}</strong></div>
    <div class="metric info"><span>信息</span><strong>{{$counts.info}}</strong></div>
  </section>
  <p class="muted" style="margin-top:14px">
    本次扫描共发现 <strong>{{len .Vulnerabilities}}</strong> 个漏洞，探测到 <strong>{{len .Targets}}</strong> 个存活服务。
    {{if gt (len .Vulnerabilities) 0}}
    建议优先修复严重及高危漏洞。
    {{else}}
    未发现安全漏洞。
    {{end}}
    {{if .Scan.POCSkipped}}POC 阶段未执行：{{.Scan.POCSkipReason}}。{{end}}
    {{if .Scan.Errors}}扫描过程出现错误：{{join .Scan.Errors}}。{{end}}
  </p>

  {{/* ===== Table of Contents ===== */}}
  <div class="toc">
    <span class="muted">目录</span>
    <ol>
      <li><a href="#scope">扫描范围</a></li>
      <li><a href="#services">服务探测结果</a></li>
      {{if gt (len .Vulnerabilities) 0}}<li><a href="#vulns">漏洞详情</a></li>{{end}}
      <li><a href="#params">扫描参数</a></li>
      <li><a href="#logs">任务日志</a></li>
    </ol>
  </div>

  {{/* ===== Scope ===== */}}
  <h2 id="scope">扫描范围</h2>
  <table>
    <tbody>
      <tr><th>扫描状态</th><td>{{.Scan.Status}}</td></tr>
      <tr><th>目标数</th><td>{{len .Targets}}</td></tr>
      {{if .Scan.POC.Engine}}
      <tr><th>POC 引擎</th><td>{{.Scan.POC.Engine}}（模板 {{.Scan.POC.TemplateCount}} 个{{if .Scan.POC.TemplateVersion}}，版本 {{.Scan.POC.TemplateVersion}}{{end}}）</td></tr>
      {{if .Scan.POC.Tags}}<tr><th>Nuclei Tags</th><td><code>{{join .Scan.POC.Tags}}</code></td></tr>{{end}}
      {{if .Scan.POC.Severity}}<tr><th>Nuclei Severity</th><td><code>{{.Scan.POC.Severity}}</code></td></tr>{{end}}
      {{end}}
    </tbody>
  </table>

  {{/* ===== Services ===== */}}
  <h2 id="services">服务探测结果</h2>
  {{if .Targets}}
  <table>
    <thead><tr><th>#</th><th>主机</th><th>端口</th><th>状态</th><th>标题</th><th>Server</th><th>技术栈</th><th>URL</th></tr></thead>
    <tbody>
      {{range $i, $svc := .Targets}}
      <tr>
        <td>{{add $i 1}}</td><td>{{$svc.Host}}</td><td>{{$svc.Port}}</td><td>{{$svc.StatusCode}}</td><td>{{$svc.Title}}</td><td>{{$svc.Server}}</td><td>{{join $svc.Technologies}}</td>
        <td>{{if $svc.URL}}<a href="{{$svc.URL}}">{{cleanURL $svc.URL}}</a>{{end}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}<p class="muted">未发现服务探测结果。</p>{{end}}

  {{/* ===== Vulnerability Details ===== */}}
  <h2 id="vulns">漏洞详情</h2>
  {{if .Vulnerabilities}}
    {{range $i, $v := .Vulnerabilities}}
    <div class="vuln-card {{severityClass $v.Severity}}">
      <div class="vuln-head">
        <div class="vuln-title">
          {{add $i 1}}. {{zhName $v}}
          <span class="tid">{{$v.TemplateID}}</span>
        </div>
        <div class="vuln-tags">
          <span class="sev-pill {{severityClass $v.Severity}}">{{severityLabel $v.Severity}}</span>
          {{if hasCVSS $v}}<span class="cvss-pill">CVSS {{cvssText $v.CVSSScore}}</span>{{end}}
          {{if $v.Type}}<span class="muted" style="font-size:12px">{{$v.Type}}</span>{{end}}
        </div>
      </div>
      <div class="vuln-body">
        {{if $v.Description}}
        <div class="field"><div class="label">描述</div><div class="value">{{$v.Description}}</div></div>
        {{end}}
        {{if $v.Impact}}
        <div class="field"><div class="label">影响</div><div class="value">{{$v.Impact}}</div></div>
        {{end}}
        <div class="field"><div class="label">受影响目标</div><div class="value">
          {{if isLink $v.MatchedAt}}<a href="{{$v.MatchedAt}}">{{cleanURL $v.MatchedAt}}</a>{{else if $v.Target}}<a href="{{$v.Target}}">{{cleanURL $v.Target}}</a>{{end}}
        </div></div>
        {{if or (len $v.CVE) (len $v.CWE) $v.CPE}}
        <div class="field"><div class="label">分类</div><div class="value">
          {{if $v.CVE}}<code>{{join $v.CVE}}</code> {{end}}
          {{if $v.CWE}}<code>{{join $v.CWE}}</code> {{end}}
          {{if $v.CPE}}<code>{{$v.CPE}}</code>{{end}}
        </div></div>
        {{end}}
        {{if $v.ExtractedResults}}
        <div class="field"><div class="label">提取结果</div><div class="value"><code>{{join $v.ExtractedResults}}</code></div></div>
        {{end}}
        <div class="field"><div class="label">修复建议</div><div class="value">{{remediation $v}}</div></div>
        {{if $v.References}}
        <div class="field"><div class="label">参考链接</div><ul class="ref-list">
          {{range $ref := $v.References}}<li><a href="{{$ref}}">{{$ref}}</a></li>{{end}}
        </ul></div>
        {{end}}
        {{if $v.CURLCommand}}
        <div class="field"><div class="label">复现命令</div><div class="value"><pre><code>{{$v.CURLCommand}}</code></pre></div></div>
        {{end}}
        {{if or $v.RequestSummary $v.ResponseSummary}}
        <details><summary>请求/响应证据</summary>
          {{if $v.RequestSummary}}<div class="field"><div class="label">请求</div><pre>{{$v.RequestSummary}}</pre></div>{{end}}
          {{if $v.ResponseSummary}}<div class="field"><div class="label">响应</div><pre>{{$v.ResponseSummary}}</pre></div>{{end}}
        </details>
        {{end}}
      </div>
    </div>
    {{end}}
  {{else}}<p class="muted">{{if .Scan.POCSkipped}}POC 未执行：{{.Scan.POCSkipReason}}。{{else}}未发现安全漏洞。{{end}}</p>{{end}}

  {{/* ===== Parameters ===== */}}
  <h2 id="params">扫描参数</h2>
  {{$fp := filterParams .Parameters}}
  {{if $fp}}
  <details open><summary>有效参数</summary>
  <table>
    <thead><tr><th>参数</th><th>值</th></tr></thead>
    <tbody>{{range $key := sortedKeys $fp}}<tr><td><code>{{$key}}</code></td><td><code>{{param $fp $key}}</code></td></tr>{{end}}</tbody>
  </table>
  </details>
  {{else}}<p class="muted">无有效参数。</p>{{end}}

  {{/* ===== Logs ===== */}}
  <h2 id="logs">任务日志</h2>
  {{if .Logs}}
  <details><summary>展开日志（{{len .Logs}} 行）</summary>
  <pre>{{range .Logs}}{{.}}
{{end}}</pre>
  </details>
  {{else}}<p class="muted">无日志。</p>{{end}}
</main>
</body>
</html>`
