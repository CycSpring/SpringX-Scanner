package report

import (
	"bytes"
	"html/template"
	"sort"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

func RenderHTML(result *model.Result) string {
	funcs := template.FuncMap{
		"formatTime": formatTime,
		"join":       join,
		"sortedKeys": sortedKeys,
		"param":      func(m map[string]any, key string) any { return m[key] },
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
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for _, value := range values[1:] {
		out += ", " + value
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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
  <title>SpringX 扫描报告</title>
  <style>
    :root { color-scheme: dark; --bg: #0c1218; --panel: #121d29; --line: #2d4057; --text: #edf6ff; --muted: #9fb2c7; --blue: #2da8ff; --green: #22c55e; --red: #ef4444; --yellow: #f59e0b; }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", Arial, sans-serif; line-height: 1.55; }
    main { max-width: 1180px; margin: 0 auto; padding: 32px 24px 56px; }
    h1 { margin: 0 0 8px; font-size: 32px; letter-spacing: 0; }
    h2 { margin: 34px 0 14px; padding-bottom: 8px; border-bottom: 1px solid var(--line); font-size: 22px; }
    .muted { color: var(--muted); }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-top: 20px; }
    .metric { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
    .metric strong { display: block; font-size: 24px; color: var(--blue); }
    table { width: 100%; border-collapse: collapse; overflow-wrap: anywhere; }
    th, td { border-bottom: 1px solid var(--line); padding: 10px 12px; text-align: left; vertical-align: top; }
    th { background: #18283a; color: #d9ebff; }
    tr:hover td { background: rgba(45, 168, 255, .06); }
    code, pre { font-family: Consolas, "Cascadia Mono", monospace; }
    pre { background: #071017; border: 1px solid var(--line); border-radius: 8px; padding: 14px; max-height: 420px; overflow: auto; }
    .badge { display: inline-block; border-radius: 999px; padding: 2px 8px; background: #19324a; color: #bfe4ff; font-size: 12px; }
    .severity-critical { color: #ff7b72; font-weight: 700; }
    .severity-high { color: #ffa657; font-weight: 700; }
    .severity-medium { color: #f2cc60; font-weight: 700; }
    .severity-low { color: #7ee787; font-weight: 700; }
    .severity-info { color: #79c0ff; font-weight: 700; }
    a { color: #79c0ff; }
  </style>
</head>
<body>
<main>
  <h1>SpringX 扫描报告</h1>
  <div class="muted">任务 {{.Scan.ID}} · {{.Scan.Version}} · {{formatTime .Scan.StartedAt}} - {{formatTime .Scan.FinishedAt}}</div>
  <section class="summary">
    <div class="metric"><span>状态</span><strong>{{.Scan.Status}}</strong></div>
    <div class="metric"><span>耗时</span><strong>{{.Scan.Duration}}</strong></div>
    <div class="metric"><span>存活服务</span><strong>{{len .Targets}}</strong></div>
    <div class="metric"><span>POC 发现</span><strong>{{len .Vulnerabilities}}</strong></div>
  </section>

  {{if .Scan.POCSkipped}}<p class="muted">POC 未执行：{{.Scan.POCSkipReason}}</p>{{end}}
  {{if .Scan.POC.Engine}}
  <h2>POC 状态</h2>
  <table>
    <tbody>
      <tr><th>引擎</th><td>{{.Scan.POC.Engine}}</td></tr>
      <tr><th>模板目录</th><td><code>{{.Scan.POC.TemplateDir}}</code></td></tr>
      <tr><th>目标数</th><td>{{.Scan.POC.Targets}}</td></tr>
      <tr><th>发现数</th><td>{{.Scan.POC.Findings}}</td></tr>
      <tr><th>耗时</th><td>{{.Scan.POC.Duration}}</td></tr>
      <tr><th>Tags</th><td>{{join .Scan.POC.Tags}}</td></tr>
      <tr><th>Severity</th><td>{{.Scan.POC.Severity}}</td></tr>
      <tr><th>IDs</th><td>{{join .Scan.POC.IDs}}</td></tr>
      {{if .Scan.POC.SkipReason}}<tr><th>跳过原因</th><td>{{.Scan.POC.SkipReason}}</td></tr>{{end}}
      {{if .Scan.POC.Error}}<tr><th>错误</th><td>{{.Scan.POC.Error}}</td></tr>{{end}}
    </tbody>
  </table>
  {{end}}
  {{if .Scan.Errors}}<p class="muted">错误：{{join .Scan.Errors}}</p>{{end}}

  <h2>存活服务</h2>
  {{if .Targets}}
  <table>
    <thead><tr><th>#</th><th>主机</th><th>端口</th><th>协议</th><th>状态</th><th>标题</th><th>Server</th><th>URL</th></tr></thead>
    <tbody>
      {{range $i, $svc := .Targets}}
      <tr>
        <td>{{$i}}</td><td>{{$svc.Host}}</td><td>{{$svc.Port}}</td><td>{{$svc.Protocol}}</td><td>{{$svc.StatusCode}}</td><td>{{$svc.Title}}</td><td>{{$svc.Server}}</td><td>{{if $svc.URL}}<a href="{{$svc.URL}}">{{$svc.URL}}</a>{{end}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}<p class="muted">未发现存活服务。</p>{{end}}

  <h2>POC 发现</h2>
  {{if .Vulnerabilities}}
  <table>
    <thead><tr><th>#</th><th>严重级别</th><th>模板</th><th>名称</th><th>目标</th><th>匹配</th></tr></thead>
    <tbody>
      {{range $i, $v := .Vulnerabilities}}
      <tr>
        <td>{{$i}}</td><td class="severity-{{$v.Severity}}">{{$v.Severity}}</td><td>{{$v.TemplateID}}</td><td>{{$v.Name}}</td><td>{{$v.Target}}</td><td>{{$v.MatchedAt}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}<p class="muted">{{if .Scan.POCSkipped}}POC 未执行：{{.Scan.POCSkipReason}}。{{else}}未发现 POC 结果。{{end}}</p>{{end}}

  <h2>参数摘要</h2>
  {{if .Parameters}}
  <table>
    <thead><tr><th>参数</th><th>值</th></tr></thead>
    <tbody>{{range $key := sortedKeys .Parameters}}<tr><td><code>{{$key}}</code></td><td><code>{{param $.Parameters $key}}</code></td></tr>{{end}}</tbody>
  </table>
  {{else}}<p class="muted">无参数记录。</p>{{end}}

  <h2>任务日志</h2>
  {{if .Logs}}<pre>{{range .Logs}}{{.}}
{{end}}</pre>{{else}}<p class="muted">无日志。</p>{{end}}
</main>
</body>
</html>`
