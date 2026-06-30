package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

func RenderMarkdown(result *model.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# SpringX 扫描报告\n\n")
	fmt.Fprintf(&b, "## 扫描概览\n\n")
	fmt.Fprintf(&b, "- 状态: %s\n", result.Scan.Status)
	fmt.Fprintf(&b, "- 开始时间: %s\n", formatTime(result.Scan.StartedAt))
	fmt.Fprintf(&b, "- 结束时间: %s\n", formatTime(result.Scan.FinishedAt))
	fmt.Fprintf(&b, "- 耗时: %s\n", result.Scan.Duration)
	fmt.Fprintf(&b, "- 服务探测结果: %d\n", len(result.Targets))
	fmt.Fprintf(&b, "- POC 发现: %d\n", len(result.Vulnerabilities))
	if result.Scan.POC.Engine != "" {
		fmt.Fprintf(&b, "- POC 引擎: %s\n", result.Scan.POC.Engine)
		fmt.Fprintf(&b, "- POC 模板目录: `%s`\n", result.Scan.POC.TemplateDir)
		if result.Scan.POC.TemplateCount > 0 {
			fmt.Fprintf(&b, "- POC 模板数: %d\n", result.Scan.POC.TemplateCount)
		}
		if result.Scan.POC.TemplateVersion != "" {
			fmt.Fprintf(&b, "- POC 模板版本: %s\n", result.Scan.POC.TemplateVersion)
		}
		fmt.Fprintf(&b, "- POC 目标数: %d\n", result.Scan.POC.Targets)
		fmt.Fprintf(&b, "- POC 耗时: %s\n", md(firstNonEmpty(result.Scan.POC.Duration, "-")))
		if len(result.Scan.POC.Tags) > 0 {
			fmt.Fprintf(&b, "- Nuclei Tags: `%s`\n", strings.Join(result.Scan.POC.Tags, ","))
		}
		if result.Scan.POC.Severity != "" {
			fmt.Fprintf(&b, "- Nuclei Severity: `%s`\n", result.Scan.POC.Severity)
		}
		if len(result.Scan.POC.IDs) > 0 {
			fmt.Fprintf(&b, "- Nuclei IDs: `%s`\n", strings.Join(result.Scan.POC.IDs, ","))
		}
		if result.Scan.POC.Error != "" {
			fmt.Fprintf(&b, "- POC 错误: %s\n", result.Scan.POC.Error)
		}
	}
	if result.Scan.POCSkipped {
		fmt.Fprintf(&b, "- POC 状态: 未执行（%s）\n", result.Scan.POCSkipReason)
	} else if result.Scan.POCExecuted {
		fmt.Fprintf(&b, "- POC 状态: 已执行\n")
	}
	if len(result.Scan.Errors) > 0 {
		fmt.Fprintf(&b, "- 错误: %s\n", strings.Join(result.Scan.Errors, "; "))
	}

	fmt.Fprintf(&b, "\n## 服务探测结果\n\n")
	if len(result.Targets) == 0 {
		fmt.Fprintf(&b, "未发现服务探测结果。\n")
	} else {
		fmt.Fprintf(&b, "| # | 主机 | 端口 | 协议 | 状态 | 标题 | Server | 技术栈 | 内容类型 | Favicon | URL | Banner | 错误 |\n")
		fmt.Fprintf(&b, "|---:|---|---:|---|---:|---|---|---|---|---|---|---|---|\n")
		for i, svc := range result.Targets {
			fmt.Fprintf(&b, "| %d | %s | %d | %s | %d | %s | %s | %s | %s | %s | %s | %s | %s |\n",
				i+1, md(svc.Host), svc.Port, md(firstNonEmpty(svc.Protocol, svc.Scheme, svc.Service)),
				svc.StatusCode, md(svc.Title), md(svc.Server), md(strings.Join(svc.Technologies, ",")),
				md(svc.ContentType), md(svc.FaviconHash), md(svc.URL), md(svc.Banner), md(svc.Error))
		}
	}

	fmt.Fprintf(&b, "\n## POC 发现\n\n")
	if len(result.Vulnerabilities) == 0 {
		if result.Scan.POCSkipped {
			fmt.Fprintf(&b, "POC 未执行：%s。\n", result.Scan.POCSkipReason)
		} else {
			fmt.Fprintf(&b, "未发现 POC 结果。\n")
		}
	} else {
		fmt.Fprintf(&b, "| # | 严重级别 | 模板 | 名称 | 目标 | 匹配 | 元数据 |\n")
		fmt.Fprintf(&b, "|---:|---|---|---|---|---|---|\n")
		for i, vuln := range result.Vulnerabilities {
			meta := mdMetadata(vuln.Metadata)
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s | %s |\n",
				i+1, md(vuln.Severity), md(vuln.TemplateID), md(vuln.Name), md(vuln.Target), md(vuln.MatchedAt), meta)
		}
	}

	fmt.Fprintf(&b, "\n## 参数摘要\n\n")
	if len(result.Parameters) == 0 {
		fmt.Fprintf(&b, "无参数记录。\n")
	} else {
		keys := sortedKeys(result.Parameters)
		for _, key := range keys {
			fmt.Fprintf(&b, "- `%s`: `%v`\n", key, result.Parameters[key])
		}
	}

	fmt.Fprintf(&b, "\n## 任务日志\n\n")
	if len(result.Logs) == 0 {
		fmt.Fprintf(&b, "无日志。\n")
	} else {
		fmt.Fprintf(&b, "```text\n")
		for _, line := range result.Logs {
			fmt.Fprintf(&b, "%s\n", line)
		}
		fmt.Fprintf(&b, "```\n")
	}
	return b.String()
}

func md(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

// mdMetadata renders a vulnerability's metadata map as sorted "key=value"
// pairs joined by "; ", for the markdown report's 元数据 column.
func mdMetadata(m map[string]any) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+fmt.Sprintf("%v", m[k]))
	}
	return md(strings.Join(parts, "; "))
}
