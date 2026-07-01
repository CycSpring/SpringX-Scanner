package report

import (
	"fmt"
	"strings"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

func RenderMarkdown(result *model.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# SpringX 安全扫描报告\n\n")
	fmt.Fprintf(&b, "- 扫描任务: `%s`\n", result.Scan.ID)
	fmt.Fprintf(&b, "- 引擎版本: %s\n", result.Scan.Version)
	fmt.Fprintf(&b, "- 扫描时间: %s — %s（耗时 %s）\n", formatTime(result.Scan.StartedAt), formatTime(result.Scan.FinishedAt), result.Scan.Duration)
	fmt.Fprintf(&b, "- 扫描状态: %s\n", result.Scan.Status)

	// ===== Executive Summary =====
	fmt.Fprintf(&b, "\n## 执行摘要\n\n")
	counts := sevCounts(result.Vulnerabilities)
	fmt.Fprintf(&b, "| 严重 | 高危 | 中危 | 低危 | 信息 | 总计 |\n")
	fmt.Fprintf(&b, "|:---:|:---:|:---:|:---:|:---:|:---:|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %d |\n\n",
		counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"], len(result.Vulnerabilities))
	fmt.Fprintf(&b, "- 整体风险评级: **%s**\n", riskLevel(result.Vulnerabilities))
	fmt.Fprintf(&b, "- 存活服务: %d\n", len(result.Targets))
	fmt.Fprintf(&b, "- 漏洞总数: %d\n", len(result.Vulnerabilities))
	if result.Scan.POCSkipped {
		fmt.Fprintf(&b, "- POC 状态: 未执行（%s）\n", result.Scan.POCSkipReason)
	} else if result.Scan.POC.Engine != "" {
		fmt.Fprintf(&b, "- POC 引擎: %s（模板 %d 个", result.Scan.POC.Engine, result.Scan.POC.TemplateCount)
		if result.Scan.POC.TemplateVersion != "" {
			fmt.Fprintf(&b, "，版本 %s", result.Scan.POC.TemplateVersion)
		}
		fmt.Fprintf(&b, "）\n")
	}
	if len(result.Scan.Errors) > 0 {
		fmt.Fprintf(&b, "- 扫描错误: %s\n", strings.Join(result.Scan.Errors, "; "))
	}

	// ===== Scope =====
	fmt.Fprintf(&b, "\n## 扫描范围\n\n")
	if result.Scan.POC.Tags != nil {
		fmt.Fprintf(&b, "- Nuclei Tags: `%s`\n", strings.Join(result.Scan.POC.Tags, ","))
	}
	if result.Scan.POC.Severity != "" {
		fmt.Fprintf(&b, "- Nuclei Severity: `%s`\n", result.Scan.POC.Severity)
	}

	// ===== Services =====
	fmt.Fprintf(&b, "\n## 服务探测结果\n\n")
	if len(result.Targets) == 0 {
		fmt.Fprintf(&b, "未发现服务探测结果。\n")
	} else {
		fmt.Fprintf(&b, "| # | 主机 | 端口 | 状态 | 标题 | Server | 技术栈 | URL |\n")
		fmt.Fprintf(&b, "|---:|---|---:|---:|---|---|---|---|\n")
		for i, svc := range result.Targets {
			fmt.Fprintf(&b, "| %d | %s | %d | %d | %s | %s | %s | %s |\n",
				i+1, md(svc.Host), svc.Port, svc.StatusCode,
				md(svc.Title), md(svc.Server),
				md(strings.Join(svc.Technologies, ",")),
				md(cleanURL(svc.URL)))
		}
	}

	// ===== Vulnerability Details =====
	fmt.Fprintf(&b, "\n## 漏洞详情\n\n")
	if len(result.Vulnerabilities) == 0 {
		if result.Scan.POCSkipped {
			fmt.Fprintf(&b, "POC 未执行：%s。\n", result.Scan.POCSkipReason)
		} else {
			fmt.Fprintf(&b, "未发现安全漏洞。\n")
		}
	} else {
		for i, v := range result.Vulnerabilities {
			fmt.Fprintf(&b, "### %d. %s\n\n", i+1, md(translateVulnName(v)))
			fmt.Fprintf(&b, "- 严重级别: **%s**\n", severityLabel(v.Severity))
			fmt.Fprintf(&b, "- 模板 ID: `%s`\n", md(v.TemplateID))
			if v.Type != "" {
				fmt.Fprintf(&b, "- 类型: %s\n", md(v.Type))
			}
			if v.CVSSScore > 0 {
				fmt.Fprintf(&b, "- CVSS: %.1f\n", v.CVSSScore)
				if v.CVSSMetrics != "" {
					fmt.Fprintf(&b, "- CVSS Vector: `%s`\n", md(v.CVSSMetrics))
				}
			}
			if v.Description != "" {
				fmt.Fprintf(&b, "- 描述: %s\n", md(v.Description))
			}
			if v.Impact != "" {
				fmt.Fprintf(&b, "- 影响: %s\n", md(v.Impact))
			}
			if v.MatchedAt != "" {
				fmt.Fprintf(&b, "- 受影响目标: %s\n", md(cleanURL(v.MatchedAt)))
			} else if v.Target != "" {
				fmt.Fprintf(&b, "- 受影响目标: %s\n", md(cleanURL(v.Target)))
			}
			if len(v.CVE) > 0 {
				fmt.Fprintf(&b, "- CVE: %s\n", md(strings.Join(v.CVE, ", ")))
			}
			if len(v.CWE) > 0 {
				fmt.Fprintf(&b, "- CWE: %s\n", md(strings.Join(v.CWE, ", ")))
			}
			if v.CPE != "" {
				fmt.Fprintf(&b, "- CPE: `%s`\n", md(v.CPE))
			}
			if len(v.ExtractedResults) > 0 {
				fmt.Fprintf(&b, "- 提取结果: `%s`\n", md(strings.Join(v.ExtractedResults, ", ")))
			}
			fmt.Fprintf(&b, "- 修复建议: %s\n", md(defaultRemediation(v)))
			if len(v.References) > 0 {
				fmt.Fprintf(&b, "- 参考链接:\n")
				for _, ref := range v.References {
					fmt.Fprintf(&b, "  - %s\n", md(ref))
				}
			}
			if v.CURLCommand != "" {
				fmt.Fprintf(&b, "- 复现命令:\n\n```\n%s\n```\n", v.CURLCommand)
			}
			if v.RequestSummary != "" {
				fmt.Fprintf(&b, "\n<details><summary>请求证据</summary>\n\n```\n%s\n```\n\n</details>\n", v.RequestSummary)
			}
			if v.ResponseSummary != "" {
				fmt.Fprintf(&b, "\n<details><summary>响应证据</summary>\n\n```\n%s\n```\n\n</details>\n", v.ResponseSummary)
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	// ===== Parameters =====
	fmt.Fprintf(&b, "\n## 扫描参数\n\n")
	fp := filterParams(result.Parameters)
	if len(fp) == 0 {
		fmt.Fprintf(&b, "无有效参数。\n")
	} else {
		keys := sortedKeys(fp)
		for _, key := range keys {
			fmt.Fprintf(&b, "- `%s`: `%v`\n", key, fp[key])
		}
	}

	// ===== Logs =====
	fmt.Fprintf(&b, "\n## 任务日志\n\n")
	if len(result.Logs) == 0 {
		fmt.Fprintf(&b, "无日志。\n")
	} else {
		fmt.Fprintf(&b, "<details><summary>展开日志（%d 行）</summary>\n\n```text\n", len(result.Logs))
		for _, line := range result.Logs {
			fmt.Fprintf(&b, "%s\n", line)
		}
		fmt.Fprintf(&b, "```\n\n</details>\n")
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
