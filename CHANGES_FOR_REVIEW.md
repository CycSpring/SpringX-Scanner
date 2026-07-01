# SpringX-Scanner 变动说明（2026-06-30 ~ 2026-07-01）

> 供 codex 审计。以下为相对于最近一次提交 `decb17f` 的所有未提交改动。

---

## 一、新增功能

### 1. POC 模板拉取（从 GitHub 拉取官方 nuclei-templates）

**背景**：用户反馈 POC 模板为空，扫描时 POC 阶段被跳过。需要从 GitHub 拉取官方模板。

**新增文件**：
- `internal/scan/templates_pull.go` — 核心拉取逻辑
  - `PullTemplates(ctx, opts)` — 克隆或更新官方 nuclei-templates 仓库
  - 使用 go-git 浅克隆（depth=1），默认拉取 `projectdiscovery/nuclei-templates` main 分支
  - 已存在 git 仓库时走 `git pull` 更新，非 git 目录默认拒绝覆盖（提示 `--force`）
  - 拉取后写 `VERSION` 文件记录 commit + 日期，并统计模板数
  - `TemplateStatus(dir)` — 查询目录下模板数和版本（复用 `countTemplates`）
- `internal/scan/templates_pull_test.go` — 4 个单元测试（本地 bare repo，不触网）
  - `TestPullTemplates_Clone` — 首次克隆验证
  - `TestPullTemplates_Update` — 二次拉取走更新分支
  - `TestPullTemplates_ForceReplaces` — 非空非 git 目录的拒绝 + `--force` 覆盖
  - `TestPullTemplates_RequiresDir` — 空目录参数校验
- `cmd/templates.go` — CLI 子命令 `springx templates pull`
  - flags: `--dir`（默认 `./pocs/nuclei`）、`--repo`、`--branch`、`--force`、`--depth`

**WebUI 集成**：
- `internal/web/handlers.go` — 新增两个 API
  - `GET /api/templates` — 查询本地模板状态（count/version/exists）
  - `POST /api/templates/pull` — 同步拉取（20 分钟超时，进度转发到 server 日志）
- `internal/web/server.go` — 注册路由
- `internal/web/assets/index.html` — 扫描 tab 顶部加「POC 模板」状态条
- `internal/web/assets/app.js` — `loadTplStatus()` + 拉取按钮逻辑（确认框 + 防重复点击）
- `internal/web/assets/app.css` — `.muted.ok`（绿）/`.muted.warn`（红）状态色

**依赖变更**：
- `go.mod` — `github.com/go-git/go-git/v5` 从 indirect 提升为 direct 依赖

**用户实际操作**：手动下载 nuclei-templates v10.4.5 release zip，解压到 `pocs/nuclei/`，手写 `VERSION` 文件。`templates pull` 命令检测到非 git 目录时拒绝覆盖（保护用户数据），但 `countTemplates` 按文件统计能正确识别 13368 个模板。

---

### 2. POC 进度条（确定性百分比，基于 nuclei 真实请求计数）

**背景**：用户反馈 POC 扫描几分钟无进度反馈，不知道是否卡死。需要进度条显示「已处理/总请求数 + 百分比」。

**新增文件**：
- `internal/poc/nuclei/progress.go` — 自定义 `progress.Progress` 接口实现
  - `pocProgress` 结构体实现 nuclei 的 `progress.Progress` 接口（8 个方法）
  - `Init(hostCount, rulesCount, requestCount)` — nuclei 调用，记录总模板数和总请求数
  - `IncrementRequests()` — nuclei 每发一个请求调用，更新已完成计数
  - 内部 ticker 每 3 秒通过 `OnProgress` 回调上报 `ProgressStats{Done, Total, Rules, Found, Errors}`
  - `Stop()` — 停止 ticker + 发最终快照

**修改文件**：
- `internal/poc/nuclei/runner.go`
  - `Config` 新增 `OnProgress func(ProgressStats)` 和 `ProgressStats` 结构体
  - `Run()` 注入 `lib.UseStatsWriter(prog)` 到 nuclei engine
  - 去掉之前的时间心跳 goroutine 方案
- `internal/scan/runner.go`
  - `runPOC()` 的 `OnProgress` 回调发 `poc_progress` JSONL 事件：
    ```json
    {"type":"poc_progress","data":{"done":42,"total":817,"percent":5,"rules":760,"findings":0,"errors":0,"template_count":13368,"targets":1}}
    ```

**前端集成**：
- `internal/web/assets/index.html` — metrics 面板下方加进度条 UI
  - 百分比文字 + `<div class="progress-bar">` + 详情行（已处理/已发现/模板数）
- `internal/web/assets/app.js`
  - `handleEvent` 处理 `poc_started`/`poc_progress`/`poc_completed` 三个事件
  - `showPocProgress()` — 显示进度条，启动本地 1 秒计时器
  - `updatePocProgress(data)` — 更新百分比、进度条宽度、详情文字
  - `hidePocProgress()` — 隐藏进度条
- `internal/web/assets/app.css` — `.progress-bar` + `.progress-fill` + shimmer 动画

**实测数据**（扫描 example.com）：
```
done:42→49→61→...→125   total:817   percent:5%→7%→...→15%
rules:760  findings:0  errors:0→1→...→60
```
每 3 秒上报一次，百分比随真实请求数增长。

---

### 3. SSE 修复（昨日遗留，已验证）

**修改文件**：`internal/web/assets/app.js`
- 新增 `scanFinished` flag，`finishScan()` 调用 `eventSource.close()`
- `onerror` 检查 `scanFinished` 决定是否允许重连
- 取消按钮显示「正在取消…」反馈

---

## 二、专业报告改造（参考 Nessus + HCL AppScan）

### 4. 扩展 Vulnerability 数据模型

**修改文件**：`internal/model/model.go`
- `Vulnerability` 新增 10 个字段：
  - `Tags []string` — 模板标签
  - `References []string` — 参考链接（Info.Reference）
  - `Remediation string` — 修复建议（Info.Remediation）
  - `Impact string` — 影响（Info.Impact）
  - `CVE []string` — CVE 编号（Classification.CVEID）
  - `CWE []string` — CWE 编号（Classification.CWEID）
  - `CVSSScore float64` — CVSS 分数
  - `CVSSMetrics string` — CVSS Vector
  - `CPE string` — 受影响产品
  - `CURLCommand string` — curl 复现命令

### 5. 扩展 nuclei 事件转换

**修改文件**：`internal/poc/nuclei/runner.go`
- `convertEvent()` 从 `ResultEvent` 提取新字段：
  - `ev.Info.Tags.ToSlice()` → Tags
  - `ev.Info.Reference`（nil check）→ References
  - `ev.Info.Remediation` → Remediation
  - `ev.Info.Impact` → Impact
  - `ev.Info.Classification`（nil check）→ CVE/CWE/CVSSScore/CVSSMetrics/CPE
  - `ev.CURLCommand` → CURLCommand
- 从 `Metadata["classification"]` 改为独立结构化字段（不再 dump Go struct）
- `compact()` 改为保留换行（不再 `strings.Fields` 压成单行），上限 512→2048

### 6. HTML 报告重写

**修改文件**：`internal/report/html.go`（完全重写模板）
- **封面** — 标题 + 任务ID + 版本 + 时间 + 整体风险评级徽章
- **执行摘要** — 5 个严重级别计数卡片（Critical/High/Medium/Low/Info）
- **目录** — 可跳转锚点
- **扫描范围** — 状态 + 目标数 + POC 引擎/模板数/Tags
- **服务探测结果** — 精简表格（去掉 Favicon/Banner/错误等不常用列）
- **漏洞详情** — 卡片式（参考 Nessus per-finding block）：
  - 左边框色标（Critical=红, High=橙, Medium=黄, Low=绿, Info=蓝）
  - 标题（中文名）+ 模板ID + 严重级别徽章 + CVSS 分数
  - 描述 / 影响 / 受影响目标（链接，URL 清理双斜杠）
  - 分类（CVE/CWE/CPE）
  - 修复建议（始终显示，模板无自带时从知识库补全）
  - 参考链接列表
  - 复现命令（curl）
  - 可折叠的请求/响应证据（`<details>`，保留换行格式）
- **扫描参数** — 可折叠，过滤空值/compat flags/nested maps
- **任务日志** — 可折叠

**新增辅助函数**：
- `cleanURL(s)` — 去除 URL 路径中的双斜杠（保留 `://`）
- `severityClass(sev)` / `severityLabel(sev)` — 严重级别→CSS 类名/中文标签
- `severityWeight(sev)` — 排序权重
- `sevCounts(vulns)` — 按严重级别计数
- `riskLevel(vulns)` — 整体风险评级（极高/高/中/低/信息/无风险）
- `filterParams(params)` — 过滤空值和 compat flags
- `isLink(s)` — 判断是否为 URL

### 7. 漏洞中文译名 + 修复建议知识库

**新增文件**：`internal/report/vuln_i18n.go`
- `vulnTranslations` — 30+ 条漏洞翻译规则，按三种方式匹配：
  - CWE ID 精确匹配（`cwe-552` → 敏感文件泄露）
  - 模板 ID 精确匹配（`codeigniter-env` → CodeIgniter .env 配置文件泄露）
  - 名称关键词匹配（`.git` → Git 仓库信息泄露）
- `translateVulnName(v)` — 返回中文名，未匹配返回英文原名
- `defaultRemediation(v)` — 返回修复建议：优先模板自带 > 知识库匹配 > 通用建议

覆盖类型：.env 泄露、git 泄露、备份文件、管理面板、phpinfo、目录列表、XSS、SQL 注入、RCE、SSRF、文件包含、开放重定向、默认凭据、CORS、TLS/SSL 等。

### 8. Markdown 报告同步优化

**修改文件**：`internal/report/markdown.go`（完全重写）
- 结构化标题：`# 报告` → `## 执行摘要` → `## 扫描范围` → `## 服务探测结果` → `## 漏洞详情` → `## 扫描参数` → `## 任务日志`
- 执行摘要含严重级别计数表 + 风险评级
- 漏洞详情按 `### N. 中文名` 分节，含 CVSS/描述/影响/目标/CVE/CWE/修复建议/参考链接/复现命令
- 请求/响应证据用 `<details>` 折叠，保留换行
- 参数摘要过滤空值

### 9. 测试更新

**修改文件**：`internal/report/report_test.go`
- `sampleResult()` fixture 扩展：填充 CVE/CWE/CVSSScore/References/Remediation/Tags/CURLCommand
- 新增 4 个单元测试：
  - `TestCleanURL` — URL 双斜杠清理
  - `TestSeverityWeight` — 严重级别权重
  - `TestRiskLevel` — 整体风险评级计算
  - `TestFilterParams` — 参数过滤
- HTML/Markdown 测试断言更新：验证中文名、CVSS、CWE、修复建议、参考链接、curl 命令等新字段

---

## 三、死锁修复

### 10. pocProgress.Stop() 自死锁修复

**问题**：`pocProgress.Stop()` 持有 `p.mu` 锁后调 `p.snapshot()`，而 `snapshot()` 又要 `p.mu.Lock()` —— 同 goroutine 重入互斥锁，自死锁。导致 nuclei `engine.Close()` → `customProgress.Stop()` 永远回不来，smoke 测试卡死超时。

**修复**：`Stop()` 里先 `Unlock` 再内联读原子值（不调 `snapshot()`），避免重入。

---

## 四、.gitignore 更新

- 新增 `pocs/` — nuclei 模板目录（78MB，13368 文件）不入库，用户自行 `templates pull` 或手动下载

---

## 五、验证结果

| 检查项 | 结果 |
|---|---|
| `go build ./...` | ✅ |
| `go vet ./...` | ✅ 干净 |
| `go test ./internal/report/` | ✅ 7 个测试全过 |
| `go test ./internal/scan/` | ✅ |
| `go test ./internal/web/` | ✅ |
| `gofmt -l` | ✅ 无输出 |
| 死锁修复 | ✅ smoke 测试 1.14s 通过（之前卡死超时） |
| 进度条实测 | ✅ 真实请求计数，每 3 秒更新百分比 |
| 专业报告实测 | ✅ 4 个漏洞正确渲染（中文名+CVSS+CWE+修复建议+参考链接+curl+请求/响应换行） |

---

## 六、文件变更清单

### 新增文件（6 个）
| 文件 | 用途 |
|---|---|
| `cmd/templates.go` | CLI 子命令 `springx templates pull` |
| `internal/poc/nuclei/progress.go` | 自定义 progress.Progress 实现 |
| `internal/report/vuln_i18n.go` | 漏洞中文译名 + 修复建议知识库 |
| `internal/scan/templates_pull.go` | 模板拉取核心逻辑 |
| `internal/scan/templates_pull_test.go` | 拉取逻辑单元测试 |

### 修改文件（12 个）
| 文件 | 改动概述 |
|---|---|
| `go.mod` | go-git/v5 提升为 direct 依赖 |
| `.gitignore` | 新增 `pocs/` |
| `internal/model/model.go` | Vulnerability 新增 10 个字段 |
| `internal/poc/nuclei/runner.go` | convertEvent 提取新字段 + compact 保留换行 + UseStatsWriter 注入 |
| `internal/report/html.go` | 完全重写 HTML 报告模板 |
| `internal/report/markdown.go` | 完全重写 Markdown 报告 |
| `internal/report/report_test.go` | 扩展 fixture + 新增 4 个单元测试 |
| `internal/scan/runner.go` | runPOC 发 poc_progress 事件 |
| `internal/web/assets/app.css` | 进度条样式 + 状态色 |
| `internal/web/assets/app.js` | SSE 修复 + POC 进度条 + 模板拉取按钮 |
| `internal/web/assets/index.html` | 模板状态条 + 进度条 UI |
| `internal/web/handlers.go` | GET/POST /api/templates API |
| `internal/web/server.go` | 注册 templates 路由 |

---

## 七、需要 codex 重点审计的点

1. **pocProgress 死锁修复**（`progress.go` Stop 方法）— 确认不再有重入风险
2. **UseStatsWriter 注入**（`runner.go` Run 方法）— 确认不影响 nuclei 生命周期
3. **convertEvent 字段提取**（`nuclei/runner.go`）— nil check 是否完备（Reference/Classification）
4. **filterParams 过滤逻辑**（`html.go`）— 是否过度过滤了有用参数
5. **vuln_i18n 匹配优先级**（`vuln_i18n.go`）— templateID > CWE > nameKeyword 的顺序是否合理
6. **poc_progress 事件协议**（`scan/runner.go`）— 字段是否足够，是否需要加 elapsed 时间
7. **templates pull 安全性**（`templates_pull.go`）— Force 删除逻辑是否有风险
8. **报告 XSS 安全**（`html.go` 模板）— html/template 自动转义是否足够，vuln_i18n 的中文内容是否安全
