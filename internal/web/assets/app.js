// SpringX WebUI 前端逻辑：表单提交 → SSE 订阅 → 事件渲染 → 结果 → 历史报告。
"use strict";

const $ = (id) => document.getElementById(id);

// ---- tabs ----
document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("tab-scan").classList.toggle("hidden", t.dataset.tab !== "scan");
    $("tab-reports").classList.toggle("hidden", t.dataset.tab !== "reports");
    if (t.dataset.tab === "reports") loadReports();
  });
});

// ---- version line ----
fetch("/api/health").then(() => {
  $("versionLine").textContent = "WebUI 已就绪";
  loadTplStatus();
});

// ---- scan form ----
let currentJob = null;
let eventSource = null;
let scanFinished = false;

$("scanForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const req = collectForm();
  $("startBtn").disabled = true;
  resetScanView();
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || "启动扫描失败");
    }
    const data = await res.json();
    currentJob = data.job_id;
    $("jobInfo").textContent = "job_id: " + currentJob;
    $("cancelBtn").classList.remove("hidden");
    subscribeEvents(currentJob);
  } catch (err) {
    appendLog("error", err.message);
  } finally {
    $("startBtn").disabled = false;
  }
});

$("cancelBtn").addEventListener("click", async () => {
  if (!currentJob || scanFinished) return;
  try {
    const res = await fetch(`/api/scan/${currentJob}/cancel`, { method: "POST" });
    if (res.ok) {
      appendLog("info", "已发送取消请求，等待扫描停止…");
      setMetric("m-status", "正在取消…", "stopped");
      $("cancelBtn").disabled = true;
    } else {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      appendLog("error", "取消失败: " + (err.error || res.status));
    }
  } catch (err) {
    appendLog("error", "取消失败: " + err.message);
  }
});

function collectForm() {
  const num = (id) => {
    const v = parseInt($(id).value, 10);
    return Number.isFinite(v) ? v : 0;
  };
  return {
    url: $("f-url").value.trim(),
    ip: $("f-ip").value.trim(),
    urlfile: $("f-urlfile").value.trim(),
    ipfile: $("f-ipfile").value.trim(),
    ports: $("f-ports").value.trim(),
    threads: num("f-threads"),
    done: num("f-done"),
    proxy: $("f-proxy").value.trim(),
    nopoc: $("f-nopoc").checked,
    nuclei_tags: $("f-nuclei-tags").value.trim(),
    nuclei_severity: $("f-nuclei-severity").value.trim(),
    nuclei_ids: $("f-nuclei-ids").value.trim(),
    nuclei_template_dir: $("f-nuclei-template-dir").value.trim(),
    poc_concurrency: num("f-poc-concurrency"),
    gonmap_timeout: num("f-gonmap-timeout"),
    temp_dir: $("f-temp-dir").value.trim(),
  };
}

// ---- SSE ----
function subscribeEvents(jobID) {
  if (eventSource) eventSource.close();
  scanFinished = false;
  eventSource = new EventSource(`/api/events?id=${encodeURIComponent(jobID)}`);
  eventSource.onmessage = (msg) => {
    let ev;
    try {
      ev = JSON.parse(msg.data);
    } catch {
      return;
    }
    handleEvent(ev);
  };
  eventSource.onerror = () => {
    // Once the scan is finished, close the stream so the browser stops
    // auto-reconnecting (which otherwise loops forever replaying history).
    if (scanFinished) {
      eventSource.close();
      eventSource = null;
    }
    // While running, EventSource auto-reconnects; cached history replays missed events.
  };
}

function resetScanView() {
  scanFinished = false;
  $("cancelBtn").disabled = false;
  $("svcTable").querySelector("tbody").innerHTML = "";
  $("vulnTable").querySelector("tbody").innerHTML = "";
  $("svcTable").classList.add("hidden");
  $("vulnTable").classList.add("hidden");
  $("svcEmpty").classList.remove("hidden");
  $("vulnEmpty").classList.remove("hidden");
  $("eventLog").innerHTML = "";
  setMetric("m-status", "—", "running");
  setMetric("m-scanid", "—");
  setMetric("m-services", "0");
  setMetric("m-vulns", "0");
  $("pocProgress").classList.add("hidden");
}

function handleEvent(ev) {
  appendLog(ev.type, describe(ev));
  switch (ev.type) {
    case "scan_started":
      setMetric("m-scanid", ev.data?.id || "—");
      setMetric("m-status", "running", "running");
      break;
    case "target_discovered":
      break;
    case "service_detected":
    case "port_open":
      if (ev.data && (ev.data.host || ev.data.url)) addServiceRow(ev.data);
      break;
    case "vulnerability_found":
      addVulnRow(ev.data);
      break;
    case "poc_started":
      appendLog("info", `POC 启动: engine=${ev.data?.engine} targets=${ev.data?.targets} templates=${ev.data?.template_count || "—"}`);
      showPocProgress(ev.data?.template_count || 0, ev.data?.targets || 0);
      break;
    case "poc_progress":
      updatePocProgress(ev.data);
      break;
    case "poc_completed":
      appendLog("info", `POC 完成: findings=${ev.data?.findings} skipped=${ev.data?.skipped} duration=${ev.data?.duration || "—"}`);
      hidePocProgress(ev.data?.findings || 0);
      break;
    case "scan_completed":
      setStatusFromCompleted(ev.data?.status || "completed");
      finishScan();
      break;
    case "scan_failed":
      setMetric("m-status", "failed", "failed");
      finishScan();
      break;
    case "report_written":
      appendLog("info", `报告已生成: ${ev.data?.json || ""}`);
      break;
    case "log":
      // already shown via describe(); no extra action
      break;
  }
}

function setStatusFromCompleted(status) {
  const cls = status === "stopped" ? "stopped" : "completed";
  setMetric("m-status", status, cls);
}

function finishScan() {
  scanFinished = true;
  $("cancelBtn").classList.add("hidden");
  $("cancelBtn").disabled = false;
  // Close the SSE stream now that the terminal event arrived, so the browser
  // does not auto-reconnect and replay history forever.
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
}

// ---- service / vuln rows ----
let serviceCount = 0;
let vulnCount = 0;

function addServiceRow(svc) {
  serviceCount++;
  setMetric("m-services", String(serviceCount));
  $("svcEmpty").classList.add("hidden");
  const t = $("svcTable");
  t.classList.remove("hidden");
  const tbody = t.querySelector("tbody");
  const row = tbody.insertRow();
  row.className = "expandable";
  row.innerHTML = `<td><span class="caret">▸</span> ${esc(svc.host || "")}</td><td>${svc.port || ""}</td>` +
    `<td>${svc.status_code || ""}</td><td>${esc(svc.title || "")}</td>` +
    `<td>${esc(svc.server || "")}</td><td>${chips(svc.technologies)}</td>`;
  attachDetail(row, () => serviceDetailHTML(svc));
}

function addVulnRow(v) {
  if (!v) return;
  vulnCount++;
  setMetric("m-vulns", String(vulnCount));
  $("vulnEmpty").classList.add("hidden");
  const t = $("vulnTable");
  t.classList.remove("hidden");
  const sev = v.severity || "info";
  const row = t.querySelector("tbody").insertRow();
  row.className = "expandable";
  row.innerHTML = `<td class="severity-${esc(sev)}">${esc(sev)}</td>` +
    `<td class="mono">${esc(v.template_id || "")}</td>` +
    `<td class="mono">${esc(v.target || "")}</td>` +
    `<td class="mono">${esc(v.matched_at || "")}</td>`;
  attachDetail(row, () => vulnDetailHTML(v));
}

// attachDetail makes a row expandable: clicking toggles a detail row beneath it.
// detailHTML is a function returning the HTML for the detail cell (deferred so
// it renders with the latest data).
function attachDetail(row, detailHTML) {
  let open = false;
  let detailRow = null;
  row.addEventListener("click", () => {
    if (open) {
      if (detailRow) detailRow.remove();
      row.classList.remove("expanded");
      open = false;
      return;
    }
    detailRow = row.parentNode.insertRow(row.rowIndex);
    detailRow.className = "detail-row";
    const cell = detailRow.insertCell();
    cell.colSpan = row.cells.length;
    cell.innerHTML = detailHTML();
    row.classList.add("expanded");
    open = true;
  });
}

// ---- detail HTML builders ----
function serviceDetailHTML(s) {
  const f = (label, value) => `<div class="field"><span class="label">${label}</span><span class="value">${value || `<span class="empty">—</span>`}</span></div>`;
  return [
    f("IP", esc(s.ip || "")),
    f("协议", esc(s.protocol || "")),
    f("Scheme", esc(s.scheme || "")),
    f("TLS", esc(s.tls || "")),
    f("内容类型", esc(s.content_type || "")),
    f("内容长度", s.content_length != null ? String(s.content_length) : ""),
    f("Location", esc(s.location || "")),
    f("Favicon", `<span class="mono">${esc(s.favicon_hash || "")}</span>`),
    f("指纹来源", chips(s.fingerprint_sources)),
    f("技术栈", chips(s.technologies)),
    s.url ? f("URL", `<a href="${esc(s.url)}" target="_blank">${esc(s.url)}</a>`) : "",
    s.banner ? f("Banner", `<pre>${esc(s.banner)}</pre>`) : "",
    s.error ? f("错误", `<span class="severity-high">${esc(s.error)}</span>`) : "",
  ].join("");
}

function vulnDetailHTML(v) {
  const f = (label, value) => `<div class="field"><span class="label">${label}</span><span class="value">${value || `<span class="empty">—</span>`}</span></div>`;
  const metaRows = (m) => {
    if (!m || Object.keys(m).length === 0) return "";
    const rows = Object.keys(m).sort().map((k) => `<code>${esc(k)}=${esc(String(m[k]))}</code>`).join(" ");
    return f("元数据", `<span class="chips">${rows}</span>`);
  };
  return [
    f("名称", esc(v.name || "")),
    f("类型", esc(v.type || "")),
    f("匹配位置", `<span class="mono">${esc(v.matched_at || "")}</span>`),
    f("Matcher", esc(v.matcher_name || "")),
    f("Extractor", esc(v.extractor_name || "")),
    f("描述", esc(v.description || "")),
    (v.extracted_results && v.extracted_results.length) ? f("提取结果", v.extracted_results.map(esc).join("<br>")) : "",
    v.request_summary ? f("请求", `<pre>${esc(v.request_summary)}</pre>`) : "",
    v.response_summary ? f("响应", `<pre>${esc(v.response_summary)}</pre>`) : "",
    metaRows(v.metadata),
    v.timestamp ? f("时间", esc(fmtTime(v.timestamp))) : "",
  ].join("");
}

// chips renders an array as badge chips; empty array yields an em-dash.
function chips(arr) {
  if (!arr || !arr.length) return `<span class="empty">—</span>`;
  return `<span class="chips">${arr.map((x) => `<span class="badge">${esc(String(x))}</span>`).join("")}</span>`;
}

// ---- POC progress ----
let pocTimer = null;
let pocStartTs = 0;

function showPocProgress(templateCount, targets) {
  $("pocProgress").classList.remove("hidden");
  $("pocBar").style.width = "0%";
  $("pocElapsed").textContent = "0s";
  $("pocDetail").textContent = `已发现 0 个漏洞 · ${templateCount} 个模板 · ${targets} 个目标`;
  pocStartTs = Date.now();
  // Local ticker updates elapsed time every second between server heartbeats.
  if (pocTimer) clearInterval(pocTimer);
  pocTimer = setInterval(() => {
    const sec = Math.floor((Date.now() - pocStartTs) / 1000);
    $("pocElapsed").textContent = sec >= 60 ? `${Math.floor(sec/60)}m${sec%60}s` : `${sec}s`;
  }, 1000);
}

function updatePocProgress(data) {
  const done = data.done ?? 0;
  const total = data.total ?? 0;
  const percent = data.percent ?? 0;
  const findings = data.findings ?? 0;
  $("pocBar").style.width = percent + "%";
  $("pocPercent").textContent = percent + "%";
  $("pocDetail").textContent = `已处理 ${done}/${total} 请求 · 已发现 ${findings} 个漏洞 · ${data.rules || 0} 个模板`;
  setMetric("m-vulns", String(findings));
}

function hidePocProgress(findings) {
  if (pocTimer) { clearInterval(pocTimer); pocTimer = null; }
  $("pocBar").style.width = "0%";
  $("pocProgress").classList.add("hidden");
}

// ---- event log ----
function appendLog(type, msg) {
  const log = $("eventLog");
  if (log.children.length === 1 && log.children[0].classList.contains("muted")) {
    log.innerHTML = "";
  }
  const ts = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  const line = document.createElement("div");
  line.className = "line";
  line.innerHTML = `<span class="ts">${ts}</span><span class="type">${esc(type)}</span>${esc(msg)}`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function describe(ev) {
  const d = ev.data || {};
  switch (ev.type) {
    case "scan_started": return `args: ${(d.args || []).join(" ")}`;
    case "target_discovered": return `url: ${d.url || ""}`;
    case "service_detected":
    case "port_open":
      return `${d.host || ""}:${d.port || ""} ${d.title || ""} ${d.server || ""}`.trim();
    case "vulnerability_found":
      return `${d.template_id} [${d.severity}] ${d.target || ""}`;
    case "poc_progress":
      return `POC 进度: ${d.percent ?? 0}% (${d.done ?? 0}/${d.total ?? 0}) 已发现 ${d.findings ?? 0} 个`;
    case "log": return d.message || "";
    default: return "";
  }
}

// ---- metrics ----
function setMetric(id, value, statusClass) {
  const el = $(id);
  el.textContent = value;
  el.className = "";
  if (statusClass) {
    el.className = `status-pill status-${statusClass}`;
    // keep inline display for the pill inside a <strong>
    el.style.fontSize = statusClass ? "14px" : "22px";
  }
}

// ---- reports ----
async function loadReports() {
  try {
    const res = await fetch("/api/reports");
    const items = await res.json();
    const t = $("reportsTable");
    const tbody = t.querySelector("tbody");
    tbody.innerHTML = "";
    if (!items || items.length === 0) {
      t.classList.add("hidden");
      $("reportsEmpty").classList.remove("hidden");
      return;
    }
    $("reportsEmpty").classList.add("hidden");
    t.classList.remove("hidden");
    for (const it of items) {
      const row = tbody.insertRow();
      row.innerHTML =
        `<td><button class="link-btn" data-name="${esc(it.name)}">${esc(it.name)}</button></td>` +
        `<td class="mono">${esc(it.scan_id || "—")}</td>` +
        `<td>${fmtTime(it.started_at)}</td>` +
        `<td><span class="status-pill status-${esc(it.status || "completed")}">${esc(it.status || "—")}</span></td>` +
        `<td>${it.targets}</td><td>${it.vulns}</td>` +
        `<td class="muted">${(it.size / 1024).toFixed(1)} KB</td>`;
    }
    tbody.querySelectorAll(".link-btn").forEach((btn) => {
      btn.addEventListener("click", () => openReport(btn.dataset.name));
    });
  } catch (err) {
    appendLog("error", "加载报告失败: " + err.message);
  }
}

async function openReport(name) {
  try {
    const res = await fetch(`/api/reports/${encodeURIComponent(name)}`);
    if (!res.ok) throw new Error("报告不存在");
    const result = await res.json();
    renderReportDetail(name, result);
  } catch (err) {
    appendLog("error", err.message);
  }
}

function renderReportDetail(name, r) {
  $("reportsTable").classList.add("hidden");
  $("reportsEmpty").classList.add("hidden");
  const d = $("reportDetail");
  d.classList.remove("hidden");
  $("rd-title").textContent = name;
  const scan = r.scan || {};
  $("rd-metrics").innerHTML =
    metricCard("状态", scan.status || "—", scan.status) +
    metricCard("scan_id", scan.id || "—") +
    metricCard("耗时", scan.duration || "—") +
    metricCard("存活服务", (r.targets || []).length) +
    metricCard("POC 发现", (r.vulnerabilities || []).length);

  $("rd-services").innerHTML = servicesTable(r.targets || []);
  $("rd-vulns").innerHTML = vulnsTable(r.vulnerabilities || []);
  // Wire delegated expand/collapse on the historical tables now that they
  // exist in the DOM.
  wireExpandableDetail(r.targets || [], r.vulnerabilities || []);
}

function servicesTable(targets) {
  if (!targets.length) return `<p class="muted">未发现存活服务。</p>`;
  let rows = targets.map((s, i) =>
    `<tr class="expandable" data-kind="svc" data-idx="${i}"><td><span class="caret">▸</span> ${esc(s.host || "")}</td><td>${s.port || ""}</td><td>${s.protocol || ""}</td>` +
    `<td>${s.status_code || ""}</td><td>${esc(s.title || "")}</td><td>${esc(s.server || "")}</td>` +
    `<td>${chips(s.technologies)}</td>` +
    `<td class="mono">${esc(s.favicon_hash || "")}</td>` +
    `<td>${s.url ? `<a href="${esc(s.url)}" target="_blank">${esc(s.url)}</a>` : ""}</td></tr>`
  ).join("");
  return `<table><thead><tr><th>主机</th><th>端口</th><th>协议</th><th>状态</th><th>标题</th><th>Server</th><th>技术栈</th><th>Favicon</th><th>URL</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function vulnsTable(vulns) {
  if (!vulns.length) return `<p class="muted">未发现 POC 结果。</p>`;
  let rows = vulns.map((v, i) =>
    `<tr class="expandable" data-kind="vuln" data-idx="${i}"><td class="severity-${esc(v.severity || "info")}">${esc(v.severity || "")}</td>` +
    `<td class="mono">${esc(v.template_id || "")}</td><td>${esc(v.name || "")}</td>` +
    `<td class="mono">${esc(v.target || "")}</td><td class="mono">${esc(v.matched_at || "")}</td></tr>`
  ).join("");
  return `<table><thead><tr><th>严重级别</th><th>模板</th><th>名称</th><th>目标</th><th>匹配</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// wireExpandableDetail attaches delegated click handlers to the historical
// report tables so their expandable rows open/close detail rows. It stashes the
// source arrays on the table element so the delegated handler can build detail
// HTML for the clicked index.
function wireExpandableDetail(services, vulns) {
  const svcBody = $("rd-services").querySelector("tbody");
  const vulnBody = $("rd-vulns").querySelector("tbody");
  if (svcBody) svcBody._data = services;
  if (vulnBody) vulnBody._data = vulns;
  const handler = (tbody, builder) => (e) => {
    const row = e.target.closest("tr.expandable");
    if (!row || row.parentNode !== tbody) return;
    if (row.classList.contains("expanded")) {
      const next = row.nextElementSibling;
      if (next && next.classList.contains("detail-row")) next.remove();
      row.classList.remove("expanded");
      return;
    }
    const idx = Number(row.dataset.idx);
    const data = tbody._data && tbody._data[idx];
    if (!data) return;
    const detailRow = tbody.insertRow(row.rowIndex);
    detailRow.className = "detail-row";
    const cell = detailRow.insertCell();
    cell.colSpan = row.cells.length;
    cell.innerHTML = builder(data);
    row.classList.add("expanded");
  };
  if (svcBody) svcBody.onclick = handler(svcBody, serviceDetailHTML);
  if (vulnBody) vulnBody.onclick = handler(vulnBody, vulnDetailHTML);
}

function metricCard(label, value, status) {
  const cls = status ? `status-pill status-${esc(status)}` : "";
  return `<div class="metric"><span>${esc(label)}</span><strong class="${cls}" style="${status ? "font-size:14px" : ""}">${esc(String(value))}</strong></div>`;
}

$("rd-back").addEventListener("click", () => {
  $("reportDetail").classList.add("hidden");
  $("reportsTable").classList.remove("hidden");
  loadReports();
});

// ---- POC templates: status + pull ----
function setTplStatus(text, cls) {
  const el = $("tplStatus");
  el.textContent = text;
  el.className = "muted" + (cls ? " " + cls : "");
}

async function loadTplStatus() {
  setTplStatus("查询中…");
  try {
    const res = await fetch("/api/templates");
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    if (!data.exists) {
      setTplStatus(`未拉取（${data.dir}）`, "warn");
    } else {
      setTplStatus(`已加载 ${data.count} 个模板${data.version ? " · " + data.version : ""}`, "ok");
    }
  } catch (err) {
    setTplStatus("查询失败: " + err.message, "warn");
  }
}

$("tplRefresh").addEventListener("click", loadTplStatus);

$("tplPull").addEventListener("click", async () => {
  const btn = $("tplPull");
  if (!confirm("将从 GitHub 拉取官方 nuclei-templates（浅克隆，可能需数分钟）。继续？")) return;
  btn.disabled = true;
  const force = $("tplForce").checked;
  setTplStatus(force ? "强制重新克隆中…（可能较慢）" : "拉取中…（可能较慢）");
  try {
    const res = await fetch("/api/templates/pull", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ force }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "HTTP " + res.status);
    setTplStatus(`${data.action === "cloned" ? "克隆" : "更新"}完成：${data.count} 个模板 · ${data.version || data.commit}`, "ok");
    appendLog("info", `POC 模板就绪：${data.action} commit=${data.commit} count=${data.count}`);
  } catch (err) {
    setTplStatus("拉取失败: " + err.message, "warn");
    appendLog("error", "POC 模板拉取失败: " + err.message);
  } finally {
    btn.disabled = false;
  }
});

// ---- helpers ----
function esc(s) {
  return String(s == null ? "" : s)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
function fmtTime(t) {
  if (!t) return "—";
  try { return new Date(t).toLocaleString("zh-CN", { hour12: false }); }
  catch { return String(t); }
}
