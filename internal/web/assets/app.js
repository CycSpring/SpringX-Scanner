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
});

// ---- scan form ----
let currentJob = null;
let eventSource = null;

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
  if (!currentJob) return;
  try {
    await fetch(`/api/scan/${currentJob}/cancel`, { method: "POST" });
    appendLog("info", "已发送取消请求…");
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
    // EventSource auto-reconnects; cached history on the server replays missed events.
  };
}

function resetScanView() {
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
      appendLog("info", `POC 启动: engine=${ev.data?.engine} targets=${ev.data?.targets}`);
      break;
    case "poc_completed":
      appendLog("info", `POC 完成: findings=${ev.data?.findings} skipped=${ev.data?.skipped}`);
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
  $("cancelBtn").classList.add("hidden");
  if (eventSource) {
    // keep stream open until server closes it; terminal event already received
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
  const row = t.querySelector("tbody").insertRow();
  row.innerHTML = `<td>${esc(svc.host || "")}</td><td>${svc.port || ""}</td>` +
    `<td>${svc.status_code || ""}</td><td>${esc(svc.title || "")}</td>` +
    `<td>${esc(svc.server || "")}</td><td>${esc((svc.technologies || []).join(", "))}</td>`;
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
  row.innerHTML = `<td class="severity-${esc(sev)}">${esc(sev)}</td>` +
    `<td class="mono">${esc(v.template_id || "")}</td>` +
    `<td class="mono">${esc(v.target || "")}</td>` +
    `<td class="mono">${esc(v.matched_at || "")}</td>`;
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
}

function servicesTable(targets) {
  if (!targets.length) return `<p class="muted">未发现存活服务。</p>`;
  let rows = targets.map((s) =>
    `<tr><td>${esc(s.host || "")}</td><td>${s.port || ""}</td><td>${s.protocol || ""}</td>` +
    `<td>${s.status_code || ""}</td><td>${esc(s.title || "")}</td><td>${esc(s.server || "")}</td>` +
    `<td>${esc((s.technologies || []).join(", "))}</td>` +
    `<td class="mono">${esc(s.favicon_hash || "")}</td>` +
    `<td>${s.url ? `<a href="${esc(s.url)}" target="_blank">${esc(s.url)}</a>` : ""}</td></tr>`
  ).join("");
  return `<table><thead><tr><th>主机</th><th>端口</th><th>协议</th><th>状态</th><th>标题</th><th>Server</th><th>技术栈</th><th>Favicon</th><th>URL</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function vulnsTable(vulns) {
  if (!vulns.length) return `<p class="muted">未发现 POC 结果。</p>`;
  let rows = vulns.map((v) =>
    `<tr><td class="severity-${esc(v.severity || "info")}">${esc(v.severity || "")}</td>` +
    `<td class="mono">${esc(v.template_id || "")}</td><td>${esc(v.name || "")}</td>` +
    `<td class="mono">${esc(v.target || "")}</td><td class="mono">${esc(v.matched_at || "")}</td></tr>`
  ).join("");
  return `<table><thead><tr><th>严重级别</th><th>模板</th><th>名称</th><th>目标</th><th>匹配</th></tr></thead><tbody>${rows}</tbody></table>`;
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
