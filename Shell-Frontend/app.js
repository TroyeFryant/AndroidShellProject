/**
 * Android Shell Protector — 安全管理平台前端
 */

const API = "";
const POLL_INTERVAL = 2000;
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ═══════════════════════════════════════════════════════════════
//  Token & Auth
// ═══════════════════════════════════════════════════════════════

function getToken() { return localStorage.getItem("token"); }

function authHeaders() {
  const t = getToken();
  return t ? { Authorization: "Bearer " + t } : {};
}

async function authFetch(url, opts = {}) {
  opts.headers = Object.assign({}, opts.headers || {}, authHeaders());
  const res = await fetch(url, opts);
  if (res.status === 401) { localStorage.removeItem("token"); window.location.href = "/login"; throw new Error("未授权"); }
  return res;
}

function logout() { localStorage.removeItem("token"); window.location.href = "/login"; }

// ═══════════════════════════════════════════════════════════════
//  Tab Switching
// ═══════════════════════════════════════════════════════════════

const tabPanels = {};
["dashboard","harden","history","protection","risk","system"].forEach(t => { tabPanels[t] = $("#tab-" + t); });
const navButtons = $$(".nav-item[data-tab]");
let adminLoaded = false;
let dashboardLoaded = false;

function switchTab(name) {
  Object.entries(tabPanels).forEach(([k, el]) => { if (el) el.style.display = k === name ? "" : "none"; });
  navButtons.forEach(btn => { const a = btn.dataset.tab === name; btn.classList.toggle("active", a); btn.classList.toggle("text-slate-400", !a); });
  if (name === "dashboard" && !dashboardLoaded) { dashboardLoaded = true; loadDashboard(); }
  if (name === "history") loadHistory();
  if (name === "risk") loadRiskData();
  if ((name === "protection" || name === "system") && !adminLoaded) { adminLoaded = true; loadAdminData(); }
  if (name === "system") loadDbStatus();
}

navButtons.forEach(btn => btn.addEventListener("click", () => switchTab(btn.dataset.tab)));

// ═══════════════════════════════════════════════════════════════
//  ECharts Dark Theme Defaults
// ═══════════════════════════════════════════════════════════════

const EC_TEXT = "#94a3b8";
const EC_LINE = "#334155";
const EC_COLORS = ["#818cf8","#34d399","#fbbf24","#f87171","#a78bfa","#38bdf8","#fb923c"];

function ecBase() {
  return {
    textStyle: { color: EC_TEXT, fontFamily: "-apple-system,BlinkMacSystemFont,sans-serif" },
    legend: { textStyle: { color: EC_TEXT, fontSize: 11 } },
  };
}

// ═══════════════════════════════════════════════════════════════
//  1. Dashboard
// ═══════════════════════════════════════════════════════════════

async function loadDashboard() {
  try {
    const res = await authFetch(`${API}/api/dashboard/stats`);
    const d = await res.json();

    $("#dash-tasks").textContent = d.tasks.total;
    $("#dash-rate").textContent = d.tasks.success_rate + "%";
    $("#dash-risk").textContent = d.risk.total;
    $("#dash-layers").textContent = d.protection_layers;

    renderTrendChart(d.trend);
    renderRiskPie(d.risk);
    renderRadarChart();
    renderEncFlow();
    renderAlerts(d.recent_alerts);
  } catch (e) { console.error("Dashboard load failed:", e); }
}

function renderTrendChart(trend) {
  const chart = echarts.init($("#chart-trend"));
  const dates = Object.keys(trend).map(d => d.slice(5));
  const completed = Object.values(trend).map(v => v.completed);
  const failed = Object.values(trend).map(v => v.failed);
  chart.setOption({
    ...ecBase(),
    color: ["#34d399", "#f87171"],
    tooltip: { trigger: "axis", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontSize: 12 } },
    grid: { top: 30, right: 20, bottom: 30, left: 40 },
    xAxis: { type: "category", data: dates, axisLine: { lineStyle: { color: EC_LINE } }, axisLabel: { color: EC_TEXT, fontSize: 11 } },
    yAxis: { type: "value", minInterval: 1, splitLine: { lineStyle: { color: EC_LINE, type: "dashed" } }, axisLabel: { color: EC_TEXT, fontSize: 11 } },
    legend: { data: ["成功", "失败"], right: 0, top: 0, textStyle: { color: EC_TEXT, fontSize: 11 } },
    series: [
      { name: "成功", type: "line", data: completed, smooth: true, symbol: "circle", symbolSize: 6, areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[{offset:0,color:"rgba(52,211,153,.25)"},{offset:1,color:"rgba(52,211,153,0)"}]) } },
      { name: "失败", type: "line", data: failed, smooth: true, symbol: "circle", symbolSize: 6, areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[{offset:0,color:"rgba(248,113,113,.2)"},{offset:1,color:"rgba(248,113,113,0)"}]) } },
    ],
  });
  window.addEventListener("resize", () => chart.resize());
}

function renderRiskPie(risk) {
  const chart = echarts.init($("#chart-risk-pie"));
  const total = risk.total || 0;
  chart.setOption({
    ...ecBase(),
    color: ["#f87171","#fbbf24","#34d399"],
    tooltip: { trigger: "item", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontSize: 12 } },
    graphic: [{ type: "text", left: "center", top: "42%", style: { text: total.toString(), fontSize: 28, fontWeight: "bold", fill: "#fff", textAlign: "center" } }, { type: "text", left: "center", top: "56%", style: { text: "总上报", fontSize: 11, fill: "#94a3b8", textAlign: "center" } }],
    series: [{
      type: "pie", radius: ["55%","78%"], center: ["50%","50%"],
      label: { color: EC_TEXT, fontSize: 11, formatter: "{b}\n{c}" },
      data: [
        { value: risk.high, name: "高危" },
        { value: risk.medium, name: "中危" },
        { value: risk.low, name: "低危/安全" },
      ],
      itemStyle: { borderRadius: 6, borderColor: "#0f172a", borderWidth: 3 },
    }],
  });
  window.addEventListener("resize", () => chart.resize());
}

function renderRadarChart() {
  const chart = echarts.init($("#chart-radar"));
  chart.setOption({
    ...ecBase(),
    color: ["#818cf8"],
    radar: {
      indicator: [
        { name: "进程级", max: 6 },
        { name: "环境级", max: 6 },
        { name: "工具级", max: 6 },
        { name: "代码级", max: 8 },
        { name: "Java层", max: 6 },
      ],
      shape: "polygon",
      splitNumber: 4,
      axisName: { color: EC_TEXT, fontSize: 11 },
      splitLine: { lineStyle: { color: EC_LINE } },
      splitArea: { areaStyle: { color: ["rgba(99,102,241,.03)","rgba(99,102,241,.06)"] } },
      axisLine: { lineStyle: { color: EC_LINE } },
    },
    series: [{
      type: "radar",
      data: [{ value: [4, 5, 3, 7, 3], name: "防护层分布" }],
      areaStyle: { color: "rgba(129,140,248,.15)" },
      lineStyle: { width: 2 },
      symbol: "circle", symbolSize: 5,
    }],
  });
  window.addEventListener("resize", () => chart.resize());
}

function renderEncFlow() {
  const steps = [
    { icon: "M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z", title: "AES-128-CBC", desc: "每包随机 16 字节密钥" },
    { icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z", title: "HMAC-SHA256", desc: "密文完整性校验" },
    { icon: "M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01", title: "设备绑定", desc: "ANDROID_ID + 签名哈希" },
    { icon: "M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16", title: "内存清理", desc: "Arrays.fill + madvise" },
  ];
  const container = $("#dash-enc-flow");
  container.innerHTML = steps.map((s, i) => `
    <div class="flex items-center gap-3 bg-slate-900/40 rounded-xl p-3">
      <div class="w-9 h-9 rounded-lg bg-brand-600/15 flex items-center justify-center shrink-0">
        <svg class="w-4.5 h-4.5 text-brand-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="${s.icon}"/></svg>
      </div>
      <div class="min-w-0">
        <p class="text-white text-sm font-medium">${s.title}</p>
        <p class="text-slate-500 text-xs">${s.desc}</p>
      </div>
    </div>`).join("");
}

function renderAlerts(alerts) {
  const container = $("#dash-alerts");
  if (!alerts || alerts.length === 0) {
    container.innerHTML = '<p class="text-slate-500 text-xs py-4 text-center">暂无告警记录</p>';
    return;
  }
  container.innerHTML = alerts.map(a => {
    const colors = { HIGH: "text-red-400 bg-red-500/10", CRITICAL: "text-red-400 bg-red-500/10", MEDIUM: "text-amber-400 bg-amber-500/10", LOW: "text-emerald-400 bg-emerald-500/10" };
    const c = colors[a.risk_level] || "text-slate-400 bg-slate-500/10";
    const t = a.created_at ? a.created_at.replace("T"," ").slice(0,16) : "-";
    return `<div class="flex items-center gap-3 p-3 rounded-xl bg-slate-900/40">
      <div class="w-8 h-8 rounded-lg ${c} flex items-center justify-center text-xs font-bold">${a.risk_score || 0}</div>
      <div class="flex-1 min-w-0">
        <p class="text-white text-sm truncate">${a.device_fingerprint || "unknown"}</p>
        <p class="text-slate-500 text-[11px]">${t}</p>
      </div>
      <span class="tag ${c.replace('bg-','bg-').replace('/10','/15')}">${a.risk_level}</span>
    </div>`;
  }).join("");
}

// ═══════════════════════════════════════════════════════════════
//  2. APK 加固
// ═══════════════════════════════════════════════════════════════

const dom = {
  sectionUpload: $("#section-upload"), sectionProgress: $("#section-progress"), sectionResult: $("#section-result"),
  dropZone: $("#drop-zone"), fileInput: $("#file-input"), uploadError: $("#upload-error"),
  progressBar: $("#progress-bar"), progressPercent: $("#progress-percent"),
  progressFile: $("#progress-filename"), progressMsg: $("#progress-message"),
  btnToggleLog: $("#btn-toggle-log"), logBox: $("#log-box"),
  resultSuccess: $("#result-success"), resultFail: $("#result-fail"),
  resultFilename: $("#result-filename"), resultCompare: $("#result-compare"),
  failMessage: $("#fail-message"), btnDownload: $("#btn-download"),
  btnRestart: $("#btn-restart"), btnRetry: $("#btn-retry"),
  historyList: $("#history-list"), historyEmpty: $("#history-empty"),
  historyCount: $("#history-count"), btnRefresh: $("#btn-refresh"), btnClearAll: $("#btn-clear-all"),
};

let taskId = null, pollTimer = null, logVisible = false, uploadStartTime = 0;

function showSection(name) {
  dom.sectionUpload.classList.toggle("hidden", name !== "upload");
  dom.sectionProgress.classList.toggle("hidden", name !== "progress");
  dom.sectionResult.classList.toggle("hidden", name !== "result");
}

function resetAll() {
  taskId = null;
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  logVisible = false;
  dom.logBox.classList.add("hidden");
  dom.logBox.textContent = "";
  dom.progressBar.style.width = "0%";
  dom.progressPercent.textContent = "0%";
  dom.uploadError.classList.add("hidden");
  dom.resultSuccess.classList.add("hidden");
  dom.resultFail.classList.add("hidden");
  dom.fileInput.value = "";
  updateStepBar(-1);
  showSection("upload");
}

function updateStepBar(activeIdx) {
  const steps = $$("#step-bar [data-step]");
  const lines = $$("#step-bar .step-line");
  steps.forEach((el, i) => {
    const dot = el.querySelector(".step-dot");
    if (i < activeIdx) {
      dot.className = "step-dot bg-brand-600 text-white";
    } else if (i === activeIdx) {
      dot.className = "step-dot bg-brand-500 text-white ring-2 ring-brand-400/40";
    } else {
      dot.className = "step-dot bg-slate-700 text-slate-400";
    }
  });
  lines.forEach((el, i) => {
    el.className = "step-line " + (i < activeIdx ? "bg-brand-500" : "bg-slate-700");
  });
}

function progressToStep(pct) {
  if (pct >= 100) return 4;
  if (pct >= 80) return 3;
  if (pct >= 70) return 2;
  if (pct >= 20) return 1;
  if (pct >= 5) return 0;
  return -1;
}

function handleFile(file) {
  if (!file || !file.name.toLowerCase().endsWith(".apk")) {
    dom.uploadError.textContent = "请选择 .apk 文件";
    dom.uploadError.classList.remove("hidden");
    return;
  }
  dom.uploadError.classList.add("hidden");
  uploadFile(file);
}

let uploadFileSize = 0;

async function uploadFile(file) {
  dom.progressFile.textContent = file.name;
  dom.progressMsg.textContent = "正在上传...";
  dom.progressBar.style.width = "5%";
  dom.progressPercent.textContent = "5%";
  uploadFileSize = file.size;
  uploadStartTime = Date.now();
  updateStepBar(0);
  showSection("progress");
  const form = new FormData();
  form.append("file", file);
  try {
    const res = await authFetch(`${API}/api/upload`, { method: "POST", body: form });
    if (!res.ok) { const err = await res.json(); throw new Error(err.detail || "上传失败"); }
    const data = await res.json();
    taskId = data.task_id;
    startPolling();
  } catch (e) {
    dom.uploadError.textContent = e.message;
    dom.uploadError.classList.remove("hidden");
    showSection("upload");
  }
}

function startPolling() { poll(); pollTimer = setInterval(poll, POLL_INTERVAL); }

async function poll() {
  if (!taskId) return;
  try {
    const res = await authFetch(`${API}/api/status/${taskId}`);
    const data = await res.json();
    const pct = data.progress || 0;
    dom.progressBar.style.width = pct + "%";
    dom.progressPercent.textContent = pct + "%";
    dom.progressMsg.textContent = data.message || "";
    updateStepBar(progressToStep(pct));
    if (logVisible) await fetchLogs();
    if (data.status === "completed") {
      clearInterval(pollTimer); pollTimer = null; await fetchLogs(); showCompleted(data);
    } else if (data.status === "failed") {
      clearInterval(pollTimer); pollTimer = null; await fetchLogs(); showFailed(data);
    }
  } catch (_) {}
}

async function fetchLogs() {
  if (!taskId) return;
  try {
    const res = await authFetch(`${API}/api/logs/${taskId}`);
    const data = await res.json();
    if (data.logs) { dom.logBox.textContent = data.logs; dom.logBox.scrollTop = dom.logBox.scrollHeight; }
  } catch (_) {}
}

function showCompleted(data) {
  dom.resultFilename.textContent = data.filename;
  const elapsed = ((Date.now() - uploadStartTime) / 1000).toFixed(1);
  dom.resultCompare.innerHTML = `
    <div class="bg-slate-900/50 rounded-xl p-4 text-center">
      <p class="text-slate-500 text-xs mb-1">原始大小</p>
      <p class="text-white font-bold">${formatSize(uploadFileSize)}</p>
    </div>
    <div class="bg-slate-900/50 rounded-xl p-4 text-center">
      <p class="text-slate-500 text-xs mb-1">加固耗时</p>
      <p class="text-white font-bold">${elapsed}s</p>
    </div>`;
  dom.btnDownload.href = "#";
  dom.btnDownload.onclick = async (e) => {
    e.preventDefault();
    try {
      const res = await authFetch(`${API}/api/download/${taskId}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `protected_${data.filename}`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch (_) {}
  };
  dom.resultSuccess.classList.remove("hidden");
  dom.resultFail.classList.add("hidden");
  showSection("result");
}

function showFailed(data) {
  dom.failMessage.textContent = data.message || "未知错误";
  dom.resultFail.classList.remove("hidden");
  dom.resultSuccess.classList.add("hidden");
  showSection("result");
}

dom.dropZone.addEventListener("click", () => dom.fileInput.click());
dom.fileInput.addEventListener("change", (e) => handleFile(e.target.files[0]));
dom.dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dom.dropZone.classList.add("drag-over"); });
dom.dropZone.addEventListener("dragleave", () => dom.dropZone.classList.remove("drag-over"));
dom.dropZone.addEventListener("drop", (e) => { e.preventDefault(); dom.dropZone.classList.remove("drag-over"); handleFile(e.dataTransfer.files[0]); });
dom.btnToggleLog.addEventListener("click", () => { logVisible = !logVisible; dom.logBox.classList.toggle("hidden", !logVisible); if (logVisible) fetchLogs(); });
dom.btnRestart.addEventListener("click", resetAll);
dom.btnRetry.addEventListener("click", resetAll);

// ═══════════════════════════════════════════════════════════════
//  3. History
// ═══════════════════════════════════════════════════════════════

let currentFilter = "all";

function formatTime(ts) {
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function formatSize(bytes) {
  if (!bytes || bytes <= 0) return "-";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1048576).toFixed(1) + " MB";
}
function statusBadge(status) {
  const m = { completed:{t:"已完成",c:"bg-emerald-500/15 text-emerald-400"}, processing:{t:"加固中",c:"bg-blue-500/15 text-blue-400"}, pending:{t:"等待中",c:"bg-yellow-500/15 text-yellow-400"}, failed:{t:"失败",c:"bg-red-500/15 text-red-400"} };
  const s = m[status] || { t: status, c: "bg-slate-500/15 text-slate-400" };
  return `<span class="inline-block px-2 py-0.5 rounded text-xs font-medium ${s.c}">${s.t}</span>`;
}

async function loadHistory() {
  try {
    const res = await authFetch(`${API}/api/tasks`);
    const data = await res.json();
    let tasks = data.tasks || [];
    dom.historyCount.textContent = tasks.length > 0 ? `(${tasks.length})` : "";

    if (currentFilter !== "all") tasks = tasks.filter(t => t.status === currentFilter);

    if (tasks.length === 0) {
      dom.historyEmpty.classList.remove("hidden");
      dom.historyList.innerHTML = "";
      return;
    }
    dom.historyEmpty.classList.add("hidden");
    let html = `<table class="w-full text-sm"><thead><tr class="text-slate-500 text-xs border-b border-slate-700/40">
      <th class="text-left py-3 px-4 font-medium w-10">#</th>
      <th class="text-left py-3 px-4 font-medium">文件名</th><th class="text-left py-3 px-4 font-medium">状态</th>
      <th class="text-left py-3 px-4 font-medium">时间</th><th class="text-right py-3 px-4 font-medium">大小</th>
      <th class="text-right py-3 px-4 font-medium">操作</th></tr></thead><tbody>`;
    tasks.forEach((t, idx) => {
      const a = [];
      if (t.status === "completed" && t.has_output) a.push(`<button onclick="downloadTask('${t.task_id}','${t.filename}')" class="text-emerald-400 hover:text-emerald-300 transition-colors">下载</button>`);
      a.push(`<button onclick="deleteTask('${t.task_id}')" class="text-red-400/70 hover:text-red-300 transition-colors">删除</button>`);
      html += `<tr class="task-row border-b border-slate-700/20">
        <td class="py-3 px-4 text-slate-600 text-xs">${idx+1}</td>
        <td class="py-3 px-4 text-slate-300 truncate max-w-[200px]" title="${t.filename}">${t.filename}</td>
        <td class="py-3 px-4">${statusBadge(t.status)}</td>
        <td class="py-3 px-4 text-slate-500 text-xs">${formatTime(t.created_at)}</td>
        <td class="py-3 px-4 text-slate-500 text-xs text-right">${t.has_output ? formatSize(t.output_size) : "-"}</td>
        <td class="py-3 px-4 text-right space-x-3 text-xs">${a.join("")}</td></tr>`;
    });
    html += `</tbody></table>`;
    dom.historyList.innerHTML = html;
  } catch (_) {}
}

async function downloadTask(tid, filename) {
  try {
    const res = await authFetch(`${API}/api/download/${tid}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `protected_${filename}`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  } catch (_) {}
}

async function deleteTask(tid) {
  if (!confirm("确定删除此任务？")) return;
  try { await authFetch(`${API}/api/tasks/${tid}`, { method: "DELETE" }); loadHistory(); } catch (_) {}
}
async function clearAllTasks() {
  if (!confirm("确定清理所有历史记录？此操作不可撤销。")) return;
  try { await authFetch(`${API}/api/tasks`, { method: "DELETE" }); loadHistory(); } catch (_) {}
}

$$(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    $$(".filter-btn").forEach(b => { b.classList.remove("active","bg-brand-500/15","text-brand-300"); b.classList.add("bg-slate-700/40","text-slate-400"); });
    btn.classList.add("active","bg-brand-500/15","text-brand-300");
    btn.classList.remove("bg-slate-700/40","text-slate-400");
    currentFilter = btn.dataset.filter;
    loadHistory();
  });
});

dom.btnRefresh.addEventListener("click", loadHistory);
dom.btnClearAll.addEventListener("click", clearAllTasks);

// ═══════════════════════════════════════════════════════════════
//  4. Protection System
// ═══════════════════════════════════════════════════════════════

const TYPE_COLORS = {
  "进程级": { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/20", tag: "bg-red-500/15 text-red-300", hex: "#f87171" },
  "环境级": { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/20", tag: "bg-amber-500/15 text-amber-300", hex: "#fbbf24" },
  "工具级": { bg: "bg-purple-500/10", text: "text-purple-400", border: "border-purple-500/20", tag: "bg-purple-500/15 text-purple-300", hex: "#a78bfa" },
  "代码级": { bg: "bg-cyan-500/10", text: "text-cyan-400", border: "border-cyan-500/20", tag: "bg-cyan-500/15 text-cyan-300", hex: "#22d3ee" },
  "Java层": { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/20", tag: "bg-blue-500/15 text-blue-300", hex: "#60a5fa" },
};
const MODE_COLORS = { "启动时":"bg-slate-600/40 text-slate-300", "后台线程":"bg-emerald-500/15 text-emerald-300", "独立进程":"bg-orange-500/15 text-orange-300", "关键段":"bg-pink-500/15 text-pink-300" };

async function loadAdminData() {
  try {
    const res = await authFetch(`${API}/api/admin/info`);
    const d = await res.json();
    const allLayers = [...d.anti_debug.native_layers, ...d.anti_debug.java_layers];

    renderProtection(d, allLayers);
    renderSystemPage(d);
  } catch (e) { console.error("Admin load failed:", e); }
}

function renderProtection(d, allLayers) {
  const groups = {};
  allLayers.forEach(l => { (groups[l.type] = groups[l.type] || []).push(l); });

  // Category stats
  const catHtml = Object.entries(TYPE_COLORS).map(([type, c]) => {
    const count = (groups[type] || []).length;
    return `<div class="stat-card ${c.bg} border ${c.border} rounded-2xl p-4 text-center">
      <p class="${c.text} text-2xl font-bold">${count}</p>
      <p class="text-slate-500 text-xs mt-1">${type}</p>
    </div>`;
  }).join("");
  $("#prot-category-stats").innerHTML = catHtml;

  // Protection pie chart
  const protPie = echarts.init($("#chart-prot-pie"));
  protPie.setOption({
    ...ecBase(),
    color: Object.values(TYPE_COLORS).map(c => c.hex),
    tooltip: { trigger: "item", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontSize: 12 } },
    series: [{
      type: "pie", radius: ["45%","72%"],
      label: { color: EC_TEXT, fontSize: 11, formatter: "{b}: {c}层" },
      data: Object.entries(groups).map(([t, ls]) => ({ value: ls.length, name: t })),
      itemStyle: { borderRadius: 5, borderColor: "#0f172a", borderWidth: 3 },
    }],
  });
  window.addEventListener("resize", () => protPie.resize());

  // Mode pie chart
  const modeGroups = {};
  allLayers.forEach(l => { (modeGroups[l.mode] = modeGroups[l.mode] || []).push(l); });
  const modePie = echarts.init($("#chart-mode-pie"));
  modePie.setOption({
    ...ecBase(),
    color: ["#818cf8","#34d399","#fb923c","#f472b6"],
    tooltip: { trigger: "item", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontSize: 12 } },
    series: [{
      type: "pie", radius: ["45%","72%"],
      label: { color: EC_TEXT, fontSize: 11, formatter: "{b}: {c}层" },
      data: Object.entries(modeGroups).map(([m, ls]) => ({ value: ls.length, name: m })),
      itemStyle: { borderRadius: 5, borderColor: "#0f172a", borderWidth: 3 },
    }],
  });
  window.addEventListener("resize", () => modePie.resize());

  // Architecture flow
  const archSteps = [
    { label: "原始 APK", sub: "上传到服务端", color: "bg-slate-600" },
    { label: "DEX 提取", sub: "解压 classes*.dex", color: "bg-blue-600" },
    { label: "AES-128-CBC\n加密", sub: "每包随机密钥", color: "bg-brand-600" },
    { label: "HMAC-SHA256\n签名", sub: "密文完整性", color: "bg-purple-600" },
    { label: "清单修改", sub: "注入壳 Application", color: "bg-cyan-600" },
    { label: "重打包", sub: "注入壳 DEX + SO", color: "bg-amber-600" },
    { label: "签名 & 对齐", sub: "apksigner v2", color: "bg-emerald-600" },
    { label: "加固 APK", sub: "分发 / 下载", color: "bg-emerald-500" },
  ];
  $("#prot-arch-flow").innerHTML = archSteps.map((s, i) => {
    const arrow = i < archSteps.length - 1 ? `<svg class="w-6 h-6 text-slate-600 shrink-0 mx-1" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/></svg>` : "";
    return `<div class="flex items-center shrink-0">
      <div class="w-28 ${s.color}/15 border ${s.color.replace("bg-","border-")}/25 rounded-xl p-3 text-center">
        <p class="text-white text-xs font-medium whitespace-pre-line leading-tight">${s.label}</p>
        <p class="text-slate-500 text-[10px] mt-1">${s.sub}</p>
      </div>
      ${arrow}
    </div>`;
  }).join("");

  // Encryption pipeline
  const encSteps = [
    { title: "算法", val: d.encryption.algorithm, icon: "M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" },
    { title: "密钥策略", val: d.encryption.key_mode, icon: "M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" },
    { title: "完整性", val: d.encryption.integrity, icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" },
    { title: "DEX 校验", val: d.encryption.dex_verify, icon: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" },
    { title: "内存清理", val: d.encryption.memory_cleanup, icon: "M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" },
    { title: "密钥存储", val: d.encryption.key_storage, icon: "M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" },
    { title: "设备绑定", val: d.encryption.device_bind, icon: "M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" },
    { title: "数据格式", val: d.encryption.format, icon: "M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" },
  ];
  $("#prot-enc-pipeline").innerHTML = encSteps.map(s => `
    <div class="bg-slate-900/50 rounded-xl p-4">
      <div class="flex items-center gap-2 mb-2">
        <div class="w-7 h-7 rounded-lg bg-brand-600/15 flex items-center justify-center">
          <svg class="w-3.5 h-3.5 text-brand-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="${s.icon}"/></svg>
        </div>
        <span class="text-slate-500 text-[11px]">${s.title}</span>
      </div>
      <p class="text-white text-xs font-medium leading-relaxed">${s.val}</p>
    </div>`).join("");

  // Grouped layers
  $("#prot-layer-count").textContent = `Native ${d.anti_debug.native_layers.length} 层 + Java ${d.anti_debug.java_layers.length} 层`;

  let groupsHtml = "";
  const typeOrder = ["进程级","环境级","工具级","代码级","Java层"];
  typeOrder.forEach(type => {
    const layers = groups[type];
    if (!layers) return;
    const c = TYPE_COLORS[type];
    groupsHtml += `<div class="border-b border-slate-700/20">
      <div class="group-header px-5 py-3 flex items-center justify-between ${c.bg}" onclick="this.nextElementSibling.classList.toggle('hidden')">
        <div class="flex items-center gap-2">
          <span class="tag ${c.tag}">${type}</span>
          <span class="text-white text-sm font-medium">${layers.length} 层防护</span>
        </div>
        <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/></svg>
      </div>
      <div class="divide-y divide-slate-700/15">`;
    layers.forEach(l => {
      groupsHtml += `<div class="px-5 py-3 flex items-start gap-3">
        <div class="w-7 h-7 rounded-lg ${c.bg} flex items-center justify-center text-[11px] font-bold ${c.text} shrink-0 mt-0.5">${l.id}</div>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="text-white text-sm font-medium">${l.name}</span>
            <span class="tag ${MODE_COLORS[l.mode] || 'bg-slate-600/40 text-slate-300'}">${l.mode}</span>
          </div>
          <p class="text-slate-400 text-xs mt-1 leading-relaxed">${l.desc}</p>
        </div>
        <div class="w-2 h-2 rounded-full bg-emerald-400 shrink-0 mt-2.5 animate-pulse" title="已启用"></div>
      </div>`;
    });
    groupsHtml += `</div></div>`;
  });
  $("#prot-groups").innerHTML = groupsHtml;

  // Response info
  $("#prot-response").innerHTML = `
    <div class="flex items-center gap-2 text-xs text-slate-400 mb-2">
      <svg class="w-3.5 h-3.5 text-red-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
      <span>触发响应：<span class="text-red-300">${d.anti_debug.response}</span></span>
    </div>
    <div class="flex items-center gap-2 text-xs text-slate-400">
      <svg class="w-3.5 h-3.5 text-brand-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>
      <span>符号隐藏：<span class="text-brand-300">${d.anti_debug.symbol_hiding}</span></span>
    </div>`;
}

// ═══════════════════════════════════════════════════════════════
//  5. Device Risk
// ═══════════════════════════════════════════════════════════════

function riskBadge(level) {
  const m = {
    CRITICAL: { t:"严重", c:"bg-red-600/20 text-red-300 border-red-500/30" },
    HIGH: { t:"高危", c:"bg-red-500/15 text-red-400 border-red-500/20" },
    MEDIUM: { t:"中危", c:"bg-amber-500/15 text-amber-400 border-amber-500/20" },
    LOW: { t:"低危", c:"bg-blue-500/15 text-blue-400 border-blue-500/20" },
    NONE: { t:"安全", c:"bg-emerald-500/15 text-emerald-400 border-emerald-500/20" },
  };
  const s = m[level] || { t: level || "未知", c:"bg-slate-500/15 text-slate-400 border-slate-500/20" };
  return `<span class="inline-block px-2 py-0.5 rounded border text-xs font-medium ${s.c}">${s.t}</span>`;
}

async function loadRiskData() {
  try {
    const [statsRes, reportsRes] = await Promise.all([
      authFetch(`${API}/api/risk/stats`),
      authFetch(`${API}/api/risk/reports`),
    ]);
    const stats = await statsRes.json();
    const reportsData = await reportsRes.json();
    const reports = reportsData.reports || [];

    $("#risk-total").textContent = stats.total;
    $("#risk-high").textContent = stats.high;
    $("#risk-medium").textContent = stats.medium;
    $("#risk-low").textContent = stats.low;

    const countEl = $("#risk-report-count");
    if (countEl) countEl.textContent = reports.length > 0 ? `(${reports.length})` : "";

    // Risk detail pie
    const riskPie = echarts.init($("#chart-risk-detail-pie"));
    riskPie.setOption({
      ...ecBase(),
      color: ["#f87171","#fbbf24","#34d399"],
      tooltip: { trigger: "item", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontSize: 12 } },
      series: [{
        type: "pie", radius: ["50%","75%"],
        label: { color: EC_TEXT, fontSize: 11, formatter: "{b}\n{c}" },
        data: [
          { value: stats.high, name: "高危" },
          { value: stats.medium, name: "中危" },
          { value: stats.low, name: "低危/安全" },
        ],
        itemStyle: { borderRadius: 5, borderColor: "#0f172a", borderWidth: 3 },
      }],
    });
    window.addEventListener("resize", () => riskPie.resize());

    // Risk trend (from reports dates)
    const trendMap = {};
    reports.forEach(r => {
      if (r.created_at) {
        const day = r.created_at.slice(0, 10);
        trendMap[day] = (trendMap[day] || 0) + 1;
      }
    });
    const trendDays = Object.keys(trendMap).sort().slice(-7);
    const trendChart = echarts.init($("#chart-risk-trend"));
    trendChart.setOption({
      ...ecBase(),
      color: ["#fbbf24"],
      tooltip: { trigger: "axis", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontSize: 12 } },
      grid: { top: 20, right: 20, bottom: 30, left: 40 },
      xAxis: { type: "category", data: trendDays.map(d => d.slice(5)), axisLine: { lineStyle: { color: EC_LINE } }, axisLabel: { color: EC_TEXT, fontSize: 11 } },
      yAxis: { type: "value", minInterval: 1, splitLine: { lineStyle: { color: EC_LINE, type: "dashed" } }, axisLabel: { color: EC_TEXT, fontSize: 11 } },
      series: [{
        type: "bar", data: trendDays.map(d => trendMap[d]),
        barWidth: "40%",
        itemStyle: { borderRadius: [4,4,0,0], color: new echarts.graphic.LinearGradient(0,0,0,1,[{offset:0,color:"#fbbf24"},{offset:1,color:"rgba(251,191,36,.3)"}]) },
      }],
    });
    window.addEventListener("resize", () => trendChart.resize());

    // Table
    const container = $("#risk-table-container");
    const emptyEl = $("#risk-empty");
    if (reports.length === 0) {
      emptyEl.style.display = "";
      container.innerHTML = "";
      return;
    }
    emptyEl.style.display = "none";
    let html = `<table class="w-full text-sm"><thead><tr class="text-slate-500 text-xs border-b border-slate-700/40">
      <th class="text-left py-3 px-4 font-medium">ID</th>
      <th class="text-left py-3 px-4 font-medium">设备标识</th>
      <th class="text-left py-3 px-4 font-medium">风险等级</th>
      <th class="text-left py-3 px-4 font-medium">评分</th>
      <th class="text-left py-3 px-4 font-medium">告警</th>
      <th class="text-left py-3 px-4 font-medium">上报时间</th>
      <th class="text-right py-3 px-4 font-medium">操作</th>
    </tr></thead><tbody>`;
    for (const r of reports) {
      const t = r.created_at ? r.created_at.replace("T"," ").slice(0,16) : "-";
      const pct = r.max_risk_score > 0 ? Math.min(100, r.risk_score / r.max_risk_score * 100) : 0;
      let barColor = "from-emerald-500 to-emerald-400";
      if (pct > 60) barColor = "from-red-500 to-red-400";
      else if (pct > 30) barColor = "from-amber-500 to-amber-400";
      html += `<tr class="task-row border-b border-slate-700/20">
        <td class="py-3 px-4 text-slate-500 text-xs">#${r.id}</td>
        <td class="py-3 px-4 text-slate-300 text-xs font-mono truncate max-w-[140px]" title="${r.device_fingerprint||''}">${r.device_fingerprint||'-'}</td>
        <td class="py-3 px-4">${riskBadge(r.risk_level)}</td>
        <td class="py-3 px-4"><div class="flex items-center gap-2 w-28">
          <div class="flex-1 bg-slate-700/30 rounded-full h-1.5 overflow-hidden"><div class="h-full rounded-full bg-gradient-to-r ${barColor}" style="width:${pct.toFixed(0)}%"></div></div>
          <span class="text-xs text-slate-400">${r.risk_score}/${r.max_risk_score}</span>
        </div></td>
        <td class="py-3 px-4 text-xs">
          ${r.warning_count > 0 ? `<span class="text-amber-400">${r.warning_count} 警告</span>` : ''}
          ${r.danger_count > 0 ? `<span class="text-red-400 ml-1">${r.danger_count} 危险</span>` : ''}
          ${r.warning_count === 0 && r.danger_count === 0 ? '<span class="text-slate-500">无</span>' : ''}
        </td>
        <td class="py-3 px-4 text-slate-500 text-xs">${t}</td>
        <td class="py-3 px-4 text-right space-x-3 text-xs">
          <button onclick="viewRiskDetail(${r.id})" class="text-brand-400 hover:text-brand-300 transition-colors">详情</button>
          <button onclick="deleteRiskReport(${r.id})" class="text-red-400/70 hover:text-red-300 transition-colors">删除</button>
        </td>
      </tr>`;
    }
    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (e) { console.error("Risk load failed:", e); }
}

async function viewRiskDetail(id) {
  const modal = $("#risk-detail-modal");
  const body = $("#risk-detail-body");
  body.innerHTML = '<p class="text-slate-400 text-center py-8">加载中...</p>';
  modal.style.display = "";

  try {
    const res = await authFetch(`${API}/api/risk/reports/${id}`);
    const data = await res.json();
    const report = data.report;
    const fps = data.fingerprints || [];
    const dets = data.detections || [];

    let html = `<div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <div class="bg-slate-900/60 rounded-xl p-3 text-center"><p class="text-xs text-slate-500 mb-1">风险等级</p>${riskBadge(report.risk_level)}</div>
      <div class="bg-slate-900/60 rounded-xl p-3 text-center"><p class="text-xs text-slate-500 mb-1">评分</p><p class="text-white font-bold">${report.risk_score}/${report.max_risk_score}</p></div>
      <div class="bg-slate-900/60 rounded-xl p-3 text-center"><p class="text-xs text-slate-500 mb-1">警告</p><p class="text-amber-400 font-bold">${report.warning_count}</p></div>
      <div class="bg-slate-900/60 rounded-xl p-3 text-center"><p class="text-xs text-slate-500 mb-1">危险</p><p class="text-red-400 font-bold">${report.danger_count}</p></div>
    </div>`;

    if (dets.length > 0) {
      html += `<div><h4 class="text-white text-sm font-semibold mb-3">检测结果 (${dets.length})</h4><div class="space-y-2">`;
      for (const d of dets) {
        const isFound = d.status === "FOUND" || d.status === "DETECTED";
        const sc = isFound ? "text-red-400" : "text-emerald-400";
        const bgc = isFound ? "bg-red-500/5 border-red-500/10" : "bg-emerald-500/5 border-emerald-500/10";
        const detailStr = d.details && typeof d.details === "object" && Object.keys(d.details).length > 0
          ? `<pre class="mt-2 text-[11px] text-slate-500 bg-slate-900/50 rounded-lg p-2.5 overflow-x-auto">${JSON.stringify(d.details, null, 2)}</pre>` : "";
        html += `<div class="border ${bgc} rounded-xl px-4 py-3">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="text-white text-sm font-medium">${d.detector_name}</span>
            <span class="${sc} text-xs font-medium">${d.status}</span>
            ${riskBadge(d.risk_level)}
            <span class="text-xs text-slate-500 ml-auto">+${d.score}</span>
          </div>${detailStr}
        </div>`;
      }
      html += `</div></div>`;
    }

    if (fps.length > 0) {
      html += `<div><h4 class="text-white text-sm font-semibold mb-3">设备指纹 (${fps.length})</h4>
        <div class="bg-slate-900/40 rounded-xl overflow-hidden"><table class="w-full text-sm"><tbody>`;
      for (const f of fps) {
        html += `<tr class="border-b border-slate-700/15">
          <td class="py-2 px-4 text-slate-500 text-xs w-40 font-mono">${f.field_name}</td>
          <td class="py-2 px-4 text-slate-300 text-xs break-all">${f.field_value || '-'}</td>
        </tr>`;
      }
      html += `</tbody></table></div></div>`;
    }
    body.innerHTML = html;
  } catch (e) { body.innerHTML = `<p class="text-red-400 text-center py-8">加载失败: ${e.message}</p>`; }
}

async function deleteRiskReport(id) {
  if (!confirm("确定删除此风险报告？")) return;
  try { await authFetch(`${API}/api/risk/reports/${id}`, { method: "DELETE" }); loadRiskData(); } catch (_) {}
}

const btnRiskRefresh = $("#btn-risk-refresh");
if (btnRiskRefresh) btnRiskRefresh.addEventListener("click", loadRiskData);
const riskModal = $("#risk-detail-modal");
const riskCloseBtn = $("#risk-detail-close");
if (riskCloseBtn) riskCloseBtn.addEventListener("click", () => { riskModal.style.display = "none"; });
if (riskModal) riskModal.addEventListener("click", (e) => { if (e.target === riskModal) riskModal.style.display = "none"; });

// ═══════════════════════════════════════════════════════════════
//  6. System Management
// ═══════════════════════════════════════════════════════════════

function renderSystemPage(d) {
  const allLayers = [...d.anti_debug.native_layers, ...d.anti_debug.java_layers];

  $("#sys-layers").textContent = allLayers.length;
  $("#sys-lines").textContent = d.stats.total_code_lines.toLocaleString();
  $("#sys-tasks").textContent = `${d.stats.completed}/${d.stats.total_tasks}`;
  $("#sys-abis").textContent = d.components.native.abis.length;

  // Components
  const compMap = {
    protector_tool: { name: "Protector-Tool", desc: "PC 端加壳工具 (Java 17)" },
    stub_app: { name: "Stub-App", desc: "设备端壳程序 (Android)" },
    native: { name: "Native Layer", desc: "C++ 反调试 + AES 解密 (NDK)" },
    web_server: { name: "Web Server", desc: "FastAPI 异步后端 (Python)" },
  };
  $("#sys-components").innerHTML = Object.entries(d.components).map(([k, v]) => {
    const c = compMap[k];
    return `<div class="flex items-center gap-3 p-3 rounded-xl ${v.ready ? 'bg-emerald-500/5 border border-emerald-500/15' : 'bg-red-500/5 border border-red-500/15'}">
      <div class="flex-1 min-w-0"><p class="text-white text-sm font-medium">${c.name}</p><p class="text-slate-500 text-[11px]">${c.desc}</p></div>
      <span class="tag ${v.ready ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/15 text-red-300'}">${v.ready ? '就绪' : '未就绪'}</span>
    </div>`;
  }).join("");

  // Tools
  const toolNames = { java: "Java (JDK 17)", apksigner: "apksigner", zipalign: "zipalign" };
  $("#sys-tools").innerHTML = Object.entries(d.tools).map(([k, ok]) => `
    <div class="flex items-center justify-between py-2">
      <span class="text-sm text-slate-300">${toolNames[k] || k}</span>
      <span class="tag ${ok ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/15 text-red-300'}">${ok ? '可用' : '未找到'}</span>
    </div>`).join("");

  // Native libs
  const soSizes = d.components.native.so_sizes || {};
  if (Object.keys(soSizes).length) {
    $("#sys-native").innerHTML = Object.entries(soSizes).map(([abi, sz]) => `
      <div class="flex items-center justify-between py-2">
        <span class="text-sm font-mono text-slate-300">${abi}</span>
        <span class="text-xs text-slate-500">${(sz / 1024).toFixed(0)} KB</span>
      </div>`).join("");
  } else {
    $("#sys-native").innerHTML = '<p class="text-xs text-slate-500 py-2">未编译</p>';
  }

  // Source bar chart
  const allFiles = {};
  for (const [, cv] of Object.entries(d.components)) { if (cv.files) Object.assign(allFiles, cv.files); }
  const sorted = Object.entries(allFiles).sort((a, b) => b[1] - a[1]);

  const sourceChart = echarts.init($("#chart-source-bar"));
  sourceChart.setOption({
    ...ecBase(),
    color: ["#818cf8"],
    tooltip: { trigger: "axis", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontSize: 12 }, axisPointer: { type: "shadow" } },
    grid: { top: 10, right: 30, bottom: 20, left: 140 },
    xAxis: { type: "value", splitLine: { lineStyle: { color: EC_LINE, type: "dashed" } }, axisLabel: { color: EC_TEXT, fontSize: 11 } },
    yAxis: { type: "category", data: sorted.map(([n]) => n).reverse(), axisLine: { lineStyle: { color: EC_LINE } }, axisLabel: { color: EC_TEXT, fontSize: 10, width: 130, overflow: "truncate" } },
    series: [{
      type: "bar", data: sorted.map(([, v]) => v).reverse(),
      barWidth: "60%",
      itemStyle: { borderRadius: [0, 4, 4, 0], color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [{ offset: 0, color: "rgba(129,140,248,.4)" }, { offset: 1, color: "#818cf8" }]) },
      label: { show: true, position: "right", color: EC_TEXT, fontSize: 10 },
    }],
  });
  window.addEventListener("resize", () => sourceChart.resize());
}

async function loadDbStatus() {
  try {
    const res = await authFetch(`${API}/api/system/db-status`);
    const d = await res.json();
    if (d.connected) {
      $("#sys-db").innerHTML = `
        <div class="flex items-center justify-between py-2">
          <span class="text-sm text-slate-300">连接状态</span>
          <span class="tag bg-emerald-500/15 text-emerald-300">已连接</span>
        </div>
        <div class="flex items-center justify-between py-2">
          <span class="text-sm text-slate-300">风险报告数</span>
          <span class="text-sm text-white font-medium">${d.report_count}</span>
        </div>
        <div class="flex items-center justify-between py-2">
          <span class="text-sm text-slate-300">用户数</span>
          <span class="text-sm text-white font-medium">${d.user_count}</span>
        </div>`;
    } else {
      $("#sys-db").innerHTML = `
        <div class="flex items-center justify-between py-2">
          <span class="text-sm text-slate-300">连接状态</span>
          <span class="tag bg-red-500/15 text-red-300">未连接</span>
        </div>
        <p class="text-xs text-red-400">${d.error || "连接失败"}</p>`;
    }
  } catch (_) {
    $("#sys-db").innerHTML = '<p class="text-xs text-slate-500 py-2">无法获取状态</p>';
  }
}

// ═══════════════════════════════════════════════════════════════
//  Init: load dashboard on start
// ═══════════════════════════════════════════════════════════════

switchTab("dashboard");
