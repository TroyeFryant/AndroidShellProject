/**
 * Android Shell Protector — 统一前端
 */

const API = "";
const POLL_INTERVAL = 2000;
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ═══════════════════════════════════════════════════════════════
//  标签页切换
// ═══════════════════════════════════════════════════════════════

const tabPanels = { harden: $("#tab-harden"), history: $("#tab-history"), protection: $("#tab-protection"), system: $("#tab-system") };
const navButtons = $$(".nav-item[data-tab]");
let adminLoaded = false;

function switchTab(name) {
  Object.entries(tabPanels).forEach(([k, el]) => {
    if (!el) return;
    el.style.display = (k === name) ? "" : "none";
  });
  navButtons.forEach(btn => {
    const active = btn.dataset.tab === name;
    btn.classList.toggle("active", active);
    btn.classList.toggle("text-slate-400", !active);
  });
  if (name === "history") loadHistory();
  if ((name === "protection" || name === "system") && !adminLoaded) {
    adminLoaded = true;
    loadAdminData();
  }
}

navButtons.forEach(btn => btn.addEventListener("click", () => switchTab(btn.dataset.tab)));

switchTab("harden");

// ═══════════════════════════════════════════════════════════════
//  加固页面逻辑
// ═══════════════════════════════════════════════════════════════

const dom = {
  sectionUpload:   $("#section-upload"),
  sectionProgress: $("#section-progress"),
  sectionResult:   $("#section-result"),
  dropZone:        $("#drop-zone"),
  fileInput:       $("#file-input"),
  uploadError:     $("#upload-error"),
  progressBar:     $("#progress-bar"),
  progressPercent: $("#progress-percent"),
  progressFile:    $("#progress-filename"),
  progressMsg:     $("#progress-message"),
  btnToggleLog:    $("#btn-toggle-log"),
  logBox:          $("#log-box"),
  resultSuccess:   $("#result-success"),
  resultFail:      $("#result-fail"),
  resultFilename:  $("#result-filename"),
  failMessage:     $("#fail-message"),
  btnDownload:     $("#btn-download"),
  btnRestart:      $("#btn-restart"),
  btnRetry:        $("#btn-retry"),
  historyList:     $("#history-list"),
  historyEmpty:    $("#history-empty"),
  historyCount:    $("#history-count"),
  btnRefresh:      $("#btn-refresh"),
  btnClearAll:     $("#btn-clear-all"),
};

let taskId = null;
let pollTimer = null;
let logVisible = false;

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
  showSection("upload");
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

async function uploadFile(file) {
  dom.progressFile.textContent = file.name;
  dom.progressMsg.textContent = "正在上传...";
  dom.progressBar.style.width = "5%";
  dom.progressPercent.textContent = "5%";
  showSection("progress");
  const form = new FormData();
  form.append("file", file);
  try {
    const res = await fetch(`${API}/api/upload`, { method: "POST", body: form });
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
    const res = await fetch(`${API}/api/status/${taskId}`);
    const data = await res.json();
    const pct = data.progress || 0;
    dom.progressBar.style.width = pct + "%";
    dom.progressPercent.textContent = pct + "%";
    dom.progressMsg.textContent = data.message || "";
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
    const res = await fetch(`${API}/api/logs/${taskId}`);
    const data = await res.json();
    if (data.logs) { dom.logBox.textContent = data.logs; dom.logBox.scrollTop = dom.logBox.scrollHeight; }
  } catch (_) {}
}

function showCompleted(data) {
  dom.resultFilename.textContent = data.filename;
  dom.btnDownload.href = `${API}/api/download/${taskId}`;
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

// ── 历史记录 ──

function formatTime(ts) {
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function formatSize(bytes) {
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
    const res = await fetch(`${API}/api/tasks`);
    const data = await res.json();
    const tasks = data.tasks || [];
    dom.historyCount.textContent = tasks.length > 0 ? `(${tasks.length})` : "";
    if (tasks.length === 0) {
      dom.historyEmpty.classList.remove("hidden");
      const t = dom.historyList.querySelector("table"); if (t) t.remove();
      return;
    }
    dom.historyEmpty.classList.add("hidden");
    let html = `<table class="w-full text-sm"><thead><tr class="text-slate-500 text-xs border-b border-slate-700/40">
      <th class="text-left py-2 px-4 font-medium">文件名</th><th class="text-left py-2 px-4 font-medium">状态</th>
      <th class="text-left py-2 px-4 font-medium">时间</th><th class="text-right py-2 px-4 font-medium">大小</th>
      <th class="text-right py-2 px-4 font-medium">操作</th></tr></thead><tbody>`;
    for (const t of tasks) {
      const a = [];
      if (t.status === "completed" && t.has_output) a.push(`<a href="${API}/api/download/${t.task_id}" class="text-emerald-400 hover:text-emerald-300 transition-colors">下载</a>`);
      a.push(`<button onclick="deleteTask('${t.task_id}')" class="text-red-400/70 hover:text-red-300 transition-colors">删除</button>`);
      html += `<tr class="task-row border-b border-slate-700/20">
        <td class="py-2.5 px-4 text-slate-300 truncate max-w-[180px]" title="${t.filename}">${t.filename}</td>
        <td class="py-2.5 px-4">${statusBadge(t.status)}</td>
        <td class="py-2.5 px-4 text-slate-500 text-xs">${formatTime(t.created_at)}</td>
        <td class="py-2.5 px-4 text-slate-500 text-xs text-right">${t.has_output ? formatSize(t.output_size) : "-"}</td>
        <td class="py-2.5 px-4 text-right space-x-3 text-xs">${a.join("")}</td></tr>`;
    }
    html += `</tbody></table>`;
    const ex = dom.historyList.querySelector("table"); if (ex) ex.remove();
    dom.historyList.insertAdjacentHTML("beforeend", html);
  } catch (_) {}
}

async function deleteTask(tid) {
  if (!confirm("确定删除此任务？")) return;
  try { await fetch(`${API}/api/tasks/${tid}`, { method: "DELETE" }); loadHistory(); } catch (_) {}
}
async function clearAllTasks() {
  if (!confirm("确定清理所有历史记录？此操作不可撤销。")) return;
  try { await fetch(`${API}/api/tasks`, { method: "DELETE" }); loadHistory(); } catch (_) {}
}

// ── 事件绑定 ──

dom.dropZone.addEventListener("click", () => dom.fileInput.click());
dom.fileInput.addEventListener("change", (e) => handleFile(e.target.files[0]));
dom.dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dom.dropZone.classList.add("drag-over"); });
dom.dropZone.addEventListener("dragleave", () => dom.dropZone.classList.remove("drag-over"));
dom.dropZone.addEventListener("drop", (e) => { e.preventDefault(); dom.dropZone.classList.remove("drag-over"); handleFile(e.dataTransfer.files[0]); });
dom.btnToggleLog.addEventListener("click", () => { logVisible = !logVisible; dom.logBox.classList.toggle("hidden", !logVisible); if (logVisible) fetchLogs(); });
dom.btnRestart.addEventListener("click", resetAll);
dom.btnRetry.addEventListener("click", resetAll);
dom.btnRefresh.addEventListener("click", loadHistory);
dom.btnClearAll.addEventListener("click", clearAllTasks);

loadHistory();

// ═══════════════════════════════════════════════════════════════
//  管理后台数据加载
// ═══════════════════════════════════════════════════════════════

async function loadAdminData() {
  try {
    const res = await fetch(`${API}/api/admin/info`);
    const d = await res.json();

    const allLayers = [...d.anti_debug.native_layers, ...d.anti_debug.java_layers];

    // Stats
    $("#stat-layers").textContent = allLayers.length;
    $("#stat-lines").textContent = d.stats.total_code_lines.toLocaleString();
    $("#stat-tasks").textContent = `${d.stats.completed}/${d.stats.total_tasks}`;
    $("#stat-abis").textContent = d.components.native.abis.length;

    // Anti-debug layers
    $("#debug-count").textContent = `Native ${d.anti_debug.native_layers.length} 层 + Java ${d.anti_debug.java_layers.length} 层`;

    const typeColors = { '进程级':'bg-red-500/15 text-red-300', '环境级':'bg-amber-500/15 text-amber-300', '工具级':'bg-purple-500/15 text-purple-300', '代码级':'bg-cyan-500/15 text-cyan-300', 'Java层':'bg-blue-500/15 text-blue-300' };
    const modeColors = { '启动时':'bg-slate-600/40 text-slate-300', '后台线程':'bg-emerald-500/15 text-emerald-300', '独立进程':'bg-orange-500/15 text-orange-300', '关键段':'bg-pink-500/15 text-pink-300' };

    const layersHtml = allLayers.map(l => `
      <div class="layer-row px-5 py-3 flex items-start gap-3">
        <div class="w-7 h-7 rounded-lg bg-slate-700/50 flex items-center justify-center text-[11px] font-bold text-white shrink-0 mt-0.5">${l.id}</div>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="text-white text-sm font-medium">${l.name}</span>
            <span class="tag ${typeColors[l.type]||'bg-slate-600/40 text-slate-300'}">${l.type}</span>
            <span class="tag ${modeColors[l.mode]||'bg-slate-600/40 text-slate-300'}">${l.mode}</span>
          </div>
          <p class="text-slate-400 text-xs mt-1 leading-relaxed">${l.desc}</p>
        </div>
        <div class="w-2 h-2 rounded-full bg-emerald-400 shrink-0 mt-2.5 animate-pulse" title="已启用"></div>
      </div>`).join('');

    $("#debug-layers").innerHTML = layersHtml +
      `<div class="px-5 py-2.5 bg-slate-900/40 flex items-center gap-2 text-xs text-slate-400">
         <svg class="w-3.5 h-3.5 text-red-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
         <span>触发响应：<span class="text-red-300">${d.anti_debug.response}</span></span>
       </div>
       <div class="px-5 py-2.5 bg-slate-900/40 border-t border-slate-700/20 flex items-center gap-2 text-xs text-slate-400">
         <svg class="w-3.5 h-3.5 text-brand-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>
         <span>符号隐藏：<span class="text-brand-300">${d.anti_debug.symbol_hiding}</span></span>
       </div>`;

    // Encryption
    const encMap = { algorithm:'加密算法', key_mode:'密钥策略', integrity:'完整性校验', dex_verify:'DEX 校验', memory_cleanup:'内存清理', key_storage:'密钥存储', device_bind:'设备绑定' };
    const encIcons = { algorithm:'🔐', key_mode:'🔑', integrity:'✅', dex_verify:'🔍', memory_cleanup:'🧹', key_storage:'📦', device_bind:'📱' };
    $("#enc-grid").innerHTML = Object.entries(encMap).map(([k, label]) => `
      <div class="bg-slate-900/40 rounded-xl p-3">
        <div class="flex items-center gap-2 mb-1">
          <span class="text-sm">${encIcons[k]||'•'}</span>
          <span class="text-[11px] text-slate-500">${label}</span>
        </div>
        <p class="text-[13px] text-white font-medium leading-snug">${d.encryption[k]}</p>
      </div>`).join('');

    // Components
    const compMap = { protector_tool:{name:'Protector-Tool',desc:'PC 端加壳工具 (Java 17)',icon:'☕'}, stub_app:{name:'Stub-App',desc:'设备端壳程序 (Android)',icon:'📱'}, native:{name:'Native Layer',desc:'C++ 反调试 + AES 解密 (NDK)',icon:'⚙️'}, web_server:{name:'Web Server',desc:'FastAPI 异步后端 (Python)',icon:'🌐'} };
    $("#component-list").innerHTML = Object.entries(d.components).map(([k,v]) => {
      const c = compMap[k];
      return `<div class="flex items-center gap-3 p-2.5 rounded-xl ${v.ready?'bg-emerald-500/5':'bg-red-500/5'}">
        <span class="text-lg">${c.icon}</span>
        <div class="flex-1 min-w-0"><p class="text-white text-sm font-medium">${c.name}</p><p class="text-slate-500 text-[11px]">${c.desc}</p></div>
        <div class="w-2 h-2 rounded-full ${v.ready?'bg-emerald-400':'bg-red-400'}"></div>
      </div>`;
    }).join('');

    // Tools
    const toolNames = { java:'Java (JDK 17)', apksigner:'apksigner', zipalign:'zipalign' };
    $("#tools-list").innerHTML = Object.entries(d.tools).map(([k,ok]) => `
      <div class="flex items-center justify-between py-1.5">
        <span class="text-sm text-slate-300">${toolNames[k]||k}</span>
        <span class="tag ${ok?'bg-emerald-500/15 text-emerald-300':'bg-red-500/15 text-red-300'}">${ok?'可用':'未找到'}</span>
      </div>`).join('');

    // Native libs
    const soSizes = d.components.native.so_sizes || {};
    if (Object.keys(soSizes).length) {
      $("#native-list").innerHTML = Object.entries(soSizes).map(([abi,sz]) => `
        <div class="flex items-center justify-between py-1.5">
          <span class="text-sm font-mono text-slate-300">${abi}</span>
          <span class="text-xs text-slate-500">${(sz/1024).toFixed(0)} KB</span>
        </div>`).join('');
    } else {
      $("#native-list").innerHTML = '<p class="text-xs text-slate-500 py-2">未编译</p>';
    }

    // Source files
    const allFiles = {};
    for (const [,cv] of Object.entries(d.components)) { if (cv.files) Object.assign(allFiles, cv.files); }
    const sorted = Object.entries(allFiles).sort((a,b) => b[1]-a[1]);
    const maxL = sorted[0]?.[1] || 1;
    $("#source-list").innerHTML = sorted.map(([name,lines]) => `
      <div class="flex items-center gap-2">
        <span class="text-xs text-slate-400 w-32 truncate font-mono" title="${name}">${name}</span>
        <div class="flex-1 bg-slate-700/30 rounded-full h-1.5 overflow-hidden">
          <div class="h-full rounded-full bg-gradient-to-r from-brand-500 to-cyan-500" style="width:${(lines/maxL*100).toFixed(0)}%"></div>
        </div>
        <span class="text-[11px] text-slate-500 w-10 text-right">${lines}</span>
      </div>`).join('');

  } catch (e) {
    console.error("Failed to load admin data:", e);
  }
}
