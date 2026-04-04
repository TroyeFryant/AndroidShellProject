/**
 * Android Shell Protector — 前端交互逻辑
 */

const API = "";
const POLL_INTERVAL = 2000;

const $ = (sel) => document.querySelector(sel);

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

// ═══════════════════════════════════════════════════════════════
//  视图切换
// ═══════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════
//  上传
// ═══════════════════════════════════════════════════════════════

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
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "上传失败");
    }
    const data = await res.json();
    taskId = data.task_id;
    startPolling();
  } catch (e) {
    dom.uploadError.textContent = e.message;
    dom.uploadError.classList.remove("hidden");
    showSection("upload");
  }
}

// ═══════════════════════════════════════════════════════════════
//  轮询
// ═══════════════════════════════════════════════════════════════

function startPolling() {
  poll();
  pollTimer = setInterval(poll, POLL_INTERVAL);
}

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
      clearInterval(pollTimer);
      pollTimer = null;
      await fetchLogs();
      showCompleted(data);
      loadHistory();
    } else if (data.status === "failed") {
      clearInterval(pollTimer);
      pollTimer = null;
      await fetchLogs();
      showFailed(data);
      loadHistory();
    }
  } catch (_) {}
}

async function fetchLogs() {
  if (!taskId) return;
  try {
    const res = await fetch(`${API}/api/logs/${taskId}`);
    const data = await res.json();
    if (data.logs) {
      dom.logBox.textContent = data.logs;
      dom.logBox.scrollTop = dom.logBox.scrollHeight;
    }
  } catch (_) {}
}

// ═══════════════════════════════════════════════════════════════
//  结果
// ═══════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════
//  历史记录
// ═══════════════════════════════════════════════════════════════

function formatTime(ts) {
  const d = new Date(ts * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1024 / 1024).toFixed(1) + " MB";
}

function statusBadge(status) {
  const map = {
    completed: { text: "已完成", cls: "bg-emerald-500/15 text-emerald-400" },
    processing: { text: "加固中", cls: "bg-blue-500/15 text-blue-400" },
    pending: { text: "等待中", cls: "bg-yellow-500/15 text-yellow-400" },
    failed: { text: "失败", cls: "bg-red-500/15 text-red-400" },
  };
  const s = map[status] || { text: status, cls: "bg-slate-500/15 text-slate-400" };
  return `<span class="inline-block px-2 py-0.5 rounded text-xs font-medium ${s.cls}">${s.text}</span>`;
}

async function loadHistory() {
  try {
    const res = await fetch(`${API}/api/tasks`);
    const data = await res.json();
    const tasks = data.tasks || [];

    dom.historyCount.textContent = tasks.length > 0 ? `(${tasks.length})` : "";

    if (tasks.length === 0) {
      dom.historyEmpty.classList.remove("hidden");
      dom.historyEmpty.nextElementSibling?.remove();
      const existing = dom.historyList.querySelector("table");
      if (existing) existing.remove();
      return;
    }

    dom.historyEmpty.classList.add("hidden");

    let html = `<table class="w-full text-sm">
      <thead>
        <tr class="text-slate-500 text-xs border-b border-slate-700/40">
          <th class="text-left py-2 px-4 font-medium">文件名</th>
          <th class="text-left py-2 px-4 font-medium">状态</th>
          <th class="text-left py-2 px-4 font-medium">时间</th>
          <th class="text-right py-2 px-4 font-medium">大小</th>
          <th class="text-right py-2 px-4 font-medium">操作</th>
        </tr>
      </thead><tbody>`;

    for (const t of tasks) {
      const actions = [];
      if (t.status === "completed" && t.has_output) {
        actions.push(`<a href="${API}/api/download/${t.task_id}" class="text-emerald-400 hover:text-emerald-300 transition-colors">下载</a>`);
      }
      actions.push(`<button onclick="deleteTask('${t.task_id}')" class="text-red-400/70 hover:text-red-300 transition-colors">删除</button>`);

      html += `<tr class="task-row border-b border-slate-700/20">
        <td class="py-2.5 px-4 text-slate-300 truncate max-w-[180px]" title="${t.filename}">${t.filename}</td>
        <td class="py-2.5 px-4">${statusBadge(t.status)}</td>
        <td class="py-2.5 px-4 text-slate-500 text-xs">${formatTime(t.created_at)}</td>
        <td class="py-2.5 px-4 text-slate-500 text-xs text-right">${t.has_output ? formatSize(t.output_size) : "-"}</td>
        <td class="py-2.5 px-4 text-right space-x-3 text-xs">${actions.join("")}</td>
      </tr>`;
    }

    html += `</tbody></table>`;

    const existing = dom.historyList.querySelector("table");
    if (existing) existing.remove();

    dom.historyList.insertAdjacentHTML("beforeend", html);
  } catch (_) {}
}

async function deleteTask(tid) {
  if (!confirm("确定删除此任务？")) return;
  try {
    await fetch(`${API}/api/tasks/${tid}`, { method: "DELETE" });
    loadHistory();
  } catch (_) {}
}

async function clearAllTasks() {
  if (!confirm("确定清理所有历史记录？此操作不可撤销。")) return;
  try {
    await fetch(`${API}/api/tasks`, { method: "DELETE" });
    loadHistory();
  } catch (_) {}
}

// ═══════════════════════════════════════════════════════════════
//  事件绑定
// ═══════════════════════════════════════════════════════════════

dom.dropZone.addEventListener("click", () => dom.fileInput.click());
dom.fileInput.addEventListener("change", (e) => handleFile(e.target.files[0]));

dom.dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dom.dropZone.classList.add("drag-over");
});
dom.dropZone.addEventListener("dragleave", () => {
  dom.dropZone.classList.remove("drag-over");
});
dom.dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dom.dropZone.classList.remove("drag-over");
  handleFile(e.dataTransfer.files[0]);
});

dom.btnToggleLog.addEventListener("click", () => {
  logVisible = !logVisible;
  dom.logBox.classList.toggle("hidden", !logVisible);
  if (logVisible) fetchLogs();
});

dom.btnRestart.addEventListener("click", resetAll);
dom.btnRetry.addEventListener("click", resetAll);
dom.btnRefresh.addEventListener("click", loadHistory);
dom.btnClearAll.addEventListener("click", clearAllTasks);

// 页面加载时获取历史记录
loadHistory();
