/**
 * Android Shell Protector — 前端交互逻辑
 * 负责 APK 上传、进度轮询、日志展示和文件下载。
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
    } else if (data.status === "failed") {
      clearInterval(pollTimer);
      pollTimer = null;
      await fetchLogs();
      showFailed(data);
    }
  } catch (_) { /* 网络抖动忽略 */ }
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
