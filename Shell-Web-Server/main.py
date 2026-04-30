"""
Android Shell Protector — 后端管理系统入口
启动: uvicorn main:app --reload   或   python main.py
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import task_manager as tm
from auth import authenticate, create_token, require_auth
from database import get_db

FRONTEND_DIR = str(Path(__file__).resolve().parent.parent / "Shell-Frontend")


# ── 生命周期 ─────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    cleanup_task = asyncio.create_task(tm.cleanup_loop())
    yield
    cleanup_task.cancel()


app = FastAPI(title="Android Shell Protector", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="frontend")


# ═══════════════════════════════════════════════════════════════
#  认证路由（无需 token）
# ═══════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(req: LoginRequest):
    user = authenticate(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    token = create_token(user["username"], user["role"])
    return {"token": token, "username": user["username"], "role": user["role"]}


@app.get("/login")
async def login_page():
    html = os.path.join(FRONTEND_DIR, "login.html")
    if os.path.isfile(html):
        return FileResponse(html, media_type="text/html")
    return {"message": "Login page not found"}


@app.get("/")
async def index():
    html = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.isfile(html):
        return FileResponse(html, media_type="text/html")
    return {"message": "Android Shell Protector API"}


# ═══════════════════════════════════════════════════════════════
#  加固 API（需要 token）
# ═══════════════════════════════════════════════════════════════

@app.post("/api/upload")
async def upload_apk(file: UploadFile = File(...), _user=Depends(require_auth)):
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="仅支持 .apk 文件")
    task_id = tm.create_task(file.filename)
    save_path = tm.raw_path(task_id)
    content = await file.read()
    with open(save_path, "wb") as f:
        f.write(content)
    asyncio.create_task(tm.process_task(task_id))
    return {"task_id": task_id, "filename": file.filename, "size": len(content)}


@app.get("/api/status/{task_id}")
async def get_status(task_id: str, _user=Depends(require_auth)):
    task = tm.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    return task.to_dict()


@app.get("/api/download/{task_id}")
async def download(task_id: str, _user=Depends(require_auth)):
    task = tm.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.status != tm.TaskStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="任务尚未完成")
    apk_path = tm.output_apk(task_id)
    if not os.path.isfile(apk_path):
        raise HTTPException(status_code=404, detail="输出文件不存在")
    download_name = f"protected_{Path(task.filename).stem}.apk"
    return FileResponse(apk_path, filename=download_name,
                        media_type="application/vnd.android.package-archive")


@app.get("/api/logs/{task_id}")
async def get_logs(task_id: str, _user=Depends(require_auth)):
    lp = tm.log_path(task_id)
    if not os.path.isfile(lp):
        return {"logs": ""}
    with open(lp, "r", encoding="utf-8", errors="replace") as f:
        return {"logs": f.read()}


@app.get("/api/tasks")
async def list_tasks(_user=Depends(require_auth)):
    return {"tasks": tm.list_tasks()}


@app.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str, _user=Depends(require_auth)):
    ok = tm.delete_task(task_id)
    if not ok:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"ok": True}


@app.delete("/api/tasks")
async def delete_all(_user=Depends(require_auth)):
    count = tm.delete_all_tasks()
    return {"ok": True, "deleted": count}


# ═══════════════════════════════════════════════════════════════
#  设备风险上报 API
# ═══════════════════════════════════════════════════════════════

@app.post("/api/risk/report")
async def receive_risk_report(report: dict = Body(...)):
    """接收设备上报的 RiskReport JSON，存入数据库。无需 token（设备端调用）。"""
    fingerprint_data = report.get("fingerprint") or report.get("deviceFingerprint") or {}
    fp_summary = fingerprint_data.get("android_id") or fingerprint_data.get("androidId") or "unknown"
    risk_level = report.get("overallRiskLevel", "UNKNOWN")
    risk_score = report.get("riskScore", 0)
    max_score = report.get("maxRiskScore", 0)
    warning_count = report.get("warningCount", 0)
    danger_count = report.get("dangerCount", 0)
    sdk_version = report.get("sdkVersion", "")

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO risk_reports
            (device_fingerprint, risk_level, risk_score, max_risk_score, warning_count, danger_count, sdk_version, report_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (fp_summary, risk_level, risk_score, max_score, warning_count, danger_count, sdk_version, json.dumps(report, ensure_ascii=False)))
        report_id = cur.lastrowid

        if isinstance(fingerprint_data, dict):
            for k, v in fingerprint_data.items():
                if v is not None:
                    cur.execute(
                        "INSERT INTO device_fingerprints (report_id, field_name, field_value) VALUES (%s, %s, %s)",
                        (report_id, k, str(v) if not isinstance(v, str) else v),
                    )

        detections = report.get("detections") or []
        for d in detections:
            cur.execute("""
                INSERT INTO detection_results (report_id, detector_name, status, risk_level, score, details)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                report_id,
                d.get("detectorName", d.get("detector_name", "")),
                d.get("status", "UNKNOWN"),
                d.get("riskLevel", d.get("risk_level", "")),
                d.get("score", 0),
                json.dumps(d.get("details") or d.get("evidence") or {}, ensure_ascii=False),
            ))

        conn.commit()

    return {"ok": True, "report_id": report_id}


@app.get("/api/risk/reports")
async def list_risk_reports(_user=Depends(require_auth)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, device_fingerprint, risk_level, risk_score, max_risk_score,
                   warning_count, danger_count, sdk_version, created_at
            FROM risk_reports ORDER BY created_at DESC LIMIT 200
        """)
        rows = cur.fetchall()
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
    return {"reports": rows}


@app.get("/api/risk/reports/{report_id}")
async def get_risk_report(report_id: int, _user=Depends(require_auth)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM risk_reports WHERE id = %s", (report_id,))
        report = cur.fetchone()
        if not report:
            raise HTTPException(status_code=404, detail="报告不存在")
        if report.get("created_at"):
            report["created_at"] = report["created_at"].isoformat()
        if isinstance(report.get("report_json"), str):
            report["report_json"] = json.loads(report["report_json"])

        cur.execute("SELECT * FROM device_fingerprints WHERE report_id = %s", (report_id,))
        fps = cur.fetchall()
        for f in fps:
            if f.get("created_at"):
                f["created_at"] = f["created_at"].isoformat()

        cur.execute("SELECT * FROM detection_results WHERE report_id = %s", (report_id,))
        dets = cur.fetchall()
        for d in dets:
            if d.get("created_at"):
                d["created_at"] = d["created_at"].isoformat()
            if isinstance(d.get("details"), str):
                try:
                    d["details"] = json.loads(d["details"])
                except Exception:
                    pass

    return {"report": report, "fingerprints": fps, "detections": dets}


@app.delete("/api/risk/reports/{report_id}")
async def delete_risk_report(report_id: int, _user=Depends(require_auth)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM risk_reports WHERE id = %s", (report_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="报告不存在")
    return {"ok": True}


@app.get("/api/risk/stats")
async def risk_stats(_user=Depends(require_auth)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as total FROM risk_reports")
        total = cur.fetchone()["total"]
        cur.execute("SELECT risk_level, COUNT(*) as cnt FROM risk_reports GROUP BY risk_level")
        levels = {r["risk_level"]: r["cnt"] for r in cur.fetchall()}
    return {
        "total": total,
        "high": levels.get("HIGH", 0) + levels.get("CRITICAL", 0),
        "medium": levels.get("MEDIUM", 0),
        "low": levels.get("LOW", 0) + levels.get("NONE", 0) + levels.get("UNKNOWN", 0),
    }


# ═══════════════════════════════════════════════════════════════
#  管理后台元信息
# ═══════════════════════════════════════════════════════════════

@app.get("/api/admin/info")
async def admin_info(_user=Depends(require_auth)):
    import shutil

    project_root = Path(__file__).resolve().parent.parent

    def file_exists(rel_path):
        return os.path.isfile(project_root / rel_path)

    def dir_files(rel_path, ext=None):
        d = project_root / rel_path
        if not d.is_dir():
            return []
        files = list(d.iterdir())
        if ext:
            files = [f for f in files if f.suffix == ext]
        return [f.name for f in files]

    def file_size(rel_path):
        p = project_root / rel_path
        return p.stat().st_size if p.is_file() else 0

    def line_count(rel_path):
        p = project_root / rel_path
        if not p.is_file():
            return 0
        try:
            return sum(1 for _ in open(p, encoding="utf-8", errors="replace"))
        except Exception:
            return 0

    native_abis = dir_files("Stub-App/libs")
    so_sizes = {}
    for abi in native_abis:
        sz = file_size(f"Stub-App/libs/{abi}/libguard.so")
        if sz > 0:
            so_sizes[abi] = sz

    tasks_all = tm.list_tasks()
    completed = sum(1 for t in tasks_all if t.get("status") == "completed")
    failed = sum(1 for t in tasks_all if t.get("status") == "failed")

    return {
        "framework": {
            "name": "Android Shell Protector",
            "version": "2.0",
            "title": "基于主动反调试和动态DEX加密解密机制的Android加壳框架",
        },
        "components": {
            "protector_tool": {
                "ready": file_exists("Protector-Tool/build/com/shell/protector/Main.class"),
                "files": {
                    "DexEncryptor.java": line_count("Protector-Tool/src/com/shell/protector/DexEncryptor.java"),
                    "ManifestEditor.java": line_count("Protector-Tool/src/com/shell/protector/ManifestEditor.java"),
                    "Main.java": line_count("Protector-Tool/src/com/shell/protector/Main.java"),
                },
            },
            "stub_app": {
                "ready": file_exists("Stub-App/build/classes.dex"),
                "dex_size": file_size("Stub-App/build/classes.dex"),
                "files": {
                    "ProxyApplication.java": line_count("Stub-App/src/com/shell/stub/ProxyApplication.java"),
                    "RefInvoke.java": line_count("Stub-App/src/com/shell/stub/utils/RefInvoke.java"),
                },
            },
            "native": {
                "ready": len(so_sizes) > 0,
                "abis": native_abis,
                "so_sizes": so_sizes,
                "files": {
                    "guard.cpp": line_count("Stub-App/app/src/main/cpp/guard.cpp"),
                    "anti_debug.cpp": line_count("Stub-App/app/src/main/cpp/anti_debug.cpp"),
                    "anti_debug.h": line_count("Stub-App/app/src/main/cpp/anti_debug.h"),
                },
            },
            "web_server": {
                "ready": True,
                "files": {
                    "main.py": line_count("Shell-Web-Server/main.py"),
                    "task_manager.py": line_count("Shell-Web-Server/task_manager.py"),
                    "shell_wrapper.py": line_count("Shell-Web-Server/utils/shell_wrapper.py"),
                },
            },
        },
        "encryption": {
            "algorithm": "AES-128-CBC",
            "key_mode": "每包随机密钥 (SecureRandom, 16 bytes)",
            "integrity": "HMAC-SHA256 (Encrypt-then-MAC)",
            "format": "[IV(16B)] || [Ciphertext] || [HMAC-SHA256(32B)]",
            "dex_verify": "Magic (dex\\n) + Adler32 Checksum",
            "memory_cleanup": "Arrays.fill + memset",
            "key_storage": "shell_config.properties (Base64)",
            "device_bind": "HMAC-SHA256(key || ANDROID_ID || sig_hash) — 可选",
        },
        "anti_debug": {
            "native_layers": [
                {"id": 1,  "name": "ptrace 自占位",       "desc": "调用 PTRACE_TRACEME 抢占调试槽位，配合 TracerPid 双重验证，兼容 MIUI SELinux 策略", "type": "进程级", "mode": "启动时"},
                {"id": 2,  "name": "TracerPid 后台轮询",   "desc": "独立线程每 800ms 读取 /proc/self/status 的 TracerPid，防御延迟附加攻击", "type": "进程级", "mode": "后台线程"},
                {"id": 3,  "name": "双进程 ptrace 交叉守护","desc": "fork 子进程互相 PTRACE_ATTACH，心跳存活检测，调试器无法附加到任一进程", "type": "进程级", "mode": "独立进程"},
                {"id": 4,  "name": "模拟器环境检测",        "desc": "检测 18+ 特征文件路径（QEMU/VBox/Nox 等）+ /proc/cpuinfo 虚拟化标记", "type": "环境级", "mode": "启动时"},
                {"id": 5,  "name": "Frida 即时检测",        "desc": "TCP 27042 端口 + D-Bus 协议探测 + /proc/self/maps 扫描 + 线程名匹配", "type": "工具级", "mode": "启动时"},
                {"id": 6,  "name": "Frida 持续监控",        "desc": "独立线程每 1.5s 执行三维 Frida 检测（端口/内存映射/线程名）", "type": "工具级", "mode": "后台线程"},
                {"id": 7,  "name": "GOT/PLT Hook 检测",    "desc": "校验 fopen/ptrace/open/read/mmap 地址是否在 libc.so 映射范围内", "type": "代码级", "mode": "启动时"},
                {"id": 8,  "name": "Root/Magisk/Xposed 检测","desc": "13+ 特征文件检测 + /proc/self/maps 扫描 XposedBridge/riru/edxposed/lspd", "type": "环境级", "mode": "启动时"},
                {"id": 9,  "name": ".text 段 CRC32 校验",   "desc": "运行时解析 ELF 定位 .text 段，计算 CRC32 基准值，后台线程每 3s 复验", "type": "代码级", "mode": "后台线程"},
                {"id": 10, "name": "时间差反调试检测",      "desc": "clock_gettime(CLOCK_MONOTONIC) 在解密前后设检测点，阈值 800ms", "type": "代码级", "mode": "关键段"},
                {"id": 11, "name": "容器/沙箱环境检测",     "desc": "检测多开应用特征文件、cgroup 标记、虚拟化路径（VirtualApp/DualSpace/Parallel）", "type": "环境级", "mode": "启动时"},
                {"id": 12, "name": "云手机环境检测",        "desc": "检测云手机特征属性（ro.cloud.*）+ 低温区计数 + 特征进程", "type": "环境级", "mode": "启动时"},
                {"id": 13, "name": "Mount 异常分析",        "desc": "解析 /proc/mounts 检测 overlay/tmpfs 异常挂载到系统关键路径", "type": "环境级", "mode": "启动时"},
                {"id": 14, "name": "ART 方法完整性检测",    "desc": "检验关键 Java 方法的 ART entry_point 地址是否在合法模块范围内", "type": "代码级", "mode": "启动时"},
            ],
            "java_layers": [
                {"id": 15, "name": "JDWP 调试器检测",       "desc": "Debug.isDebuggerConnected() 检测 Java 调试协议连接", "type": "Java层", "mode": "启动时"},
                {"id": 16, "name": "FLAG_DEBUGGABLE 检测",   "desc": "ApplicationInfo.flags & FLAG_DEBUGGABLE 检测调试标志位", "type": "Java层", "mode": "启动时"},
                {"id": 17, "name": "waitingForDebugger 检测","desc": "Debug.waitingForDebugger() 检测是否等待调试器附加", "type": "Java层", "mode": "启动时"},
            ],
            "response": "空函数指针触发 SIGSEGV 静默崩溃（不可 Hook、不可拦截）",
            "symbol_hiding": "JNI 动态注册 + -fvisibility=hidden，仅导出 JNI_OnLoad",
        },
        "stats": {
            "total_tasks": len(tasks_all),
            "completed": completed,
            "failed": failed,
            "total_code_lines": sum([
                line_count("Protector-Tool/src/com/shell/protector/DexEncryptor.java"),
                line_count("Protector-Tool/src/com/shell/protector/ManifestEditor.java"),
                line_count("Protector-Tool/src/com/shell/protector/Main.java"),
                line_count("Stub-App/src/com/shell/stub/ProxyApplication.java"),
                line_count("Stub-App/src/com/shell/stub/utils/RefInvoke.java"),
                line_count("Stub-App/app/src/main/cpp/guard.cpp"),
                line_count("Stub-App/app/src/main/cpp/anti_debug.cpp"),
                line_count("Shell-Web-Server/main.py"),
                line_count("Shell-Web-Server/task_manager.py"),
                line_count("Shell-Web-Server/utils/shell_wrapper.py"),
            ]),
        },
        "tools": {
            "java": shutil.which("java") is not None,
            "apksigner": shutil.which("apksigner") is not None,
            "zipalign": shutil.which("zipalign") is not None,
        },
    }


# ═══════════════════════════════════════════════════════════════
#  启动入口
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=1078, reload=True)
