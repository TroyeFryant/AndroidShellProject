"""
Android Shell Protector — 后端管理系统入口
启动: uvicorn main:app --reload   或   python main.py
"""

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import task_manager as tm

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

# 挂载前端静态文件（如目录存在）
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="frontend")


# ═══════════════════════════════════════════════════════════════
#  API 路由
# ═══════════════════════════════════════════════════════════════

@app.get("/")
async def index():
    html = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.isfile(html):
        return FileResponse(html, media_type="text/html")
    return {"message": "Android Shell Protector API"}


@app.post("/api/upload")
async def upload_apk(file: UploadFile = File(...)):
    """上传 APK 文件，返回 task_id。后台自动启动加固任务。"""
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="仅支持 .apk 文件")

    task_id = tm.create_task(file.filename)

    save_path = tm.raw_path(task_id)
    content = await file.read()
    with open(save_path, "wb") as f:
        f.write(content)

    asyncio.create_task(tm.process_task(task_id))

    return {
        "task_id": task_id,
        "filename": file.filename,
        "size": len(content),
    }


@app.get("/api/status/{task_id}")
async def get_status(task_id: str):
    """查询加固任务进度。"""
    task = tm.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    return task.to_dict()


@app.get("/api/download/{task_id}")
async def download(task_id: str):
    """下载加固后的 APK。"""
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
async def get_logs(task_id: str):
    """获取加固任务的执行日志。"""
    lp = tm.log_path(task_id)
    if not os.path.isfile(lp):
        return {"logs": ""}
    with open(lp, "r", encoding="utf-8", errors="replace") as f:
        return {"logs": f.read()}


@app.get("/api/tasks")
async def list_tasks():
    """列出所有历史加固任务。"""
    return {"tasks": tm.list_tasks()}


@app.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str):
    """删除单个任务。"""
    ok = tm.delete_task(task_id)
    if not ok:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"ok": True}


@app.delete("/api/tasks")
async def delete_all():
    """一键清理所有任务。"""
    count = tm.delete_all_tasks()
    return {"ok": True, "deleted": count}


# ═══════════════════════════════════════════════════════════════
#  管理后台
# ═══════════════════════════════════════════════════════════════

@app.get("/api/admin/info")
async def admin_info():
    """返回框架防护能力、组件状态等元信息。"""
    import subprocess, shutil

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
            ],
            "java_layers": [
                {"id": 11, "name": "JDWP 调试器检测",       "desc": "Debug.isDebuggerConnected() 检测 Java 调试协议连接", "type": "Java层", "mode": "启动时"},
                {"id": 12, "name": "FLAG_DEBUGGABLE 检测",   "desc": "ApplicationInfo.flags & FLAG_DEBUGGABLE 检测调试标志位", "type": "Java层", "mode": "启动时"},
                {"id": 13, "name": "waitingForDebugger 检测","desc": "Debug.waitingForDebugger() 检测是否等待调试器附加", "type": "Java层", "mode": "启动时"},
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
