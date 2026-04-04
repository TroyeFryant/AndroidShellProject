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
#  启动入口
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=1078, reload=True)
