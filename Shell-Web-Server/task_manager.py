"""
异步任务调度：管理 APK 加固任务的生命周期。
"""

import asyncio
import json
import os
import time
import uuid
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Dict, Optional

from utils import shell_wrapper


class TaskStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskInfo:
    task_id: str
    filename: str
    status: TaskStatus
    created_at: float
    message: str = ""
    progress: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


STORAGE_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage")

_tasks: Dict[str, TaskInfo] = {}


def _ensure_dirs():
    for sub in ("raw", "output", "logs", "meta"):
        os.makedirs(os.path.join(STORAGE_BASE, sub), exist_ok=True)


def _meta_path(task_id: str) -> str:
    return os.path.join(STORAGE_BASE, "meta", f"{task_id}.json")


def _save_meta(task_id: str, filename: str, created_at: float):
    try:
        with open(_meta_path(task_id), "w", encoding="utf-8") as f:
            json.dump({"filename": filename, "created_at": created_at}, f)
    except OSError:
        pass


def _load_meta(task_id: str) -> dict:
    p = _meta_path(task_id)
    if os.path.isfile(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
    return {}


_ensure_dirs()


def _recover_tasks():
    """启动时扫描 storage/ 目录，恢复磁盘上已有的历史任务记录。"""
    raw_dir = os.path.join(STORAGE_BASE, "raw")
    if not os.path.isdir(raw_dir):
        return

    for fname in os.listdir(raw_dir):
        if not fname.endswith(".apk"):
            continue
        tid = fname[:-4]  # strip .apk
        if tid in _tasks:
            continue

        raw = os.path.join(raw_dir, fname)
        apk_out = output_apk(tid)
        log_file = log_path(tid)

        meta = _load_meta(tid)
        original_name = meta.get("filename", f"{tid}.apk")
        created_at = meta.get("created_at", os.path.getmtime(raw))

        if os.path.isfile(apk_out):
            status = TaskStatus.COMPLETED
            msg = "加固完成"
            progress = 100
        elif os.path.isfile(log_file):
            status = TaskStatus.FAILED
            msg = "加固失败（历史记录）"
            progress = 100
        else:
            status = TaskStatus.FAILED
            msg = "状态未知（历史记录）"
            progress = 100

        _tasks[tid] = TaskInfo(
            task_id=tid,
            filename=original_name,
            status=status,
            created_at=created_at,
            message=msg,
            progress=progress,
        )


# _recover_tasks() 在下方函数定义后调用


# ═══════════════════════════════════════════════════════════════
#  任务 CRUD
# ═══════════════════════════════════════════════════════════════

def create_task(filename: str) -> str:
    task_id = uuid.uuid4().hex[:12]
    now = time.time()
    _tasks[task_id] = TaskInfo(
        task_id=task_id,
        filename=filename,
        status=TaskStatus.PENDING,
        created_at=now,
    )
    _save_meta(task_id, filename, now)
    return task_id


def get_task(task_id: str) -> Optional[TaskInfo]:
    return _tasks.get(task_id)


def list_tasks() -> list[dict]:
    """返回所有任务（按创建时间倒序）。"""
    items = sorted(_tasks.values(), key=lambda t: t.created_at, reverse=True)
    result = []
    for t in items:
        d = t.to_dict()
        d["has_output"] = os.path.isfile(output_apk(t.task_id))
        d["output_size"] = (
            os.path.getsize(output_apk(t.task_id))
            if d["has_output"] else 0
        )
        result.append(d)
    return result


def delete_task(task_id: str) -> bool:
    """删除单个任务的所有文件和记录。"""
    task = _tasks.pop(task_id, None)
    if not task:
        return False
    apk = output_apk(task_id)
    candidates = [
        raw_path(task_id), apk, f"{apk}.idsig",
        log_path(task_id), _meta_path(task_id),
    ]
    for p in candidates:
        if os.path.isfile(p):
            os.remove(p)
    od = output_dir(task_id)
    if os.path.isdir(od):
        import shutil
        shutil.rmtree(od, ignore_errors=True)
    return True


def delete_all_tasks() -> int:
    """删除所有任务，返回删除数量。"""
    import shutil
    ids = list(_tasks.keys())
    for tid in ids:
        delete_task(tid)
    # 兜底：清除 storage 各子目录下可能遗留的孤立文件
    for sub in ("raw", "output", "logs", "meta"):
        d = os.path.join(STORAGE_BASE, sub)
        if os.path.isdir(d):
            for f in os.listdir(d):
                fp = os.path.join(d, f)
                if os.path.isfile(fp):
                    os.remove(fp)
                elif os.path.isdir(fp):
                    shutil.rmtree(fp, ignore_errors=True)
    return len(ids)


def raw_path(task_id: str) -> str:
    return os.path.join(STORAGE_BASE, "raw", f"{task_id}.apk")


def output_dir(task_id: str) -> str:
    return os.path.join(STORAGE_BASE, "output", task_id)


def output_apk(task_id: str) -> str:
    return os.path.join(STORAGE_BASE, "output", f"{task_id}_protected.apk")


def log_path(task_id: str) -> str:
    return os.path.join(STORAGE_BASE, "logs", f"{task_id}.log")


_recover_tasks()


# ═══════════════════════════════════════════════════════════════
#  后台处理
# ═══════════════════════════════════════════════════════════════

async def process_task(task_id: str):
    """核心异步流程：加壳 → 打包 → (可选)签名。"""
    task = _tasks.get(task_id)
    if not task:
        return

    task.status = TaskStatus.PROCESSING
    task.progress = 10
    task.message = "准备加固环境..."

    apk_in = raw_path(task_id)
    out_dir = output_dir(task_id)
    out_apk = output_apk(task_id)
    log_file = log_path(task_id)

    try:
        os.makedirs(out_dir, exist_ok=True)

        # ① 调用 Protector-Tool
        task.progress = 20
        task.message = "正在加密 DEX 并修改清单..."

        ok = await shell_wrapper.run_protector(apk_in, out_dir, log_file)
        if not ok:
            task.status = TaskStatus.FAILED
            task.progress = 100
            task.message = "加壳工具执行失败，请查看日志"
            return

        # ② 基于原始 APK 重打包
        task.progress = 70
        task.message = "正在重打包 APK..."

        await shell_wrapper.repackage_apk(apk_in, out_dir, out_apk)

        loop = asyncio.get_event_loop()

        if shell_wrapper.has_apksigner():
            # apksigner 流程：zipalign → apksigner（v2 签名不能被后续修改破坏）
            task.progress = 80
            task.message = "对齐优化..."
            await loop.run_in_executor(None, shell_wrapper.zipalign, out_apk)

            task.progress = 90
            task.message = "v2 签名处理..."
            await shell_wrapper.sign_apk(out_apk, log_file)
        else:
            # jarsigner 流程：jarsigner → zipalign（v1 签名不受对齐影响）
            task.progress = 80
            task.message = "v1 签名处理..."
            await shell_wrapper.sign_apk(out_apk, log_file)

            task.progress = 90
            task.message = "对齐优化..."
            await loop.run_in_executor(None, shell_wrapper.zipalign, out_apk)

        # 完成
        task.progress = 100
        task.status = TaskStatus.COMPLETED
        task.message = "加固完成"

    except Exception as e:
        task.status = TaskStatus.FAILED
        task.progress = 100
        task.message = f"处理异常: {e}"


# ═══════════════════════════════════════════════════════════════
#  定时清理
# ═══════════════════════════════════════════════════════════════

async def cleanup_loop(interval: int = 3600):
    """每 interval 秒清理一次过期文件。"""
    while True:
        await asyncio.sleep(interval)
        shell_wrapper.cleanup_old_files(STORAGE_BASE)
