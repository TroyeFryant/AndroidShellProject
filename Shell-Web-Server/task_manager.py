"""
异步任务调度：管理 APK 加固任务的生命周期。
"""

import asyncio
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
    for sub in ("raw", "output", "logs"):
        os.makedirs(os.path.join(STORAGE_BASE, sub), exist_ok=True)


_ensure_dirs()


# ═══════════════════════════════════════════════════════════════
#  任务 CRUD
# ═══════════════════════════════════════════════════════════════

def create_task(filename: str) -> str:
    task_id = uuid.uuid4().hex[:12]
    _tasks[task_id] = TaskInfo(
        task_id=task_id,
        filename=filename,
        status=TaskStatus.PENDING,
        created_at=time.time(),
    )
    return task_id


def get_task(task_id: str) -> Optional[TaskInfo]:
    return _tasks.get(task_id)


def raw_path(task_id: str) -> str:
    return os.path.join(STORAGE_BASE, "raw", f"{task_id}.apk")


def output_dir(task_id: str) -> str:
    return os.path.join(STORAGE_BASE, "output", task_id)


def output_apk(task_id: str) -> str:
    return os.path.join(STORAGE_BASE, "output", f"{task_id}_protected.apk")


def log_path(task_id: str) -> str:
    return os.path.join(STORAGE_BASE, "logs", f"{task_id}.log")


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
