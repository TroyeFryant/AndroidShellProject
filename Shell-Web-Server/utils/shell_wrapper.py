"""
封装对 Java 加壳工具的命令行调用、APK 签名和文件清理。
"""

import asyncio
import glob as _glob
import os
import shutil
import time
import zipfile
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _BASE.parent

PROTECTOR_CLASSPATH = str(_PROJECT_ROOT / "Protector-Tool" / "build")
PROTECTOR_MAIN_CLASS = "com.shell.protector.Main"

STUB_DEX_PATH = str(_PROJECT_ROOT / "Stub-App" / "build" / "classes.dex")

import re
_DEX_PATTERN = re.compile(r"^classes\d*\.dex$")

KEYSTORE_PATH = os.environ.get("KEYSTORE_PATH", "/Users/fangyanchao/code/AndroidShellProject/Shell-Web-Server/utils/shell.jks")
KEYSTORE_PASS = os.environ.get("KEYSTORE_PASS", "123456")
KEY_ALIAS = os.environ.get("KEY_ALIAS", "shell")

CLEANUP_MAX_AGE_SECONDS = 24 * 3600


def _find_apksigner() -> str | None:
    """Auto-detect apksigner: check PATH first, then search Android SDK."""
    found = shutil.which("apksigner")
    if found:
        return found
    sdk_dirs = [
        os.path.expanduser("~/Library/Android/sdk"),
        os.environ.get("ANDROID_HOME", ""),
        os.environ.get("ANDROID_SDK_ROOT", ""),
    ]
    for sdk in sdk_dirs:
        if not sdk or not os.path.isdir(sdk):
            continue
        bt = os.path.join(sdk, "build-tools")
        if not os.path.isdir(bt):
            continue
        versions = sorted(os.listdir(bt), reverse=True)
        for ver in versions:
            candidate = os.path.join(bt, ver, "apksigner")
            if os.path.isfile(candidate):
                return candidate
    return None


APKSIGNER_BIN = _find_apksigner()


# ═══════════════════════════════════════════════════════════════
#  加壳工具调用
# ═══════════════════════════════════════════════════════════════

async def run_protector(input_apk: str, output_dir: str, log_path: str) -> bool:
    """
    异步调用 Protector-Tool，将 stdout/stderr 实时写入日志文件。
    返回 True 表示执行成功。
    """
    cmd = [
        "java", "-cp", PROTECTOR_CLASSPATH,
        PROTECTOR_MAIN_CLASS,
        input_apk, output_dir,
    ]

    with open(log_path, "w", encoding="utf-8") as log_file:
        log_file.write(f"[shell_wrapper] 执行命令: {' '.join(cmd)}\n")
        log_file.flush()

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=log_file,
            stderr=asyncio.subprocess.STDOUT,
        )
        await proc.wait()

        log_file.write(f"\n[shell_wrapper] 进程退出码: {proc.returncode}\n")

    return proc.returncode == 0


# ═══════════════════════════════════════════════════════════════
#  APK 签名
# ═══════════════════════════════════════════════════════════════

def has_apksigner() -> bool:
    return APKSIGNER_BIN is not None


async def sign_apk(apk_path: str, log_path: str) -> bool:
    """
    对 APK 签名。
    apksigner (v2/v3) → 必须在 zipalign 之后调用。
    jarsigner (v1)    → 必须在 zipalign 之前调用（调用方负责顺序）。
    """
    if not KEYSTORE_PATH or not os.path.isfile(KEYSTORE_PATH):
        _append_log(log_path, "[签名] 未配置有效的 keystore 路径，跳过签名")
        return True

    if APKSIGNER_BIN:
        return await _run_apksigner(apk_path, log_path)

    return await _run_jarsigner(apk_path, log_path)


async def _run_apksigner(apk_path: str, log_path: str) -> bool:
    cmd = [
        APKSIGNER_BIN, "sign",
        "--ks", KEYSTORE_PATH,
        "--ks-pass", f"pass:{KEYSTORE_PASS}",
        "--ks-key-alias", KEY_ALIAS,
        apk_path,
    ]
    _append_log(log_path, f"[签名] apksigner: {' '.join(cmd)}")
    with open(log_path, "a", encoding="utf-8") as lf:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=lf, stderr=asyncio.subprocess.STDOUT)
        await proc.wait()
    ok = proc.returncode == 0
    _append_log(log_path, f"[签名] apksigner {'成功' if ok else '失败'}")
    return ok


async def _run_jarsigner(apk_path: str, log_path: str) -> bool:
    cmd = [
        "jarsigner",
        "-keystore", KEYSTORE_PATH,
        "-storepass", KEYSTORE_PASS,
        "-signedjar", apk_path,
        apk_path,
        KEY_ALIAS,
    ]
    try:
        _append_log(log_path, f"[签名] jarsigner (v1 only): {' '.join(cmd)}")
        with open(log_path, "a", encoding="utf-8") as lf:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=lf, stderr=asyncio.subprocess.STDOUT)
            await proc.wait()
        ok = proc.returncode == 0
        _append_log(log_path, f"[签名] jarsigner {'成功' if ok else '失败'}")
        return ok
    except FileNotFoundError:
        _append_log(log_path, "[签名] jarsigner 未找到，跳过签名")
        return True


# ═══════════════════════════════════════════════════════════════
#  APK 重打包
# ═══════════════════════════════════════════════════════════════

async def repackage_apk(original_apk: str, protector_output_dir: str, dest_apk: str):
    """
    基于原始 APK 重打包：
    1. 跳过 META-INF/ 和原始 classes*.dex
    2. 用加壳工具输出的 AndroidManifest.xml 替换原清单
    3. 用壳程序的 stub classes.dex 替换原始 DEX
    4. 将 classes.dex.enc 和 shell_config.properties 注入 assets/
    """
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None, _do_repackage, original_apk, protector_output_dir, dest_apk
    )


def _calc_padding(fp_offset: int, filename: str, alignment: int) -> bytes:
    header_size = 30 + len(filename.encode("utf-8"))
    padding = (alignment - ((fp_offset + header_size) % alignment)) % alignment
    return b"\x00" * padding


def _copy_zipinfo(item: zipfile.ZipInfo) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(item.filename)
    info.compress_type = item.compress_type
    info.external_attr = item.external_attr
    info.date_time = item.date_time
    info.flag_bits = item.flag_bits
    return info


def _do_repackage(original_apk: str, out_dir: str, dest_apk: str):
    new_manifest = os.path.join(out_dir, "AndroidManifest.xml")
    encrypted_dex = os.path.join(out_dir, "classes.dex.enc")
    config_file = os.path.join(out_dir, "shell_config.properties")

    if not os.path.isfile(STUB_DEX_PATH):
        raise FileNotFoundError(
            f"壳程序 stub DEX 不存在: {STUB_DEX_PATH}，请先运行 Stub-App/build.sh")

    with zipfile.ZipFile(original_apk, "r") as src, \
         zipfile.ZipFile(dest_apk, "w") as dst:

        for item in src.infolist():
            if item.filename.startswith("META-INF/"):
                continue
            if item.filename == "AndroidManifest.xml":
                dst.write(new_manifest, "AndroidManifest.xml")
                continue
            if _DEX_PATTERN.match(item.filename):
                continue

            data = src.read(item.filename)
            info = _copy_zipinfo(item)
            dst.writestr(info, data)

        dst.write(STUB_DEX_PATH, "classes.dex")

        if os.path.isfile(encrypted_dex):
            dst.write(encrypted_dex, "assets/classes.dex.enc")
        if os.path.isfile(config_file):
            dst.write(config_file, "assets/shell_config.properties")


def zipalign(apk_path: str):
    """Rewrite the APK with proper alignment (equivalent to zipalign -p 4).
    STORED .so under lib/ → 4096-byte page alignment.
    Other STORED entries → 4-byte alignment.
    Must be called AFTER jarsigner (v1) signing."""
    tmp = apk_path + ".aligned"

    with zipfile.ZipFile(apk_path, "r") as src, \
         zipfile.ZipFile(tmp, "w") as dst:

        for item in src.infolist():
            data = src.read(item.filename)
            info = _copy_zipinfo(item)

            if item.compress_type == zipfile.ZIP_STORED:
                if item.filename.startswith("lib/") and item.filename.endswith(".so"):
                    alignment = 4096
                else:
                    alignment = 4
                info.extra = _calc_padding(dst.fp.tell(), info.filename, alignment)

            dst.writestr(info, data)

    os.replace(tmp, apk_path)


# ═══════════════════════════════════════════════════════════════
#  文件清理 —— 删除超过 24 小时的临时文件
# ═══════════════════════════════════════════════════════════════

def cleanup_old_files(storage_base: str):
    """遍历 storage/ 子目录，删除超过 CLEANUP_MAX_AGE_SECONDS 的文件和文件夹。"""
    now = time.time()
    removed = 0

    for sub in ("raw", "output", "logs"):
        dir_path = os.path.join(storage_base, sub)
        if not os.path.isdir(dir_path):
            continue
        for item in os.listdir(dir_path):
            item_path = os.path.join(dir_path, item)
            try:
                if now - os.path.getmtime(item_path) > CLEANUP_MAX_AGE_SECONDS:
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    else:
                        os.remove(item_path)
                    removed += 1
            except OSError:
                pass

    return removed


# ═══════════════════════════════════════════════════════════════
#  工具
# ═══════════════════════════════════════════════════════════════

def _append_log(log_path: str, message: str):
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(message + "\n")
