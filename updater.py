"""
Auto-update system.

At startup, fetches a remote JSON manifest and compares versions.
If a newer version exists, downloads the new executable and replaces
the current one via a helper batch script that runs after exit.

Manifest format (host this JSON at UPDATE_MANIFEST_URL):
{
    "latest_version": "1.2.0",
    "download_url": "https://example.com/releases/WeChatExtractor-1.2.0.exe",
    "changelog": "Bug fixes and performance improvements.",
    "sha256": "abc123..."
}
"""

import hashlib
import json
import os
import sys
import tempfile
import urllib.request
import ssl
from typing import Optional, Tuple

from app_config import APP_VERSION, UPDATE_MANIFEST_URL


def cleanup_old_update_files() -> None:
    """Remove leftover .old and .update files from a previous update."""
    if not getattr(sys, "frozen", False):
        return
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    for suffix in (".old", ".update"):
        path = os.path.join(exe_dir, "WeChatExtractor" + suffix)
        try:
            if os.path.exists(path):
                os.unlink(path)
        except OSError:
            pass


def _get_ssl_context() -> ssl.SSLContext:
    """Return an SSL context that uses the system certificate store."""
    return ssl.create_default_context()


def fetch_manifest(timeout: int = 10) -> Optional[dict]:
    """Fetch the remote update manifest. Returns parsed JSON or None."""
    if not UPDATE_MANIFEST_URL or "example.com" in UPDATE_MANIFEST_URL:
        return None
    try:
        req = urllib.request.Request(
            UPDATE_MANIFEST_URL,
            headers={"User-Agent": "WeChatExtractor-Updater"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=_get_ssl_context()) as resp:
            if resp.status != 200:
                return None
            data = resp.read(1024 * 64)  # 64 KB max
            return json.loads(data)
    except Exception:
        return None


def _version_tuple(v: str) -> Tuple[int, ...]:
    """Convert '1.2.3' to (1, 2, 3) for comparison."""
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except (ValueError, AttributeError):
        return (0,)


def is_update_available(manifest: dict) -> bool:
    """Return True if the manifest advertises a version newer than ours."""
    remote = manifest.get("latest_version", "")
    return _version_tuple(remote) > _version_tuple(APP_VERSION)


def download_update(manifest: dict, progress_cb=None) -> Optional[str]:
    """Download the new executable. Returns path or None.

    Downloads next to the running exe (same drive) to avoid cross-drive
    move issues.  Verifies SHA-256 if provided in the manifest.
    """
    url = manifest.get("download_url", "")
    expected_hash = manifest.get("sha256", "").lower().strip()
    if not url:
        return None

    # Place the download next to the current exe so the later rename
    # is a same-directory operation (atomic on NTFS, no cross-drive move).
    if getattr(sys, "frozen", False):
        dest_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        dest_dir = tempfile.gettempdir()

    download_path = os.path.join(dest_dir, "WeChatExtractor.update")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "WeChatExtractor-Updater"})
        with urllib.request.urlopen(req, timeout=120, context=_get_ssl_context()) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            hasher = hashlib.sha256()
            downloaded = 0
            with open(download_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    hasher.update(chunk)
                    downloaded += len(chunk)
                    if progress_cb and total > 0:
                        progress_cb(downloaded, total)

        if expected_hash and hasher.hexdigest() != expected_hash:
            os.unlink(download_path)
            return None

        # Quick PE sanity check
        with open(download_path, "rb") as f:
            if f.read(2) != b"MZ":
                os.unlink(download_path)
                return None

        return download_path
    except Exception:
        if os.path.exists(download_path):
            os.unlink(download_path)
        return None


def apply_update(downloaded_exe: str) -> None:
    """Replace the running executable with the downloaded one, then restart.

    Strategy: the downloaded file sits next to the current exe.  A batch
    script waits for this process to exit, renames the old exe out of the
    way, renames the new file into place (same-directory rename is atomic
    on NTFS), launches the new exe, then cleans up.
    """
    current_exe = os.path.abspath(sys.executable)
    exe_dir = os.path.dirname(current_exe)
    exe_name = os.path.basename(current_exe)
    old_name = exe_name + ".old"
    update_name = os.path.basename(downloaded_exe)

    pid = os.getpid()
    bat_path = os.path.join(exe_dir, "_wxext_update.bat")

    bat_content = f'''@echo off
cd /d "{exe_dir}"

:: ── Wait for the original process to exit ──
:wait_exit
tasklist /FI "PID eq {pid}" 2>nul | find /i "{pid}" >nul
if not errorlevel 1 (
    ping 127.0.0.1 -n 2 > nul
    goto :wait_exit
)
:: Extra pause for file-handle release
ping 127.0.0.1 -n 3 > nul

:: ── Clean up any leftover .old from a previous update ──
if exist "{old_name}" del /f /q "{old_name}"

:: ── Rename current exe out of the way (retry up to 15 times) ──
set tries=0
:retry_rename
rename "{exe_name}" "{old_name}" 2>nul
if exist "{exe_name}" (
    set /a tries+=1
    if %tries% lss 15 (
        ping 127.0.0.1 -n 2 > nul
        goto :retry_rename
    )
    :: Could not rename — abort, leave everything as-is
    del /f /q "{update_name}" 2>nul
    goto :cleanup
)

:: ── Rename the downloaded update into place ──
rename "{update_name}" "{exe_name}"
if errorlevel 1 (
    :: Rollback: restore the original
    rename "{old_name}" "{exe_name}" 2>nul
    goto :cleanup
)

:: ── Wait until updated exe is readable to avoid transient start failures ──
set ready_tries=0
:wait_ready
if not exist "{exe_name}" goto :not_ready
for %%F in ("{exe_name}") do if %%~zF lss 1024 goto :not_ready
powershell -NoProfile -Command "try {{$s=[System.IO.File]::Open('{current_exe}','Open','Read','ReadWrite'); $s.Close(); exit 0}} catch {{ exit 1 }}" >nul 2>nul
if errorlevel 1 goto :not_ready
goto :launch

:not_ready
set /a ready_tries+=1
if %ready_tries% lss 20 (
    ping 127.0.0.1 -n 2 > nul
    goto :wait_ready
)
goto :cleanup

:: ── Launch the updated exe, retry once, then remove old copy ──
:launch
start "" "{exe_name}"
ping 127.0.0.1 -n 3 > nul
tasklist /FI "IMAGENAME eq {exe_name}" 2>nul | find /i "{exe_name}" >nul
if errorlevel 1 (
    ping 127.0.0.1 -n 3 > nul
    start "" "{exe_name}"
)
ping 127.0.0.1 -n 2 > nul
del /f /q "{old_name}" 2>nul

:cleanup
del /f /q "%~f0"
'''
    with open(bat_path, "w", encoding="utf-8") as f:
        f.write(bat_content)

    os.startfile(bat_path)
    sys.exit(0)
