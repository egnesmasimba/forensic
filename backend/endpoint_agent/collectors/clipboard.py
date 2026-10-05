from __future__ import annotations

import logging
import platform
import threading
from typing import Any, Iterable, Optional

from . import Collector, current_os_tag

logger = logging.getLogger(__name__)


def _pyperclip_available() -> bool:
    try:
        import pyperclip  # noqa: F401
        return True
    except ImportError:
        return False


def _active_window_available() -> bool:
    os_tag = current_os_tag()
    if os_tag == "windows":
        try:
            import win32gui  # noqa: F401
            import win32process  # noqa: F401
            return True
        except ImportError:
            return False
    if os_tag == "linux":
        return True
    if os_tag == "macos":
        try:
            from Quartz import (
                CGWindowListCopyWindowInfo,
                kCGWindowListOptionOnScreenOnly,
                kCGNullWindowID,
            )  # noqa: F401
            return True
        except ImportError:
            return False
    return False


def _get_active_window() -> dict[str, Any]:
    info: dict[str, Any] = {}
    os_tag = current_os_tag()
    try:
        if os_tag == "windows":
            import win32gui
            import win32process
            hwnd = win32gui.GetForegroundWindow()
            if hwnd:
                title = win32gui.GetWindowText(hwnd)
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                info = {"title": str(title or ""), "pid": int(pid or 0), "hwnd": int(hwnd)}
        elif os_tag == "linux":
            import subprocess
            try:
                root = subprocess.check_output(["xprop", "-root", "_NET_ACTIVE_WINDOW"], text=True).strip()
                wid = root.split("#")[-1].strip().split(",")[0].strip() if "#" in root else ""
                if wid:
                    out = subprocess.check_output(
                        ["xprop", "-id", wid, "_NET_WM_NAME", "_NET_WM_PID"], text=True
                    )
                    title = ""
                    pid = 0
                    for line in out.splitlines():
                        if "_NET_WM_NAME" in line and "=" in line:
                            title = line.split("=", 1)[1].strip().strip('"')
                        if "_NET_WM_PID" in line and "=" in line:
                            try:
                                pid = int(line.split("=", 1)[1].strip())
                            except ValueError:
                                pass
                    info = {"title": title, "pid": pid, "window_id": wid}
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                pass
        elif os_tag == "macos":
            from Quartz import (
                CGWindowListCopyWindowInfo,
                kCGWindowListOptionOnScreenOnly,
                kCGNullWindowID,
            )
            wins = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID)
            for w in wins or []:
                if int(w.get("kCGWindowLayer", 0)) == 0 and w.get("kCGWindowOwnerPID"):
                    info = {
                        "title": str(w.get("kCGWindowName", "") or ""),
                        "pid": int(w.get("kCGWindowOwnerPID", 0) or 0),
                        "owner": str(w.get("kCGWindowOwnerName", "") or ""),
                    }
                    break
    except Exception as exc:  # noqa: BLE001
        logger.debug("clipboard active_window probe failed: %s", exc)
    return info


class ClipboardCollector(Collector):
    name = "clipboard"
    default_interval_seconds = 2.0
    sensitive = True

    @classmethod
    def effective_requires(cls) -> tuple[str, ...]:
        os_tag = current_os_tag()
        if os_tag == "windows":
            return ("pyperclip", "win32gui")
        if os_tag == "macos":
            return ("pyperclip", "Quartz")
        return ("pyperclip",)

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._last_text: str = ""
        self._last_hash: str = ""
        self._lock = threading.Lock()

    @classmethod
    def supports_current_os(cls) -> bool:
        if not _pyperclip_available():
            logger.info("clipboard unsupported: pyperclip not installed")
            return False
        return True

    def _collect(self) -> Iterable[dict[str, Any]]:
        import hashlib
        try:
            import pyperclip
            text = pyperclip.paste() or ""
        except Exception as exc:  # noqa: BLE001
            logger.warning("clipboard poll failed: %s", exc)
            return []
        if not isinstance(text, str):
            return []
        content_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        events: list[dict[str, Any]] = []
        with self._lock:
            if content_hash != self._last_hash and text:
                prev = self._last_text
                self._last_text = text
                self._last_hash = content_hash
                aw = _get_active_window() if _active_window_available() else {}
                payload: dict[str, Any] = {
                    "len": len(text),
                    "sha256": content_hash,
                    "active_window": aw,
                }
                max_len = int(self._config.get("max_content_len", 4096))
                payload["content_preview"] = text[:max_len]
                if prev:
                    payload["previous_sha256"] = hashlib.sha256(
                        prev.encode("utf-8", "replace")
                    ).hexdigest()
                severity = "medium" if len(text) >= 1024 else "low"
                events.append({"type": "clipboard_change", "severity": severity, "payload": payload})
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "clipboard_change",
            "severity": "low",
            "payload": {
                "len": 17,
                "sha256": "1e722f73b6b21e9a41e96af3119392a732c3f838a2c29c55e7d1f00f0a263d6c",
                "content_preview": "Hello, clipboard!",
                "active_window": {"title": "Notepad", "pid": 1234},
            },
        }
