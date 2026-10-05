from __future__ import annotations

import logging
import platform
from typing import Any

from endpoint_agent.collectors import Collector


logger = logging.getLogger(__name__)


class IncognitoCollector(Collector):
    name = "incognito"
    default_interval_seconds = 5.0
    requires = ("psutil",)
    sensitive = True

    # (process_name_lower, window_title_substrings_lower)
    _BROWSER_MARKERS = [
        ("chrome", ("incognito",)),
        ("msedge", ("inprivate",)),
        ("edge", ("inprivate",)),
        ("firefox", ("private browsing", "private window")),
        ("safari", ("private",)),
        ("brave", ("incognito",)),
        ("opera", ("private", "incognito")),
        ("vivaldi", ("private",)),
    ]

    @classmethod
    def supports_current_os(cls) -> bool:
        return True

    def _iter_processes(self) -> list[dict[str, Any]]:
        try:
            import psutil  # type: ignore
        except Exception:
            return []
        out: list[dict[str, Any]] = []
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                info = proc.info or {}
                out.append({
                    "pid": info.get("pid"),
                    "name": (info.get("name") or "").lower(),
                    "cmdline": " ".join(info.get("cmdline") or []).lower(),
                })
            except Exception:
                continue
        return out

    def _active_window_title(self) -> str:
        title = ""
        sysname = platform.system().lower()
        try:
            if sysname == "windows":
                import ctypes
                user32 = ctypes.windll.user32
                hwnd = user32.GetForegroundWindow()
                length = user32.GetWindowTextLengthW(hwnd)
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                title = buf.value or ""
            elif sysname == "linux":
                import subprocess as _sp
                out = _sp.check_output(
                    ["xdotool", "getactivewindow", "getwindowname"],
                    stderr=_sp.DEVNULL, timeout=2,
                ).decode("utf-8", "replace").strip() if shutil_which("xdotool") else ""
                title = out
            elif sysname == "darwin":
                import subprocess as _sp
                script = ('tell application "System Events" to get name of first application '
                          'process whose frontmost is true')
                out = _sp.check_output(["osascript", "-e", script],
                                       stderr=_sp.DEVNULL, timeout=2).decode("utf-8", "replace").strip()
                title = out
        except Exception:
            pass
        return title or ""

    def _collect(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        window_title = self._active_window_title()
        window_lower = window_title.lower()
        seen: set[tuple[str, str]] = set()
        for proc in self._iter_processes():
            nm = proc["name"]
            cmd = proc["cmdline"]
            for proc_stem, markers in self._BROWSER_MARKERS:
                if proc_stem not in nm and proc_stem not in cmd:
                    continue
                for m in markers:
                    hit = (m in nm) or (m in cmd) or (m in window_lower)
                    if hit and (proc_stem, m) not in seen:
                        seen.add((proc_stem, m))
                        events.append({
                            "type": "incognito_detected",
                            "severity": "medium",
                            "payload": {
                                "browser": proc_stem,
                                "marker": m,
                                "process_name": proc["name"],
                                "pid": proc["pid"],
                                "window_title": window_title[:300],
                            },
                        })
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "incognito_detected",
            "severity": "medium",
            "payload": {"browser": "chrome", "marker": "incognito",
                        "process_name": "chrome.exe", "pid": 1234,
                        "window_title": "New Tab - Google Chrome (Incognito)"},
        }


def shutil_which(x: str) -> str | None:
    import shutil
    return shutil.which(x)
