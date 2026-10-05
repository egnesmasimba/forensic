from __future__ import annotations

import logging
import subprocess
from typing import Any, Iterable, Optional

from . import Collector, current_os_tag

logger = logging.getLogger(__name__)


def _windows_window_available() -> bool:
    try:
        import win32gui  # noqa: F401
        import win32process  # noqa: F401
        return True
    except ImportError:
        return False


def _linux_window_available() -> bool:
    try:
        subprocess.run(["xprop", "-root", "_NET_CLIENT_LIST"], capture_output=True, timeout=2)
        return True
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return False


def _macos_window_available() -> bool:
    try:
        from Quartz import (
            CGWindowListCopyWindowInfo,
            kCGWindowListOptionOnScreenOnly,
            kCGNullWindowID,
        )  # noqa: F401
        return True
    except ImportError:
        return False


class WindowCollector(Collector):
    name = "window"
    default_interval_seconds = 3.0
    sensitive = True

    @classmethod
    def effective_requires(cls) -> tuple[str, ...]:
        os_tag = current_os_tag()
        if os_tag == "windows":
            return ("win32gui", "win32process")
        if os_tag == "macos":
            return ("Quartz",)
        # Linux enumerates windows through the xprop binary.
        return ()

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._active_title: str = ""
        self._active_pid: int = 0
        self._last_windows: set[tuple[str, int]] = set()

    @classmethod
    def supports_current_os(cls) -> bool:
        os_tag = current_os_tag()
        if os_tag == "windows":
            if not _windows_window_available():
                logger.info("window unsupported on windows: pywin32 not installed")
                return False
            return True
        if os_tag == "linux":
            if not _linux_window_available():
                logger.info("window unsupported on linux: xprop not available (X11 session required)")
                return False
            return True
        if os_tag == "macos":
            if not _macos_window_available():
                logger.info("window unsupported on macos: pyobjc Quartz not installed")
                return False
            return True
        return False

    def _scan_windows_win32(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        import win32gui
        import win32process
        windows: list[dict[str, Any]] = []

        def _cb(hwnd, _):
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return
                title = win32gui.GetWindowText(hwnd)
                if not title:
                    return
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                windows.append({"title": str(title), "pid": int(pid or 0), "hwnd": int(hwnd)})
            except Exception:  # noqa: BLE001
                pass

        win32gui.EnumWindows(_cb, None)
        active: dict[str, Any] = {}
        try:
            hwnd = win32gui.GetForegroundWindow()
            if hwnd:
                title = win32gui.GetWindowText(hwnd)
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                active = {"title": str(title or ""), "pid": int(pid or 0), "hwnd": int(hwnd)}
        except Exception:  # noqa: BLE001
            pass
        return windows, active

    def _scan_windows_linux(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        windows: list[dict[str, Any]] = []
        active: dict[str, Any] = {}
        try:
            out = subprocess.check_output(
                ["xprop", "-root", "_NET_CLIENT_LIST"], text=True, timeout=3
            )
            wids: list[str] = []
            for token in out.replace("#", ",").split(","):
                t = token.strip().lstrip("0x")
                if t:
                    try:
                        int(t, 16)
                        wids.append("0x" + t)
                    except ValueError:
                        pass
            for wid in wids:
                try:
                    out2 = subprocess.check_output(
                        ["xprop", "-id", wid, "_NET_WM_NAME", "_NET_WM_PID"],
                        text=True,
                        timeout=2,
                    )
                    title = ""
                    pid = 0
                    for line in out2.splitlines():
                        if "_NET_WM_NAME" in line and "=" in line:
                            title = line.split("=", 1)[1].strip().strip('"')
                        if "_NET_WM_PID" in line and "=" in line:
                            try:
                                pid = int(line.split("=", 1)[1].strip())
                            except ValueError:
                                pass
                    if title:
                        windows.append({"title": title, "pid": pid, "window_id": wid})
                except (subprocess.SubprocessError, FileNotFoundError, OSError):
                    continue
            try:
                root = subprocess.check_output(
                    ["xprop", "-root", "_NET_ACTIVE_WINDOW"], text=True, timeout=2
                )
                awid = root.split("#")[-1].strip().split(",")[0].strip() if "#" in root else ""
                if awid and awid.startswith("0x"):
                    for w in windows:
                        if str(w.get("window_id", "")).lower() == awid.lower():
                            active = dict(w)
                            break
                    if not active:
                        try:
                            out3 = subprocess.check_output(
                                ["xprop", "-id", awid, "_NET_WM_NAME", "_NET_WM_PID"],
                                text=True, timeout=2,
                            )
                            atitle = ""
                            apid = 0
                            for line in out3.splitlines():
                                if "_NET_WM_NAME" in line and "=" in line:
                                    atitle = line.split("=", 1)[1].strip().strip('"')
                                if "_NET_WM_PID" in line and "=" in line:
                                    try:
                                        apid = int(line.split("=", 1)[1].strip())
                                    except ValueError:
                                        pass
                            active = {"title": atitle, "pid": apid, "window_id": awid}
                        except (subprocess.SubprocessError, FileNotFoundError, OSError):
                            pass
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                pass
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
            logger.warning("window linux scan failed: %s", exc)
        return windows, active

    def _scan_windows_macos(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        from Quartz import (
            CGWindowListCopyWindowInfo,
            kCGWindowListOptionOnScreenOnly,
            kCGNullWindowID,
        )
        windows: list[dict[str, Any]] = []
        active: dict[str, Any] = {}
        try:
            raw = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID) or []
            for w in raw:
                if int(w.get("kCGWindowLayer", 0)) != 0:
                    continue
                title = str(w.get("kCGWindowName", "") or "")
                pid = int(w.get("kCGWindowOwnerPID", 0) or 0)
                owner = str(w.get("kCGWindowOwnerName", "") or "")
                if not title and not owner:
                    continue
                entry = {"title": title, "pid": pid, "owner": owner}
                windows.append(entry)
                if not active:
                    active = dict(entry)
        except Exception as exc:  # noqa: BLE001
            logger.warning("window macos scan failed: %s", exc)
        return windows, active

    def _scan(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        os_tag = current_os_tag()
        if os_tag == "windows":
            return self._scan_windows_win32()
        if os_tag == "linux":
            return self._scan_windows_linux()
        if os_tag == "macos":
            return self._scan_windows_macos()
        return [], {}

    def _collect(self) -> Iterable[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        windows, active = self._scan()
        cur_set = set()
        for w in windows:
            key = (str(w.get("title", "")), int(w.get("pid", 0)))
            cur_set.add(key)
            if key not in self._last_windows:
                events.append({"type": "window_change", "severity": "low", "payload": w})
        self._last_windows = cur_set

        a_title = str(active.get("title", ""))
        a_pid = int(active.get("pid", 0))
        if a_title and (a_title != self._active_title or a_pid != self._active_pid):
            self._active_title = a_title
            self._active_pid = a_pid
            events.append({"type": "window_active", "severity": "low", "payload": active})
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "window_active",
            "severity": "low",
            "payload": {
                "title": "Confidential - Q4-Report.docx - Microsoft Word",
                "pid": 8821,
                "owner": "Microsoft Word",
            },
        }
