from __future__ import annotations

import logging
import subprocess
import time
from typing import Any, Iterable, Optional

from . import Collector, current_os_tag

logger = logging.getLogger(__name__)


def _windows_idle_available() -> bool:
    try:
        import win32api  # noqa: F401
        return True
    except ImportError:
        return False


def _linux_idle_available() -> bool:
    try:
        subprocess.run(["xprintidle"], capture_output=True, timeout=2)
        return True
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        try:
            subprocess.run(["xssstate", "-i"], capture_output=True, timeout=2)
            return True
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            return False


def _macos_idle_available() -> bool:
    try:
        from Quartz import CGEventSourceSecondsSinceLastEventType  # noqa: F401
        return True
    except ImportError:
        return False


class IdleCollector(Collector):
    name = "idle"
    default_interval_seconds = 5.0
    sensitive = True

    @classmethod
    def effective_requires(cls) -> tuple[str, ...]:
        os_tag = current_os_tag()
        if os_tag == "windows":
            return ("win32api",)
        if os_tag == "macos":
            return ("Quartz",)
        # Linux relies on the xprintidle/xssstate binaries, checked separately.
        return ()

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._threshold = float(self._config.get("threshold_seconds", 30.0))
        self._is_idle = False

    @classmethod
    def supports_current_os(cls) -> bool:
        os_tag = current_os_tag()
        if os_tag == "windows":
            if not _windows_idle_available():
                logger.info("idle unsupported on windows: pywin32 not installed")
                return False
            return True
        if os_tag == "linux":
            if not _linux_idle_available():
                logger.info("idle unsupported on linux: xprintidle or xssstate not available")
                return False
            return True
        if os_tag == "macos":
            if not _macos_idle_available():
                logger.info("idle unsupported on macos: pyobjc Quartz not installed")
                return False
            return True
        return False

    def _idle_seconds_windows(self) -> float:
        import ctypes
        from ctypes import wintypes
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]
        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            return 0.0
        ms = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
        return max(0.0, float(ms) / 1000.0)

    def _idle_seconds_linux(self) -> float:
        try:
            try:
                out = subprocess.check_output(["xprintidle"], text=True, timeout=2).strip()
                return max(0.0, float(out) / 1000.0)
            except (FileNotFoundError, subprocess.SubprocessError):
                out = subprocess.check_output(["xssstate", "-i"], text=True, timeout=2).strip()
                if out.isdigit():
                    return max(0.0, float(out) / 1000.0)
        except Exception as exc:  # noqa: BLE001
            logger.debug("idle linux probe failed: %s", exc)
        return 0.0

    def _idle_seconds_macos(self) -> float:
        from Quartz import CGEventSourceSecondsSinceLastEventType, kCGEventSourceStateHIDSystemState
        try:
            any_event_type = -1
            seconds = CGEventSourceSecondsSinceLastEventType(kCGEventSourceStateHIDSystemState, any_event_type)
            return max(0.0, float(seconds))
        except Exception as exc:  # noqa: BLE001
            logger.debug("idle macos probe failed: %s", exc)
            return 0.0

    def _idle_seconds(self) -> float:
        os_tag = current_os_tag()
        if os_tag == "windows":
            return self._idle_seconds_windows()
        if os_tag == "linux":
            return self._idle_seconds_linux()
        if os_tag == "macos":
            return self._idle_seconds_macos()
        return 0.0

    def _collect(self) -> Iterable[dict[str, Any]]:
        idle = self._idle_seconds()
        events: list[dict[str, Any]] = []
        payload = {"idle_seconds": round(idle, 2), "threshold_seconds": self._threshold}
        now_idle = idle >= self._threshold
        if now_idle and not self._is_idle:
            self._is_idle = True
            events.append({"type": "idle_start", "severity": "low", "payload": payload})
        elif not now_idle and self._is_idle:
            self._is_idle = False
            events.append({"type": "idle_end", "severity": "low", "payload": payload})
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "idle_start",
            "severity": "low",
            "payload": {
                "idle_seconds": 45.2,
                "threshold_seconds": 30.0,
            },
        }
