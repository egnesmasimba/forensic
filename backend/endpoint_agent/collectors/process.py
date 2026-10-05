from __future__ import annotations

import logging
import time
from typing import Any, Iterable, Optional

from . import Collector, current_os_tag

logger = logging.getLogger(__name__)


def _psutil_available() -> bool:
    try:
        import psutil  # noqa: F401
        return True
    except ImportError:
        return False


class ProcessCollector(Collector):
    name = "process"
    default_interval_seconds = 2.0
    requires = ("psutil",)

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._snapshot: dict[int, dict[str, Any]] = {}
        self._max_history = int(self._config.get("max_history", 4000))

    @classmethod
    def supports_current_os(cls) -> bool:
        if not _psutil_available():
            logger.info("process unsupported: psutil not installed")
            return False
        return True

    def _snap_proc(self, proc) -> Optional[dict[str, Any]]:
        try:
            info = proc.as_dict(
                attrs=["pid", "ppid", "cmdline", "username", "exe", "name", "create_time"],
                ad_value=None,
            )
        except Exception:  # noqa: BLE001
            return None
        cmdline = info.get("cmdline") or []
        if isinstance(cmdline, list):
            cmdline = " ".join(str(c) for c in cmdline)
        return {
            "pid": int(info.get("pid", 0)),
            "ppid": int(info.get("ppid") or 0),
            "name": str(info.get("name") or ""),
            "exe": str(info.get("exe") or ""),
            "cmdline": str(cmdline or ""),
            "username": str(info.get("username") or ""),
            "create_time": float(info.get("create_time") or 0.0),
        }

    def _collect(self) -> Iterable[dict[str, Any]]:
        import psutil
        events: list[dict[str, Any]] = []
        current: dict[int, dict[str, Any]] = {}
        for proc in psutil.process_iter([]):
            try:
                snap = self._snap_proc(proc)
                if snap is None:
                    continue
                current[snap["pid"]] = snap
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

        prev = self._snapshot
        for pid, info in current.items():
            if pid not in prev:
                payload = dict(info)
                payload.pop("create_time", None)
                sev = "high" if any(
                    m in (info.get("cmdline", "") + info.get("exe", "")).lower()
                    for m in ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "regsvr32")
                ) else "low"
                events.append({"type": "process_start", "severity": sev, "payload": payload})

        for pid, info in prev.items():
            if pid not in current:
                payload = dict(info)
                payload.pop("create_time", None)
                try:
                    proc = psutil.Process(pid)
                    try:
                        exit_code = proc.wait(timeout=0)
                        payload["exit_code"] = exit_code
                    except (psutil.TimeoutExpired, psutil.NoSuchProcess):
                        with proc.oneshot():
                            try:
                                payload["exit_code"] = proc.returncode
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                events.append({"type": "process_exit", "severity": "low", "payload": payload})

        if len(current) > self._max_history:
            self._snapshot = {}
        else:
            self._snapshot = current
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "process_start",
            "severity": "low",
            "payload": {
                "pid": 5001,
                "ppid": 1024,
                "name": "notepad.exe",
                "exe": "C:\\Windows\\System32\\notepad.exe",
                "cmdline": "notepad.exe C:\\Users\\alice\\secret.txt",
                "username": "DESKTOP-123\\alice",
            },
        }
