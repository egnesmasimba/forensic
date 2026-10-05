from __future__ import annotations

import logging
import threading
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


class ProcForensicsCollector(Collector):
    name = "procforensics"
    default_interval_seconds = 30.0
    requires = ("psutil",)

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._known_pids: set[int] = set()
        self._lock = threading.Lock()
        self._pending_starts: list[int] = []
        try:
            import psutil
            for p in psutil.process_iter(["pid"]):
                try:
                    self._known_pids.add(int(p.pid))
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
        except Exception:  # noqa: BLE001
            pass

    @classmethod
    def supports_current_os(cls) -> bool:
        if not _psutil_available():
            logger.info("procforensics unsupported: psutil not installed")
            return False
        return True

    def _parent_chain(self, pid: int, max_depth: int = 32) -> list[dict[str, Any]]:
        import psutil
        chain: list[dict[str, Any]] = []
        cur_pid = pid
        seen: set[int] = set()
        for _ in range(max_depth):
            if cur_pid in seen or cur_pid <= 0:
                break
            seen.add(cur_pid)
            try:
                proc = psutil.Process(cur_pid)
                with proc.oneshot():
                    chain.append({
                        "pid": int(proc.pid),
                        "ppid": int(proc.ppid() or 0),
                        "name": str(proc.name() or ""),
                        "exe": str(proc.exe() or ""),
                        "username": str(proc.username() or ""),
                    })
                    cur_pid = int(proc.ppid() or 0)
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                break
        return chain

    def _memory_maps(self, pid: int) -> list[dict[str, Any]]:
        import psutil
        out: list[dict[str, Any]] = []
        try:
            proc = psutil.Process(pid)
            maps = proc.memory_maps(grouped=True)
            for m in maps[:200]:
                out.append({
                    "path": str(getattr(m, "path", "") or ""),
                    "rss": int(getattr(m, "rss", 0) or 0),
                    "size": int(getattr(m, "size", 0) or 0),
                    "perms": str(getattr(m, "perms", "") or ""),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
        return out

    def _tree_snapshot(self, new_pid: int) -> dict[str, Any]:
        import psutil
        tree: list[dict[str, Any]] = []
        try:
            root_map: dict[int, list[int]] = {}
            for proc in psutil.process_iter(["pid", "ppid", "name", "exe"]):
                try:
                    info = proc.info
                    pid = int(info.get("pid", 0))
                    ppid = int(info.get("ppid") or 0)
                    root_map.setdefault(ppid, []).append(pid)
                    tree.append({
                        "pid": pid,
                        "ppid": ppid,
                        "name": str(info.get("name") or ""),
                        "exe": str(info.get("exe") or ""),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
        except Exception:  # noqa: BLE001
            pass
        return {"trigger_pid": new_pid, "count": len(tree), "nodes": tree[:500]}

    def _snapshot_new_process(self, pid: int) -> Optional[dict[str, Any]]:
        import psutil
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                try:
                    info = proc.as_dict(
                        attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "cwd", "uids", "gids"],
                        ad_value=None,
                    )
                except Exception:  # noqa: BLE001
                    info = {}
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return None

        cmdline = info.get("cmdline") or []
        if isinstance(cmdline, list):
            cmdline = " ".join(str(c) for c in cmdline)
        base = {
            "pid": int(info.get("pid", pid)),
            "ppid": int(info.get("ppid") or 0),
            "name": str(info.get("name") or ""),
            "exe": str(info.get("exe") or ""),
            "cmdline": str(cmdline or ""),
            "username": str(info.get("username") or ""),
            "cwd": str(info.get("cwd") or ""),
            "create_time": float(info.get("create_time") or 0.0),
        }
        payload: dict[str, Any] = {
            "process": base,
            "parent_chain": self._parent_chain(pid),
            "memory_maps": self._memory_maps(pid),
            "tree": self._tree_snapshot(pid),
        }
        sev = "medium" if any(
            marker in (base["cmdline"] + base["exe"] + base["name"]).lower()
            for marker in ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "regsvr32", "rundll32")
        ) else "low"
        return {"type": "process_tree", "severity": sev, "payload": payload}

    def _collect(self) -> Iterable[dict[str, Any]]:
        import psutil
        events: list[dict[str, Any]] = []
        current: set[int] = set()
        new_pids: list[int] = []
        try:
            for proc in psutil.process_iter(["pid"]):
                try:
                    pid = int(proc.pid)
                    current.add(pid)
                    if pid not in self._known_pids:
                        new_pids.append(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
        except Exception:  # noqa: BLE001
            pass

        with self._lock:
            for pid in new_pids[:20]:
                ev = self._snapshot_new_process(pid)
                if ev is not None:
                    events.append(ev)
            self._known_pids = current
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "process_tree",
            "severity": "medium",
            "payload": {
                "process": {
                    "pid": 7001,
                    "ppid": 1024,
                    "name": "powershell.exe",
                    "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "cmdline": "powershell -enc ZgBvAHIA",
                    "username": "DESKTOP-123\\alice",
                    "cwd": "C:\\Users\\alice",
                    "create_time": time.time() - 5,
                },
                "parent_chain": [
                    {"pid": 7001, "ppid": 1024, "name": "powershell.exe"},
                    {"pid": 1024, "ppid": 512, "name": "explorer.exe"},
                    {"pid": 512, "ppid": 4, "name": "userinit.exe"},
                    {"pid": 4, "ppid": 0, "name": "System"},
                ],
                "memory_maps": [
                    {"path": "C:\\Windows\\System32\\ntdll.dll", "rss": 1048576, "size": 2097152, "perms": "r-x"},
                ],
                "tree": {"trigger_pid": 7001, "count": 120, "nodes": []},
            },
        }
