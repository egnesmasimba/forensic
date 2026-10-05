from __future__ import annotations

import hashlib
import logging
import os
import platform
import threading
from pathlib import Path
from typing import Any, Iterable, Optional

from . import Collector, current_os_tag

logger = logging.getLogger(__name__)

_MAX_HASH_SIZE = 25 * 1024 * 1024
_EVENT_ACTION_MAP = {
    "created": "file_create",
    "modified": "file_write",
    "deleted": "file_delete",
    "moved": "file_rename",
    "read": "file_read",
}


def _sha256_file(path: str) -> Optional[str]:
    try:
        st = os.stat(path)
        if st.st_size > _MAX_HASH_SIZE:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, ValueError):
        return None


def _watchdog_available() -> bool:
    try:
        import watchdog  # noqa: F401
        import watchdog.events  # noqa: F401
        import watchdog.observers  # noqa: F401
        return True
    except ImportError:
        return False


def _psutil_available() -> bool:
    try:
        import psutil  # noqa: F401
        return True
    except ImportError:
        return False


class FileOpsCollector(Collector):
    name = "fileops"
    default_interval_seconds = 5.0
    requires = ("watchdog",)

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._watch_paths: list[str] = list(self._config.get("watch_paths") or [])
        if not self._watch_paths:
            home = Path.home()
            candidates = [home / "Documents", home / "Desktop", home / "Downloads"]
            for cand in candidates:
                try:
                    if cand.exists():
                        self._watch_paths.append(str(cand))
                except OSError:
                    pass
        self._observer = None
        self._observer_lock = threading.Lock()
        self._pending: list[dict[str, Any]] = []
        self._pending_lock = threading.Lock()

    @classmethod
    def supports_current_os(cls) -> bool:
        if not _watchdog_available():
            logger.info("fileops unsupported: watchdog library not installed")
            return False
        if not _psutil_available():
            logger.info("fileops unsupported: psutil library not installed")
            return False
        return True

    def _queue_event(self, action: str, src: str, dst: Optional[str] = None) -> None:
        payload: dict[str, Any] = {"path": src}
        if dst:
            payload["dest_path"] = dst
        try:
            if action != "deleted":
                if os.path.exists(src):
                    st = os.stat(src)
                    payload["size"] = st.st_size
                    payload["mode"] = oct(st.st_mode)
                    sha = _sha256_file(src)
                    if sha:
                        payload["sha256"] = sha
                elif dst and action == "moved" and os.path.exists(dst):
                    st = os.stat(dst)
                    payload["size"] = st.st_size
                    payload["mode"] = oct(st.st_mode)
                    sha = _sha256_file(dst)
                    if sha:
                        payload["sha256"] = sha
        except OSError:
            pass
        try:
            import psutil
            proc_list: list[dict[str, Any]] = []
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    of = proc.open_files()
                    for ent in of:
                        if ent.path == src or (dst and ent.path == dst):
                            proc_list.append({"pid": proc.pid, "name": proc.name(), "exe": proc.exe()})
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
            if proc_list:
                payload["processes"] = proc_list
        except Exception:  # noqa: BLE001
            pass
        event_type = _EVENT_ACTION_MAP.get(action, "file_write")
        severity = "high" if action in ("deleted", "created") else "low"
        with self._pending_lock:
            self._pending.append({"type": event_type, "severity": severity, "payload": payload})

    def _start_watchdog(self) -> None:
        if self._observer is not None:
            return
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            return

        class _Handler(FileSystemEventHandler):
            def __init__(h_self, outer: FileOpsCollector) -> None:
                h_self.outer = outer

            def on_created(h_self, event):
                if not event.is_directory:
                    h_self.outer._queue_event("created", event.src_path)

            def on_modified(h_self, event):
                if not event.is_directory:
                    h_self.outer._queue_event("modified", event.src_path)

            def on_deleted(h_self, event):
                if not event.is_directory:
                    h_self.outer._queue_event("deleted", event.src_path)

            def on_moved(h_self, event):
                if not event.is_directory:
                    h_self.outer._queue_event("moved", event.src_path, event.dest_path)

        with self._observer_lock:
            if self._observer is not None:
                return
            try:
                observer = Observer()
                handler = _Handler(self)
                started = 0
                for p in self._watch_paths:
                    try:
                        if os.path.exists(p):
                            observer.schedule(handler, p, recursive=True)
                            started += 1
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("fileops: cannot watch %s: %s", p, exc)
                if started > 0:
                    observer.start()
                    self._observer = observer
                    logger.info("fileops: watching %d path(s)", started)
            except Exception as exc:  # noqa: BLE001
                logger.warning("fileops: watchdog start failed: %s", exc)

    def start(self) -> None:
        super().start()
        self._start_watchdog()

    def stop(self) -> None:
        super().stop()
        with self._observer_lock:
            if self._observer is not None:
                try:
                    self._observer.stop()
                    self._observer.join(timeout=2.0)
                except Exception:  # noqa: BLE001
                    pass
                self._observer = None

    def _collect(self) -> Iterable[dict[str, Any]]:
        if self._observer is None:
            self._start_watchdog()
        with self._pending_lock:
            out = self._pending
            self._pending = []
        return out

    def produce_event(self) -> dict[str, Any]:
        sample_path = str(Path.home() / "Documents" / "example.txt")
        return {
            "type": "file_create",
            "severity": "low",
            "payload": {
                "path": sample_path,
                "size": 1024,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "processes": [{"pid": 1234, "name": "notepad.exe", "exe": "C:\\Windows\\notepad.exe"}],
            },
        }
