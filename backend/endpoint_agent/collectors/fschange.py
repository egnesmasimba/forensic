from __future__ import annotations

import ctypes
import logging
import os
import platform
import threading
from pathlib import Path
from typing import Any, Iterable, Optional

from . import Collector, current_os_tag

logger = logging.getLogger(__name__)

_WATCHDOG_OK = False
try:
    import watchdog  # noqa: F401
    import watchdog.events  # noqa: F401
    import watchdog.observers  # noqa: F401
    _WATCHDOG_OK = True
except ImportError:
    pass

_CTYPES_OK = True


def _windows_usn_available() -> bool:
    return current_os_tag() == "windows" and _CTYPES_OK


def _linux_inotify_available() -> bool:
    if current_os_tag() != "linux":
        return False
    return _WATCHDOG_OK


def _macos_fsevents_available() -> bool:
    if current_os_tag() != "macos":
        return False
    return _WATCHDOG_OK


class FSChangeCollector(Collector):
    name = "fschange"
    default_interval_seconds = 5.0
    requires = ("watchdog",)

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._watch_paths: list[str] = list(self._config.get("watch_paths") or [])
        if not self._watch_paths:
            home = Path.home()
            for cand in [home / "Documents", home / "Desktop", home / "Downloads"]:
                try:
                    if cand.exists():
                        self._watch_paths.append(str(cand))
                except OSError:
                    pass
        self._observer = None
        self._observer_lock = threading.Lock()
        self._pending: list[dict[str, Any]] = []
        self._pending_lock = threading.Lock()
        self._usn_handle = None
        self._usn_volume = None

    @classmethod
    def supports_current_os(cls) -> bool:
        os_tag = current_os_tag()
        if os_tag == "windows":
            if not _windows_usn_available() and not _WATCHDOG_OK:
                logger.info("fschange unsupported on windows: ctypes USN + watchdog unavailable")
                return False
            return True
        if os_tag == "linux":
            if not _linux_inotify_available():
                logger.info("fschange unsupported on linux: watchdog inotify unavailable")
                return False
            return True
        if os_tag == "macos":
            if not _macos_fsevents_available():
                logger.info("fschange unsupported on macos: watchdog fsevents unavailable")
                return False
            return True
        logger.info("fschange unsupported: platform %s", platform.system())
        return False

    def _queue(self, action: str, path: str, journal: str, extra: Optional[dict[str, Any]] = None) -> None:
        payload: dict[str, Any] = {"path": path, "action": action, "journal_source": journal}
        if extra:
            payload.update(extra)
        try:
            if action != "deleted" and os.path.exists(path):
                st = os.stat(path)
                payload["size"] = st.st_size
                payload["mtime"] = st.st_mtime_ns if hasattr(st, "st_mtime_ns") else st.st_mtime
        except OSError:
            pass
        with self._pending_lock:
            self._pending.append({"type": "fschange", "severity": "low", "payload": payload})

    def _start_watchdog(self) -> None:
        if self._observer is not None or not _WATCHDOG_OK:
            return
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            return

        os_tag = current_os_tag()
        journal = {"linux": "inotify", "macos": "fsevents", "windows": "watchdog_fallback"}.get(os_tag, "watchdog")

        class _H(FileSystemEventHandler):
            def __init__(h, outer):
                h.outer = outer

            def on_created(h, ev):
                if not ev.is_directory:
                    h.outer._queue("created", ev.src_path, journal)

            def on_modified(h, ev):
                if not ev.is_directory:
                    h.outer._queue("modified", ev.src_path, journal)

            def on_deleted(h, ev):
                if not ev.is_directory:
                    h.outer._queue("deleted", ev.src_path, journal)

            def on_moved(h, ev):
                if not ev.is_directory:
                    h.outer._queue("renamed", ev.src_path, journal, {"dest_path": ev.dest_path})

        with self._observer_lock:
            if self._observer is not None:
                return
            try:
                observer = Observer()
                handler = _H(self)
                count = 0
                for p in self._watch_paths:
                    try:
                        if os.path.exists(p):
                            observer.schedule(handler, p, recursive=True)
                            count += 1
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("fschange: cannot watch %s: %s", p, exc)
                if count:
                    observer.start()
                    self._observer = observer
                    logger.info("fschange: watchdog started on %d path(s)", count)
            except Exception as exc:  # noqa: BLE001
                logger.warning("fschange: watchdog start failed: %s", exc)

    def _try_usn_poll(self) -> None:
        if current_os_tag() != "windows":
            return
        try:
            import ctypes.wintypes
            for p in self._watch_paths:
                try:
                    drive = os.path.splitdrive(os.path.abspath(p))[0]
                    if not drive:
                        continue
                    ctypes.windll.kernel32.GetVolumeInformationW(drive + "\\", None, 0, None, None, None, None, 0)
                    journal_root = str(Path(p).resolve())
                    for root, dirs, files in os.walk(p):
                        for fn in files:
                            fp = os.path.join(root, fn)
                            try:
                                st = os.stat(fp)
                            except OSError:
                                continue
                            self._queue(
                                "enum",
                                fp,
                                "USN_ENUM",
                                {"drive": drive, "mtime": st.st_mtime_ns if hasattr(st, "st_mtime_ns") else st.st_mtime, "size": st.st_size},
                            )
                        break
                    break
                except Exception:  # noqa: BLE001
                    continue
        except Exception as exc:  # noqa: BLE001
            logger.debug("fschange USN enum fallback: %s", exc)

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
        try:
            self._try_usn_poll()
        except Exception:  # noqa: BLE001
            pass
        with self._pending_lock:
            out = self._pending
            self._pending = []
        return out

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "fschange",
            "severity": "low",
            "payload": {
                "path": str(Path.home() / "Documents" / "ledger.xlsx"),
                "action": "modified",
                "journal_source": "inotify",
                "size": 20480,
                "mtime": 1_700_000_000,
            },
        }
