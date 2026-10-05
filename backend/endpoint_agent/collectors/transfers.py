import ctypes
import hashlib
import os
import time
from pathlib import Path

from endpoint_agent.content_scan import MAX_FILE, scan_bytes
from . import Collector
from .capture_state import CaptureState, bounded_int


CHANNELS = {"local", "usb", "network_share", "cloud", "downloads"}
PROVIDERS = {"onedrive", "dropbox", "google drive", "box"}


def discover_roots():
    roots = []
    home = Path.home()
    for provider, candidates in {
        "onedrive": [os.getenv("OneDrive"), os.getenv("OneDriveCommercial"), str(home / "OneDrive")],
        "dropbox": [str(home / "Dropbox")], "google drive": [str(home / "Google Drive"), str(home / "GoogleDrive")],
        "box": [str(home / "Box"), str(home / "Box Sync")],
    }.items():
        for path in candidates:
            if path and Path(path).is_dir():
                roots.append({"path": path, "channel": "cloud", "provider": provider})
    if os.name == "nt":
        kernel = ctypes.windll.kernel32
        for index in range(26):
            root = chr(65 + index) + ":\\"
            kind = kernel.GetDriveTypeW(ctypes.c_wchar_p(root))
            if kind in (2, 4):
                roots.append({"path": root, "channel": "usb" if kind == 2 else "network_share", "drive_type": kind})
    else:
        # Mounted volumes must be named explicitly on Unix: a mountpoint alone does
        # not establish that the underlying device is removable or a network share.
        pass
    return roots


def inspect_file(path):
    before = path.stat()
    with path.open("rb") as stream:
        data = stream.read(min(before.st_size, MAX_FILE) + 1)
    oversized = before.st_size > MAX_FILE
    scan = scan_bytes(data[:65536] if oversized else data, path.name)
    scan["size"] = before.st_size
    if oversized:
        scan["partial"] = True
        scan["notes"].append("Content scanning limited to a prefix of this large file")
        scan["sha256"] = None
    if before.st_size <= 25 * 1024 * 1024:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        scan["sha256"] = digest.hexdigest()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise OSError("File changed during inspection")
    return scan


class TransferCollector(Collector):
    name = "transfers"
    default_interval_seconds = 5

    def __init__(self, config=None):
        config = {"enabled": False, **(config or {})}
        super().__init__(config)
        self.max_files = bounded_int(config, "max_files", 5000, 1, 10000)
        self.max_changes = bounded_int(config, "max_changes", 100, 1, 200)
        self.state = CaptureState(config.get("state_path", "transfer-state.sqlite")) if self._enabled else None
        self.roots = list(config.get("roots", []))
        if config.get("auto_discover", False):
            self.roots.extend(discover_roots())
        if len(self.roots) > 30:
            raise ValueError("Use at most 30 monitored roots")
        for root in self.roots:
            if root.get("channel") not in CHANNELS or not root.get("path"):
                raise ValueError("Each root needs a path and supported channel")
            if root["channel"] == "cloud" and root.get("provider") not in PROVIDERS:
                raise ValueError("Cloud roots require a supported provider")
        self.pending = {}
        self.coverage = "not_started"

    @classmethod
    def supports_current_os(cls):
        return True

    def status(self):
        return {**super().status(), "coverage": self.coverage, "roots": len(self.roots)}

    def _walk(self, root):
        found = {}
        base = Path(root["path"]).absolute()
        if base.is_symlink():
            return found, False
        complete = True
        def failure(error):
            nonlocal complete
            complete = False
        for directory, dirs, files in os.walk(base, followlinks=False, onerror=failure):
            dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
            for filename in sorted(files):
                path = Path(directory) / filename
                if path.is_symlink() or filename.endswith((".crdownload", ".part", ".tmp")):
                    continue
                # Never observe our own persistent collector state.
                if str(path.absolute()).startswith(str(self.state.path.absolute())):
                    continue
                try:
                    stat = path.stat()
                    found[str(path)] = [stat.st_size, stat.st_mtime_ns]
                except OSError:
                    complete = False
                if len(found) >= self.max_files:
                    return found, False
        return found, complete and base.is_dir()

    def _collect(self):
        if not self.state:
            return []
        events, scanned, read_budget, sources = [], 0, 64 * 1024 * 1024, {}
        snapshots = []
        for root in sorted(self.roots, key=lambda r: r["channel"] != "local"):
            key = "root:" + str(Path(root["path"]).absolute()) + ":" + root["channel"]
            current, complete = self._walk(root)
            previous = self.state.get(key)
            snapshots.append((root, key, current, previous, complete))
            if root["channel"] == "local":
                for path, entry in (previous or {}).items():
                    if entry.get("sha256"):
                        sources[entry["sha256"]] = path
        self.coverage = "complete" if all(s[-1] for s in snapshots) else "partial"
        for root, key, current, previous, complete in snapshots:
            saved = dict(previous or {})
            baseline = previous is None
            for path, signature in current.items():
                old = saved.get(path, {})
                if old.get("signature") == signature and not old.get("baseline_unscanned"):
                    continue
                pending_key = (key, path)
                if not baseline and self.pending.get(pending_key) != signature:
                    self.pending[pending_key] = signature
                    continue
                if scanned >= self.max_changes or read_budget < min(signature[0], 25 * 1024 * 1024):
                    self.coverage = "partial"
                    if baseline:
                        saved[path] = {"signature": signature, "sha256": None, "baseline_unscanned": True}
                    continue
                try:
                    scan = inspect_file(Path(path))
                except OSError:
                    self.coverage = "partial"
                    continue
                scanned += 1
                read_budget -= min(signature[0], 25 * 1024 * 1024)
                saved[path] = {"signature": signature, "sha256": scan["sha256"]}
                self.pending.pop(pending_key, None)
                if root["channel"] == "local" and scan["sha256"]:
                    sources[scan["sha256"]] = path
                was_baseline = baseline or old.get("baseline_unscanned") and old.get("signature") == signature
                if was_baseline and not self._config.get("capture_existing", False):
                    continue
                source_path = sources.get(scan["sha256"]) if scan["sha256"] else None
                event_type = "file_observation" if root["channel"] == "local" else "transfer_observed"
                payload = {"path": path, "destination": root.get("provider") or root["channel"],
                           "channel": root["channel"], "bytes": signature[0], "source_path": source_path,
                           "source_match": "content_hash" if source_path else "not_observed",
                           "transfer_status": "destination_write_observed", "operation": "created" if not old else "modified",
                           "file_scan": scan, "coverage": self.coverage}
                fingerprint = hashlib.sha256((key + path + repr(signature)).encode()).hexdigest()
                events.append({"type": event_type, "severity": "low", "event_key": fingerprint, "payload": payload})
            if complete:
                saved = {path: entry for path, entry in saved.items() if path in current}
            self.state.put(key, saved)
        return events
