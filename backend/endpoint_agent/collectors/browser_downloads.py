import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from endpoint_agent.content_scan import safe_url
from . import Collector
from .capture_state import CaptureState, bounded_int


class BrowserDownloadCollector(Collector):
    """Read completed Chromium/Edge downloads without modifying browser profiles."""
    name = "browser_downloads"
    default_interval_seconds = 15

    def __init__(self, config=None):
        config = {"enabled": False, **(config or {})}
        super().__init__(config)
        self.databases = list(config.get("databases", []))
        if len(self.databases) > 20:
            raise ValueError("Use at most 20 browser history databases")
        self.limit = bounded_int(config, "max_downloads", 200, 1, 500)
        self.state = CaptureState(config.get("state_path", "download-state.sqlite")) if self._enabled else None
        self.coverage = "not_started"

    @classmethod
    def supports_current_os(cls):
        return True

    def status(self):
        return {**super().status(), "coverage": self.coverage, "databases": len(self.databases)}

    def _collect(self):
        events = []
        self.coverage = "complete"
        for source in self.databases:
            path = Path(source["path"]).absolute()
            if not path.is_file() or path.is_symlink():
                self.coverage = "partial"
                continue
            key = "downloads:" + str(path)
            previous = self.state.get(key)
            seen = dict(previous or {})
            try:
                with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.2) as db:
                    db.row_factory = sqlite3.Row
                    columns = {row[1] for row in db.execute("PRAGMA table_info(downloads)")}
                    selected = [c for c in ("id", "guid", "target_path", "current_path", "total_bytes", "received_bytes", "start_time", "end_time", "tab_url") if c in columns]
                    if not {"id", "state", "start_time"} <= columns:
                        self.coverage = "unsupported_schema"
                        continue
                    rows = db.execute("SELECT " + ",".join(selected) + " FROM downloads WHERE state=1 ORDER BY id DESC LIMIT ?", (self.limit + 1,)).fetchall()
                    self.coverage = "partial" if len(rows) > self.limit else self.coverage
                    for row in rows[:self.limit]:
                        item = dict(row)
                        identity = hashlib.sha256((str(item.get("guid") or item["id"]) + str(item["start_time"]) + str(item.get("target_path", ""))).encode()).hexdigest()
                        if identity in seen:
                            continue
                        seen[identity] = item["id"]
                        if previous is None and not self._config.get("capture_existing", False):
                            continue
                        micros = item.get("end_time") or item["start_time"]
                        when = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)
                        url = item.get("tab_url", "")
                        if "downloads_url_chains" in {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}:
                            chain = db.execute("SELECT url FROM downloads_url_chains WHERE id=? ORDER BY chain_index DESC LIMIT 1", (item["id"],)).fetchone()
                            url = chain[0] if chain else url
                        events.append({"type": "browser_download", "severity": "low", "event_key": identity,
                                       "occurred_at": when.isoformat(), "payload": {"channel": "downloads", "browser": source.get("browser", "chromium"),
                                       "path": item.get("target_path") or item.get("current_path") or "", "bytes": max(0, item.get("total_bytes") or item.get("received_bytes") or 0),
                                       "source_url": safe_url(url), "transfer_status": "browser_download_completed"}})
                self.state.put(key, dict(list(seen.items())[-2000:]))
            except (sqlite3.Error, ValueError, OverflowError):
                self.coverage = "partial"
                self._errors += 1
        return events
