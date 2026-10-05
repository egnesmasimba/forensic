import json
import sqlite3
from pathlib import Path


class CaptureState:
    """Small persistent checkpoints shared by mail and file collectors."""
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS checkpoints (key TEXT PRIMARY KEY, value TEXT NOT NULL)")

    def connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def get(self, key, default=None):
        with self.connect() as db:
            row = db.execute("SELECT value FROM checkpoints WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key, value):
        with self.connect() as db:
            db.execute("INSERT INTO checkpoints VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))


def bounded_int(config, key, default, low, high):
    value = int(config.get(key, default))
    if not low <= value <= high:
        raise ValueError(f"{key} must be between {low} and {high}")
    return value
