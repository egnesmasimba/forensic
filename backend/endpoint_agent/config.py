from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional


DEFAULT_CONFIG: dict[str, Any] = {
    "server_url": "http://localhost:8000",
    "agent_token": "",
    "poll_interval_seconds": 30,
    "heartbeat_interval_seconds": 10,
    "stall_timeout_seconds": 120,
    "max_restarts_per_hour": 6,
    "offline_queue_path": "offline_queue.jsonl",
    "offline_queue_max_mb": 100,
    "update_url": "",
    "update_poll_hours": 24,
    "current_version": "0.1.0",
    "collectors": {},
    # Transport security. These keys are written by the platform installers and
    # are read by endpoint_agent.tls; see that module for the policy.
    "tls": {
        "verify_tls": True,
        "ca_bundle": None,
        "client_cert": None,
        "client_key": None,
        "server_hostname": None,
        "allow_insecure_http": False,
        "proxy": None,
    },
    "logging": {
        "level": "INFO",
        "file": "agent.log",
        "max_bytes": 5 * 1024 * 1024,
        "backup_count": 3,
    },
}


def _config_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _default_config() -> dict[str, Any]:
    """A private copy of the defaults.

    A shallow copy would share the nested sections with DEFAULT_CONFIG, so a
    ``set()`` on one Config would rewrite the defaults for every other Config in
    the process - which is how one agent's CA bundle path ends up in another
    agent's configuration.
    """
    return copy.deepcopy(DEFAULT_CONFIG)


class ConfigError(Exception):
    pass


class Config:
    def __init__(self, path: Optional[os.PathLike[str] | str] = None) -> None:
        if path is None:
            env_path = os.environ.get("ENDPOINT_AGENT_CONFIG")
            if env_path:
                path = env_path
            else:
                path = Path.cwd() / "agent_config.json"
        self._path = Path(path)
        self._data: dict[str, Any] = _default_config()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def data(self) -> dict[str, Any]:
        return self._data

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        cur: Any = self._data
        for k in keys:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                return default
        return cur

    def set(self, key: str, value: Any) -> None:
        keys = key.split(".")
        cur = self._data
        for k in keys[:-1]:
            if k not in cur or not isinstance(cur[k], dict):
                cur[k] = {}
            cur = cur[k]
        cur[keys[-1]] = value

    def load(self) -> bool:
        if not self._path.exists():
            self._data = _default_config()
            return False
        try:
            raw_text = self._path.read_text(encoding="utf-8")
            envelope = json.loads(raw_text)
            if isinstance(envelope, dict) and "config" in envelope and "hash" in envelope:
                payload = envelope["config"]
                expected = envelope["hash"]
                if _config_hash(payload) != expected:
                    raise ConfigError("Config hash mismatch, file may be tampered")
                self._data = self._merge(_default_config(), payload)
            else:
                self._data = self._merge(_default_config(), envelope)
            return True
        except (json.JSONDecodeError, OSError) as exc:
            raise ConfigError(f"Failed to read config: {exc}") from exc

    def save(self, with_hash: bool = True) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = dict(self._data)
            if with_hash:
                envelope = {"config": payload, "hash": _config_hash(payload)}
                text = json.dumps(envelope, indent=2, sort_keys=True)
            else:
                text = json.dumps(payload, indent=2, sort_keys=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as exc:
            raise ConfigError(f"Failed to write config: {exc}") from exc

    def verify_integrity(self) -> bool:
        if not self._path.exists():
            return False
        try:
            raw_text = self._path.read_text(encoding="utf-8")
            envelope = json.loads(raw_text)
            if not isinstance(envelope, dict) or "config" not in envelope or "hash" not in envelope:
                return False
            return _config_hash(envelope["config"]) == envelope["hash"]
        except (json.JSONDecodeError, OSError):
            return False

    @staticmethod
    def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        result = dict(base)
        for k, v in override.items():
            if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                result[k] = Config._merge(result[k], v)
            else:
                result[k] = v
        return result
