from __future__ import annotations

import collections
import logging
from typing import Any

from endpoint_agent.collectors import Collector


logger = logging.getLogger(__name__)


class AgentLogCollector(Collector):
    name = "agent_log"
    default_interval_seconds = 2.0

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._min_level = str(self._config.get("min_level", "WARNING")).upper()
        self._buffer: collections.deque[dict[str, Any]] = collections.deque(maxlen=500)
        self._handler: _Handler | None = None

    @classmethod
    def supports_current_os(cls) -> bool:
        return True

    def attach_to_root_logger(self) -> None:
        if self._handler is not None:
            return
        self._handler = _Handler(self._buffer, self._min_level)
        logging.getLogger().addHandler(self._handler)

    def detach_from_root_logger(self) -> None:
        if self._handler is None:
            return
        try:
            logging.getLogger().removeHandler(self._handler)
        except Exception:
            pass
        self._handler = None

    def _collect(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        while self._buffer:
            rec = self._buffer.popleft()
            sev = "low"
            level = rec.get("levelname", "INFO")
            if level == "ERROR":
                sev = "high"
            elif level in ("WARNING", "WARN"):
                sev = "medium"
            elif level == "CRITICAL":
                sev = "critical"
            out.append({
                "type": "agent_log",
                "severity": sev,
                "payload": {
                    "level": level,
                    "logger": rec.get("name", ""),
                    "message": rec.get("message", "")[:2000],
                    "module": rec.get("module", ""),
                    "exc_info": rec.get("exc_info", "")[:1500],
                },
            })
        return out

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "agent_log",
            "severity": "medium",
            "payload": {"level": "WARNING", "logger": "endpoint_agent",
                        "message": "collector started", "module": "agentlog", "exc_info": ""},
        }


class _Handler(logging.Handler):
    def __init__(self, sink: collections.deque, min_level: str) -> None:
        super().__init__()
        self._sink = sink
        try:
            self.setLevel(getattr(logging, min_level, logging.WARNING))
        except Exception:
            self.setLevel(logging.WARNING)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            exc = ""
            if record.exc_info:
                try:
                    exc = self.formatException(record.exc_info)
                except Exception:
                    exc = str(record.exc_info[:2])
            self._sink.append({
                "name": record.name,
                "levelname": record.levelname,
                "module": record.module,
                "message": record.getMessage(),
                "exc_info": exc,
            })
        except Exception:
            pass
