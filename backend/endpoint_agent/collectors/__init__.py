from __future__ import annotations

import abc
import logging
import platform
import threading
import time
from typing import Any, Iterable, Optional, Sequence

from . import dependencies


logger = logging.getLogger(__name__)


class Collector(abc.ABC):
    name: str = "base"
    default_interval_seconds: float = 60.0
    #: Import names outside the standard library that this collector needs. A
    #: collector with an unsatisfied requirement stays visible but collects
    #: nothing, so the gap must be reported instead of only logged.
    requires: tuple[str, ...] = ()
    #: Operating systems this collector is designed for. An empty tuple means
    #: every platform; listing platforms keeps "wrong OS" and "missing module"
    #: distinguishable, which subclass guards otherwise conflate.
    platforms: tuple[str, ...] = ()
    #: Collectors that capture potentially sensitive material stay off until an
    #: operator opts in by name, rather than coming up enabled everywhere.
    sensitive: bool = False

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        self._config: dict[str, Any] = dict(config or {})
        # Collectors flagged ``sensitive`` capture window titles, clipboard
        # contents, screen images or user activity. Those stay off until an
        # operator enables them by name, so registering every collector does
        # not silently start surveillance on every endpoint.
        self._enabled: bool = bool(self._config.get("enabled", not self.sensitive))
        self._interval: float = float(
            self._config.get("interval_seconds", self.default_interval_seconds)
        )
        self._running: bool = False
        self._buffer: list[dict[str, Any]] = []
        self._buffer_lock = threading.Lock()
        self._last_run: float = 0.0
        self._errors: int = 0
        self._collected: int = 0

    @classmethod
    @abc.abstractmethod
    def supports_current_os(cls) -> bool:
        """Return True if this collector works on the current platform."""

    @classmethod
    def effective_requires(cls) -> tuple[str, ...]:
        """Requirements that actually apply on this host.

        Defaults to :attr:`requires`. Collectors whose dependencies differ per
        operating system override this so that, for example, the macOS-only
        ``Quartz`` module is not reported as missing on a Linux endpoint.
        """
        return tuple(cls.requires)

    @classmethod
    def missing_requirements(cls) -> tuple[str, ...]:
        """Import names this collector needs that are not installed."""
        return dependencies.missing_modules(cls.effective_requires())

    @classmethod
    def platform_supported(cls) -> bool:
        """True when this collector is designed for the current OS.

        Subclass ``supports_current_os`` guards often also test for optional
        imports, so they cannot answer this question on their own.
        """
        if not cls.platforms:
            return True
        return current_os_tag() in cls.platforms

    @classmethod
    def is_available(cls) -> bool:
        """True when the collector can actually collect on this host."""
        return (
            cls.platform_supported()
            and cls.supports_current_os()
            and not cls.missing_requirements()
        )

    @classmethod
    def unavailable_reason(cls) -> Optional[str]:
        """Human-readable reason this collector is inert, or None if usable.

        Collectors with alternative backends (pywin32 or WMI, for example)
        override this so the message names the real prerequisite rather than
        implying that every listed module is mandatory.
        """
        missing = dependencies.missing_modules(cls.effective_requires())
        reasons: list[str] = []
        if not cls.platform_supported():
            supported = ", ".join(cls.platforms)
            reasons.append(
                f"not supported on {current_os_tag()} (designed for: {supported})"
            )
        if missing:
            reasons.append(
                f"missing optional dependencies: {', '.join(missing)} "
                f"(install with: {dependencies.install_command(missing)})"
            )
        return "; ".join(reasons) if reasons else None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def interval(self) -> float:
        return self._interval

    @property
    def enabled(self) -> bool:
        return self._enabled and self.is_available()

    @property
    def stat_collected(self) -> int:
        return self._collected

    @property
    def stat_errors(self) -> int:
        return self._errors

    def configure(self, config: dict[str, Any]) -> None:
        self._config.update(config)
        self._enabled = bool(self._config.get("enabled", not self.sensitive))
        self._interval = float(
            self._config.get("interval_seconds", self.default_interval_seconds)
        )

    def status(self) -> dict[str, Any]:
        missing = self.missing_requirements()
        return {
            "name": self.name,
            "enabled": self._enabled,
            "supported": self.is_available(),
            "platform_supported": self.platform_supported(),
            "available": self.is_available(),
            "requires": list(self.effective_requires()),
            "missing_dependencies": list(missing),
            "install_command": dependencies.install_command(missing),
            "unavailable_reason": self.unavailable_reason(),
            "sensitive": self.sensitive,
            "running": self._running,
            "interval_seconds": self._interval,
            "events_collected": self._collected,
            "errors": self._errors,
            "pending": len(self._buffer),
        }

    def tick_if_due(self) -> list[dict[str, Any]]:
        if not self.enabled or self._interval <= 0:
            return []
        now = time.monotonic()
        if now - self._last_run < self._interval:
            return []
        self._last_run = now
        return self.collect()

    def collect(self) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        try:
            out = list(self._collect() or [])
        except Exception as exc:  # noqa: BLE001
            self._errors += 1
            logger.warning("Collector %s failed: %s", self.name, exc)
            return []
        stamped: list[dict[str, Any]] = []
        for ev in out:
            if not isinstance(ev, dict):
                continue
            event = dict(ev)
            event.setdefault("ts", int(time.time()))
            event.setdefault("collector", self.name)
            stamped.append(event)
        self._collected += len(stamped)
        with self._buffer_lock:
            self._buffer.extend(stamped)
        return stamped

    @abc.abstractmethod
    def _collect(self) -> Iterable[dict[str, Any]]:
        """Collect and return raw events (ts/collector keys added by wrapper)."""

    def flush(self) -> list[dict[str, Any]]:
        with self._buffer_lock:
            out = self._buffer
            self._buffer = []
        return out

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def __repr__(self) -> str:
        return f"<Collector {self.name!r} enabled={self.enabled} running={self._running}>"


class NoopCollector(Collector):
    name = "noop"

    @classmethod
    def supports_current_os(cls) -> bool:
        return True

    def _collect(self) -> Iterable[dict[str, Any]]:
        return []


class CollectorManager:
    def __init__(
        self,
        collector_configs: dict[str, Any],
        *,
        collectors: Optional[Sequence[type[Collector]]] = None,
    ) -> None:
        self._configs = dict(collector_configs or {})
        self._collectors: dict[str, Collector] = {}
        self._init_errors: dict[str, str] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        classes: list[type[Collector]] = list(collectors or [])
        if not classes:
            classes.append(NoopCollector)
        for cls in classes:
            name = cls.name
            cfg = self._configs.get(name) or {}
            try:
                inst = cls(cfg)
                self._collectors[name] = inst
            except Exception as exc:  # noqa: BLE001
                # Keep the failure visible: a collector that cannot even be
                # constructed is still evidence the examiner is not getting.
                self._init_errors[name] = f"{type(exc).__name__}: {exc}"
                logger.warning("Cannot initialize collector %s: %s", name, exc)

    @property
    def collectors(self) -> dict[str, Collector]:
        return dict(self._collectors)

    def register(self, *collectors: Collector) -> None:
        with self._lock:
            for c in collectors:
                self._collectors[c.name] = c

    def get(self, name: str) -> Optional[Collector]:
        return self._collectors.get(name)

    def start_all(self) -> None:
        with self._lock:
            for c in self._collectors.values():
                try:
                    c.start()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Collector %s start failed: %s", c.name, exc)
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name="collector-manager",
                daemon=True,
            )
            self._thread.start()

    def stop_all(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=timeout)
            except RuntimeError:
                pass
            self._thread = None
        with self._lock:
            for c in self._collectors.values():
                try:
                    c.stop()
                except Exception:  # noqa: BLE001
                    pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick_all()
            except Exception:  # noqa: BLE001
                logger.exception("Collector manager tick failed")
            time.sleep(0.5)

    def tick_all(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        with self._lock:
            values = list(self._collectors.values())
        for c in values:
            if not c.is_running:
                continue
            try:
                out.extend(c.tick_if_due())
            except Exception as exc:  # noqa: BLE001
                logger.warning("Collector %s tick error: %s", c.name, exc)
        return out

    def flush_all(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        with self._lock:
            values = list(self._collectors.values())
        for c in values:
            try:
                out.extend(c.flush())
            except Exception as exc:  # noqa: BLE001
                logger.warning("Collector %s flush error: %s", c.name, exc)
        return out

    def status(self) -> dict[str, Any]:
        with self._lock:
            items = {name: c.status() for name, c in self._collectors.items()}
            init_errors = dict(self._init_errors)
        inert = sorted(n for n, s in items.items() if not s["available"])
        missing = sorted({m for s in items.values() for m in s["missing_dependencies"]})
        return {
            "thread_alive": bool(self._thread and self._thread.is_alive()),
            "collectors": items,
            "registered": len(items),
            "inert": inert,
            "missing_dependencies": missing,
            "install_command": dependencies.install_command(missing),
            "init_errors": init_errors,
        }


def current_os_tag() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "macos"
    if system.startswith("linux"):
        return "linux"
    return system or "unknown"


__all__ = [
    "Collector",
    "CollectorManager",
    "NoopCollector",
    "current_os_tag",
    "dependencies",
]
