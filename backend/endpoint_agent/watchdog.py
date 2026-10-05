from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

logger = logging.getLogger(__name__)


class WatchdogError(Exception):
    pass


class RateLimiter:
    def __init__(self, max_events: int, window_seconds: float) -> None:
        self._max = max_events
        self._window = window_seconds
        self._events: deque[float] = deque()

    def record_and_check(self) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        if len(self._events) >= self._max:
            return False
        self._events.append(now)
        return True


class SubprocessWatchdog:
    def __init__(
        self,
        args: Sequence[str],
        *,
        cwd: Optional[os.PathLike[str] | str] = None,
        env: Optional[dict[str, str]] = None,
        stall_timeout_seconds: float = 120.0,
        poll_interval_seconds: float = 2.0,
        max_restarts_per_hour: int = 6,
        graceful_shutdown_seconds: float = 15.0,
        stdout: Optional[int | Any] = None,
        stderr: Optional[int | Any] = None,
        on_restart: Optional[Callable[[int, Optional[int]], None]] = None,
    ) -> None:
        if not args:
            raise WatchdogError("Subprocess args are required")
        self._args = list(args)
        self._cwd = Path(cwd) if cwd else None
        self._env = env
        self._stall_timeout = max(1.0, float(stall_timeout_seconds))
        self._poll_interval = max(0.1, float(poll_interval_seconds))
        self._graceful = max(1.0, float(graceful_shutdown_seconds))
        self._rate = RateLimiter(max_events=max(max_restarts_per_hour, 1), window_seconds=3600.0)
        self._on_restart = on_restart
        self._stdout = stdout if stdout is not None else sys.stdout
        self._stderr = stderr if stderr is not None else sys.stderr

        self._proc: Optional[subprocess.Popen[str]] = None
        self._last_heartbeat: float = time.monotonic()
        self._stop = threading.Event()
        self._pid: Optional[int] = None
        self._start_count: int = 0
        self._watch_thread: Optional[threading.Thread] = None

    @property
    def pid(self) -> Optional[int]:
        return self._pid

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def start_count(self) -> int:
        return self._start_count

    def notify_alive(self) -> None:
        self._last_heartbeat = time.monotonic()

    def _merge_env(self) -> Optional[dict[str, str]]:
        if self._env is None:
            return None
        base = dict(os.environ)
        base.update(self._env)
        return base

    def start_once(self) -> None:
        if self.is_running:
            return
        if not self._rate.record_and_check():
            raise WatchdogError(
                "Refusing to restart: exceeded max restarts per hour; sleeping"
            )
        try:
            self._proc = subprocess.Popen(
                self._args,
                cwd=str(self._cwd) if self._cwd else None,
                env=self._merge_env(),
                stdout=self._stdout,
                stderr=self._stderr,
                text=True,
            )
        except (OSError, ValueError) as exc:
            raise WatchdogError(f"Failed to launch subprocess: {exc}") from exc
        self._pid = self._proc.pid
        self._last_heartbeat = time.monotonic()
        self._start_count += 1
        logger.info("Started subprocess pid=%s args=%s", self._pid, self._args)

    def _terminate_proc(self) -> None:
        if self._proc is None:
            return
        pid = self._proc.pid
        try:
            if self._proc.poll() is None:
                try:
                    self._proc.terminate()
                except (ProcessLookupError, PermissionError, OSError):
                    pass
                deadline = time.monotonic() + self._graceful
                while time.monotonic() < deadline:
                    if self._proc.poll() is not None:
                        break
                    time.sleep(0.2)
            if self._proc.poll() is None:
                try:
                    self._proc.kill()
                except (ProcessLookupError, PermissionError, OSError):
                    pass
                self._proc.wait(timeout=self._graceful)
        except (subprocess.TimeoutExpired, OSError):
            pass
        self._pid = None
        logger.info("Terminated subprocess pid=%s", pid)

    def stop(self) -> None:
        self._stop.set()
        if self._watch_thread is not None:
            try:
                self._watch_thread.join(timeout=self._graceful + 5.0)
            except RuntimeError:
                pass
            self._watch_thread = None
        self._terminate_proc()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._watch_thread is not None:
            self._watch_thread.join(timeout=timeout)

    def restart(self, reason: str = "manual") -> None:
        prev = self._proc
        prev_code: Optional[int] = prev.returncode if prev is not None and prev.returncode is not None else None
        self._terminate_proc()
        if self._on_restart is not None:
            try:
                self._on_restart(self._start_count, prev_code)
            except Exception:  # noqa: BLE001
                logger.exception("on_restart callback failed")
        logger.info("Restarting subprocess reason=%s", reason)
        self.start_once()

    def run_forever(self) -> None:
        self._stop.clear()
        try:
            self.start_once()
        except WatchdogError:
            logger.exception("Initial start failed; will retry")
            while not self._stop.is_set():
                time.sleep(min(10.0, self._poll_interval * 5))
                try:
                    self.start_once()
                    break
                except WatchdogError:
                    continue

        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                logger.exception("Watchdog tick error")
            time.sleep(self._poll_interval)

    def start_background(self) -> threading.Thread:
        if self._watch_thread is not None and self._watch_thread.is_alive():
            return self._watch_thread
        self._watch_thread = threading.Thread(
            target=self.run_forever,
            name="endpoint-agent-watchdog",
            daemon=True,
        )
        self._watch_thread.start()
        return self._watch_thread

    def _tick(self) -> None:
        if self._proc is None:
            self.restart("missing_process")
            return
        exit_code = self._proc.poll()
        if exit_code is not None:
            logger.warning("Subprocess exited code=%s pid=%s", exit_code, self._pid)
            self.restart(f"exit_code_{exit_code}")
            return
        staleness = time.monotonic() - self._last_heartbeat
        if staleness > self._stall_timeout:
            logger.warning(
                "Subprocess stalled no heartbeat for %.1fs pid=%s",
                staleness,
                self._pid,
            )
            self.restart(f"stall_{int(staleness)}s")
            return
