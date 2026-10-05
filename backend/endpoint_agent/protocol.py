from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
import logging
import os
import random
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from . import tls

try:
    import httpx
except ImportError:  # pragma: no cover - httpx is expected
    httpx = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)


class ProtocolError(Exception):
    pass


class OfflineQueue:
    def __init__(
        self,
        path: Optional[os.PathLike[str] | str] = None,
        max_bytes: int = 100 * 1024 * 1024,
    ) -> None:
        self._path = Path(path) if path else None
        self._max_bytes = max_bytes
        self._memory: list[bytes] = []
        self._file_size: int = 0
        if self._path is not None:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                if self._path.exists():
                    self._file_size = self._path.stat().st_size
            except OSError:
                self._path = None

    @contextmanager
    def delivery_guard(self, blocking=False):
        if self._path is None:
            yield True
            return
        guard = self._path.with_name(self._path.name + ".delivery-lock")
        handle = guard.open("a+b")
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        acquired = False
        deadline = time.monotonic() + (15 if blocking else 0)
        try:
            while True:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
            yield acquired
        finally:
            if acquired:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle, fcntl.LOCK_UN)
            handle.close()

    def __len__(self) -> int:
        total = len(self._memory)
        if self._path and self._path.exists():
            try:
                with self._path.open("rb") as fh:
                    total += sum(1 for _ in fh)
            except OSError:
                pass
        return total

    def enqueue(self, payload: dict[str, Any]) -> None:
        with self.delivery_guard(blocking=True) as acquired:
            if not acquired:
                raise ProtocolError("Offline queue is busy; observation was not queued")
            self._enqueue_unlocked(payload)

    def _enqueue_unlocked(self, payload: dict[str, Any]) -> None:
        try:
            line = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ProtocolError(f"Cannot serialize event: {exc}") from exc
        if len(line) > self._max_bytes:
            raise ProtocolError("Observation exceeds offline queue capacity")
        if self._path is None:
            while self._memory and sum(map(len, self._memory)) + len(line) > self._max_bytes:
                self._memory.pop(0)
            self._memory.append(line)
            return
        try:
            self._file_size = self._path.stat().st_size if self._path.exists() else 0
            while self._file_size + len(line) > self._max_bytes:
                self._drop_oldest()
            with self._path.open("ab") as fh:
                fh.write(line)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except (AttributeError, OSError):
                    pass
            self._file_size += len(line)
        except OSError:
            self._memory.append(line)

    def _drop_oldest(self) -> None:
        if self._path is None or not self._path.exists():
            if self._memory:
                self._memory = self._memory[len(self._memory) // 2 :]
            return
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="wb",
                prefix="offline_queue_",
                suffix=".jsonl.tmp",
                dir=str(self._path.parent),
                delete=False,
            )
            try:
                with self._path.open("rb") as src:
                    lines = src.readlines()
                keep = lines[max(len(lines) // 2, 1) :]
                tmp.writelines(keep)
                tmp.flush()
                try:
                    os.fsync(tmp.fileno())
                except (AttributeError, OSError):
                    pass
                tmp_path = Path(tmp.name)
            finally:
                tmp.close()
            os.replace(tmp_path, self._path)
            self._file_size = self._path.stat().st_size
        except OSError:
            self._memory.clear()
            self._file_size = 0

    def peek_pending(self, limit: int = 100) -> list[bytes]:
        out: list[bytes] = []
        out.extend(self._memory[:limit])
        if len(out) < limit and self._path and self._path.exists():
            try:
                with self._path.open("rb") as fh:
                    for _ in range(limit - len(out)):
                        line = fh.readline()
                        if not line:
                            break
                        out.append(line)
            except OSError:
                pass
        return out

    def remove_front(self, count: int) -> None:
        mem_count = min(count, len(self._memory))
        del self._memory[:mem_count]
        count -= mem_count
        if count <= 0 or self._path is None or not self._path.exists():
            return
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="wb",
                prefix="offline_queue_",
                suffix=".jsonl.tmp",
                dir=str(self._path.parent),
                delete=False,
            )
            try:
                with self._path.open("rb") as src:
                    idx = 0
                    for line in src:
                        if idx >= count:
                            tmp.write(line)
                        idx += 1
                tmp.flush()
                try:
                    os.fsync(tmp.fileno())
                except (AttributeError, OSError):
                    pass
                tmp_path = Path(tmp.name)
            finally:
                tmp.close()
            os.replace(tmp_path, self._path)
            self._file_size = self._path.stat().st_size
        except OSError:
            pass


class Backoff:
    def __init__(
        self,
        base: float = 1.0,
        max_wait: float = 60.0,
        jitter: float = 0.5,
        factor: float = 2.0,
    ) -> None:
        self._base = base
        self._max = max_wait
        self._jitter = jitter
        self._factor = factor
        self._attempt = 0

    def reset(self) -> None:
        self._attempt = 0

    def next(self) -> float:
        wait = min(self._max, self._base * (self._factor ** self._attempt))
        if self._jitter > 0:
            wait = wait * (1 - self._jitter + random.random() * self._jitter * 2)
        self._attempt += 1
        return max(0.0, wait)


class AgentClient:
    def __init__(
        self,
        server_url: str,
        agent_token: str,
        *,
        timeout: float = 30.0,
        verify: tls.VerifyArgument = True,
        proxy: Optional[str] = None,
        allow_insecure_http: bool = False,
        retries: int = 5,
        queue_path: Optional[os.PathLike[str] | str] = None,
        queue_max_mb: int = 100,
    ) -> None:
        if httpx is None:
            raise ProtocolError("httpx is not available")
        self._server = tls.require_secure_url(server_url, allow_insecure=allow_insecure_http)
        self._token = agent_token
        self._timeout = timeout
        self._verify = verify
        self._proxy = proxy
        self._retries = max(0, retries)
        self._queue = OfflineQueue(queue_path, queue_max_mb * 1024 * 1024)
        self._backoff = Backoff()
        self._client: Optional["httpx.Client"] = None
        self._async_client: Optional["httpx.AsyncClient"] = None

    @property
    def queue(self) -> OfflineQueue:
        return self._queue

    def _headers(self, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
        hdrs = {
            "X-Agent-Token": self._token,
            "User-Agent": f"endpoint-agent/{'0.1.0' if True else 'dev'}",
            "Accept": "application/json",
        }
        if extra:
            hdrs.update(extra)
        return hdrs

    def _transport_kwargs(self) -> dict[str, Any]:
        """Options shared by the sync and async clients.

        Both legs must authenticate the server identically; building the options
        in one place is what stops them drifting apart.
        """
        options: dict[str, Any] = {"verify": self._verify}
        if self._proxy:
            options["proxy"] = self._proxy
        return options

    def _get_client(self) -> "httpx.Client":
        if self._client is None:
            self._client = httpx.Client(
                base_url=self._server,
                timeout=self._timeout,
                **self._transport_kwargs(),
            )
        return self._client

    def _get_async_client(self) -> "httpx.AsyncClient":
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self._server,
                timeout=self._timeout,
                **self._transport_kwargs(),
            )
        return self._async_client

    def close(self) -> None:
        try:
            if self._client is not None:
                self._client.close()
        finally:
            self._client = None

    async def aclose(self) -> None:
        try:
            if self._async_client is not None:
                await self._async_client.aclose()
        finally:
            self._async_client = None

    def _should_retry(self, status: Optional[int], exc: Optional[Exception]) -> bool:
        if exc is not None:
            return isinstance(exc, (httpx.TransportError, httpx.TimeoutException))
        if status is None:
            return True
        return status in (408, 429, 500, 502, 503, 504)

    def _prepare_event(self, event):
        import hashlib
        import uuid
        event = dict(event)
        event.setdefault("ts", int(time.time()))
        event.setdefault("event_key", hashlib.sha256(uuid.uuid4().bytes).hexdigest())
        return event

    def post_event(self, event: dict[str, Any]) -> bool:
        return self.post_events([event])

    def post_events(self, events) -> bool:
        # Persist before sending: a timeout after server commit can safely be retried.
        for event in events:
            self._queue.enqueue(self._prepare_event(event))
        self.flush_queue()
        return len(self._queue) == 0

    async def apost_event(self, event: dict[str, Any]) -> bool:
        self._queue.enqueue(self._prepare_event(event))
        await self.aflush_queue()
        return len(self._queue) == 0

    def flush_queue(self, batch_size: int = 50) -> tuple[int, int]:
        with self._queue.delivery_guard() as acquired:
            if not acquired:
                return 0, len(self._queue)
            return self._flush_queue_unlocked(batch_size)

    def _flush_queue_unlocked(self, batch_size: int = 50) -> tuple[int, int]:
        total = len(self._queue)
        sent = 0
        while True:
            batch_raw = self._queue.peek_pending(batch_size)
            if not batch_raw:
                break
            events: list[dict[str, Any]] = []
            consumed, size = 0, 0
            for raw in batch_raw:
                try:
                    event = json.loads(raw.decode("utf-8"))
                    wire_size = len(json.dumps(self._wire_event(event)).encode("utf-8"))
                    if wire_size > 4 * 1024 * 1024:
                        raise ProtocolError("One queued event exceeds the transport size limit")
                    if events and size + wire_size > 4 * 1024 * 1024:
                        break
                    events.append(event)
                    size += wire_size
                except (ValueError, UnicodeDecodeError):
                    pass
                consumed += 1
            if not events:
                self._queue.remove_front(consumed)
                continue
            try:
                self._send_batch_sync(events)
            except ProtocolError:
                break
            self._queue.remove_front(consumed)
            sent += len(events)
        return sent, total

    async def aflush_queue(self, batch_size: int = 50) -> tuple[int, int]:
        with self._queue.delivery_guard() as acquired:
            if not acquired:
                return 0, len(self._queue)
            return await self._aflush_queue_unlocked(batch_size)

    async def _aflush_queue_unlocked(self, batch_size: int = 50) -> tuple[int, int]:
        total = len(self._queue)
        sent = 0
        while True:
            batch_raw = self._queue.peek_pending(batch_size)
            if not batch_raw:
                break
            events: list[dict[str, Any]] = []
            consumed, size = 0, 0
            for raw in batch_raw:
                try:
                    event = json.loads(raw.decode("utf-8"))
                    wire_size = len(json.dumps(self._wire_event(event)).encode("utf-8"))
                    if wire_size > 4 * 1024 * 1024:
                        raise ProtocolError("One queued event exceeds the transport size limit")
                    if events and size + wire_size > 4 * 1024 * 1024:
                        break
                    events.append(event)
                    size += wire_size
                except (ValueError, UnicodeDecodeError):
                    pass
                consumed += 1
            if not events:
                self._queue.remove_front(consumed)
                continue
            try:
                await self._send_batch_async(events)
            except ProtocolError:
                break
            self._queue.remove_front(consumed)
            sent += len(events)
        return sent, total

    @staticmethod
    def _wire_event(event):
        from datetime import datetime, timezone
        wire = {key: event[key] for key in ("type", "severity", "payload", "occurred_at", "event_key") if key in event}
        if not wire.get("occurred_at") and event.get("ts"):
            wire["occurred_at"] = datetime.fromtimestamp(event["ts"], timezone.utc).isoformat()
        return wire

    def _send_batch_sync(self, events: list[dict[str, Any]]) -> None:
        last_exc: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            try:
                client = self._get_client()
                resp = client.post(
                    "/api/agents/events",
                    headers=self._headers({"Content-Type": "application/json"}),
                    json={"events": [self._wire_event(event) for event in events]},
                )
                if 200 <= resp.status_code < 300:
                    self._backoff.reset()
                    return
                if not self._should_retry(resp.status_code, None):
                    raise ProtocolError(f"Server rejected events: HTTP {resp.status_code}")
            except Exception as exc:  # noqa: BLE001 - we re-raise after retries
                last_exc = exc
                if not self._should_retry(None, exc):
                    raise ProtocolError(f"Request failed: {exc}") from exc
            wait = self._backoff.next()
            if wait > 0:
                time.sleep(wait)
        raise ProtocolError(f"Send failed after retries: {last_exc}")

    async def _send_batch_async(self, events: list[dict[str, Any]]) -> None:
        last_exc: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            try:
                client = self._get_async_client()
                resp = await client.post(
                    "/api/agents/events",
                    headers=self._headers({"Content-Type": "application/json"}),
                    json={"events": [self._wire_event(event) for event in events]},
                )
                if 200 <= resp.status_code < 300:
                    self._backoff.reset()
                    return
                if not self._should_retry(resp.status_code, None):
                    raise ProtocolError(f"Server rejected events: HTTP {resp.status_code}")
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if not self._should_retry(None, exc):
                    raise ProtocolError(f"Request failed: {exc}") from exc
            wait = self._backoff.next()
            if wait > 0:
                await asyncio.sleep(wait)
        raise ProtocolError(f"Send failed after retries: {last_exc}")

    def response_request(self, method, path, payload=None):
        if not path.startswith(("/api/response/", "/api/replay/agent/", "/api/education/agent/", "/api/privacy/agent/", "/api/biometrics/agent/")):
            raise ProtocolError("Unsupported response route")
        response = self._get_client().request(method, path, headers=self._headers(), json=payload)
        if not 200 <= response.status_code < 300:
            raise ProtocolError(f"Response request failed: {response.status_code}")
        return response.json()

    def heartbeat(self, status: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        status = status or {}
        payload = {key: status[key] for key in ("cpu_pct", "memory_pct", "disk_free_bytes", "last_event_id", "agent_version", "update_status", "tamper_events") if key in status}
        payload["collector_status"] = {name: json.dumps(value, separators=(",", ":"))[:4000] for name, value in status.get("collectors", {}).get("collectors", {}).items()}
        last_exc: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            try:
                client = self._get_client()
                resp = client.post(
                    "/api/agents/heartbeat",
                    headers=self._headers({"Content-Type": "application/json"}),
                    json=payload,
                )
                if 200 <= resp.status_code < 300:
                    self._backoff.reset()
                    try:
                        return resp.json() if resp.content else {}
                    except ValueError:
                        return {}
                if not self._should_retry(resp.status_code, None):
                    raise ProtocolError(f"Heartbeat failed: HTTP {resp.status_code}")
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if not self._should_retry(None, exc):
                    raise ProtocolError(f"Heartbeat error: {exc}") from exc
            wait = self._backoff.next()
            if wait > 0:
                time.sleep(wait)
        raise ProtocolError(f"Heartbeat failed after retries: {last_exc}")

    def __enter__(self) -> "AgentClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    async def __aenter__(self) -> "AgentClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()
