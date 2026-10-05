"""Optional forwarding of the compliance audit log to an external SIEM.

Phase 10 writes audit exports to a local directory, which is the right default:
it cannot be made to fail by a third party's outage, and nothing leaves the
deployment unasked. Some deployments still need the audit trail in Splunk,
QRadar, or ArcSight, so this module forwards the same rows those exports already
select. It is **opt-in and off unless configured**: with no environment
variables set, :func:`siem_forwarder` reports disabled and nothing is attempted.

The framing is not reimplemented here. :func:`app.audit_export.cef_line` and
:func:`app.audit_export.syslog_line` already produce correctly escaped CEF and
RFC 5424 output and are the single definition of what this deployment means by
those formats. The forwarder calls exactly those functions, and applies the
owning schedule's export template, so the escaping a locally verified file went
through is the escaping the remote copy went through.

Byte-for-byte agreement with the local file is narrower than that, and is worth
being precise about when reading an export as evidence:

* **Syslog transports** send the same framed lines the local file contains. The
  one field that can differ is the hostname: the local render falls back to
  ``socket.gethostname()`` while the forwarder uses ``ZANAQ_SIEM_HOSTNAME``, so
  the two agree only when that is set to the local hostname.
* **HEC** carries structured JSON events, which is the shape HEC expects, not
  framed CEF. :meth:`SiemForwarder._send_hec` therefore posts the row inside a
  sourcetype envelope instead of calling :meth:`frame`. The row content is
  equivalent and the export template does not apply, but a byte comparison
  against a local CEF file is only meaningful for the syslog transports.

Deliberate properties:

* **Secrets come from the environment only.** The HEC token is never stored in
  the database, never returned by an API, and never written to a log line. A
  leaked database backup does not become a leaked SIEM credential.
* **TLS verification is on by default** and can only be disabled by an explicit
  environment variable, because forwarding audit data over an unverified
  connection is how audit trails get tampered with in transit.
* **Everything is bounded.** Rows per request, request body size, and time per
  attempt are all capped, so an unreachable collector cannot exhaust memory or
  wedge the collection loop.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

from app.audit_export import cef_line, syslog_line

logger = logging.getLogger(__name__)

#: Transports understood by ``ZANAQ_SIEM_TARGET``.
TARGETS = ("hec", "syslog_udp", "syslog_tcp")
#: Frames of CEF or syslog text sent in a single request.
MAX_ROWS_PER_REQUEST = 500
#: Ceiling on one request body, so a large batch cannot exhaust memory.
MAX_BODY_BYTES = 4 * 1024 * 1024
#: Seconds allowed for one delivery attempt.
HTTP_TIMEOUT = 10.0
#: Attempts per batch, including the first.
MAX_ATTEMPTS = 3
#: Base seconds for exponential backoff between attempts.
BACKOFF_SECONDS = 0.5


@dataclass
class SiemResult:
    """Outcome of forwarding one batch."""

    sent: bool = False
    rows: int = 0
    attempts: int = 0
    #: True when the failure is a rejection that retrying cannot fix.
    permanent: bool = False
    detail: str = ""

    def as_payload(self) -> dict[str, Any]:
        return {"sent": self.sent, "rows": self.rows, "attempts": self.attempts,
                "permanent": self.permanent, "detail": self.detail}


@dataclass
class SiemConfig:
    """Deployment-level SIEM settings, read from the environment.

    Built by :func:`siem_config` rather than stored, because these values
    include a credential. Nothing here is ever persisted or returned by the API.
    """

    target: str = ""
    url: str = ""
    host: str = ""
    port: int = 0
    token: str = ""
    ca_bundle: str = ""
    verify_tls: bool = True
    sourcetype: str = "zanaq:audit"
    hostname: str = ""
    index: str = ""
    #: ``cef`` or ``syslog``; syslog targets always send syslog framing.
    format: str = "cef"

    @property
    def enabled(self) -> bool:
        return bool(self.target) and (bool(self.url) if self.target == "hec" else bool(self.host))

    def public_status(self) -> dict[str, Any]:
        """Configuration safe to return from an API: no token, no full URL."""
        return {
            "enabled": self.enabled,
            "target": self.target,
            # The path is useful for diagnosing a misconfiguration; the host is
            # not secret, but a query string can carry a token, so it is cut.
            "url_path": self.url.split("?", 1)[0] if self.url else "",
            "host": self.host,
            "port": self.port,
            "format": self.format,
            "verify_tls": self.verify_tls,
            "token_configured": bool(self.token),
        }


def siem_config(environ: Optional[dict[str, str]] = None) -> SiemConfig:
    """Read SIEM settings from the environment, defaulting to disabled."""
    env = os.environ if environ is None else environ

    def _int(name: str, default: int) -> int:
        try:
            return int(env.get(name, "") or default)
        except (TypeError, ValueError):
            return default

    def _bool(name: str, default: bool) -> bool:
        raw = str(env.get(name, "") or "").strip().lower()
        if not raw:
            return default
        return raw in {"1", "true", "yes", "on"}

    target = str(env.get("ZANAQ_SIEM_TARGET", "") or "").strip().lower()
    if target not in TARGETS:
        if target:
            # A typo must not silently disable forwarding: the operator asked
            # for it, so it is reported and surfaced rather than ignored.
            logger.warning("unknown ZANAQ_SIEM_TARGET %r; forwarding disabled", target)
        target = ""
    fmt = str(env.get("ZANAQ_SIEM_FORMAT", "") or "").strip().lower()
    if fmt not in {"cef", "syslog"}:
        fmt = "syslog" if target.startswith("syslog") else "cef"

    return SiemConfig(
        target=target,
        url=str(env.get("ZANAQ_SIEM_URL", "") or "").strip(),
        host=str(env.get("ZANAQ_SIEM_HOST", "") or "").strip(),
        port=_int("ZANAQ_SIEM_PORT", 0),
        token=str(env.get("ZANAQ_SIEM_TOKEN", "") or "").strip(),
        ca_bundle=str(env.get("ZANAQ_SIEM_CA", "") or "").strip(),
        verify_tls=_bool("ZANAQ_SIEM_VERIFY_TLS", True),
        sourcetype=str(env.get("ZANAQ_SIEM_SOURCETYPE", "") or "zanaq:audit").strip(),
        hostname=str(env.get("ZANAQ_SIEM_HOSTNAME", "") or socket.gethostname()).strip(),
        index=str(env.get("ZANAQ_SIEM_INDEX", "") or "").strip(),
        format=fmt,
    )


class SiemForwarder:
    """Sends bounded batches of audit rows to a configured SIEM endpoint."""

    def __init__(self, config: SiemConfig) -> None:
        self.config = config

    # -- framing ---------------------------------------------------------

    def frame(self, row: dict[str, Any], template: str = "") -> str:
        """Render one audit row the way the local export would have.

        ``template`` is the owning schedule's export template, so a templated
        local export forwards the same substituted body rather than a raw row.
        """
        if self.config.format == "syslog":
            return syslog_line(row, hostname=self.config.hostname, template=template)
        return cef_line(row, template)

    def _batches(self, rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        return [rows[i:i + MAX_ROWS_PER_REQUEST]
                for i in range(0, len(rows), MAX_ROWS_PER_REQUEST)]

    # -- transports ------------------------------------------------------

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=self.config.ca_bundle or None)
        if not self.config.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def _send_hec(self, rows: list[dict[str, Any]]) -> None:
        """POST one batch as newline-delimited JSON to an HEC endpoint.

        Used for Splunk, and compatible with any collector that accepts the HEC
        event shape (including QRadar and ArcSight via an HEC-compatible
        receiver).
        """
        lines = [json.dumps({self.config.sourcetype: row}, separators=(",", ":"),
                            default=str) for row in rows]
        body = "\n".join(lines).encode()
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("forward batch exceeds the body ceiling")
        request = urllib.request.Request(self.config.url, data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        if self.config.token:
            request.add_header("Authorization", f"Splunk {self.config.token}")
        if self.config.index:
            request.add_header("X-Splunk-Index", self.config.index)
        if not self.config.url.lower().startswith("https://") and self.config.verify_tls:
            logger.warning("ZANAQ_SIEM_URL is not https; audit rows would travel in clear text")
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT,
                                    context=self._ssl_context() if self.config.url.lower().startswith("https") else None) as response:
            if response.status >= 400:
                raise urllib.error.HTTPError(self.config.url, response.status, "rejected",
                                             response.headers, None)

    def _send_syslog(self, rows: list[dict[str, Any]], template: str = "") -> None:
        """Send one batch as newline-delimited RFC 5424 over UDP or TCP."""
        payload = ("\n".join(self.frame(row, template) for row in rows) + "\n").encode()
        if len(payload) > MAX_BODY_BYTES:
            raise ValueError("forward batch exceeds the body ceiling")
        family = socket.SOCK_DGRAM if self.config.target == "syslog_udp" else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, family) as sock:
            sock.settimeout(HTTP_TIMEOUT)
            if family is socket.SOCK_STREAM:
                context = self._ssl_context() if self.config.verify_tls else None
                sock = context.wrap_socket(sock, server_hostname=self.config.host)
            sock.connect((self.config.host, self.config.port))
            sock.sendall(payload)

    def _attempt(self, rows: list[dict[str, Any]], template: str = "") -> SiemResult:
        result = SiemResult(rows=len(rows), attempts=1)
        try:
            if self.config.target == "hec":
                self._send_hec(rows)
            else:
                self._send_syslog(rows, template)
            result.sent = True
        except urllib.error.HTTPError as error:
            # 4xx is a rejection that will recur identically; only 408 and 429
            # are worth another attempt.
            result.permanent = error.code not in (408, 429)
            result.detail = f"http_{error.code}"
        except urllib.error.URLError as error:
            result.detail = f"unreachable: {type(error.reason).__name__}"
        except (TimeoutError, socket.timeout):
            result.detail = "timeout"
        except ssl.SSLError as error:
            result.permanent = True
            result.detail = f"tls: {type(error).__name__}"
        except ValueError as error:
            result.permanent = True
            result.detail = str(error)
        except OSError as error:
            result.detail = f"{type(error).__name__}: {error}"
        # The token is never included in a detail string.
        return result

    # -- entry point -----------------------------------------------------

    def forward(self, rows: list[dict[str, Any]], template: str = "") -> SiemResult:
        """Forward ``rows``, retrying transient failures with backoff.

        ``template`` is the owning schedule's export template. HEC carries the
        row itself and ignores it; the syslog transports apply it exactly as the
        local file does.

        Returns a result describing the whole batch rather than raising: a
        collector being down must not stop the export schedule or crash the
        collection loop.
        """
        if not self.config.enabled:
            return SiemResult(sent=False, detail="forwarding not configured")
        if not rows:
            return SiemResult(sent=True, rows=0, detail="nothing to forward")

        batches = self._batches(rows)
        sent_batches = 0
        sent_rows = 0
        attempts = 0
        permanent = False
        detail = ""
        for batch in batches:
            result = SiemResult(sent=False, rows=len(batch))
            for attempt in range(MAX_ATTEMPTS):
                result = self._attempt(batch, template)
                attempts += 1
                if result.sent or result.permanent:
                    break
                if attempt + 1 < MAX_ATTEMPTS:
                    time.sleep(BACKOFF_SECONDS * (2 ** attempt))
            if result.sent:
                sent_batches += 1
                sent_rows += len(batch)
            else:
                permanent = permanent or result.permanent
                detail = detail or result.detail

        return SiemResult(
            sent=sent_batches == len(batches),
            rows=sent_rows,
            attempts=attempts,
            permanent=permanent,
            detail=detail or f"{sent_batches}/{len(batches)} batch(es) accepted",
        )


def siem_forwarder(environ: Optional[dict[str, str]] = None) -> SiemForwarder:
    """Build a forwarder from the current environment."""
    return SiemForwarder(siem_config(environ))


__all__ = [
    "BACKOFF_SECONDS",
    "MAX_ATTEMPTS",
    "MAX_BODY_BYTES",
    "MAX_ROWS_PER_REQUEST",
    "TARGETS",
    "SiemConfig",
    "SiemForwarder",
    "SiemResult",
    "siem_config",
    "siem_forwarder",
]