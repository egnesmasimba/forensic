"""Outbound delivery for playbook email and SMS steps.

A playbook ``email`` or ``sms`` step currently renders a notice template and
writes an in-product :class:`~app.models.Notice` row, so an operator sees the
message in the message centre and nothing more. This module adds the transport
that lets a message actually leave the deployment.

Three properties matter more than the sending itself:

**Sending is opt-in and configured from the environment.** Nothing here reads a
host, token or credential from the database, and with no configuration every
delivery is recorded as ``not_configured`` rather than silently dropped. An
investigation tool that starts emailing alert text to an unknown relay the
moment it is upgraded would be a data leak, not a feature.

**Failures are recorded, never raised.** A playbook run must not abort because
a relay timed out. The in-product notice is already durable, and the delivery
attempt is recorded next to it with its reason.

**Permanent and transient failures are distinguished.** A refused recipient or
an invalid token will fail identically on every retry, so those are recorded as
``bounced`` and abandoned. A timeout or a 5xx is retried with backoff before
being recorded as ``failed``. Retrying a hard rejection just delays the alert.

The transport is deliberately a plain SMTP conversation and a plain HTTP POST.
Neither is an integration with a vendor's product: SOAR and ticketing
connectors are a separate concern, and the webhook trigger remains inbound-only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import smtplib
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Callable, Mapping, Optional

logger = logging.getLogger(__name__)

#: Attempts per delivery, including the first.
MAX_ATTEMPTS = 3
#: Base seconds for the exponential backoff between attempts.
BACKOFF_SECONDS = 0.5
#: Ceiling on a single HTTP request, so a hung gateway cannot stall automation.
HTTP_TIMEOUT = 10.0
#: Statuses a delivery attempt can end in.
STATUSES = ("sent", "bounced", "failed", "not_configured", "disabled")


@dataclass(frozen=True)
class DeliveryResult:
    """Outcome of one delivery attempt."""

    status: str
    detail: str = ""
    attempts: int = 1
    #: Set when the failure is a permanent rejection that retrying cannot fix.
    permanent: bool = False

    def as_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "detail": self.detail[:300],
            "attempts": self.attempts,
            "permanent": self.permanent,
        }


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


class SmtpChannel:
    """Plain SMTP delivery with STARTTLS and credential auth.

    Configured entirely from the environment so a credential never reaches the
    database or a configuration file that gets committed::

        ZANAQ_SMTP_HOST, ZANAQ_SMTP_PORT, ZANAQ_SMTP_FROM
        ZANAQ_SMTP_USER, ZANAQ_SMTP_PASS, ZANAQ_SMTP_STARTTLS, ZANAQ_SMTP_CA
    """

    name = "email"

    def __init__(self, environ: Optional[Mapping[str, str]] = None) -> None:
        get = environ.get if environ is not None else os.environ.get
        self.host = (get("ZANAQ_SMTP_HOST") or "").strip()
        self.port = int((get("ZANAQ_SMTP_PORT") or "").strip() or 587)
        self.sender = (get("ZANAQ_SMTP_FROM") or "").strip()
        self.user = (get("ZANAQ_SMTP_USER") or "").strip()
        self.password = get("ZANAQ_SMTP_PASS") or ""
        self.starttls = (get("ZANAQ_SMTP_STARTTLS") or "1").strip() not in {"0", "false", "no"}
        self.ca_bundle = (get("ZANAQ_SMTP_CA") or "").strip()

    @property
    def configured(self) -> bool:
        return bool(self.host and self.sender)

    def _message(self, recipient: str, subject: str, body: str) -> EmailMessage:
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = recipient
        message["Subject"] = subject[:160]
        message.set_content(body)
        return message

    def send(self, recipient: str, subject: str, body: str) -> DeliveryResult:
        """Deliver one message, reporting permanent rejections distinctly."""
        if not recipient or "@" not in recipient:
            return DeliveryResult("bounced", f"invalid recipient {recipient!r}", permanent=True)
        try:
            with smtplib.SMTP(self.host, self.port, timeout=HTTP_TIMEOUT) as client:
                if self.starttls:
                    client.starttls(context=self._context())
                if self.user:
                    client.login(self.user, self.password)
                client.send_message(self._message(recipient, subject, body))
        except smtplib.SMTPRecipientsRefused as error:
            # 5xx at RCPT: the mailbox is gone or was refused. Retrying cannot
            # change that, and hammering a refused address is abusive.
            return DeliveryResult("bounced", f"recipient refused: {error.recipients}", permanent=True)
        except smtplib.SMTPResponseException as error:
            code = error.smtp_code
            if 500 <= code < 600:
                return DeliveryResult("bounced", f"permanent SMTP {code}", permanent=True)
            return DeliveryResult("failed", f"transient SMTP {code}")
        except smtplib.SMTPAuthenticationError as error:
            return DeliveryResult("bounced", f"SMTP auth rejected: {error.smtp_code}", permanent=True)
        except (smtplib.SMTPException, OSError) as error:
            return DeliveryResult("failed", f"{type(error).__name__}: {error}")
        return DeliveryResult("sent")

    def _context(self) -> Any:
        if not self.ca_bundle:
            return None
        import ssl

        return ssl.create_default_context(cafile=self.ca_bundle)


class SmsChannel:
    """HTTP POST delivery to an SMS gateway.

    A generic JSON POST rather than a vendor SDK, so an existing gateway can be
    used without shipping a client library for it::

        ZANAQ_SMS_URL, ZANAQ_SMS_TOKEN, ZANAQ_SMS_FROM
    """

    name = "sms"

    def __init__(self, environ: Optional[Mapping[str, str]] = None) -> None:
        get = environ.get if environ is not None else os.environ.get
        self.url = (get("ZANAQ_SMS_URL") or "").strip()
        self.token = (get("ZANAQ_SMS_TOKEN") or "").strip()
        self.sender = (get("ZANAQ_SMS_FROM") or "").strip()

    @property
    def configured(self) -> bool:
        return bool(self.url)

    def send(self, recipient: str, subject: str, body: str) -> DeliveryResult:
        if not recipient:
            return DeliveryResult("bounced", "no recipient", permanent=True)
        # Subject and body are combined so a gateway that renders one field
        # still shows enough to identify the alert.
        text = f"{subject}\n{body}".strip() if subject else body
        payload = json.dumps({
            "to": recipient,
            "from": self.sender or None,
            "text": text[:1600],
        }).encode()
        request = urllib.request.Request(self.url, data=payload, method="POST")
        request.add_header("Content-Type", "application/json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                if 200 <= response.status < 300:
                    return DeliveryResult("sent")
                return DeliveryResult("failed", f"HTTP {response.status}")
        except urllib.error.HTTPError as error:
            if 400 <= error.code < 500 and error.code not in {408, 429}:
                # Rejected input or an invalid token: the same request will be
                # rejected again, so stop.
                return DeliveryResult("bounced", f"HTTP {error.code}", permanent=True)
            return DeliveryResult("failed", f"HTTP {error.code}")
        except (urllib.error.URLError, OSError, ValueError) as error:
            return DeliveryResult("failed", f"{type(error).__name__}: {error}")


def _with_retries(channel: Any, recipient: str, subject: str, body: str,
                  sleeper: Callable[[float], None]) -> DeliveryResult:
    """Retry transient failures with exponential backoff; stop on rejection."""
    result = DeliveryResult("failed", "not attempted")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        result = channel.send(recipient, subject, body)
        if result.status == "sent" or result.permanent or attempt == MAX_ATTEMPTS:
            return DeliveryResult(result.status, result.detail, attempt, result.permanent)
        logger.warning("delivery attempt %d/%d failed (%s); retrying",
                       attempt, MAX_ATTEMPTS, result.detail)
        sleeper(BACKOFF_SECONDS * (2 ** (attempt - 1)))
    return result


class DeliveryService:
    """Resolves a channel name to a configured transport and delivers."""

    def __init__(self, environ: Optional[Mapping[str, str]] = None,
                 sleeper: Callable[[float], None] = time.sleep) -> None:
        self.sleeper = sleeper
        self._channels = {
            "email": SmtpChannel(environ),
            "sms": SmsChannel(environ),
        }

    def configured_channels(self) -> list[str]:
        return sorted(name for name, channel in self._channels.items() if channel.configured)

    def status(self) -> dict[str, Any]:
        """Describe transport readiness without exposing any credential."""
        return {
            name: {
                "configured": channel.configured,
                "target": getattr(channel, "host", None) or getattr(channel, "url", None) or "",
            }
            for name, channel in sorted(self._channels.items())
        }

    def deliver(self, channel_name: str, recipient: str, subject: str, body: str) -> DeliveryResult:
        """Deliver one message, or explain why it could not be sent."""
        channel = self._channels.get(channel_name)
        if channel is None:
            return DeliveryResult("disabled", f"unknown channel {channel_name!r}", permanent=True)
        if not channel.configured:
            # Recorded rather than dropped: the reader needs to know the message
            # exists but never left the deployment.
            return DeliveryResult("not_configured",
                                  f"no transport configured for {channel_name}",
                                  permanent=True)
        return _with_retries(channel, recipient, subject, body, self.sleeper)


def message_id(alert_id: Optional[int], channel: str, subject: str) -> str:
    """Stable idempotency key for one alert/channel delivery."""
    seed = f"{alert_id}|{channel}|{subject}".encode()
    return hashlib.sha256(seed).hexdigest()[:32]


__all__ = [
    "BACKOFF_SECONDS",
    "DeliveryResult",
    "DeliveryService",
    "MAX_ATTEMPTS",
    "STATUSES",
    "SmtpChannel",
    "SmsChannel",
    "message_id",
]