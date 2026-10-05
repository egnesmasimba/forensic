"""Creating and updating tickets in an external IT service management system.

The in-product :class:`app.models.Ticket` records that work was raised. This
module pushes that record to whatever the deployment already uses to track
incidents, so an investigator does not have to re-key it into a second system.

Scope, and why it is narrow:

* **ServiceNow** and **Jira** are implemented against their documented REST
  create endpoints.
* **Remedy is not implemented.** BMC Remedy's incident creation needs an ARCM
  form or an ITSM bridge, and there is no stable public REST endpoint to code
  against. Inventing a plausible URL would produce a connector that silently
  never works, so Remedy deployments are expected to front it with a webhook
  bridge and use the ``webhook`` target instead.
* A **generic ``webhook``** target covers any other ITSM, including a Remedy
  bridge, without pretending to know its API.

Two properties matter more than the endpoint details:

* **Credentials come from the environment only.** They are never stored in the
  database, so a database backup does not hand over the ITSM account.
* **Only what was asked for leaves the deployment.** By default the payload is
  the ticket title and internal reference. Alert detail, case notes, and
  evidence are *not* included unless ``ZANAQ_TICKET_INCLUDE_DETAIL`` is set,
  because pushing an alert body into a third-party SaaS ticket is a data
  egress decision, not an integration detail.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

#: Connector targets understood by ``ZANAQ_TICKET_SYSTEM``.
TARGETS = ("servicenow", "jira", "webhook")
#: Seconds allowed for one create/update attempt.
HTTP_TIMEOUT = 10.0
#: Attempts per operation, including the first.
MAX_ATTEMPTS = 3
#: Base seconds for exponential backoff between attempts.
BACKOFF_SECONDS = 0.5
#: Ceiling on any single field sent to an external system.
MAX_FIELD_CHARS = 2000
#: Ceiling on the assembled request body.
MAX_BODY_BYTES = 256 * 1024

#: Local status -> external status, per target.
STATUS_MAP = {
    "servicenow": {"open": "1", "pending": "2", "closed": "7"},
    "jira": {"open": "Open", "pending": "In Progress", "closed": "Done"},
    "webhook": {"open": "open", "pending": "pending", "closed": "closed"},
}


@dataclass
class TicketResult:
    """Outcome of one push to the external system."""

    pushed: bool = False
    external_id: str = ""
    external_url: str = ""
    status: str = ""
    attempts: int = 0
    #: True when the failure is a rejection that retrying cannot fix.
    permanent: bool = False
    detail: str = ""
    #: Decoded JSON response, used by callers that must read the body (the
    #: Jira transition lookup). Never logged, since it echoes what was sent.
    parsed: dict[str, Any] | None = None

    def as_payload(self) -> dict[str, Any]:
        return {"pushed": self.pushed, "external_id": self.external_id,
                "external_url": self.external_url, "status": self.status,
                "attempts": self.attempts, "permanent": self.permanent,
                "detail": self.detail}


@dataclass
class TicketConfig:
    """Deployment-level ITSM settings, read from the environment."""

    target: str = ""
    url: str = ""
    user: str = ""
    token: str = ""
    project: str = ""
    queue: str = ""
    priority: str = "3"
    verify_tls: bool = True
    include_detail: bool = False

    @property
    def enabled(self) -> bool:
        return bool(self.target) and bool(self.url)

    def public_status(self) -> dict[str, Any]:
        """Configuration safe to return from an API: never the credentials."""
        parsed = urllib.parse.urlsplit(self.url)
        return {
            "enabled": self.enabled,
            "target": self.target,
            "host": parsed.netloc,
            "path": parsed.path,
            "project": self.project,
            "queue": self.queue,
            "verify_tls": self.verify_tls,
            "include_detail": self.include_detail,
            "credentials_configured": bool(self.user or self.token),
        }


def ticket_config(environ: Optional[dict[str, str]] = None) -> TicketConfig:
    """Read ITSM settings from the environment, defaulting to disabled."""
    env = os.environ if environ is None else environ

    def _bool(name: str, default: bool) -> bool:
        raw = str(env.get(name, "") or "").strip().lower()
        if not raw:
            return default
        return raw in {"1", "true", "yes", "on"}

    target = str(env.get("ZANAQ_TICKET_SYSTEM", "") or "").strip().lower()
    if target == "remedy":
        # Named explicitly rather than silently ignored, so an operator finds
        # out why nothing is being pushed.
        logger.warning("ZANAQ_TICKET_SYSTEM=remedy has no supported REST create "
                       "endpoint; use the webhook target with an ARCM bridge")
        target = ""
    elif target not in TARGETS:
        if target:
            logger.warning("unknown ZANAQ_TICKET_SYSTEM %r; ticket pushing disabled", target)
        target = ""

    return TicketConfig(
        target=target,
        url=str(env.get("ZANAQ_TICKET_URL", "") or "").strip(),
        user=str(env.get("ZANAQ_TICKET_USER", "") or "").strip(),
        token=str(env.get("ZANAQ_TICKET_TOKEN", "") or "").strip(),
        project=str(env.get("ZANAQ_TICKET_PROJECT", "") or "").strip(),
        queue=str(env.get("ZANAQ_TICKET_QUEUE", "") or "").strip(),
        priority=str(env.get("ZANAQ_TICKET_PRIORITY", "") or "3").strip(),
        verify_tls=_bool("ZANAQ_TICKET_VERIFY_TLS", True),
        include_detail=_bool("ZANAQ_TICKET_INCLUDE_DETAIL", False),
    )


def _clip(value: Any) -> str:
    """Bound a field so a large detail cannot blow up an external request."""
    text = "" if value is None else str(value)
    return text[:MAX_FIELD_CHARS]


class TicketConnector:
    """Pushes a local ticket to the configured external system."""

    def __init__(self, config: TicketConfig) -> None:
        self.config = config

    # -- payloads --------------------------------------------------------

    def _auth_header(self) -> dict[str, str]:
        if self.config.target == "servicenow":
            # ServiceNow's Table API takes either Basic (user + password or API
            # key) or an OAuth bearer token. Supplying both a user and a token
            # means the token is that user's secret, so it is Basic; a token on
            # its own is an OAuth access token.
            if self.config.user and self.config.token:
                raw = f"{self.config.user}:{self.config.token}".encode()
                return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
            if self.config.token:
                return {"Authorization": f"Bearer {self.config.token}"}
            return {}
        if self.config.user and self.config.token:
            raw = f"{self.config.user}:{self.config.token}".encode()
            return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
        return {}

    def build_payload(self, ticket: Any, detail: str = "") -> dict[str, Any]:
        """Assemble the external representation of ``ticket``.

        ``detail`` is only used when the deployment opted in; see the module
        docstring for why it is off by default.
        """
        title = _clip(getattr(ticket, "title", ""))
        reference = f"ZANAQ ticket #{getattr(ticket, 'id', '')}"
        summary = f"{title} ({reference})"
        # Detail is opt-in egress, never implicit.
        body = _clip(detail) if (self.config.include_detail and detail) else ""

        if self.config.target == "servicenow":
            short_description = summary[:100]
            payload: dict[str, Any] = {
                "short_description": short_description,
                "description": body or short_description,
                "priority": self.config.priority,
                "correlation_id": reference,
            }
            if self.config.queue:
                payload["assignment_group"] = self.config.queue
            return payload

        if self.config.target == "jira":
            # Atlassian document types as a project description with a label
            # rather than free text, so the reference stays queryable.
            labels = ["zanaq"]
            if self.config.queue:
                labels.append(self.config.queue)
            return {
                "fields": {
                    "project": {"key": self.config.project or "ZAN"},
                    "summary": summary[:255],
                    "description": body or summary,
                    "issuetype": {"name": "Task"},
                    "labels": labels,
                }
            }

        return {"title": summary, "status": STATUS_MAP["webhook"].get(
            getattr(ticket, "status", "open"), "open"),
            "reference": reference, "detail": body, "url": self.config.url}

    def build_update_payload(self, status: str) -> Any:
        mapped = STATUS_MAP[self.config.target].get(status, status)
        if self.config.target == "servicenow":
            return {"state": mapped}
        if self.config.target == "jira":
            return {"fields": {"resolution": {"name": "Done"}} if mapped == "Done"
                    else {"status": None}}
        return {"status": mapped}

    # -- transport -------------------------------------------------------

    def _request(self, method: str, body: dict[str, Any]) -> tuple[int, dict[str, Any], str]:
        encoded = json.dumps(body, default=str).encode()
        if len(encoded) > MAX_BODY_BYTES:
            raise ValueError("ticket payload exceeds the body ceiling")
        url = self.config.url
        if self.config.target == "servicenow" and method in {"POST", "PUT"}:
            url = url.rstrip("/") + "/api/now/table/incident"
        data = None if method == "GET" else encoded
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        for key, value in self._auth_header().items():
            request.add_header(key, value)
        context = None
        if url.lower().startswith("https"):
            context = ssl.create_default_context()
            if not self.config.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT, context=context) as response:
            raw = response.read(MAX_BODY_BYTES)
            try:
                parsed = json.loads(raw.decode() or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = {}
            return response.status, parsed if isinstance(parsed, dict) else {}, raw.decode(
                errors="replace")[:200]

    def _interpret(self, status: int, parsed: dict[str, Any], raw: str) -> TicketResult:
        """Read the vendor-specific response shape into a common result."""
        if self.config.target == "servicenow":
            result = parsed.get("result") or {}
            return TicketResult(pushed=True, external_id=_clip(result.get("sys_id")),
                                external_url=_clip(result.get("number")),
                                status=_clip(result.get("state")))
        if self.config.target == "jira":
            return TicketResult(pushed=True, external_id=_clip(parsed.get("key")),
                                external_url=_clip(parsed.get("self")), status="open")
        return TicketResult(pushed=True, external_id=_clip(parsed.get("id")),
                            external_url=_clip(parsed.get("url")), status="open")

    def _attempt(self, method: str, body: dict[str, Any]) -> TicketResult:
        result = TicketResult(attempts=1)
        try:
            status, parsed, raw = self._request(method, body)
        except urllib.error.HTTPError as error:
            result.permanent = error.code not in (408, 429, 500, 502, 503, 504)
            result.detail = f"http_{error.code}"
        except urllib.error.URLError as error:
            result.detail = f"unreachable: {type(error.reason).__name__}"
        except (TimeoutError, OSError) as error:
            result.detail = f"{type(error).__name__}: {error}"[:120]
        except ValueError as error:
            result.permanent = True
            result.detail = _clip(error)
        else:
            if 200 <= status < 300:
                result = self._interpret(status, parsed, raw)
                result.parsed = parsed or None
            else:
                result.detail = f"http_{status}"
            result.attempts = 1
        return result

    # -- entry points ----------------------------------------------------

    def push(self, ticket: Any, detail: str = "") -> TicketResult:
        """Create the external ticket, retrying only transient failures."""
        if not self.config.enabled:
            return TicketResult(pushed=False, detail="ticketing not configured")
        result = self._attempt("POST", self.build_payload(ticket, detail))
        for attempt in range(1, MAX_ATTEMPTS):
            if result.pushed or result.permanent:
                break
            time.sleep(BACKOFF_SECONDS * (2 ** (attempt - 1)))
            result = self._attempt("POST", self.build_payload(ticket, detail))
        return result

    def set_status(self, ticket: Any, status: str) -> TicketResult:
        """Update the external ticket's status, retrying transient failures.

        Each target needs a different mechanism, and pretending otherwise is how
        an integration silently fails: ServiceNow writes the ``state`` field,
        Jira requires a named transition to be discovered and then posted, and
        the webhook bridge takes whatever it was told.
        """
        if not self.config.enabled:
            return TicketResult(pushed=False, detail="ticketing not configured")

        if self.config.target == "jira":
            return self._jira_transition(ticket, status)

        body = self.build_update_payload(status)
        result = self._attempt("PUT", body)
        for attempt in range(1, MAX_ATTEMPTS):
            if result.pushed or result.permanent:
                break
            time.sleep(BACKOFF_SECONDS * (2 ** (attempt - 1)))
            result = self._attempt("PUT", body)
        result.status = status
        return result

    def _jira_transition(self, ticket: Any, status: str) -> TicketResult:
        """Post a Jira transition, discovering its id rather than assuming it.

        Jira does not accept a status name: it accepts a transition id, and the
        ids are per-workflow. Guessing one would produce a 400 on every update.
        """
        key = _clip(getattr(ticket, "external_id", ""))
        if not key:
            return TicketResult(pushed=False, permanent=True,
                                detail="ticket has no external Jira key")
        desired = STATUS_MAP["jira"].get(status, status)
        base = self.config.url.rstrip("/")
        url = f"{base}/{urllib.parse.quote(key)}/transitions"
        original = self.config.url
        self.config.url = url
        try:
            listing = self._attempt("GET", {})
            if not listing.pushed:
                listing.status = status
                return listing
            available = (listing.parsed or {}).get("transitions") or []
            match = next((t for t in available
                          if (t.get("to", {}).get("name") or t.get("name")) == desired), None)
            if match is None:
                names = ", ".join(sorted(
                    str(t.get("to", {}).get("name") or t.get("name")) for t in available))
                return TicketResult(pushed=False, permanent=True, status=status,
                                    detail=f"no Jira transition to {desired!r}; available: {names}")
            result = self._attempt("POST", {"transition": {"id": match["id"]}})
        finally:
            self.config.url = original
        result.status = status
        return result


def ticket_connector(environ: Optional[dict[str, str]] = None) -> TicketConnector:
    """Build a connector from the current environment."""
    return TicketConnector(ticket_config(environ))


__all__ = [
    "BACKOFF_SECONDS",
    "MAX_ATTEMPTS",
    "MAX_BODY_BYTES",
    "MAX_FIELD_CHARS",
    "STATUS_MAP",
    "TARGETS",
    "TicketConfig",
    "TicketConnector",
    "TicketResult",
    "ticket_config",
    "ticket_connector",
]