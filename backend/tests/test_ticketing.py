"""Tests for external IT service management ticket pushing.

These cover the vendor response shapes, the deliberate exclusions (Remedy, and
detail egress by default), and the failure classification, because an
integration that looks wired up but silently never succeeds is worse than one
that reports why it did not.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.ticketing import (STATUS_MAP, TicketConfig, TicketConnector, ticket_config,
                           ticket_connector)


class _Receiver:
    """Local HTTP server that records requests and replies with a chosen body."""

    def __init__(self, response: dict | None = None, status: int = 200):
        self.requests: list[dict] = []
        self.response = response if response is not None else {}
        self.status = status
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                outer.requests.append({
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": json.loads(raw.decode()) if raw else None,
                })
                payload = json.dumps(outer.response).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_POST = _handle
            do_PUT = _handle
            do_GET = _handle

            def log_message(self, *args):
                return

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}/api"


class _Ticket:
    """Stand-in for the local Ticket row."""

    def __init__(self, title="Exfiltration detected on FIN-WS-01", **kw):
        self.id = 42
        self.title = title
        self.status = "open"
        self.external_id = ""
        for key, value in kw.items():
            setattr(self, key, value)


# --- configuration ----------------------------------------------------------


def test_disabled_without_configuration() -> None:
    assert ticket_config({}).enabled is False
    result = ticket_connector({}).push(_Ticket())
    assert result.pushed is False
    assert result.detail == "ticketing not configured"


def test_remedy_is_refused_rather_than_faked() -> None:
    # Remedy has no stable public REST create endpoint. Inventing a URL would
    # give an operator a connector that never works, so it is refused loudly.
    config = ticket_config({"ZANAQ_TICKET_SYSTEM": "remedy", "ZANAQ_TICKET_URL": "https://x"})
    assert config.enabled is False
    assert config.target == ""


def test_unknown_target_disables() -> None:
    assert ticket_config({"ZANAQ_TICKET_SYSTEM": "freshdesk"}).target == ""


def test_public_status_never_exposes_credentials() -> None:
    config = ticket_config({
        "ZANAQ_TICKET_SYSTEM": "jira", "ZANAQ_TICKET_URL": "https://jira.example/rest",
        "ZANAQ_TICKET_USER": "alice@example.com", "ZANAQ_TICKET_TOKEN": "api-token-secret",
    })
    status = config.public_status()
    assert status["enabled"] is True
    assert "api-token-secret" not in json.dumps(status)
    assert "alice@example.com" not in json.dumps(status)


def test_verify_tls_defaults_on() -> None:
    config = ticket_config({"ZANAQ_TICKET_SYSTEM": "jira", "ZANAQ_TICKET_URL": "https://x"})
    assert config.verify_tls is True
    assert ticket_config({
        "ZANAQ_TICKET_SYSTEM": "jira", "ZANAQ_TICKET_URL": "https://x",
        "ZANAQ_TICKET_VERIFY_TLS": "false"}).verify_tls is False


# -- detail egress ----------------------------------------------------------


def test_alert_detail_is_not_sent_by_default() -> None:
    # Pushing an alert body into third-party SaaS is an egress decision, so it
    # must be explicit rather than a side effect of creating a ticket.
    with _Receiver({"result": {"sys_id": "abc", "number": "INC0001"}}) as receiver:
        connector = TicketConnector(TicketConfig(
            target="servicenow", url=receiver.url, verify_tls=False))
        connector.push(_Ticket(), detail="Suspicious PowerShell on FIN-WS-01")
    sent = json.dumps(receiver.requests[0]["body"])
    assert "Suspicious PowerShell" not in sent


def test_detail_is_sent_only_when_opted_in() -> None:
    with _Receiver({"result": {"sys_id": "abc", "number": "INC0001"}}) as receiver:
        connector = TicketConnector(TicketConfig(
            target="servicenow", url=receiver.url, verify_tls=False, include_detail=True))
        connector.push(_Ticket(), detail="Suspicious PowerShell on FIN-WS-01")
    assert "Suspicious PowerShell" in json.dumps(receiver.requests[0]["body"])


def test_oversized_fields_are_clipped() -> None:
    connector = TicketConnector(TicketConfig(target="webhook", url="https://bridge/x"))
    payload = connector.build_payload(_Ticket(), detail="x" * 100000)
    assert len(payload["detail"]) <= 2000


# -- vendor shapes -----------------------------------------------------------


def test_servicenow_create_posts_an_incident() -> None:
    with _Receiver({"result": {"sys_id": "sys1", "number": "INC0010001"}}) as receiver:
        connector = TicketConnector(TicketConfig(
            target="servicenow", url=receiver.url, token="sn-token", verify_tls=False))
        result = connector.push(_Ticket())
    assert result.pushed is True
    assert result.external_id == "sys1"
    assert result.external_url == "INC0010001"
    request = receiver.requests[0]
    assert request["method"] == "POST"
    assert request["path"] == "/api/api/now/table/incident"
    assert request["headers"]["authorization"] == "Bearer sn-token"


def test_servicenow_uses_basic_auth_without_a_bearer_token() -> None:
    with _Receiver({"result": {"sys_id": "sys1"}}) as receiver:
        connector = TicketConnector(TicketConfig(
            target="servicenow", url=receiver.url, user="svc", token="pw",
            verify_tls=False))
        connector.push(_Ticket())
    assert receiver.requests[0]["headers"]["authorization"].startswith("Basic ")


def test_servicenow_status_update_writes_state() -> None:
    with _Receiver({"result": {"sys_id": "sys1"}}) as receiver:
        connector = TicketConnector(TicketConfig(
            target="servicenow", url=receiver.url, verify_tls=False))
        result = connector.set_status(_Ticket(external_id="sys1"), "closed")
    assert result.pushed is True
    assert receiver.requests[0]["body"] == {"state": STATUS_MAP["servicenow"]["closed"]}


def test_jira_create_posts_an_issue() -> None:
    with _Receiver({"key": "ZAN-17", "self": "https://jira/browse/ZAN-17"}) as receiver:
        connector = TicketConnector(TicketConfig(
            target="jira", url=receiver.url, project="ZAN", queue="ir-team",
            user="alice@example.com", token="api-token", verify_tls=False))
        result = connector.push(_Ticket())
    assert result.pushed is True
    assert result.external_id == "ZAN-17"
    fields = receiver.requests[0]["body"]["fields"]
    assert fields["project"]["key"] == "ZAN"
    assert "ir-team" in fields["labels"]
    assert "ZANAQ ticket #42" in fields["summary"]


def test_jira_transition_is_discovered_not_guessed() -> None:
    # Jira rejects a status name; it needs a transition id, and the ids differ
    # per workflow. The connector must look it up rather than assume.
    with _Receiver({"transitions": [
        {"id": "11", "to": {"name": "Done"}},
        {"id": "21", "to": {"name": "In Progress"}},
    ]}) as receiver:
        connector = TicketConnector(TicketConfig(
            target="jira", url=receiver.url, project="ZAN", verify_tls=False))
        result = connector.set_status(_Ticket(external_id="ZAN-17"), "closed")
    assert result.pushed is True
    assert receiver.requests[0]["method"] == "GET"
    assert receiver.requests[1]["body"] == {"transition": {"id": "11"}}


def test_jira_reports_an_unavailable_transition_permanently() -> None:
    with _Receiver({"transitions": [{"id": "21", "to": {"name": "In Progress"}}]}) as receiver:
        connector = TicketConnector(TicketConfig(
            target="jira", url=receiver.url, verify_tls=False))
        result = connector.set_status(_Ticket(external_id="ZAN-17"), "closed")
    assert result.pushed is False
    assert result.permanent is True
    assert "In Progress" in result.detail
    # A missing transition will never appear on retry, so it must not be.
    assert len(receiver.requests) == 1


def test_jira_status_change_without_a_key_is_refused() -> None:
    connector = TicketConnector(TicketConfig(target="jira", url="https://jira", verify_tls=False))
    result = connector.set_status(_Ticket(), "closed")
    assert result.pushed is False
    assert result.permanent is True
    assert "external Jira key" in result.detail


def test_webhook_bridge_sends_status_and_reference() -> None:
    with _Receiver({"id": "BR-1", "url": "https://bridge/tickets/BR-1"}) as receiver:
        connector = TicketConnector(TicketConfig(
            target="webhook", url=receiver.url, verify_tls=False))
        result = connector.push(_Ticket())
    assert result.external_id == "BR-1"
    body = receiver.requests[0]["body"]
    assert body["status"] == "open"
    assert body["reference"] == "ZANAQ ticket #42"


# -- failure handling -------------------------------------------------------


def test_a_rejection_is_permanent_and_not_retried() -> None:
    with _Receiver({"error": "nope"}, status=403) as receiver:
        connector = TicketConnector(TicketConfig(
            target="servicenow", url=receiver.url, verify_tls=False))
        result = connector.push(_Ticket())
    assert result.pushed is False
    assert result.permanent is True
    assert result.attempts == 1
    assert len(receiver.requests) == 1


def test_a_server_error_is_retried() -> None:
    with _Receiver({"error": "later"}, status=503) as receiver:
        connector = TicketConnector(TicketConfig(
            target="servicenow", url=receiver.url, verify_tls=False))
        result = connector.push(_Ticket())
    assert result.pushed is False
    assert result.permanent is False
    assert len(receiver.requests) == 3


def test_an_unreachable_system_reports_without_raising() -> None:
    connector = TicketConnector(TicketConfig(
        target="servicenow", url="http://127.0.0.1:1/api", verify_tls=False))
    result = connector.push(_Ticket())
    assert result.pushed is False
    assert "unreachable" in result.detail


def test_credentials_never_appear_in_a_failure_detail() -> None:
    connector = TicketConnector(TicketConfig(
        target="jira", url="http://127.0.0.1:1/rest", user="alice@example.com",
        token="api-token-secret", verify_tls=False))
    result = connector.push(_Ticket())
    assert "api-token-secret" not in json.dumps(result.as_payload())
    assert "alice@example.com" not in json.dumps(result.as_payload())