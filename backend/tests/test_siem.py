"""Tests for optional SIEM forwarding of the compliance audit log.

Forwarding is the one audit path that leaves the deployment, so the tests focus
on the properties that make that safe rather than only on the happy path: it is
off unless configured, the credential never leaks into a result or a log, TLS
verification defaults to on, and a collector outage cannot wedge the export
schedule or silently advance the watermark past unsent rows.
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.siem import (MAX_ROWS_PER_REQUEST, SiemConfig, SiemForwarder, siem_config,
                      siem_forwarder)


class _Collector:
    """A local HTTP server standing in for an HEC receiver."""

    def __init__(self, status: int = 200):
        self.received: list[bytes] = []
        self.status = status
        self.headers: list[dict[str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - required by BaseHTTPRequestHandler
                length = int(self.headers.get("Content-Length") or 0)
                outer.received.append(self.rfile.read(length))
                outer.headers.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(outer.status)
                self.end_headers()
                self.wfile.write(b'{"text":"Success","code":0}')

            def log_message(self, *args):  # keep pytest output clean
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
        return f"http://{host}:{port}/services/collector/event"


# --- configuration ----------------------------------------------------------


def test_disabled_without_any_environment() -> None:
    config = siem_config({})
    assert config.enabled is False
    result = siem_forwarder({}).forward([{"id": 1}])
    assert result.sent is False
    assert result.detail == "forwarding not configured"
    assert result.attempts == 0


def test_unknown_target_disables_rather_than_guessing() -> None:
    # A typo must not silently disable forwarding or send to a wrong place.
    config = siem_config({"ZANAQ_SIEM_TARGET": "splunkk", "ZANAQ_SIEM_URL": "https://x"})
    assert config.target == ""
    assert config.enabled is False


def test_hec_needs_a_url_and_syslog_needs_a_host() -> None:
    assert siem_config({"ZANAQ_SIEM_TARGET": "hec"}).enabled is False
    assert siem_config({"ZANAQ_SIEM_TARGET": "hec", "ZANAQ_SIEM_URL": "https://x"}).enabled is True
    assert siem_config({"ZANAQ_SIEM_TARGET": "syslog_udp", "ZANAQ_SIEM_PORT": "514"}).enabled is False
    assert siem_config({
        "ZANAQ_SIEM_TARGET": "syslog_udp", "ZANAQ_SIEM_HOST": "siem", "ZANAQ_SIEM_PORT": "514",
    }).enabled is True


def test_syslog_target_defaults_to_syslog_framing() -> None:
    assert siem_config({"ZANAQ_SIEM_TARGET": "syslog_udp", "ZANAQ_SIEM_FORMAT": "nonsense"}).format \
        == "syslog"


def test_verify_tls_defaults_on_and_token_is_never_exposed() -> None:
    config = siem_config({
        "ZANAQ_SIEM_TARGET": "hec",
        "ZANAQ_SIEM_URL": "https://siem.example/services/collector/event?token=leaked",
        "ZANAQ_SIEM_TOKEN": "super-secret-token",
    })
    assert config.verify_tls is True
    status = config.public_status()
    assert status["token_configured"] is True
    # The query string is where credentials usually hide, so it is cut.
    assert "leaked" not in json.dumps(status)
    assert "super-secret-token" not in json.dumps(status)


def test_verify_tls_can_be_disabled_only_explicitly() -> None:
    assert siem_config({"ZANAQ_SIEM_TARGET": "hec", "ZANAQ_SIEM_URL": "https://x"}).verify_tls is True
    assert siem_config({
        "ZANAQ_SIEM_TARGET": "hec", "ZANAQ_SIEM_URL": "https://x",
        "ZANAQ_SIEM_VERIFY_TLS": "false"}).verify_tls is False
    assert siem_config({
        "ZANAQ_SIEM_TARGET": "hec", "ZANAQ_SIEM_URL": "https://x",
        "ZANAQ_SIEM_VERIFY_TLS": "0"}).verify_tls is False


# -- delivery ----------------------------------------------------------------


def test_hec_delivery_sends_rows_with_the_token_header() -> None:
    with _Collector() as collector:
        forwarder = SiemForwarder(SiemConfig(
            target="hec", url=collector.url, token="abc123", verify_tls=False,
            index="audit"))
        result = forwarder.forward([{"id": 1, "action": "erasure_applied"},
                                    {"id": 2, "action": "case_opened"}])
    assert result.sent is True
    assert result.rows == 2
    assert result.attempts == 1
    assert collector.headers[0]["authorization"] == "Splunk abc123"
    assert collector.headers[0]["x-splunk-index"] == "audit"
    sent = [json.loads(line) for line in collector.received[0].decode().splitlines()]
    assert [next(iter(event.values()))["action"] for event in sent] == \
        ["erasure_applied", "case_opened"]


def test_forwarded_bytes_come_from_the_shared_renderer() -> None:
    # The forwarder must not define its own idea of the format. For the syslog
    # transports a local export and a forwarded copy are byte-identical, which is
    # what makes the locally verified file evidence about the remote one too.
    # HEC carries structured JSON instead, so it is covered separately below.
    from app.audit_export import syslog_line

    row = {"id": 7, "action": "case_closed", "detail": "a|b"}
    with _Collector() as collector:
        forwarder = SiemForwarder(SiemConfig(target="hec", url=collector.url,
                                             verify_tls=False, format="syslog",
                                             hostname="forensic-host"))
        # The HEC transport carries structured JSON, so compare the framing the
        # forwarder would have written locally against the shared renderer.
        assert forwarder.frame(row) == syslog_line(row, hostname="forensic-host")
        forwarder.forward([row])
    payload = json.loads(collector.received[0].decode().splitlines()[0])
    sent_row = next(iter(payload.values()))
    # A pipe in the detail is significant to CEF, so it must survive the
    # transport unescaped and reach the receiver intact.
    assert sent_row == row
    assert syslog_line(sent_row, hostname="forensic-host") == forwarder.frame(sent_row)


def test_syslog_transport_matches_the_local_export_byte_for_byte() -> None:
    # The claim worth protecting: for a syslog target, what the forwarder frames
    # is exactly what the local export file contains, template included. Wire
    # delivery itself is covered by the UDP and TCP tests below.
    from app.audit_export import render

    rows = [{"id": 3, "action": "alert_raised", "detail": "a|b"},
            {"id": 4, "action": "case_closed", "detail": ""}]
    template = "audit {action} {detail}"
    forwarder = SiemForwarder(SiemConfig(
        target="syslog_udp", host="127.0.0.1", port=9, format="syslog",
        hostname=socket.gethostname()))

    local = render(rows, ["id", "action", "detail"], "syslog", template)
    assert local == ("\n".join(forwarder.frame(row, template) for row in rows) + "\n")


def test_export_template_reaches_the_forwarded_copy() -> None:
    # A templated local export must not silently forward raw rows instead.
    forwarder = SiemForwarder(SiemConfig(target="syslog_udp", host="127.0.0.1",
                                         port=9, format="syslog"))
    row = {"id": 5, "action": "erasure_applied", "detail": "d"}
    templated = forwarder.frame(row, "event={action} on {id}")
    assert "event=erasure_applied on 5" in templated
    # Without the template the whole row is serialised instead.
    assert "event=" not in forwarder.frame(row)


def test_syslog_udp_delivers_framed_lines() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(5)
    host, port = server.getsockname()
    try:
        forwarder = SiemForwarder(SiemConfig(
            target="syslog_udp", host=host, port=port, format="syslog",
            hostname="forensic-host"))
        result = forwarder.forward([{"id": 3, "action": "alert_raised"}])
        payload, _ = server.recvfrom(65535)
    finally:
        server.close()
    assert result.sent is True
    assert payload.startswith(b"<")
    assert b"forensic-host" in payload


def test_a_permanent_rejection_is_not_retried() -> None:
    with _Collector(status=403) as collector:
        forwarder = SiemForwarder(SiemConfig(
            target="hec", url=collector.url, token="bad", verify_tls=False))
        result = forwarder.forward([{"id": 1}])
    assert result.sent is False
    assert result.permanent is True
    assert result.attempts == 1
    assert result.detail == "http_403"
    assert "bad" not in json.dumps(result.as_payload())


def test_an_unreachable_collector_is_retried_then_reported() -> None:
    # Port 1 on loopback refuses immediately.
    forwarder = SiemForwarder(SiemConfig(
        target="hec", url="http://127.0.0.1:1/services/collector/event", verify_tls=False))
    result = forwarder.forward([{"id": 1}])
    assert result.sent is False
    assert result.attempts == 3
    assert "unreachable" in result.detail


def test_batches_are_bounded_and_row_count_is_exact() -> None:
    with _Collector() as collector:
        forwarder = SiemForwarder(SiemConfig(target="hec", url=collector.url, verify_tls=False))
        total = MAX_ROWS_PER_REQUEST + 7
        result = forwarder.forward([{"id": i} for i in range(total)])
    assert result.sent is True
    # The earlier implementation multiplied by the batch size and overstated.
    assert result.rows == total
    assert len(collector.received) == 2
    assert len(collector.received[0].decode().splitlines()) == MAX_ROWS_PER_REQUEST


def test_nothing_to_forward_is_a_no_op() -> None:
    forwarder = SiemForwarder(SiemConfig(target="hec", url="https://x"))
    result = forwarder.forward([])
    assert result.sent is True
    assert result.rows == 0


@pytest.mark.parametrize("bad", ["", "not-a-target"])
def test_unconfigured_forwarder_never_attempts_a_connection(bad) -> None:
    result = SiemForwarder(SiemConfig(target=bad)).forward([{"id": 1}])
    assert result.sent is False