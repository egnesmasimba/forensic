import base64

from network_sensor.packets import Packet
from network_sensor.sessions import SessionTable


def packet(timestamp, sequence=1, payload=b"", flags=0, reverse=False):
    source, destination = ("b", "a") if reverse else ("a", "b")
    sport, dport = (80, 1) if reverse else (1, 80)
    return Packet(timestamp, source, destination, sport, dport, "tcp", payload, sequence, flags)


def test_idle_expiry_retains_payload_and_unique_generation():
    table = SessionTable(session_idle_seconds=10)
    table.consume(packet(1, flags=2))
    table.consume(packet(2, 2, b"first"))
    table.consume(packet(12, 100, flags=2))
    table.consume(packet(13, 101, b"second"))
    reports = table.report()
    assert len(table.sessions) == 1
    assert reports[0]["termination_reason"] == "idle"
    assert reports[0]["id"] != reports[1]["id"]
    assert [base64.b64decode(r["directions"][0]["payload_base64"]) for r in reports] == [b"first", b"second"]


def test_half_close_grace_and_reset():
    table = SessionTable(closed_session_grace_seconds=5)
    table.consume(packet(1, flags=2))
    table.consume(packet(2, 2, flags=1))
    table.expire(8)
    assert not table.report()[0]["closed"]
    table.consume(packet(9, 20, b"response", flags=1, reverse=True))
    table.expire(13)
    assert len(table.sessions) == 1
    table.expire(14)
    assert not table.sessions
    assert table.report()[0]["termination_reason"] == "closed"
    table.consume(packet(15, flags=4))
    table.expire(20)
    assert table.report()[-1]["closed"]


def test_duration_rotation_archive_limit_and_old_timestamps():
    table = SessionTable(session_max_seconds=10, session_idle_seconds=100, max_completed_sessions=1)
    table.consume(packet(1, flags=2))
    table.consume(packet(5, 2, b"first"))
    table.consume(packet(11, 7, b"continuation"))
    assert table.report()[0]["termination_reason"] == "duration"
    assert not table.report()[1]["directions"][0]["syn_seen"]
    table.consume(packet(10, 19, b"late"))
    assert table.watermark == 11
    table.finish()
    assert table.completed_omitted == 1
    assert table.retired == 2
    assert len(table.report()) == 1
    assert table.report()[0]["termination_reason"] == "capture_end"
