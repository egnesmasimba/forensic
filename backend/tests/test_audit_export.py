from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.audit_export import (
    cef_line,
    render,
    run_due_exports,
    syslog_line,
    validate_filename,
    validate_template,
    write_export,
)
from app.models import AuditExportSchedule, utcnow
from app.privacy_models import PrivacyAudit
from test_api import make_client

ROW = {
    "id": 7,
    "actor": "alice|admin",
    "action": "erasure_applied",
    "detail": '{"a":1}\nsecond line',
    "created_at": "2026-10-04T09:00:00+00:00",
}


# --- framing ---------------------------------------------------------------


def test_cef_escapes_pipes_and_newlines() -> None:
    line = cef_line(ROW)
    header, _, extension = line.partition("|action=")
    # The header has exactly the seven fixed CEF fields, so a pipe inside the
    # actor name cannot shift the extension boundary.
    assert header.count("|") == 6
    assert header.startswith("CEF:0|Zanaq|ForensicCenter|1|erasure_applied|erasure_applied|8")
    # Per the CEF specification only the header escapes a pipe; an extension
    # value escapes backslash, equals and newlines, and escaping the pipe here
    # too would corrupt a spec-compliant parser.
    assert "actor=alice|admin" in extension
    assert "detail={\"a\":1}\\nsecond line" in extension
    # A newline must not forge a second record.
    assert "\n" not in line


def test_cef_severity_reflects_the_action() -> None:
    assert cef_line(ROW).split("|")[6] == "8"
    mild = cef_line({**ROW, "action": "notice_published"})
    assert mild.split("|")[6] == "3"
    # Anything not recognised stays a warning rather than defaulting to zero.
    assert 0 < int(mild.split("|")[6]) <= 10


def test_syslog_flattens_newlines_and_sets_priority() -> None:
    line = syslog_line(ROW, hostname="host1")
    assert line.startswith("<135>1 ")
    assert "host1" in line
    assert "\n" not in line
    # A forged newline would create an extra syslog record downstream.
    assert line.count("second line") == 1


def test_syslog_severity_is_within_the_valid_range() -> None:
    for action in ("erasure_applied", "raw_access", "notice_published", "whatever"):
        pri = int(syslog_line({**ROW, "action": action}).split(">")[0][1:])
        assert 0 <= pri <= 191


def test_template_substitutes_and_escapes() -> None:
    line = cef_line(ROW, template="actor={actor} did {action}")
    # The literal "actor=" inside the template is escaped, or the collector
    # would read it as a second extension key rather than message text.
    assert "msg=actor\\=alice|admin did erasure_applied" in line
    assert "\n" not in line


def test_unknown_template_fields_are_refused() -> None:
    with pytest.raises(ValueError):
        validate_template("{nope}", ROW)
    # Positional and attribute access are not templates this accepts.
    with pytest.raises(ValueError):
        validate_template("{0}", ROW)
    with pytest.raises(ValueError):
        validate_template("{actor.__class__}", ROW)


def test_valid_template_is_returned_unchanged() -> None:
    assert validate_template("{actor}: {action}", ROW) == "{actor}: {action}"
    assert validate_template("   ", ROW) == ""


def test_render_supports_each_format() -> None:
    assert render([ROW], list(ROW), "csv").splitlines()[0].startswith("id,actor")
    assert json.loads(render([ROW], list(ROW), "jsonl"))["action"] == "erasure_applied"
    assert render([ROW], list(ROW), "cef").startswith("CEF:0|Zanaq|")
    assert render([ROW], list(ROW), "syslog").startswith("<")
    with pytest.raises(ValueError):
        render([ROW], list(ROW), "yaml")


# --- writing ---------------------------------------------------------------


def test_write_export_is_atomic_and_refuses_to_clobber(tmp_path) -> None:
    result = write_export(str(tmp_path), "audit.log", "first\n")
    assert Path(result["path"]).read_text(encoding="utf-8") == "first\n"
    # A second run must not silently destroy the archived previous export.
    with pytest.raises(ValueError):
        write_export(str(tmp_path), "audit.log", "second\n")
    assert write_export(str(tmp_path), "audit.log", "second\n", overwrite=True)["bytes"] == 7
    assert not list(tmp_path.glob("*.partial"))


def test_write_export_rejects_a_path_as_a_filename(tmp_path) -> None:
    for name in ("../escape.log", "sub/dir.log", "", "a" * 65, "bad name.log"):
        with pytest.raises(ValueError):
            validate_filename(name)
    assert validate_filename("audit-2026.log") == "audit-2026.log"


def test_write_export_enforces_a_size_ceiling(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("app.audit_export.MAX_EXPORT_BYTES", 10)
    with pytest.raises(ValueError):
        write_export(str(tmp_path), "audit.log", "x" * 11)


# --- incremental export ----------------------------------------------------


def seed(db, count: int, action: str = "erasure_applied") -> None:
    for index in range(count):
        db.add(PrivacyAudit(actor=f"admin{index}", action=action, detail=f"detail {index}"))
    db.flush()


def schedule(db, tmp_path, **over):
    row = AuditExportSchedule(
        name="Nightly", format="cef", columns=json.dumps(["id", "action", "detail"]),
        directory=str(tmp_path), filename="audit.log", interval_seconds=300,
        next_run=utcnow(),
    )
    for key, value in over.items():
        setattr(row, key, value)
    db.add(row)
    db.flush()
    return row


def test_export_is_incremental_and_never_duplicates(tmp_path) -> None:
    with make_client(tmp_path) as client:
        with client.app.state.session_factory() as db:
            seed(db, 3)
            row = schedule(db, tmp_path)
            assert run_due_exports(db) == 1
            assert (row.last_id, row.last_rows) == (3, 3)
            first_body, first_path = Path(row.last_path).read_text(encoding="utf-8"), row.last_path
            db.commit()
        assert first_body.count("CEF:0|") == 3
        first = sorted(p.name for p in tmp_path.glob("*.log"))
        assert len(first) == 1

        # The same schedule coming round again with nothing new writes nothing.
        with client.app.state.session_factory() as db:
            existing = db.query(AuditExportSchedule).order_by(AuditExportSchedule.id).first()
            existing.next_run = utcnow()
            assert run_due_exports(db) == 0
            db.commit()
        assert sorted(p.name for p in tmp_path.glob("*.log")) == first

        # New audit rows are picked up without re-sending the earlier ones.
        with client.app.state.session_factory() as db:
            seed(db, 2)
            again = db.query(AuditExportSchedule).order_by(AuditExportSchedule.id).first()
            again.next_run = utcnow()
            assert run_due_exports(db) == 1
            assert (again.last_id, again.last_rows) == (5, 2)
            second_body = Path(again.last_path).read_text(encoding="utf-8")
            db.commit()
        assert len(sorted(tmp_path.glob("*.log"))) == 2
        assert second_body.count("CEF:0|") == 2
        # The earlier records must not reappear in the second file.
        assert "id=1 " not in second_body
        assert "id=2 " not in second_body
        assert "id=3 " not in second_body
        assert "id=4 " in second_body and "id=5 " in second_body


def test_disabled_schedule_never_runs(tmp_path) -> None:
    with make_client(tmp_path) as client:
        with client.app.state.session_factory() as db:
            seed(db, 2)
            schedule(db, tmp_path, enabled=False)
            assert run_due_exports(db) == 0
            db.commit()
        assert not list(tmp_path.glob("*.log"))


def test_forwarding_is_skipped_unless_the_schedule_opts_in(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ZANAQ_SIEM_TARGET", "hec")
    monkeypatch.setenv("ZANAQ_SIEM_URL", "http://127.0.0.1:1/never")
    with make_client(tmp_path) as client:
        with client.app.state.session_factory() as db:
            seed(db, 2)
            schedule(db, tmp_path, forward_to_siem=False)
            assert run_due_exports(db) == 1
            db.commit()
        # An unreachable SIEM cannot affect a schedule that never asked to forward.
        assert list(tmp_path.glob("*.log"))


def test_a_failed_forward_holds_the_watermark_for_retry(tmp_path, monkeypatch) -> None:
    # The important property: a collector outage must not advance past rows the
    # SIEM never received. A duplicate local file is recoverable; a silently
    # dropped remote copy is not.
    monkeypatch.setenv("ZANAQ_SIEM_TARGET", "hec")
    monkeypatch.setenv("ZANAQ_SIEM_URL", "http://127.0.0.1:1/services/collector/event")
    monkeypatch.setenv("ZANAQ_SIEM_VERIFY_TLS", "false")
    with make_client(tmp_path) as client:
        with client.app.state.session_factory() as db:
            seed(db, 2)
            row = schedule(db, tmp_path, forward_to_siem=True)
            # Nothing counted as written, and the watermark did not move.
            assert run_due_exports(db) == 0
            db.commit()
            assert row.last_id == 0
            assert row.last_rows == 0
            # last_path stays empty because the run is not counted as written.
            assert not row.last_path
            # The local file was still produced, so the data is not lost locally.
            assert list(tmp_path.glob("*.log"))


def test_a_successful_forward_advances_the_watermark(tmp_path, monkeypatch) -> None:
    from tests.test_siem import _Collector  # local receiver standing in for a SIEM

    with _Collector() as collector:
        monkeypatch.setenv("ZANAQ_SIEM_TARGET", "hec")
        monkeypatch.setenv("ZANAQ_SIEM_URL", collector.url)
        monkeypatch.setenv("ZANAQ_SIEM_VERIFY_TLS", "false")
        with make_client(tmp_path) as client:
            with client.app.state.session_factory() as db:
                seed(db, 2)
                row = schedule(db, tmp_path, forward_to_siem=True)
                assert run_due_exports(db) == 1
                db.commit()
                assert row.last_id > 0
                assert row.last_rows == 2
    assert collector.received


def test_one_broken_schedule_does_not_stop_the_others(tmp_path) -> None:
    # A path whose parent is a regular file can never be created.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    with make_client(tmp_path) as client:
        with client.app.state.session_factory() as db:
            seed(db, 2)
            schedule(db, tmp_path, directory=str(blocker / "nested"), name="Broken")
            schedule(db, tmp_path, directory=str(tmp_path / "good"), name="Good")
            # The failure is contained: only the writable schedule produced a file.
            assert run_due_exports(db) == 1
            db.commit()
        assert list((tmp_path / "good").glob("*.log"))


# --- api -------------------------------------------------------------------


def promote(client) -> None:
    """Grant the seeded test session administrator rights."""
    from app.models import User

    with client.app.state.session_factory() as db:
        user = db.query(User).filter_by(username="investigator").one()
        user.role = "administrator"
        db.commit()


def test_schedule_endpoints_are_administrator_only(tmp_path) -> None:
    with make_client(tmp_path) as client:
        assert client.post("/api/compliance/audit-exports", json={
            "name": "Nightly", "directory": str(tmp_path)}).status_code == 403
        promote(client)
        created = client.post("/api/compliance/audit-exports", json={
            "name": "Nightly", "format": "cef", "directory": str(tmp_path)})
        assert created.status_code == 201, created.text
        listing = client.get("/api/compliance/audit-exports").json()
        assert listing["formats"] == ["csv", "jsonl", "cef", "syslog"]
        # Forwarding exists but is opt-in and off unless a SIEM is configured.
        assert listing["schedules"][0]["forward_to_siem"] is False
        assert listing["siem"]["enabled"] is False
        assert "token_configured" in listing["siem"]
        assert listing["schedules"][0]["format"] == "cef"
        assert client.delete(f"/api/compliance/audit-exports/{created.json()['id']}").status_code == 200
        assert client.get("/api/compliance/audit-exports").json()["schedules"] == []


def test_api_refuses_an_unknown_template_field(tmp_path) -> None:
    with make_client(tmp_path) as client:
        promote(client)
        assert client.post("/api/compliance/audit-exports", json={
            "name": "Nightly", "directory": str(tmp_path),
            "template": "{password}"}).status_code == 422
        assert client.post("/api/compliance/audit-exports", json={
            "name": "Nightly", "directory": str(tmp_path),
            "filename": "../escape.log"}).status_code == 422


def test_manual_run_writes_a_file_and_advances_the_watermark(tmp_path) -> None:
    with make_client(tmp_path) as client:
        promote(client)
        client.get("/api/compliance/audit-export")
        created = client.post("/api/compliance/audit-exports", json={
            "name": "Nightly", "format": "syslog", "directory": str(tmp_path)}).json()
        first = client.post(f"/api/compliance/audit-exports/{created['id']}/run").json()
        assert first["written"] == 1
        assert first["last_id"] > 0
        exported = list(tmp_path.glob("*.log"))
        assert len(exported) == 1
        assert exported[0].read_text(encoding="utf-8").startswith("<")
        assert client.post("/api/compliance/audit-exports/9999/run").status_code == 404


def test_manual_run_only_touches_the_requested_schedule(tmp_path) -> None:
    # Asking for one schedule must not also fire every other due schedule.
    with make_client(tmp_path) as client:
        promote(client)
        client.get("/api/compliance/audit-export")
        first_dir = tmp_path / "first"
        second_dir = tmp_path / "second"
        first = client.post("/api/compliance/audit-exports", json={
            "name": "First", "format": "csv", "directory": str(first_dir)}).json()
        client.post("/api/compliance/audit-exports", json={
            "name": "Second", "format": "csv", "directory": str(second_dir)})
        client.get("/api/compliance/audit-export")

        client.post(f"/api/compliance/audit-exports/{first['id']}/run")

        assert list(first_dir.glob("*.log"))
        assert not list(second_dir.glob("*.log"))


def test_manual_run_refuses_a_disabled_schedule(tmp_path) -> None:
    # Silently returning "written: 0" for a paused schedule would read as a
    # successful run that produced nothing.
    with make_client(tmp_path) as client:
        promote(client)
        client.get("/api/compliance/audit-export")
        created = client.post("/api/compliance/audit-exports", json={
            "name": "Paused", "format": "csv", "directory": str(tmp_path),
            "enabled": False}).json()
        response = client.post(f"/api/compliance/audit-exports/{created['id']}/run")
        assert response.status_code == 409
        assert not list(tmp_path.glob("*.log"))
