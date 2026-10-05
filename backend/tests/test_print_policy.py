from __future__ import annotations

import json
from pathlib import Path

from app.models import Alert, EndpointEvent, User
from endpoint_agent.collectors.print import PrintCollector, _devmode_fields
from endpoint_agent.print_policy import (
    MAX_CAPTURE_BYTES,
    PrintArtifactStore,
    PrintContentPolicy,
)
from test_api import make_client


def policy(tmp_path, **over):
    """A policy wired to a real artifact store, as a deployment would run it."""
    cfg = {
        "enabled": True,
        "sensitive_terms": ["payroll"],
        "source_roots": [str(tmp_path)],
        "artifact_dir": str(tmp_path / "artifacts"),
    }
    cfg.update(over)
    return PrintContentPolicy(cfg)


def register(client):
    response = client.post(
        "/api/agents/register",
        json={"machine_id": "print-fixture", "hostname": "print-host", "os": "windows"},
    )
    assert response.status_code == 201, response.text
    return {"X-Agent-Token": response.json()["agent_token"]}


def job(**over):
    base = {
        "job_key": "HP-1",
        "printer": "HP-LaserJet",
        "printer_location": "Floor 2",
        "job_id": 7,
        "user": "alice",
        "document": "quarterly-report.pdf",
        "status": "PRINTING",
        "pages": 12,
        "size": 4096,
        "copies": 2,
        "color": True,
        "duplex": "duplex",
    }
    base.update(over)
    return base


# --- policy engine ---------------------------------------------------------


def test_policy_is_inert_without_terms() -> None:
    # Enabling capture with no terms configured must not capture everything.
    policy = PrintContentPolicy({"enabled": True, "sensitive_terms": []})
    assert policy.active is False
    decision = policy.evaluate(job())
    assert decision.capture is False
    assert decision.reason == "content_capture_disabled"


def test_policy_defaults_to_disabled() -> None:
    assert PrintContentPolicy().active is False
    assert PrintContentPolicy({}).enabled is False


def test_title_match_with_a_resolved_source_triggers_capture(tmp_path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    source = root / "2024-Payroll-Summary.pdf"
    source.write_text("quarterly figures", encoding="utf-8")
    policy = PrintContentPolicy({
        "enabled": True, "sensitive_terms": ["payroll"], "source_roots": [str(root)],
    })
    decision = policy.evaluate(job(document="2024-Payroll-Summary.pdf"))
    assert decision.capture is True
    assert decision.reason == "document_title_matched_policy"
    assert decision.matched_terms == ("payroll",)
    assert decision.source_path == str(source.resolve())


def test_title_match_is_not_a_capture_without_source_bytes() -> None:
    # A matching title with no locatable document must not be reported as a
    # capture: there are no bytes behind it, and the server treats "capture"
    # as grounds for a sensitive-print alert.
    policy = PrintContentPolicy({"enabled": True, "sensitive_terms": ["payroll"]})
    decision = policy.evaluate(job(document="2024-Payroll-Summary.pdf"))
    assert decision.capture is False
    assert decision.reason == "title_matched_source_unresolved:no_source_roots"
    assert decision.matched_terms == ("payroll",)
    assert decision.source_path is None


def test_title_matching_is_case_and_separator_insensitive(tmp_path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    for name in ("MEDICAL-RECORD-final.pdf", "medical_record.pdf"):
        (root / name).write_text("redacted", encoding="utf-8")
    policy = PrintContentPolicy({
        "enabled": True, "sensitive_terms": ["medical record"], "source_roots": [str(root)],
    })
    assert policy.evaluate(job(document="MEDICAL-RECORD-final.pdf")).capture is True
    assert policy.evaluate(job(document="medical_record.pdf")).capture is True


def test_unmatched_job_is_skipped_with_a_reason() -> None:
    policy = PrintContentPolicy({"enabled": True, "sensitive_terms": ["payroll"]})
    decision = policy.evaluate(job())
    assert decision.capture is False
    assert decision.reason == "no_source_roots"


def test_source_is_resolved_and_matched_by_content(tmp_path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    source = root / "scan.pdf"
    source.write_text("Contains confidential payroll figures", encoding="utf-8")
    policy = PrintContentPolicy({
        "enabled": True,
        "sensitive_terms": ["payroll"],
        "source_roots": [str(root)],
    })
    decision = policy.evaluate(job(document="scan.pdf"))
    assert decision.capture is True
    assert decision.reason == "source_content_matched_policy"
    assert decision.source_path == str(source.resolve())


def test_source_outside_roots_is_never_read(tmp_path) -> None:
    # A document matching no term and living outside the configured roots must
    # not be resolved, even if it exists somewhere on disk.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.pdf").write_text("payroll data", encoding="utf-8")
    root = tmp_path / "docs"
    root.mkdir()
    policy = PrintContentPolicy({
        "enabled": True,
        "sensitive_terms": ["payroll"],
        "source_roots": [str(root)],
    })
    decision = policy.evaluate(job(document="secret.pdf"))
    assert decision.capture is False
    assert decision.reason == "source_not_found_in_roots"


def test_capture_limits_are_clamped() -> None:
    policy = PrintContentPolicy({
        "enabled": True,
        "sensitive_terms": ["x"],
        "max_capture_bytes": 10 ** 12,
        "max_per_pass": 9999,
    })
    assert policy.max_capture_bytes == MAX_CAPTURE_BYTES
    assert policy.max_per_pass == 50
    # Malformed values fall back rather than disabling collection.
    bad = PrintContentPolicy({"enabled": True, "sensitive_terms": ["x"], "max_per_pass": "nope"})
    assert bad.max_per_pass == 5


# --- DEVMODE metadata ------------------------------------------------------


def test_devmode_reads_copies_color_and_duplex() -> None:
    class DevMode:
        Copies = 3
        Color = 1
        Duplex = 2

    assert _devmode_fields(DevMode()) == {
        "copies": 3, "color": True, "duplex": "duplex",
    }


def test_devmode_accepts_a_mapping() -> None:
    assert _devmode_fields({"copies": 2, "color": 0, "duplex": 1}) == {
        "copies": 2, "color": False, "duplex": "simplex",
    }


def test_devmode_absent_fields_report_none_not_guesses() -> None:
    # Nothing readable must surface as None so an examiner can tell
    # "not reported" from a real value.
    assert _devmode_fields(None) == {"copies": None, "color": None, "duplex": None}
    assert _devmode_fields(object()) == {"copies": None, "color": None, "duplex": None}


def test_unknown_duplex_code_is_labelled() -> None:
    assert _devmode_fields({"duplex": 99})["duplex"] == "unknown"


# --- collector wiring ------------------------------------------------------


def test_collector_reports_content_policy_state() -> None:
    collector = PrintCollector({"content_policy": {"enabled": True, "sensitive_terms": ["payroll"]}})
    status = collector.status()["content_policy"]
    assert status["content_capture_enabled"] is True
    assert status["active"] is True
    assert status["terms"] == 1


def test_capture_candidates_are_skipped_when_policy_is_inactive() -> None:
    collector = PrintCollector({})
    assert collector._capture_candidates([job(document="payroll.pdf")]) == []


def test_capture_candidates_record_skip_decisions() -> None:
    collector = PrintCollector({
        "content_policy": {"enabled": True, "sensitive_terms": ["payroll"]},
    })
    events = collector._capture_candidates([job()])
    assert len(events) == 1
    assert events[0]["type"] == "print_document"
    assert events[0]["payload"]["decision"] == "skip"
    assert events[0]["payload"]["reason"] == "no_source_roots"


def test_capture_candidates_bound_each_pass(tmp_path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    # Real sources, because the per-pass bound only applies to jobs that are
    # actually eligible for capture.
    for i in range(5):
        (root / f"payroll-{i}.pdf").write_text("figures", encoding="utf-8")
    collector = PrintCollector({
        "content_policy": {
            "enabled": True, "sensitive_terms": ["payroll"], "source_roots": [str(root)],
            "max_per_pass": 2,
        },
    })
    jobs = [job(job_key=f"HP-{i}", document=f"payroll-{i}.pdf") for i in range(5)]
    events = collector._capture_candidates(jobs)
    captured = [e for e in events if e["payload"]["decision"] == "capture"]
    assert len(captured) == 2
    assert events[-1]["payload"]["reason"] == "per_pass_limit_reached"


def test_capture_records_scan_and_metadata(tmp_path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    source = root / "payroll-2024.pdf"
    source.write_text("payroll totals", encoding="utf-8")
    collector = PrintCollector({
        "content_policy": {
            "enabled": True, "sensitive_terms": ["payroll"], "source_roots": [str(root)],
        },
    })
    events = collector._capture_candidates([job(document="payroll-2024.pdf")])
    payload = events[0]["payload"]
    assert payload["decision"] == "capture"
    assert payload["matched_terms"] == ["payroll"]
    assert payload["copies"] == 2
    assert payload["color"] is True
    assert payload["duplex"] == "duplex"
    assert payload["printer_location"] == "Floor 2"
    # The retained copy must be hashed so it can be tied to other evidence.
    assert payload["file_scan"]["sha256"]
    assert "this confirms a print job" not in json.dumps(payload)


def test_oversized_source_is_not_retained(tmp_path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    (root / "payroll-big.pdf").write_bytes(b"x" * 5000)
    collector = PrintCollector({
        "content_policy": {
            "enabled": True, "sensitive_terms": ["payroll"],
            "source_roots": [str(root)], "max_capture_bytes": 100,
        },
    })
    payload = collector._capture_candidates([job(document="payroll-big.pdf")])[0]["payload"]
    assert payload["decision"] == "capture"
    assert payload["file_scan"]["partial"] is True
    assert payload["file_scan"].get("sha256") is None


def test_normalised_job_has_uniform_keys() -> None:
    collector = PrintCollector({})
    entry = collector._normalise_job({"printer": "HP", "document": "a.pdf", "pages": 1})
    for key in ("printer_location", "copies", "color", "duplex"):
        assert key in entry
    assert entry["color"] is None


# --- artifact store --------------------------------------------------------


def test_retained_bytes_are_actually_written(tmp_path) -> None:
    source = tmp_path / "payroll.pdf"
    source.write_bytes(b"payroll totals\x00\x01binary")
    store = PrintArtifactStore(tmp_path / "store")
    result = store.retain(source, job=job())
    assert result["retained"] is True
    # The stored bytes must be byte-identical, not a scan summary.
    stored = Path(result["stored_path"])
    assert stored.read_bytes() == b"payroll totals\x00\x01binary"
    assert store.verify(result["artifact_id"])["verified"] is True
    manifest = store.load_manifest(result["artifact_id"])
    assert manifest["source_path"] == str(source)
    assert manifest["sha256"] == result["sha256"]
    assert manifest["printer"] == "HP-LaserJet"
    assert "spool" in manifest["scope"]


def test_store_bounds_bytes_and_artifact_count(tmp_path) -> None:
    source = tmp_path / "a.bin"
    source.write_bytes(b"x" * 4096)
    store = PrintArtifactStore(tmp_path / "store", max_bytes=8192, max_artifacts=1)
    first = store.retain(source)
    assert first["retained"] is True
    # Byte ceiling reached, so a second copy is refused rather than overrunning.
    second = store.retain(source)
    assert second["retained"] is False
    assert second["reason"] in {"artifact_store_byte_limit_reached", "artifact_count_limit_reached"}
    assert store.usage()[1] == 1


def test_store_refuses_a_source_over_its_limit(tmp_path) -> None:
    source = tmp_path / "big.bin"
    source.write_bytes(b"y" * 4096)
    store = PrintArtifactStore(tmp_path / "store")
    result = store.retain(source, max_bytes=1024)
    assert result["retained"] is False
    assert result["reason"] == "source_exceeds_capture_limit"
    assert store.usage() == (0, 0)


def test_tampered_artifact_fails_verification(tmp_path) -> None:
    source = tmp_path / "payroll.pdf"
    source.write_bytes(b"payroll totals")
    store = PrintArtifactStore(tmp_path / "store")
    result = store.retain(source)
    Path(result["stored_path"]).write_bytes(b"substituted")
    verification = store.verify(result["artifact_id"])
    assert verification["verified"] is False
    assert verification["actual_sha256"] != verification["expected_sha256"]


def test_store_rejects_a_rewritten_manifest(tmp_path) -> None:
    source = tmp_path / "payroll.pdf"
    source.write_bytes(b"payroll totals")
    store = PrintArtifactStore(tmp_path / "store")
    result = store.retain(source)
    manifest_path = store.directory / result["artifact_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_path"] = "C:/somewhere/else.txt"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    # An unknown id has no manifest at all and must not verify.
    assert store.verify("0" * 32)["verified"] is False
    # An id that is not 32 hex characters is refused outright.
    assert store.verify("../../etc")["verified"] is False


def test_store_expires_artifacts_past_retention(tmp_path) -> None:
    source = tmp_path / "payroll.pdf"
    source.write_bytes(b"payroll totals")
    store = PrintArtifactStore(tmp_path / "store")
    result = store.retain(source)
    assert result["retained"] is True
    assert store.usage()[1] == 1
    # Backdate rather than expiring with a zero window, which would race the
    # capture timestamp at the boundary.
    manifest_path = store.directory / result["artifact_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["captured_at"] = 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    dry = store.expire(0, dry_run=True)
    assert dry["removed"] == 1
    assert store.verify(result["artifact_id"])["verified"] is True
    applied = store.expire(0, dry_run=False)
    assert applied["removed"] == 1
    assert store.usage() == (0, 0)


def test_collector_retains_bytes_and_reports_them(tmp_path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    (root / "payroll-2024.pdf").write_bytes(b"payroll totals")
    collector = PrintCollector({"content_policy": {
        "enabled": True, "sensitive_terms": ["payroll"], "source_roots": [str(root)],
        "artifact_dir": str(tmp_path / "artifacts"),
    }})
    payload = collector._capture_candidates([job(document="payroll-2024.pdf")])[0]["payload"]
    assert payload["decision"] == "capture"
    retained = payload["retained_copy"]
    assert retained["retained"] is True
    assert Path(retained["stored_path"]).read_bytes() == b"payroll totals"
    assert retained["sha256"]


def test_collector_states_when_no_store_is_configured(tmp_path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    (root / "payroll-2024.pdf").write_bytes(b"payroll totals")
    collector = PrintCollector({"content_policy": {
        "enabled": True, "sensitive_terms": ["payroll"], "source_roots": [str(root)],
    }})
    payload = collector._capture_candidates([job(document="payroll-2024.pdf")])[0]["payload"]
    # Scanning still happens, but nothing is kept and the payload says so.
    assert payload["file_scan"]["sha256"]
    assert payload["retained_copy"] == {
        "retained": False, "reason": "artifact_store_not_configured",
    }


def test_status_reports_store_state(tmp_path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    (root / "payroll.pdf").write_bytes(b"payroll totals")
    wired = policy(tmp_path)
    wired.store.retain(root / "payroll.pdf")
    status = wired.status()
    assert status["artifact_store_configured"] is True
    assert status["artifact_store_available"] is True
    assert status["artifact_count"] == 1
    assert status["artifact_bytes"] > 0
    assert status["retention_days"] == 365
    unconfigured = PrintContentPolicy({
        "enabled": True, "sensitive_terms": ["payroll"], "source_roots": [str(root)],
    })
    assert unconfigured.status()["artifact_store_configured"] is False
    assert unconfigured.store is None


def test_retention_expires_artifacts_from_the_collector_tick(tmp_path) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    (root / "payroll.pdf").write_bytes(b"payroll totals")
    collector = PrintCollector({"content_policy": {
        "enabled": True, "sensitive_terms": ["payroll"], "source_roots": [str(root)],
        "artifact_dir": str(tmp_path / "artifacts"), "retention_days": 1,
    }})
    store = collector.policy.store
    assert store.retain(root / "payroll.pdf")["retained"] is True
    # Force an age beyond the window rather than waiting a day.
    for entry in store.directory.iterdir():
        if entry.is_dir():
            path = entry / "manifest.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["captured_at"] = 0
            path.write_text(json.dumps(payload), encoding="utf-8")
    collector._capture_candidates([])
    assert store.usage() == (0, 0)


def test_cups_backed_collector_advertises_non_windows_platforms() -> None:
    # _scan_cups is implemented, so declaring Windows-only support would
    # under-report a collector that works on Linux and macOS.
    assert "linux" in PrintCollector.platforms
    assert "macos" in PrintCollector.platforms


# --- server side -----------------------------------------------------------


def post_print_event(client, headers, payload, severity="high"):
    return client.post("/api/agents/events", headers=headers, json={"events": [{
        "type": "print_document",
        "event_key": "c" * 64,
        "severity": severity,
        "occurred_at": "2026-10-04T09:00:00+00:00",
        "payload": payload,
    }]})


def test_print_capture_raises_alert_with_evidence(tmp_path) -> None:
    with make_client(tmp_path) as client:
        headers = register(client)
        with client.app.state.session_factory() as db:
            user = db.query(User).filter_by(username="investigator").one()
            user.role = "administrator"
            db.commit()
        assert client.put(
            "/api/mail/policy", json={"sensitive_terms": ["payroll"]}
        ).status_code == 200
        payload = {
            "decision": "capture",
            "reason": "document_title_matched_policy",
            "matched_terms": ["payroll"],
            "printer": "HP-LaserJet",
            "printer_location": "Floor 2",
            "document": "payroll-2024.pdf",
            "user": "alice",
            "pages": 12,
            "copies": 2,
            "color": True,
            "duplex": "duplex",
            "file_scan": {"text": "payroll totals for alice", "sha256": "a" * 64},
        }
        response = post_print_event(client, headers, payload)
        assert response.status_code == 200, response.text
        assert response.json()["alerts_created"] == 1
        with client.app.state.session_factory() as db:
            alert = db.query(Alert).order_by(Alert.id.desc()).first()
            assert alert.channel == "print"
            assert alert.entity_ref == "alice"
            assert "payroll" in alert.description.lower()
            # The alert must not overstate what was observed.
            assert "not delivery" in alert.description
            assert db.query(EndpointEvent).filter_by(type="print_document").count() == 1


def test_alert_never_claims_a_copy_that_was_not_retained(tmp_path) -> None:
    # A policy match with no retained bytes must not be described as a
    # capture, and must give the reason instead.
    with make_client(tmp_path) as client:
        headers = register(client)
        response = post_print_event(client, headers, {
            "decision": "capture",
            "reason": "document_title_matched_policy",
            "matched_terms": ["payroll"],
            "printer": "HP",
            "document": "payroll-2024.pdf",
            "user": "alice",
            "file_scan": {"text": "payroll totals"},
            "retained_copy": {"retained": False, "reason": "artifact_store_not_configured"},
        })
        assert response.status_code == 200, response.text
        with client.app.state.session_factory() as db:
            description = db.query(Alert).filter_by(channel="print").one().description
            assert "no copy was retained" in description
            assert "artifact_store_not_configured" in description
            assert "was retained by the endpoint agent" not in description


def test_alert_reports_a_verified_retained_copy(tmp_path) -> None:
    with make_client(tmp_path) as client:
        headers = register(client)
        response = post_print_event(client, headers, {
            "decision": "capture",
            "reason": "document_title_matched_policy",
            "matched_terms": ["payroll"],
            "printer": "HP",
            "document": "payroll-2024.pdf",
            "user": "alice",
            "file_scan": {"text": "payroll totals"},
            "retained_copy": {"retained": True, "sha256": "b" * 64, "size": 2048},
        })
        assert response.status_code == 200, response.text
        with client.app.state.session_factory() as db:
            description = db.query(Alert).filter_by(channel="print").one().description
            assert "was retained by the endpoint agent" in description
            assert "b" * 16 in description


def test_print_skip_decision_creates_no_alert(tmp_path) -> None:
    with make_client(tmp_path) as client:
        headers = register(client)
        response = post_print_event(client, headers, {
            "decision": "skip",
            "reason": "no_source_roots",
            "printer": "HP",
            "document": "payroll.pdf",
            "user": "alice",
        }, severity="low")
        assert response.status_code == 200, response.text
        assert response.json()["alerts_created"] == 0
        with client.app.state.session_factory() as db:
            # The skip is still stored, so absent coverage stays explainable.
            assert db.query(EndpointEvent).filter_by(type="print_document").count() == 1
            assert db.query(Alert).filter_by(channel="print").count() == 0


def test_print_document_is_searchable(tmp_path) -> None:
    with make_client(tmp_path) as client:
        headers = register(client)
        post_print_event(client, headers, {
            "decision": "capture",
            "matched_terms": ["payroll"],
            "printer": "HP",
            "document": "payroll-2024.pdf",
            "user": "alice",
            "file_scan": {"text": "distinctive payroll marker zephyrus"},
        })
        found = client.get("/api/agents/events/search?q=zephyrus")
        assert found.status_code == 200
        assert any(e["type"] == "print_document" for e in found.json())