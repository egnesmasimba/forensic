from app.models import Alert, Case, Fact, User
from test_api import make_client


def administer(client):
    with client.app.state.session_factory() as db:
        db.query(User).filter_by(username="investigator").one().role = "administrator"
        db.commit()


def test_subject_rights_review_and_archive(tmp_path):
    with make_client(tmp_path) as client:
        assert client.get("/api/compliance/controls").status_code == 403
        administer(client)
        with client.app.state.session_factory() as db:
            db.add(Fact(source_key="fact-1", source="import", occurred_at="2020-01-01T00:00:00+00:00", entity_type="user", entity_ref="ada", name="note", text_value="account note"))
            db.add(Fact(source_key="fact-2", source="import", occurred_at="2026-10-01T00:00:00+00:00", entity_type="user", entity_ref="ada", name="note", text_value="recent"))
            db.commit()
        consent = client.post("/api/compliance/consents", json={"entity_ref": "ada", "purpose": "investigation notice", "granted": True})
        assert consent.status_code == 201
        assessment = client.post("/api/compliance/assessments", json={"title": "Inbox review", "scope": "Imported facts", "risks": "Personal notes", "status": "draft"})
        assert assessment.json()["status"] == "draft"
        review = client.post("/api/compliance/reviews", json={"entity_ref": "ada", "decision": "approved", "note": "Sample complete"})
        assert review.json()["decision"] == "approved"
        access = client.post("/api/compliance/requests", json={"entity_ref": "ada", "kind": "access", "regime": "gdpr"})
        assert access.status_code == 201
        assert access.json()["package"]["facts"][0]["text_value"] == "account note"
        assert access.json()["package"]["consents"][0]["granted"] is True
        patterns = client.post("/api/compliance/inspect", json={"text": "SSN 123-45-6789 MRN: AB12CD card 4242424242424242"})
        assert patterns.json()["phi"]["ssn"] == 1 and patterns.json()["phi"]["mrn"] == 1
        assert patterns.json()["phi"]["samples"] == ["SSN ending 6789"]
        assert patterns.json()["cards"] == ["card ending 4242"]
        opt_out = client.post("/api/compliance/requests", json={"entity_ref": "ada", "kind": "opt_out", "regime": "ccpa"})
        assert "Live collectors are unchanged" in opt_out.json()["package"]["notice"]
        assert client.put("/api/compliance/retention", json={"online_months": 5}).status_code == 422
        assert client.put("/api/compliance/retention", json={"online_months": 6}).json()["online_months"] == 6
        preview = client.post("/api/compliance/aging?dry_run=true")
        assert preview.json()["facts"] == 1 and preview.json()["dry_run"] is True
        applied = client.post("/api/compliance/aging?dry_run=false").json()
        assert applied["facts"] == 1
        archived = client.get("/api/compliance/archive").json()[0]
        loaded = client.get(f"/api/compliance/archive/{archived['id']}")
        assert loaded.json()["body"]["text_value"] == "account note"
        assert client.post(f"/api/compliance/archive/{archived['id']}/verify").json()["verified"] is True
        with client.app.state.session_factory() as db:
            from app.privacy_models import ArchiveRecord
            assert db.query(Fact).filter_by(source_key="fact-1").one().text_value == "[archived]"
            db.get(ArchiveRecord, archived["id"]).body = "{\"tampered\":true}"
            db.commit()
        assert client.get(f"/api/compliance/archive/{archived['id']}").status_code == 409
        case = None
        with client.app.state.session_factory() as db:
            case = Case(title="Hold", case_type="insider", status="investigating")
            db.add(case)
            db.flush()
            db.add(Alert(title="Held", entity_type="user", entity_ref="ada", case_id=case.id))
            db.commit()
        refused = client.post("/api/compliance/requests", json={"entity_ref": "ada", "kind": "erasure", "regime": "gdpr"})
        assert refused.json()["status"] == "refused"
        with client.app.state.session_factory() as db:
            db.query(Case).one().status = "closed"
            db.commit()
        erased = client.post("/api/compliance/requests", json={"entity_ref": "ada", "kind": "erasure", "regime": "gdpr"})
        assert erased.json()["status"] == "fulfilled"
        assert erased.json()["package"]["facts_redacted"] == 2
        assert erased.json()["package"]["archives_redacted"] == 1
        exported = client.get("/api/compliance/audit-export?format=csv&columns=action,created_at")
        assert exported.status_code == 200 and exported.headers["content-type"].startswith("text/csv")
        assert "actor" not in exported.text.splitlines()[0] and "subject_erasure" in exported.text
        inventory = client.get("/api/compliance/controls").json()
        assert "No certification" in inventory["gaps"]
