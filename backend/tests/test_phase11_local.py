from datetime import timedelta

from app.models import Case, utcnow
from app.report_schedule import run_due_exports
from test_api import make_client


def test_other_api_requests_are_throttled(tmp_path, monkeypatch):
    monkeypatch.setattr("app.auth.API_LIMIT", 2)
    with make_client(tmp_path) as client:
        assert client.get("/api/cases").status_code == 200
        assert client.get("/api/cases").status_code == 200
        blocked = client.get("/api/cases")
        assert blocked.status_code == 429
        assert blocked.headers["retry-after"]
        assert client.get("/api/health").status_code == 200


def test_openapi_documents_the_case_api(tmp_path):
    with make_client(tmp_path) as client:
        schema = client.get("/openapi.json")
        assert schema.status_code == 200
        assert "/api/cases" in schema.json()["paths"]
        assert schema.json()["info"]["title"]


def test_scheduled_template_export_stays_in_the_center(tmp_path):
    with make_client(tmp_path) as client:
        created = client.post("/api/cases", json={"title": "Queued review", "case_type": "Other", "score": 10})
        assert created.status_code == 201
        template = client.post("/api/reports/templates", json={"name": "Queue", "columns": ["title"], "status": ""})
        assert template.status_code == 201, template.text
        schedule = client.post("/api/reports/schedules", json={"template_id": template.json()["id"], "interval_seconds": 60})
        assert schedule.status_code == 201, schedule.text
        schedule_id = schedule.json()["id"]
        with client.app.state.session_factory() as db:
            assert run_due_exports(db) == 1
            db.commit()
        exported = client.get(f"/api/reports/schedules/{schedule_id}/export")
        assert exported.status_code == 200
        assert "Queued review" in exported.text
        with client.app.state.session_factory() as db:
            assert run_due_exports(db) == 0
            db.commit()


def test_aging_lists_an_open_case_and_skips_a_closed_one(tmp_path):
    with make_client(tmp_path) as client:
        open_id = client.post("/api/cases", json={"title": "Stale", "case_type": "Other"}).json()["id"]
        closed_id = client.post("/api/cases", json={"title": "Finished", "case_type": "Other"}).json()["id"]
        with client.app.state.session_factory() as db:
            old = utcnow() - timedelta(days=10)
            db.get(Case, open_id).updated_at = old
            closed = db.get(Case, closed_id)
            closed.status = "closed"
            closed.updated_at = old
            db.commit()
        rows = client.get("/api/cases/aging?days=7").json()
        assert [row["id"] for row in rows] == [open_id]
