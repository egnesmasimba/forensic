from test_api import make_client
from app.models import User


def admin(client):
    with client.app.state.session_factory() as db:
        db.query(User).filter_by(username="investigator").first().role = "administrator"
        db.commit()


def register(client):
    result = client.post("/api/agents/register", json={"machine_id": "machine-app", "hostname": "Review host", "os": "windows"})
    assert result.status_code == 201, result.text
    data = result.json()
    token = data.get("agent_token") or data.get("token")
    return {"X-Agent-Token": token}


def test_application_rule_matches_stored_process_and_window(tmp_path):
    with make_client(tmp_path) as client:
        assert client.post("/api/applications/rules", json={"name": "Ledger", "field": "process", "pattern": "ledger"}).status_code == 403
        admin(client)
        assert client.post("/api/applications/rules", json={"name": "Ledger", "field": "process", "pattern": "a"}).status_code == 422
        created = client.post("/api/applications/rules", json={"name": "Ledger", "field": "process", "pattern": "Ledger"})
        assert created.status_code == 201, created.text
        assert created.json()["pattern"] == "ledger"
        assert client.post("/api/applications/rules", json={"name": "Again", "field": "process", "pattern": "ledger"}).status_code == 409
        window = client.post("/api/applications/rules", json={"name": "Payments", "field": "window", "pattern": "payment queue", "score": 55})
        assert window.status_code == 201, window.text
        headers = register(client)
        matched = client.post("/api/agents/events", json={"events": [{"type": "process_start", "payload": {"name": "Ledger.exe"}, "event_key": "a" * 64}]}, headers=headers)
        assert matched.status_code == 200, matched.text
        assert matched.json()["alerts_created"] == 1
        quiet = client.post("/api/agents/events", json={"events": [{"type": "process_start", "payload": {"name": "notepad.exe"}, "event_key": "b" * 64}]}, headers=headers)
        assert quiet.json()["alerts_created"] == 0
        titled = client.post("/api/agents/events", json={"events": [{"type": "window_change", "payload": {"window_title": "Payment Queue - open items"}, "event_key": "c" * 64}]}, headers=headers)
        assert titled.status_code == 200, titled.text
        assert titled.json()["alerts_created"] == 1
        alerts = client.get("/api/alerts").json()
        titles = {row["title"] for row in alerts}
        assert "Application Ledger" in titles and "Application Payments" in titles
        rule_id = created.json()["id"]
        assert client.delete(f"/api/applications/rules/{rule_id}").status_code == 204
        assert all(row["id"] != rule_id for row in client.get("/api/applications/rules").json())
