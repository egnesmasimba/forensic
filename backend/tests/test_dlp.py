from app.models import RiskEvent
from test_api import make_client

WHEN = "2026-10-03T12:00:00+00:00"


def test_content_review_follows_risk_band(tmp_path):
    with make_client(tmp_path) as client:
        quiet = client.post("/api/dlp/inspect", json={"user": "quiet", "text": "Write to ada@example.com today."})
        assert quiet.status_code == 201
        assert quiet.json()["opened"] is False and quiet.json()["band"] == "low"
        with client.app.state.session_factory() as db:
            db.add(RiskEvent(entity_type="user", entity_ref="casey", score=120, delta=120, reason="review"))
            db.commit()
        loud = client.post("/api/dlp/inspect", json={"user": "casey", "text": "Write to ada@example.com today."})
        assert loud.json()["opened"] is True and loud.json()["band"] == "high"
        assert "customer data" in loud.json()["categories"]
        card = client.post("/api/dlp/inspect", json={"user": "casey", "text": "Pay 4242424242424242."})
        assert "financial record" in card.json()["categories"] and card.json()["cards"][0].endswith("4242")
        marked = client.post("/api/dlp/inspect", json={"user": "casey", "text": "This drawing is confidential."})
        assert "intellectual property" in marked.json()["categories"]
        saved = client.put("/api/dlp/policy", json={
            "min_matches": 2, "score": 80, "ip_terms": "confidential", "customer_terms": "customer", "financial_terms": "account number",
        })
        assert saved.status_code == 200
        assert any(row["change"].startswith("Policy") for row in client.get("/api/dlp/audit").json())


def test_devices_files_permissions_and_command_review(tmp_path):
    with make_client(tmp_path) as client:
        unknown = client.post("/api/dlp/usb/activity", json={"serial": "USB-9", "user": "casey", "bytes": 20, "occurred_at": WHEN})
        assert unknown.json()["opened"] is True
        client.put("/api/dlp/usb", json={"serial": "USB-1", "label": "Office", "allowed": True})
        allowed = client.post("/api/dlp/usb/activity", json={"serial": "USB-1", "user": "casey", "bytes": 20, "occurred_at": WHEN})
        assert allowed.json()["opened"] is False
        assert len(client.get("/api/dlp/usb/activity").json()) == 2
        cloud = client.post("/api/dlp/cloud/activity", json={"host": "drive.google.com", "user": "casey", "bytes": 10})
        assert cloud.json()["kind"] == "personal" and cloud.json()["opened"] is True
        genai = client.post("/api/dlp/cloud/activity", json={"host": "chat.openai.com", "user": "casey", "bytes": 10})
        assert genai.json()["kind"] == "genai"
        for host in ("chatgpt.com", "claude.ai", "gemini.google.com", "copilot.microsoft.com", "perplexity.ai", "ollama.com", "lmstudio.ai"):
            assert client.post("/api/dlp/cloud/activity", json={"host": host, "user": "casey", "bytes": 10}).json()["kind"] == "genai"
        client.put("/api/dlp/cloud", json={"host": "drive.google.com", "allowed": True})
        assert client.post("/api/dlp/cloud/activity", json={"host": "drive.google.com", "user": "casey", "bytes": 10}).json()["opened"] is False
        disguise = client.post("/api/dlp/files", json={"user": "casey", "changes": [
            {"action": "rename", "source": "report.docx", "target": "photo.jpg", "occurred_at": WHEN},
        ]})
        assert disguise.json()["opened"] == ["disguise"]
        moves = [{"action": "move", "source": f"a{index}.txt", "target": f"b{index}.txt", "occurred_at": WHEN} for index in range(5)]
        assert "pattern" in client.post("/api/dlp/files", json={"user": "casey", "changes": moves}).json()["opened"]
        stranger = client.post("/api/dlp/permissions", json={
            "user": "casey", "path": "/data", "principal": "guest", "change": "grant", "occurred_at": WHEN,
        })
        assert stranger.json()["opened"] is True
        client.put("/api/dlp/permissions/allow", json={"principal": "owner"})
        owner = client.post("/api/dlp/permissions", json={
            "user": "casey", "path": "/data", "principal": "owner", "change": "grant", "occurred_at": WHEN,
        })
        assert owner.json()["opened"] is False
        assert len(client.get("/api/dlp/permissions").json()) == 2
        reviewed = client.post("/api/dlp/commands", json={"user": "casey", "commands": ["rm -rf /tmp/old"]})
        assert "destructive delete" in reviewed.json()["findings"]
        sequence = client.post("/api/dlp/commands", json={"user": "casey", "commands": ["wget https://example.test/tool", "bash tool"]})
        assert "command sequence" in sequence.json()["findings"]
        assert client.get("/api/dlp/commands").json()
        printed = client.post("/api/dlp/print", json={
            "user": "casey", "printer": "Office", "document": "report.pdf", "pages": 2, "size": 4000, "occurred_at": WHEN,
        })
        assert printed.json()["opened"] is True
        assert client.post("/api/dlp/print", json={
            "user": "casey", "printer": "Office", "document": "report.pdf", "pages": 2, "size": 4000, "occurred_at": WHEN, "content": "page text",
        }).status_code == 422
        listed = client.get("/api/dlp/print").json()
        assert listed[0]["document"] == "report.pdf" and "content" not in listed[0]
        attempt = client.post("/api/dlp/screenshots", json={"user": "casey", "application": "Snipping Tool", "occurred_at": WHEN})
        assert attempt.json()["opened"] is True
        assert client.post("/api/dlp/screenshots", json={
            "user": "casey", "application": "Snipping Tool", "occurred_at": WHEN, "image": "abc",
        }).status_code == 422
        shots = client.get("/api/dlp/screenshots").json()
        assert shots[0]["application"] == "Snipping Tool" and "image" not in shots[0]


def test_clipboard_preview_flags_a_card_without_copying_it(tmp_path):
    with make_client(tmp_path) as client:
        registered = client.post("/api/agents/register", json={"machine_id": "clip-host", "hostname": "Review host", "os": "windows"})
        assert registered.status_code == 201, registered.text
        headers = {"X-Agent-Token": registered.json()["agent_token"]}
        quiet = client.post("/api/agents/events", json={"events": [{"type": "clipboard_change", "payload": {"content_preview": "hello"}, "event_key": "a" * 64}]}, headers=headers)
        assert quiet.json()["alerts_created"] == 0
        flagged = client.post("/api/agents/events", json={"events": [{"type": "clipboard_change", "payload": {"content_preview": "Pay 4242424242424242 now"}, "event_key": "b" * 64}]}, headers=headers)
        assert flagged.status_code == 200, flagged.text
        assert flagged.json()["alerts_created"] == 1
        alert = client.get("/api/alerts").json()[0]
        assert alert["title"] == "Sensitive clipboard copy"
        assert "card ending 4242" in alert["description"]
        assert "4242424242424242" not in alert["description"]
