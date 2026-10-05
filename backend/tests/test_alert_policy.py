from app.models import Notice
from test_api import make_client


def test_suppression_routing_groups_and_field_drilldown(tmp_path):
    with make_client(tmp_path) as client:
        assert client.post("/api/alerts/policies", json={"kind": "suppress"}).status_code == 422
        saved = client.post("/api/alerts/policies", json={"kind": "suppress", "title": "USB device", "entity_ref": "casey"})
        assert saved.status_code == 201
        quiet = client.post("/api/alerts", json={"title": "USB device", "entity_type": "user", "entity_ref": "casey", "score": 70, "channel": "dlp"})
        assert quiet.json()["status"] == "suppressed"
        other = client.post("/api/alerts", json={"title": "Cloud destination", "entity_type": "user", "entity_ref": "casey", "score": 70, "channel": "dlp"})
        assert other.json()["status"] == "open"
        client.post("/api/alerts/policies", json={"kind": "whitelist", "entity_ref": "ada"})
        listed = client.post("/api/alerts", json={"title": "Risk score", "entity_type": "user", "entity_ref": "ada", "score": 40, "channel": "score"})
        assert listed.json()["status"] == "suppressed"
        client.post("/api/alerts/routes", json={"channel": "dlp", "min_score": 50, "assignee": "reviewer"})
        routed = client.post("/api/alerts", json={"title": "File pattern", "entity_type": "user", "entity_ref": "blair", "score": 65, "channel": "dlp"})
        assert routed.json()["status"] == "open" and routed.json()["assignee"] == "reviewer"
        with client.app.state.session_factory() as db:
            notice = db.query(Notice).filter_by(user="reviewer").one()
            assert notice.channel == "app" and "stays in the center" in notice.body and "not sent" in notice.body
        assert client.post("/api/alerts/routes", json={"channel": "analytic", "min_score": 10, "assignee": "queue-reviewer", "delivery": "webhook"}).status_code == 422
        client.post("/api/alerts/routes", json={"channel": "analytic", "min_score": 10, "assignee": "queue-reviewer", "delivery": "mq"})
        queued = client.post("/api/alerts", json={"title": "Library review", "entity_type": "user", "entity_ref": "blair", "score": 40, "channel": "analytic"})
        assert queued.json()["assignee"] == "queue-reviewer"
        with client.app.state.session_factory() as db:
            queued_notice = db.query(Notice).filter_by(user="queue-reviewer").one()
            assert queued_notice.channel == "mq" and "not sent" in queued_notice.body
        case = client.post("/api/cases", json={"title": "Held", "case_type": "Other", "risk": "low"})
        linked = client.post("/api/alerts", json={"title": "USB device", "entity_type": "user", "entity_ref": "casey", "score": 10, "channel": "dlp", "case_id": case.json()["id"]})
        assert linked.json()["status"] == "linked"
        first = client.post("/api/alerts", json={"title": "One", "entity_type": "user", "entity_ref": "group-user", "score": 10})
        second = client.post("/api/alerts", json={"title": "Two", "entity_type": "user", "entity_ref": "group-user", "score": 20})
        assert first.json()["status"] == "open" and second.json()["status"] == "open"
        groups = client.get("/api/alerts/groups").json()
        matched = next(item for item in groups if item["entity_ref"] == "group-user")
        assert {item["title"] for item in matched["alerts"]} == {"One", "Two"}
        with client.app.state.session_factory() as db:
            from app.models import CaseField, CaseFieldValue
            field = CaseField(case_type="Other", key="callback_number", label="Callback number", required=False, position=0)
            db.add(field)
            db.flush()
            db.add(CaseFieldValue(case_id=case.json()["id"], field_id=field.id, value="555-0199"))
            db.commit()
        fields = client.get(f"/api/reports/cases/{case.json()['id']}/fields").json()
        assert fields == [{"key": "callback_number", "label": "Callback number", "value": "555-0199", "required": False}]
        with client.app.state.session_factory() as db:
            from app.models import User
            db.query(User).filter_by(username="investigator").one().role = "viewer"
            db.commit()
        assert client.post("/api/alerts/policies", json={"kind": "whitelist", "entity_ref": "ada"}).status_code == 403
