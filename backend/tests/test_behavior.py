import json
from datetime import datetime, timezone

from app.mail_models import MailEvidence
from test_api import make_client

AS_OF = "2026-10-03T18:00:00+00:00"


def fact(client, **fields):
    body = {
        "entity_type": "user", "entity_ref": "casey", "name": "account_access", "numeric_value": 1,
        "text_value": "", "occurred_at": "2026-10-01T12:00:00+00:00",
    }
    body.update(fields)
    response = client.post("/api/analytics/facts", json=body)
    assert response.status_code == 201, response.text
    return response


def test_named_indicators_custom_definition_and_baseline(tmp_path):
    with make_client(tmp_path) as client:
        client.put("/api/analytics/baseline-settings", json={"sigma": 3, "minimum_periods": 50})
        fact(client, text_value="ACC-1")
        fact(client, text_value="ACC-2", occurred_at="2026-10-01T13:00:00+00:00")
        fact(client, name="dormant_account_access", text_value="ACC-D1", occurred_at="2026-09-15T09:00:00+00:00")
        fact(client, name="dormant_account_access", text_value="ACC-D2", occurred_at="2026-09-15T10:00:00+00:00")
        fact(client, name="address_change", occurred_at="2026-09-10T09:00:00+00:00")
        fact(client, name="beneficiary_change", occurred_at="2026-09-10T10:00:00+00:00")
        fact(client, name="mailing_frequency_change", occurred_at="2026-09-10T11:00:00+00:00")
        fact(client, name="dormant_attribute_change", occurred_at="2026-09-11T09:00:00+00:00")
        fact(client, name="customer_name_query", occurred_at="2026-09-11T10:00:00+00:00")
        fact(client, name="attribute_change", text_value="address|home|office", occurred_at="2026-10-01T10:00:00+00:00")
        fact(client, name="attribute_change", text_value="address|office|home", occurred_at="2026-10-02T10:00:00+00:00")
        fact(client, name="attribute_change", text_value="limit|1|2", occurred_at="2026-09-01T10:00:00+00:00")
        fact(client, name="attribute_change", text_value="limit|2|1", occurred_at="2026-09-05T10:00:00+00:00")
        for day in ("2026-09-01", "2026-09-02", "2026-09-03", "2026-09-04"):
            fact(client, name="transfer", numeric_value=10, occurred_at=f"{day}T12:00:00+00:00")
        for index in range(20):
            fact(client, name="transfer", numeric_value=100, occurred_at=f"2026-10-03T12:{index:02d}:00+00:00")
        fact(client, entity_ref="quiet", name="transfer", numeric_value=500, occurred_at=AS_OF)
        added = client.post("/api/analytics/indicators", json={
            "key": "cash_count", "label": "Cash count per day", "fact_name": "cash", "measure": "count", "period": "day",
        })
        assert added.status_code == 201
        assert client.post("/api/analytics/indicators", json={
            "key": "cash_count", "label": "Cash count per day", "fact_name": "cash", "measure": "count", "period": "day",
        }).status_code == 409
        rows = {row["key"]: row for row in client.get("/api/analytics/indicators", params={"entity_ref": "casey", "as_of": AS_OF}).json()}
        assert rows["accounts_accessed"]["total"] == 2 and rows["accounts_accessed"]["periods"] == 90
        assert rows["dormant_accounts_accessed"]["total"] == 2
        assert rows["address_changes"]["total"] == 1
        assert rows["beneficiary_changes"]["total"] == 1
        assert rows["mailing_frequency_changes"]["total"] == 1
        assert rows["dormant_attribute_changes"]["total"] == 1
        assert rows["customer_name_queries"]["total"] == 1
        assert rows["transfer_amount"]["total"] == 2040
        assert rows["transfer_count"]["total"] == 24
        assert rows["attribute_reverts"]["total"] == 1
        assert "cash_count" in rows
        held = client.post("/api/analytics/baselines/refresh", json={"entity_ref": "casey", "as_of": AS_OF})
        assert held.json()["alerts_created"] == 0
        client.put("/api/analytics/baseline-settings", json={"sigma": 3, "minimum_periods": 4})
        opened = client.post("/api/analytics/baselines/refresh", json={"entity_ref": "casey", "as_of": AS_OF})
        assert opened.json()["alerts_created"] == 2
        assert client.post("/api/analytics/baselines/refresh", json={"entity_ref": "casey", "as_of": AS_OF}).json()["alerts_created"] == 0
        assert client.post("/api/analytics/baselines/refresh", json={"entity_ref": "quiet", "as_of": AS_OF}).json()["alerts_created"] == 0
        titles = [item["title"] for item in client.get("/api/alerts").json()]
        assert titles.count("Behavior baseline") == 2


def test_channel_events_share_one_user_view(tmp_path):
    with make_client(tmp_path) as client:
        events = [
            {"source_key": "phone-1", "channel": "phone", "user": "casey", "occurred_at": "2026-10-03T09:00:00+00:00", "action": "call", "reference": "CALL-10"},
            {"source_key": "email-1", "channel": "email", "user": "casey", "occurred_at": "2026-10-03T09:05:00+00:00", "action": "send", "reference": "MSG-2"},
            {"source_key": "chat-1", "channel": "chat", "user": "casey", "occurred_at": "2026-10-03T09:06:00+00:00", "action": "message", "reference": "CHAT-3"},
            {"source_key": "system-1", "channel": "system", "user": "casey", "occurred_at": "2026-10-03T09:07:00+00:00", "action": "login", "reference": "TERM-4"},
        ]
        assert client.post("/api/analytics/channels", json={"events": events}).json()["stored"] == 4
        assert client.post("/api/analytics/channels", json={"events": events}).json()["stored"] == 0
        with client.app.state.session_factory() as db:
            db.add(MailEvidence(
                fingerprint="f" * 64, client="thunderbird", subject="Quarterly review",
                occurred_at=datetime(2026, 10, 2, tzinfo=timezone.utc), captured_by="casey",
                report=json.dumps({
                    "body": "message body should stay out of the channel view",
                    "sender": "person@company.test", "recipient_domains": [], "attachments": [],
                }),
            ))
            db.commit()
        view = client.get("/api/analytics/channels", params={"user": "casey"})
        assert view.status_code == 200
        channels = view.json()["channels"]
        assert channels["phone"]["count"] == 1
        assert channels["chat"]["count"] == 1
        assert channels["system"]["count"] == 1
        assert channels["email"]["count"] == 2
        assert "Quarterly review" in view.text
        assert "message body should stay out of the channel view" not in view.text
