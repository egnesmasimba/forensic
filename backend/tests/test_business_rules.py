from test_api import make_client


def fact(client, **fields):
    body = {
        "entity_type": "user", "entity_ref": "casey", "name": "terminal", "numeric_value": 1,
        "text_value": "", "occurred_at": "2026-10-03T12:00:00+00:00",
    }
    body.update(fields)
    response = client.post("/api/analytics/facts", json=body)
    assert response.status_code == 201
    return response


def rule(client, **fields):
    body = {
        "name": "Sample", "version": 1, "entity_type": "user", "fact_name": "terminal",
        "aggregation": "count", "comparator": "gte", "threshold": 1, "score": 60, "kind": "what",
    }
    body.update(fields)
    return client.post("/api/analytics/rules/test", json=body)


def test_rule_types_preview_and_scores(tmp_path):
    with make_client(tmp_path) as client:
        fact(client, text_value="USB", occurred_at="2026-10-03T22:00:00+00:00")
        fact(client, text_value="branch", occurred_at="2026-10-03T22:30:00+00:00")
        client.put("/api/analytics/entities", json={
            "entity_type": "user", "entity_ref": "casey", "attribute_key": "department", "attribute_value": "IT",
        })
        assert rule(client, kind="what", list_mode="deny", list_values="USB").json()["matches"][0]["value"] == 1
        assert rule(client, kind="how", pattern="usb", name="Search").json()["matches"][0]["entity_ref"] == "casey"
        assert rule(client, kind="when", name="Hours").json()["matches"][0]["value"] == 2
        assert rule(client, kind="where", name="Department", attribute_key="department", attribute_value="IT", aggregation="count", threshold=2).json()["matches"]
        assert rule(client, kind="time_correlation", name="Terminals", threshold=2).json()["matches"][0]["value"] == 2
        fact(client, entity_type="account", entity_ref="ACC-1", name="beneficiary", text_value="Ada", occurred_at="2026-10-03T12:00:00+00:00")
        fact(client, entity_type="account", entity_ref="ACC-2", name="beneficiary", text_value="Ada", occurred_at="2026-10-03T12:10:00+00:00")
        shared = rule(client, kind="data_correlation", name="Beneficiary", entity_type="account", fact_name="beneficiary", threshold=2)
        assert shared.json()["matches"][0]["entity_ref"] == "Ada"
        fact(client, name="action", text_value="add", occurred_at="2026-10-03T12:00:00+00:00")
        fact(client, name="action", text_value="transfer", occurred_at="2026-10-03T12:20:00+00:00")
        fact(client, name="action", text_value="delete", occurred_at="2026-10-03T12:40:00+00:00")
        steps = rule(client, kind="process", name="Sequence", fact_name="action", steps="add, transfer, delete")
        assert steps.json()["matches"][0]["value"] == 3
        saved = client.post("/api/analytics/rules", json={
            "name": "After hours", "version": 1, "kind": "when", "entity_type": "user", "fact_name": "terminal",
            "aggregation": "count", "threshold": 1, "score": 70,
        })
        assert saved.status_code == 201
        assert client.post("/api/analytics/rules", json={
            "name": "After hours", "version": 2, "kind": "when", "entity_type": "user", "fact_name": "terminal",
            "aggregation": "count", "threshold": 1, "score": 40,
        }).status_code == 201
        client.put("/api/analytics/score-threshold", json={"threshold": 100})
        first = client.post("/api/analytics/evaluate")
        assert first.json()["alerts_created"] == 2
        assert client.get("/api/analytics/scores").json()["current"][0]["score"] == 110
        titles = [item["title"] for item in client.get("/api/alerts").json()]
        assert "Risk score" in titles
