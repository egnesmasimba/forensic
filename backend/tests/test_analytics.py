from test_api import make_client
from test_imports import activity_csv, upload


def test_rules_aggregate_new_and_historic_facts(tmp_path):
    with make_client(tmp_path) as client:
        first = upload(client, activity_csv(
            ["a1", "2026-10-03T09:00:00+00:00", "casey", "file_transfer", "local", 40, 2],
            ["a2", "2026-10-03T09:05:00+00:00", "casey", "file_transfer", "local", 70, 1],
        ))
        assert first.status_code == 201
        assert first.json()["alerts_created"] == 0
        saved = client.put("/api/analytics/entities", json={
            "entity_type": "user", "entity_ref": "casey", "attribute_key": "executive", "attribute_value": "yes",
        })
        assert saved.json()["static_info"]["executive"] == "yes"
        rule = client.post("/api/analytics/rules", json={
            "name": "Large bytes", "version": 1, "entity_type": "user", "fact_name": "bytes",
            "aggregation": "sum", "comparator": "gte", "threshold": 100, "score": 80,
            "attribute_key": "executive", "attribute_value": "yes",
        })
        assert rule.status_code == 201
        historic = client.post("/api/analytics/evaluate")
        assert historic.status_code == 201
        assert historic.json()["alerts_created"] == 1
        assert client.post("/api/analytics/evaluate").json()["alerts_created"] == 0
        live = upload(client, activity_csv(
            ["b1", "2026-10-03T10:00:00+00:00", "drew", "data_export", "report", 0, 5],
        ), source="second log")
        assert live.json()["alerts_created"] == 0
        counted = client.post("/api/analytics/rules", json={
            "name": "Few records", "version": 1, "entity_type": "user", "fact_name": "records",
            "aggregation": "max", "comparator": "lte", "threshold": 5, "score": 40,
        })
        assert counted.status_code == 201
        again = client.post("/api/analytics/evaluate").json()
        assert again["alerts_created"] == 2
        entities = {row["entity_ref"]: row for row in client.get("/api/analytics/entities").json()}
        assert entities["casey"]["dynamic_info"]["fact_count"] == 8
        assert client.post("/api/analytics/rules", json={
            "name": "Large bytes", "version": 1, "entity_type": "user", "fact_name": "bytes",
            "aggregation": "count", "threshold": 1,
        }).status_code == 409
