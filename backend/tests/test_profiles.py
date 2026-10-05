from datetime import datetime, timedelta, timezone

from test_api import make_client

AS_OF = datetime(2026, 10, 3, 18, tzinfo=timezone.utc)


def post_fact(client, **fields):
    body = {
        "entity_type": "user", "entity_ref": "casey", "name": "transfer", "numeric_value": 1,
        "text_value": "", "occurred_at": AS_OF.isoformat(),
    }
    body.update(fields)
    response = client.post("/api/analytics/facts", json=body)
    assert response.status_code == 201, response.text


def on_day(offset, hour=12):
    return (AS_OF - timedelta(days=offset)).replace(hour=hour, minute=0, second=0, microsecond=0).isoformat()


def test_trend_workload_time_sentiment_and_accuracy(tmp_path):
    with make_client(tmp_path) as client:
        for offset in range(28, 14, -1):
            post_fact(client, occurred_at=on_day(offset))
        for offset in range(13, -1, -1):
            for _copy in range(4):
                post_fact(client, occurred_at=on_day(offset, 8 + _copy))
        for offset in (3, 2, 1):
            post_fact(client, entity_ref="longday", name="work_minutes", numeric_value=600, occurred_at=on_day(offset))
        post_fact(client, entity_ref="signal", name="turnover_signal", numeric_value=1, occurred_at=on_day(1))
        post_fact(client, entity_ref="casey", name="activity_minutes", numeric_value=50, text_value="work", occurred_at=on_day(1))
        post_fact(client, entity_ref="casey", name="activity_minutes", numeric_value=30, text_value="meeting", occurred_at=on_day(1, 15))
        post_fact(client, entity_ref="casey", name="idle_minutes", numeric_value=20, occurred_at=on_day(2))
        post_fact(client, entity_ref="mood", name="sentiment_signal", numeric_value=-0.6, occurred_at=on_day(2))
        post_fact(client, entity_ref="mood", name="sentiment_signal", numeric_value=-0.8, text_value="distressed", occurred_at=on_day(1))
        picture = client.get("/api/profiles/review", params={"entity_ref": "casey", "as_of": AS_OF.isoformat()}).json()
        assert picture["threat"]["rising"] is True
        load = client.get("/api/profiles/review", params={"entity_ref": "longday", "as_of": AS_OF.isoformat()}).json()["workload"]
        assert load["overwork_days"] == 3 and load["score"] >= 60
        assert client.get("/api/profiles/review", params={"entity_ref": "signal", "as_of": AS_OF.isoformat()}).json()["workload"]["turnover_signals"] == 1
        used = client.get("/api/profiles/time", params={"entity_ref": "casey", "as_of": AS_OF.isoformat()}).json()
        assert used["work"] == 50 and used["meeting"] is True and used["idle"] is True
        assert used["productivity"] == 0.5
        mood = client.get("/api/profiles/review", params={"entity_ref": "mood", "as_of": AS_OF.isoformat()}).json()["sentiment"]
        assert mood["disgruntled"] is True and mood["distressed"] is True and mood["label"] == "strained"
        titles = [item["title"] for item in client.get("/api/alerts").json()]
        assert "Threat prediction" in titles
        assert "Burnout risk" in titles
        assert "Turnover signal" in titles
        assert "Sentiment signal" in titles
        assert client.post("/api/profiles/refresh", json={"entity_ref": "casey", "as_of": AS_OF.isoformat()}).json()["alerts_created"] == 0
        prediction = client.get("/api/profiles/predictions", params={"entity_ref": "casey"}).json()[0]
        assert client.post(f"/api/profiles/predictions/{prediction['id']}/outcome", json={"outcome": "confirmed"}).status_code == 200
        assert client.get("/api/profiles/predictions/accuracy").json()["rate"] == 1


def test_synthetic_profile_peers_and_library(tmp_path):
    with make_client(tmp_path) as client:
        for _index in range(10):
            post_fact(client, occurred_at=on_day(0, _index))
        post_fact(client, entity_ref="drew", occurred_at=on_day(0, 11))
        client.put("/api/analytics/entities", json={"entity_type": "user", "entity_ref": "casey", "attribute_key": "department", "attribute_value": "IT"})
        client.put("/api/analytics/entities", json={"entity_type": "user", "entity_ref": "drew", "attribute_key": "department", "attribute_value": "IT"})
        client.put("/api/analytics/entities", json={"entity_type": "user", "entity_ref": "casey", "attribute_key": "role", "attribute_value": "analyst"})
        client.put("/api/analytics/entities", json={"entity_type": "user", "entity_ref": "casey", "attribute_key": "group", "attribute_value": "branch"})
        compared = client.get("/api/profiles/peers", params={"entity_ref": "casey", "as_of": AS_OF.isoformat()}).json()
        assert compared["above_peers"] is True
        assert compared["department_mean"] > 0
        grouped = client.get("/api/profiles/groups", params={"entity_type": "user", "group": "branch", "as_of": AS_OF.isoformat()}).json()
        assert grouped["members"][0]["entity_ref"] == "casey"
        twin = client.post("/api/profiles/synthetic", json={"entity_ref": "casey", "as_of": AS_OF.isoformat()})
        assert twin.status_code == 201
        published = client.get(f"/api/profiles/synthetic/{twin.json()['token']}")
        assert "entity_ref" not in published.json()
        assert "casey" not in published.text
        rules = {row["key"]: row for row in client.get("/api/profiles/library").json()}
        assert {"nist", "mitre", "cert", "fsisac"} <= {row["framework"] for row in rules.values()}
        assert client.post("/api/profiles/library/update").json()["added"] == 0
        saved = client.put("/api/profiles/library/fsisac-wires", json={"enabled": False, "threshold": 99999, "score": 10})
        assert saved.json()["customized"] is True
        assert client.post("/api/profiles/library/update").json()["added"] == 0
        assert client.get("/api/profiles/library").json()
        kept = {row["key"]: row for row in client.get("/api/profiles/library").json()}["fsisac-wires"]
        assert kept["enabled"] is False and kept["threshold"] == 99999
        again = client.post("/api/profiles/library/evaluate", json={"entity_ref": "casey", "as_of": AS_OF.isoformat()})
        assert again.json()["alerts_created"] == 0
