from app.models import User
from app.websites import CATEGORIES
from test_api import make_client

VISITS = (
    "visit_id,occurred_at,user,url,seconds\n"
    "v1,2026-10-03T12:00:00+00:00,casey,https://news.example.com/story?q=1,30\n"
    "v2,2026-10-03T18:00:00+00:00,casey,https://games.example.net/,90\n"
).encode()


def test_visit_categories_time_and_policy(tmp_path):
    assert len(CATEGORIES) >= 42
    with make_client(tmp_path) as client:
        with client.app.state.session_factory() as db:
            db.query(User).filter_by(username="investigator").one().role = "administrator"
            db.commit()
        assert client.post("/api/websites/rules", json={"host": "example.com", "category": "News"}).status_code == 201
        assert client.post("/api/websites/rules", json={"host": "example.net", "category": "Games"}).status_code == 201
        denied = client.put("/api/websites/policy/Games", json={"denied": True})
        assert denied.status_code == 200
        imported = client.post("/api/websites/visits", data={"source": "proxy"}, files={"file": ("visits.csv", VISITS, "text/csv")})
        assert imported.status_code == 201
        assert imported.json()["accepted"] == 2
        assert imported.json()["alerts_created"] == 1
        again = client.post("/api/websites/visits", data={"source": "proxy"}, files={"file": ("visits.csv", VISITS, "text/csv")})
        assert again.json()["duplicates"] == 2
        assert again.json()["alerts_created"] == 0
        report = {row["category"]: row for row in client.get("/api/websites/report").json()}
        assert report["News"]["seconds"] == 30
        assert report["Games"]["visits"] == 1
        pattern = client.get("/api/websites/patterns").json()[0]
        assert pattern["user"] == "casey"
        assert pattern["primary_category"] == "Games"
        assert pattern["denied_visits"] == 1
        assert pattern["seconds"] == 120
        changed = VISITS.replace(b",30\n", b",40\n")
        assert client.post("/api/websites/visits", data={"source": "proxy"}, files={"file": ("visits.csv", changed, "text/csv")}).status_code == 409
