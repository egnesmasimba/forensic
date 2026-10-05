from app.auth import hash_password
from app.models import User
from test_api import make_client
from test_imports import activity_csv


def test_password_recovery_hashes_and_thresholds(tmp_path):
    with make_client(tmp_path) as client:
        with client.app.state.session_factory() as db:
            db.add(User(username="admin", password_hash=hash_password("admin-password-123"), role="administrator"))
            db.commit()

        changed = client.post("/api/auth/password", json={"current_password": "wrong-password", "new_password": "updated-password-1"})
        assert changed.status_code == 401
        changed = client.post("/api/auth/password", json={"current_password": "test-password-123", "new_password": "updated-password-1"})
        assert changed.status_code == 200
        assert client.get("/api/auth/me").status_code == 200

        case = client.post("/api/cases", json={"title": "Hash check", "case_type": "Other"}).json()
        upload = client.post(f"/api/cases/{case['id']}/attachments", files={"file": ("note.txt", b"hello")})
        assert upload.status_code == 201
        assert len(upload.json()["sha256"]) == 64
        intact = client.get(f"/api/cases/{case['id']}/attachments/{upload.json()['id']}/integrity")
        assert intact.json()["matches"] is True
        stored = next((tmp_path / "files").rglob("*.txt"))
        stored.write_bytes(b"changed")
        assert client.get(f"/api/cases/{case['id']}/attachments/{upload.json()['id']}/integrity").json()["matches"] is False

        detail = client.get(f"/api/cases/{case['id']}").json()
        assert detail["attachments"] and detail["activities"]

        login = client.post("/api/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert login.status_code == 200
        client.headers["X-CSRF-Token"] = login.json()["csrf"]
        accounts = client.get("/api/auth/users").json()
        investigator = next(account for account in accounts if account["username"] == "investigator")
        administrator = next(account for account in accounts if account["username"] == "admin")
        assert client.patch(f"/api/auth/users/{administrator['id']}", json={"disabled": True}).status_code == 409
        assert client.patch(f"/api/auth/users/{investigator['id']}", json={"disabled": True}).status_code == 200
        assert client.post("/api/auth/login", json={"username": "investigator", "password": "updated-password-1"}).status_code == 401
        assert client.post(f"/api/auth/users/{investigator['id']}/password", json={"password": "recovered-password-1"}).status_code == 200
        assert client.patch(f"/api/auth/users/{investigator['id']}", json={"disabled": False}).status_code == 200

        failures = activity_csv(
            ["f1", "2026-10-03T12:00:00Z", "omar", "login_failure", "web", 0, 0],
            ["f2", "2026-10-03T12:01:00Z", "omar", "login_failure", "web", 0, 0],
            ["f3", "2026-10-03T12:02:00Z", "omar", "login_failure", "web", 0, 0],
        )
        grouped = client.post("/api/imports/csv", data={"source": "sign-in export"}, files={"file": ("activity.csv", failures, "text/csv")})
        assert grouped.status_code == 201
        assert grouped.json()["alerts_created"] == 1
        assert client.put("/api/detection/settings/login-failures", json={"threshold": 9, "score": 60, "enabled": True}).status_code == 200
        later = activity_csv(
            ["f4", "2026-10-03T12:03:00Z", "omar", "login_failure", "web", 0, 0],
            ["f5", "2026-10-03T12:04:00Z", "omar", "login_failure", "web", 0, 0],
            ["f6", "2026-10-03T12:05:00Z", "omar", "login_failure", "web", 0, 0],
        )
        assert client.post("/api/imports/csv", data={"source": "sign-in export"}, files={"file": ("activity.csv", later, "text/csv")}).json()["alerts_created"] == 0
        recovered = client.post("/api/auth/login", json={"username": "investigator", "password": "recovered-password-1"})
        assert recovered.status_code == 200
