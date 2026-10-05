from datetime import timedelta

from fastapi.testclient import TestClient

from app.auth import hash_password
from app.main import create_app
from app.models import Base, LoginSession, User, utcnow


def test_permissions_sessions_and_attribution(tmp_path):
    app = create_app(f"sqlite:///{(tmp_path / 'auth.db').as_posix()}", seed=False,
                     attachment_dir=tmp_path / "files")
    Base.metadata.create_all(app.state.engine)
    with app.state.session_factory() as db:
        for role in ("administrator", "investigator", "viewer"):
            db.add(User(username=role, role=role, password_hash=hash_password("test-password-123")))
        db.commit()
    with TestClient(app) as client:
        for route in ("/api/cases", "/api/alerts", "/api/meta", "/api/auth/users",
                      "/api/cases/1/attachments/1", "/api/reports/cases.csv",
                      "/api/reports/cases.xlsx", "/api/reports/cases/1.pdf"):
            assert client.get(route).status_code == 401
        assert client.post("/api/auth/login", json={"username": "viewer", "password": "wrong"}).status_code == 401

        def login(role):
            result = client.post("/api/auth/login", json={"username": role, "password": "test-password-123"})
            assert result.status_code == 200
            assert "httponly" in result.headers["set-cookie"].lower()
            client.headers["X-CSRF-Token"] = result.json()["csrf"]
            return result

        login("investigator")
        payload = {"title": "Protected case", "case_type": "Other", "actor": "Forged identity"}
        client.headers.pop("X-CSRF-Token")
        assert client.post("/api/cases", json=payload).status_code == 403
        login("investigator")
        created = client.post("/api/cases", json=payload)
        assert created.status_code == 201
        assert created.json()["activities"][0]["actor"] == "investigator"
        case_id = created.json()["id"]
        note = client.post(f"/api/cases/{case_id}/notes", json={"body": "Review note", "author": "Forged"})
        assert note.json()["notes"][0]["author"] == "investigator"
        upload = client.post(f"/api/cases/{case_id}/attachments", files={"file": ("evidence.txt", b"Evidence")})
        assert upload.status_code == 201
        assert upload.json()["uploaded_by"] == "investigator"
        attachment_id = upload.json()["id"]
        assert client.post("/api/auth/users", json={"username": "other", "password": "test-password-123", "role": "viewer"}).status_code == 403

        login("viewer")
        assert client.get("/api/cases").status_code == 200
        assert client.get("/api/reports/cases.csv").status_code == 200
        for method, path, body in (
            ("POST", "/api/cases", payload),
            ("PATCH", f"/api/cases/{case_id}", {"summary": "Changed"}),
            ("POST", f"/api/cases/{case_id}/notes", {"body": "Changed"}),
            ("POST", f"/api/cases/{case_id}/transition", {"status": "closed"}),
            ("POST", "/api/alerts", {"title": "Fake alert"}),
            ("DELETE", f"/api/cases/{case_id}/attachments/{attachment_id}", None),
        ):
            assert client.request(method, path, json=body).status_code == 403
        assert client.post(f"/api/cases/{case_id}/attachments", files={"file": ("evidence.txt", b"Evidence")}).status_code == 403
        assert client.get(f"/api/cases/{case_id}/attachments/{attachment_id}").status_code == 200

        login("administrator")
        account = {"username": "NewViewer", "password": "test-password-123", "role": "viewer"}
        assert client.post("/api/auth/users", json=account).status_code == 201
        assert client.post("/api/auth/users", json=account).status_code == 409
        assert client.get("/api/auth/users").status_code == 200
        cookie = client.cookies.get("zanaq_session")
        assert client.post("/api/auth/logout").status_code == 200
        client.cookies.set("zanaq_session", cookie)
        assert client.get("/api/cases").status_code == 401
        login("viewer")
        with app.state.session_factory() as db:
            for session in db.query(LoginSession).all():
                session.expires_at = utcnow() - timedelta(seconds=1)
            db.commit()
        assert client.get("/api/auth/me").status_code == 401
