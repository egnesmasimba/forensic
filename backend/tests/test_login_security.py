from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from fastapi.testclient import TestClient

from app.auth import hash_password
from app.main import create_app
from app.models import AuthenticationAudit, Base, LoginSession, LoginThrottle, User, utcnow


def security_app(tmp_path):
    app = create_app(f"sqlite:///{(tmp_path / 'security.db').as_posix()}", seed=False)
    Base.metadata.create_all(app.state.engine)
    with app.state.session_factory() as db:
        db.add(User(username="admin", role="administrator", password_hash=hash_password("test-password-123")))
        db.commit()
    return app


def sign_in(client, username="admin", password="wrong", **kwargs):
    return client.post("/api/auth/login", json={"username": username, "password": password}, **kwargs)


def test_account_limit_persists_and_expires(tmp_path):
    app = security_app(tmp_path)
    with TestClient(app) as client:
        for _ in range(5):
            assert sign_in(client, username=" ADMIN ").status_code == 401
        blocked = sign_in(client, password="test-password-123")
        assert blocked.status_code == 429
        assert 1 <= int(blocked.headers["retry-after"]) <= 900
        with app.state.session_factory() as db:
            assert db.query(LoginSession).count() == 0
            assert db.query(AuthenticationAudit).filter_by(outcome="invalid_credentials").count() == 5
            assert db.query(AuthenticationAudit).filter_by(outcome="throttled").count() == 1
    # Recreate the application to ensure the limit survives restarts.
    restarted = create_app(f"sqlite:///{(tmp_path / 'security.db').as_posix()}", seed=False)
    with TestClient(restarted) as client:
        assert sign_in(client, password="test-password-123").status_code == 429
        with restarted.state.session_factory() as db:
            for bucket in db.query(LoginThrottle).all():
                bucket.window_start = utcnow() - timedelta(seconds=901)
            db.commit()
        success = sign_in(client, password="test-password-123")
        assert success.status_code == 200
        client.headers["X-CSRF-Token"] = success.json()["csrf"]
        audit = client.get("/api/auth/audit?limit=2").json()
        assert len(audit) == 2
        assert audit[0]["outcome"] == "signed_in"
        assert "password" not in str(audit) and "csrf" not in str(audit)
        older = client.get(f"/api/auth/audit?before_id={audit[-1]['id']}").json()
        assert all(row["id"] < audit[-1]["id"] for row in older)
        assert client.post("/api/auth/logout").status_code == 200
        assert client.get("/api/auth/audit").status_code == 401
        with restarted.state.session_factory() as db:
            assert db.query(AuthenticationAudit).order_by(AuthenticationAudit.id.desc()).first().outcome == "signed_out"


def test_address_limit_and_audit_access(tmp_path):
    app = security_app(tmp_path)
    with TestClient(app) as client:
        for number in range(20):
            # Changing an untrusted forwarded header must not evade the address bucket.
            assert sign_in(client, username=f"unknown-{number}", headers={"X-Forwarded-For": f"10.0.0.{number}"}).status_code == 401
        assert sign_in(client, username="new-name").status_code == 429
        assert client.get("/api/auth/audit").status_code == 401
        with app.state.session_factory() as db:
            assert {row.client_address for row in db.query(AuthenticationAudit).all()} == {"testclient"}
            for bucket in db.query(LoginThrottle).all():
                bucket.window_start = utcnow() - timedelta(seconds=901)
            db.commit()
        login = sign_in(client, password="test-password-123")
        client.headers["X-CSRF-Token"] = login.json()["csrf"]
        with app.state.session_factory() as db:
            db.query(User).filter_by(username="admin").first().role = "viewer"
            db.commit()
        assert client.get("/api/auth/audit").status_code == 403
        result = sign_in(client, headers={"Origin": "https://untrusted.example"})
        assert result.status_code == 403
        with app.state.session_factory() as db:
            assert db.query(AuthenticationAudit).order_by(AuthenticationAudit.id.desc()).first().outcome == "origin_rejected"


def test_concurrent_account_attempts_obey_limit(tmp_path):
    app = security_app(tmp_path)
    with TestClient(app):
        def attempt(_):
            with TestClient(app) as client:
                return sign_in(client, username="unknown-account").status_code
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(attempt, range(8)))
        assert statuses.count(401) == 5
        assert statuses.count(429) == 3
