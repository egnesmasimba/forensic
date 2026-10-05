"""Self-registration is opt-in, read-only by construction, and rate limited."""
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.auth import ADDRESS_REGISTRATION_LIMIT, REGISTRATION_ROLE, verify_password
from app.main import create_app
from app.models import AuthenticationAudit, Base, LoginThrottle, User, utcnow

PASSWORD = "registered-password-123"


@pytest.fixture
def registration_app(tmp_path, monkeypatch):
    monkeypatch.setenv("ZANAQ_ALLOW_REGISTRATION", "1")
    app = create_app(f"sqlite:///{(tmp_path / 'register.db').as_posix()}", seed=False)
    Base.metadata.create_all(app.state.engine)
    return app


def register(client, username, password=PASSWORD, **kwargs):
    return client.post("/api/auth/register",
                       json={"username": username, "password": password}, **kwargs)


def test_registration_is_off_unless_explicitly_enabled(tmp_path):
    app = create_app(f"sqlite:///{(tmp_path / 'off.db').as_posix()}", seed=False)
    Base.metadata.create_all(app.state.engine)
    with TestClient(app) as client:
        assert client.get("/api/auth/registration").json()["enabled"] is False
        # 404 rather than 403, so a disabled deployment does not advertise it.
        assert register(client, "newcomer").status_code == 404
        with app.state.session_factory() as db:
            assert db.query(User).count() == 0

    # An explicit falsy value stays disabled.
    os.environ["ZANAQ_ALLOW_REGISTRATION"] = "0"
    try:
        with TestClient(app) as client:
            assert client.get("/api/auth/registration").json()["enabled"] is False
            assert register(client, "newcomer").status_code == 404
    finally:
        os.environ.pop("ZANAQ_ALLOW_REGISTRATION", None)


def test_status_endpoint_advertises_the_granted_role(registration_app):
    with TestClient(registration_app) as client:
        status = client.get("/api/auth/registration").json()
        assert status == {"enabled": True, "password_minimum": 12, "role": "viewer"}


def test_registration_creates_a_usable_read_only_account(registration_app):
    with TestClient(registration_app) as client:
        created = register(client, "  Newcomer  ")
        assert created.status_code == 201
        body = created.json()
        assert body["username"] == "newcomer"  # trimmed and lower-cased
        assert body["role"] == REGISTRATION_ROLE == "viewer"
        assert body["disabled"] is False
        # The response must not echo the password or its hash.
        assert PASSWORD not in created.text and "password_hash" not in created.text
    with registration_app.state.session_factory() as db:
        account = db.query(User).filter_by(username="newcomer").one()
        assert verify_password(PASSWORD, account.password_hash)
    # The account can sign in, and a viewer still cannot write.
    with TestClient(registration_app) as client:
        assert register(client, "newcomer").status_code == 409
        login = client.post("/api/auth/login",
                            json={"username": "newcomer", "password": PASSWORD})
        assert login.status_code == 200
        client.headers["X-CSRF-Token"] = login.json()["csrf"]
        assert client.get("/api/auth/me").status_code == 200
        assert client.get("/api/auth/users").status_code == 403
        assert client.post("/api/cases", json={"title": "nope"}).status_code == 403


def test_role_cannot_be_requested_by_the_caller(registration_app):
    with TestClient(registration_app) as client:
        # Silently downgrading an escalation attempt would look like success.
        escalated = client.post("/api/auth/register", json={
            "username": "sneaky", "password": PASSWORD, "role": "administrator"})
        assert escalated.status_code == 422
    with registration_app.state.session_factory() as db:
        assert db.query(User).filter_by(username="sneaky").count() == 0


def test_short_password_and_blank_username_are_rejected(registration_app):
    with TestClient(registration_app) as client:
        assert register(client, "weak", password="short").status_code == 422
        assert register(client, "   ").status_code == 422
    with registration_app.state.session_factory() as db:
        assert db.query(User).count() == 0


def test_cross_origin_registration_is_refused_and_audited(registration_app):
    with TestClient(registration_app) as client:
        blocked = register(client, "cross-site", headers={"origin": "https://evil.example"})
        assert blocked.status_code == 403
    with registration_app.state.session_factory() as db:
        assert db.query(User).filter_by(username="cross-site").count() == 0
        assert db.query(AuthenticationAudit).filter_by(
            outcome="registration_origin_rejected").count() == 1


def test_registration_attempts_are_rate_limited(registration_app):
    with TestClient(registration_app) as client:
        # Distinct usernames, so only the per-address bucket can be responsible.
        for index in range(ADDRESS_REGISTRATION_LIMIT):
            assert register(client, f"user{index}").status_code == 201
        blocked = register(client, "one-too-many")
        assert blocked.status_code == 429
        assert 1 <= int(blocked.headers["retry-after"]) <= 3600
    with registration_app.state.session_factory() as db:
        assert db.query(User).filter_by(username="one-too-many").count() == 0
        assert db.query(AuthenticationAudit).filter_by(
            outcome="registration_throttled").count() == 1
        # The registration window is an hour, not the sign-in window of 15
        # minutes. SQLite returns naive datetimes, so compare against a naive now.
        freshest = max(bucket.window_start for bucket in db.query(LoginThrottle).all())
        assert freshest > utcnow().replace(tzinfo=None) - timedelta(seconds=60)


def test_registration_budget_is_separate_from_sign_in_budget(registration_app):
    # Saturating registration must not draw on the sign-in buckets. The two
    # helpers hash different scope strings, so the namespaces cannot collide;
    # this asserts that directly rather than inferring it from status codes.
    with TestClient(registration_app) as client:
        for index in range(ADDRESS_REGISTRATION_LIMIT):
            register(client, f"filler{index}")
        assert register(client, "one-too-many").status_code == 429
    client_address = "testclient"
    expected = {hashlib.sha256(f"{scope}:{value}".encode()).hexdigest()
                for scope, values in (("reg-account", [f"filler{i}" for i in range(ADDRESS_REGISTRATION_LIMIT)] + ["one-too-many"]),
                                      ("reg-address", [client_address]))
                for value in values}
    with registration_app.state.session_factory() as db:
        keys = {bucket.key for bucket in db.query(LoginThrottle).all()}
    assert keys == expected
    # No sign-in bucket was created or consumed along the way.
    assert not any(hashlib.sha256(f"account:{name}".encode()).hexdigest() in keys
                   for name in [f"filler{i}" for i in range(ADDRESS_REGISTRATION_LIMIT)])


def test_concurrent_registrations_respect_the_limit(registration_app):
    def attempt(index):
        with TestClient(registration_app) as client:
            return register(client, f"racer{index}").status_code

    with ThreadPoolExecutor(max_workers=ADDRESS_REGISTRATION_LIMIT + 4) as pool:
        codes = list(pool.map(attempt, range(ADDRESS_REGISTRATION_LIMIT + 4)))
    assert codes.count(201) == ADDRESS_REGISTRATION_LIMIT
    assert codes.count(429) == 4
    # Exactly the permitted number of distinct accounts exist. Which racers win
    # is not deterministic, so only the count and uniqueness are asserted.
    with registration_app.state.session_factory() as db:
        usernames = [row.username for row in db.query(User).all()]
        assert len(usernames) == ADDRESS_REGISTRATION_LIMIT
        assert len(set(usernames)) == ADDRESS_REGISTRATION_LIMIT
        assert all(name.startswith("racer") for name in usernames)


def test_registration_window_expires(registration_app):
    with TestClient(registration_app) as client:
        for index in range(ADDRESS_REGISTRATION_LIMIT):
            register(client, f"seed{index}")
        assert register(client, "later").status_code == 429
    with registration_app.state.session_factory() as db:
        for bucket in db.query(LoginThrottle).all():
            bucket.window_start = utcnow() - timedelta(seconds=3601)
        db.commit()
    with TestClient(registration_app) as client:
        assert register(client, "later").status_code == 201


def test_duplicate_and_success_are_audited(registration_app):
    with TestClient(registration_app) as client:
        register(client, "twice")
        register(client, "twice")
    with registration_app.state.session_factory() as db:
        outcomes = [row.outcome for row in db.query(AuthenticationAudit)
                    .filter_by(username="twice").order_by(AuthenticationAudit.id)]
        assert outcomes == ["registered", "registration_duplicate"]