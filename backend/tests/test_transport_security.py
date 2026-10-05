"""Server-side transport security: header policy, cookie policy, certificates.

The certificate generator is exercised end to end, including a real uvicorn TLS
listener, so "TLS works" is verified by a handshake rather than by inspecting
configuration values.
"""
from __future__ import annotations

import socket
import ssl
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.main import create_app
from app.models import Base, User
from app.transport_security import (TransportSettings, apply_security_headers,
                                    generate_certificate, install_transport_security,
                                    is_secure_request, secure_cookie_default, summary)
from endpoint_agent import tls


class _FakeRequest:
    def __init__(self, scheme="http", headers=None):
        self.scope = {"type": "http", "scheme": scheme}
        self.url = type("URL", (), {"scheme": scheme})()
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}


class _FakeResponse:
    def __init__(self):
        self.headers: dict[str, str] = {}


# -- settings -----------------------------------------------------------------

def test_defaults_are_conservative():
    settings = TransportSettings.from_env({})
    assert settings.require_https is False
    assert settings.trust_proxy_headers is False
    assert settings.secure_cookies is None
    assert settings.hsts is True


@pytest.mark.parametrize("raw,expected", [("1", True), ("true", True), ("YES", True), ("on", True),
                                         ("0", False), ("false", False), ("nonsense", False)])
def test_flags_accept_the_usual_spellings(raw, expected):
    settings = TransportSettings.from_env({"ZANAQ_REQUIRE_HTTPS": raw})
    assert settings.require_https is expected


def test_secure_cookies_is_a_three_state_setting():
    assert TransportSettings.from_env({}).secure_cookies is None
    assert TransportSettings.from_env({"ZANAQ_SECURE_COOKIES": "1"}).secure_cookies is True
    assert TransportSettings.from_env({"ZANAQ_SECURE_COOKIES": "0"}).secure_cookies is False


def test_hsts_max_age_is_configurable():
    assert TransportSettings.from_env({"ZANAQ_HSTS_MAX_AGE": "600"}).hsts_max_age == 600
    assert TransportSettings.from_env({"ZANAQ_HSTS": "0"}).hsts is False


def test_summary_reports_the_policy():
    text = repr(summary(TransportSettings.from_env({})))
    assert "require_https" in text and "TLS 1.2" in text


# -- request classification ---------------------------------------------------

def test_https_request_is_secure():
    assert is_secure_request(_FakeRequest(scheme="https"), TransportSettings()) is True


def test_plain_request_is_not_secure():
    assert is_secure_request(_FakeRequest(), TransportSettings()) is False


def test_forwarded_header_is_ignored_by_default():
    """A client must not be able to claim its own request was secure."""
    request = _FakeRequest(scheme="http", headers={"X-Forwarded-Proto": "https"})
    assert is_secure_request(request, TransportSettings()) is False


def test_forwarded_header_is_honoured_when_a_proxy_is_declared():
    settings = TransportSettings(trust_proxy_headers=True)
    request = _FakeRequest(scheme="http", headers={"X-Forwarded-Proto": "https"})
    assert is_secure_request(request, settings) is True


def test_forwarded_header_takes_the_first_value():
    settings = TransportSettings(trust_proxy_headers=True)
    request = _FakeRequest(headers={"X-Forwarded-Proto": "https, http"})
    assert is_secure_request(request, settings) is True


def test_cookie_secure_attribute_follows_the_request():
    assert secure_cookie_default(_FakeRequest(scheme="https"), TransportSettings()) is True
    assert secure_cookie_default(_FakeRequest(), TransportSettings()) is False


def test_explicit_cookie_setting_overrides_the_request():
    forced_off = TransportSettings(secure_cookies=False)
    assert secure_cookie_default(_FakeRequest(scheme="https"), forced_off) is False


# -- response headers ---------------------------------------------------------

def test_safe_headers_are_always_applied():
    response = _FakeResponse()
    apply_security_headers(response, secure=False, settings=TransportSettings())
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" not in response.headers


def test_hsts_is_only_sent_over_tls():
    response = _FakeResponse()
    apply_security_headers(response, secure=True, settings=TransportSettings())
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]
    assert "includeSubDomains" in response.headers["Strict-Transport-Security"]


def test_hsts_can_be_turned_off():
    response = _FakeResponse()
    apply_security_headers(response, secure=True, settings=TransportSettings(hsts=False))
    assert "Strict-Transport-Security" not in response.headers


def test_hsts_max_age_is_capped_at_one_year():
    response = _FakeResponse()
    apply_security_headers(response, secure=True, settings=TransportSettings(hsts_max_age=99_999_999))
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]


def test_existing_headers_are_not_overwritten():
    response = _FakeResponse()
    response.headers["Referrer-Policy"] = "no-referrer"
    apply_security_headers(response, secure=True, settings=TransportSettings())
    assert response.headers["Referrer-Policy"] == "no-referrer"


# -- application integration --------------------------------------------------

def _app(tmp_path, **kwargs):
    app = create_app(f"sqlite:///{(tmp_path / 'tls.db').as_posix()}", seed=False,
                     attachment_dir=tmp_path / "files", **kwargs)
    Base.metadata.create_all(app.state.engine)
    with app.state.session_factory() as db:
        db.add(User(username="investigator", role="investigator",
                    password_hash=hash_password("test-password-123")))
        db.commit()
    return app


def test_session_cookie_is_secure_over_https(tmp_path):
    app = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        result = client.post("/api/auth/login",
                             json={"username": "investigator", "password": "test-password-123"})
        assert result.status_code == 200
        cookie = result.headers["set-cookie"].lower()
        assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie


def test_session_cookie_is_not_marked_secure_over_plain_http(tmp_path):
    app = _app(tmp_path)
    with TestClient(app) as client:
        result = client.post("/api/auth/login",
                             json={"username": "investigator", "password": "test-password-123"})
        cookie = result.headers["set-cookie"].lower()
        assert "secure" not in cookie and "httponly" in cookie


def test_forced_secure_cookie_is_honoured_over_plain_http(tmp_path, monkeypatch):
    monkeypatch.setenv("ZANAQ_SECURE_COOKIES", "1")
    app = _app(tmp_path, )
    assert app.state.transport.secure_cookies is True
    with TestClient(app) as client:
        result = client.post("/api/auth/login",
                             json={"username": "investigator", "password": "test-password-123"})
        assert "secure" in result.headers["set-cookie"].lower()


def test_hsts_reaches_an_https_response(tmp_path):
    app = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        response = client.get("/api/health")
    assert "max-age=31536000" in response.headers.get("strict-transport-security", "")


def test_no_hsts_over_plain_http(tmp_path):
    app = _app(tmp_path)
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert "strict-transport-security" not in response.headers


def test_require_https_redirects_plain_requests(tmp_path):
    fresh = create_app(f"sqlite:///{(tmp_path / 'strict.db').as_posix()}", seed=False)
    install_transport_security(fresh, TransportSettings(require_https=True))
    with TestClient(fresh) as client:
        response = client.get("/api/health", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"].startswith("https://")


# -- certificate generation ---------------------------------------------------

def test_generated_material_is_written(tmp_path):
    result = generate_certificate(tmp_path / "tls", ["localhost", "127.0.0.1"], days=30)
    assert Path(result["ca"]).is_file() and Path(result["server"]).is_file()
    assert result["hosts"] == ["localhost", "127.0.0.1"]
    assert len(result["server_fingerprint"].split(":")) == 32
    assert result["ca_fingerprint"] != result["server_fingerprint"]


def test_private_keys_are_not_world_readable(tmp_path):
    import os
    import stat

    if os.name == "nt":
        pytest.skip("POSIX file modes are not meaningful on Windows")
    result = generate_certificate(tmp_path / "tls", ["localhost"], days=30)
    for key in (result["ca"].replace("ca.pem", "ca.key.pem"), result["server"]):
        mode = stat.S_IMODE(Path(key).stat().st_mode)
        assert not mode & 0o077, f"{key} is accessible to other users"


def test_certificate_is_issued_by_the_generated_ca(tmp_path):
    from cryptography import x509

    result = generate_certificate(tmp_path / "tls", ["localhost"], days=30)
    ca = x509.load_pem_x509_certificate(Path(result["ca"]).read_bytes())
    server = x509.load_pem_x509_certificate(Path(result["server"]).read_bytes())
    assert server.issuer == ca.subject
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert server.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in names.get_values_for_type(x509.DNSName)


def test_certificate_verifies_against_the_ca(tmp_path):
    """Load the CA and handshake-check the certificate chain signature."""
    result = generate_certificate(tmp_path / "tls", ["localhost"], days=30)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    ca = x509.load_pem_x509_certificate(Path(result["ca"]).read_bytes())
    server = x509.load_pem_x509_certificate(Path(result["server"]).read_bytes())
    ca.public_key().verify(server.signature, server.tbs_certificate_bytes,
                           padding.PKCS1v15(), server.signature_hash_algorithm)
    assert server.signature_hash_algorithm.name == "sha256"


def test_certificate_names_a_host_that_must_be_requested(tmp_path):
    result = generate_certificate(tmp_path / "tls", ["collector.example"], days=30)
    from cryptography import x509

    server = x509.load_pem_x509_certificate(Path(result["server"]).read_bytes())
    names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == ["collector.example"]


def test_empty_host_list_is_refused(tmp_path):
    with pytest.raises(ValueError, match="host name or address"):
        generate_certificate(tmp_path / "tls", [], days=30)


def test_invalid_validity_is_refused(tmp_path):
    with pytest.raises(ValueError, match="days must be positive"):
        generate_certificate(tmp_path / "tls", ["localhost"], days=0)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_real_https_listener_serves_the_api(tmp_path):
    """End-to-end: uvicorn with the generated certificate answers over TLS."""
    material = generate_certificate(tmp_path / "tls", ["localhost", "127.0.0.1"], days=30)
    app = create_app(f"sqlite:///{(tmp_path / 'live.db').as_posix()}", seed=False)
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error",
                            ssl_certfile=material["server"], ssl_keyfile=material["server"])
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 30
    while not server.started and time.time() < deadline:
        if not thread.is_alive():
            pytest.fail("uvicorn exited before it started")
        time.sleep(0.05)
    assert server.started, "uvicorn did not start"

    try:
        # Trusting the generated CA through the same helper the agent uses, the
        # API answers over a verified TLS session.
        verify = tls.build_ssl_context({"ca_bundle": str(material["ca"])})
        verify.verify_flags |= ssl.VERIFY_X509_STRICT
        with httpx.Client(verify=verify, timeout=10) as client:
            response = client.get(f"https://localhost:{port}/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert "max-age=31536000" in response.headers["strict-transport-security"]

        # Without the CA the handshake must fail rather than fall back.
        with httpx.Client(timeout=10) as client:
            with pytest.raises(httpx.HTTPError):
                client.get(f"https://localhost:{port}/api/health")
    finally:
        server.should_exit = True
        thread.join(timeout=15)
