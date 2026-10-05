"""Agent-to-server transport security.

The TLS tests generate a private certificate authority and drive a real TLS
listener on loopback, because ``TestClient`` never opens a socket and would not
exercise certificate validation at all. The assertions therefore cover a real
handshake: a certificate signed by an untrusted CA must be rejected, the same
certificate must be accepted when the agent is pointed at the CA bundle, and a
certificate issued for the wrong name must not be accepted either.
"""
from __future__ import annotations

import datetime
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
import pytest

from endpoint_agent import tls
from endpoint_agent.config import Config
from endpoint_agent.protocol import AgentClient
from endpoint_agent.update import StagedUpdater

# -- certificate helpers ------------------------------------------------------

def write_ca(directory: Path):
    """Create a self-signed CA; return its PEM path and private key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ZANAQ Test CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = directory / "ca.pem"
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return path, key


def write_certificate(directory: Path, ca_cert_path: Path, ca_key, *, common_name: str,
                      name: str = "server.pem") -> Path:
    """Issue a leaf certificate for ``common_name`` from the given CA."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    path = directory / name
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM)
                     + key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.TraditionalOpenSSL,
                                         serialization.NoEncryption()))
    return path


@pytest.fixture()
def authority(tmp_path):
    """A private CA plus a server certificate it issued for localhost."""
    ca_path, ca_key = write_ca(tmp_path)
    certificate = write_certificate(tmp_path, ca_path, ca_key, common_name="localhost")
    return {"ca": ca_path, "certificate": certificate, "key": ca_key}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - required by BaseHTTPRequestHandler
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


class TlsListener:
    """A minimal HTTPS server on an ephemeral loopback port."""

    def __init__(self, certificate: Path, *, client_ca: Path | None = None):
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certificate)
        if client_ca is not None:
            self._context.load_verify_locations(client_ca)
            self._context.verify_mode = ssl.CERT_REQUIRED
        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self._server.socket = self._context.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"https://localhost:{self._server.server_address[1]}"

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture()
def tls_server(authority):
    listener = TlsListener(authority["certificate"])
    yield listener
    listener.stop()


# -- URL policy ---------------------------------------------------------------

def test_plain_http_to_remote_host_is_refused():
    with pytest.raises(tls.TlsConfigError, match="Refusing plain HTTP"):
        tls.require_secure_url("http://collector.example.com:8000")


@pytest.mark.parametrize("url", ["http://127.0.0.1:8000", "http://localhost:8000"])
def test_plain_http_to_loopback_is_allowed_for_development(url):
    assert tls.require_secure_url(url) == url


def test_override_allows_plain_http_explicitly():
    assert tls.require_secure_url("http://collector.example.com", allow_insecure=True)


@pytest.mark.parametrize("url", ["", "ftp://host", "not-a-url", "https://", "file:///etc/passwd"])
def test_unusable_urls_are_refused(url):
    with pytest.raises(tls.TlsConfigError):
        tls.require_secure_url(url)


def test_credentials_in_url_are_refused():
    with pytest.raises(tls.TlsConfigError, match="must not embed credentials"):
        tls.require_secure_url("https://admin:hunter2@server.example")


@pytest.mark.parametrize("host,expected", [
    ("localhost", True), ("127.0.0.1", True), ("::1", True), ("127.5.5.5", True),
    ("192.168.1.10", False), ("collector.example.com", False), ("", False), (None, False),
])
def test_loopback_detection(host, expected):
    assert tls.is_loopback_host(host) is expected


def test_client_refuses_remote_plain_http():
    with pytest.raises(tls.TlsConfigError):
        AgentClient("http://collector.example.com", "token")


# -- certificate policy -------------------------------------------------------

def test_verification_is_on_by_default():
    assert tls.build_ssl_context({}) is True


def test_verification_cannot_be_disabled_for_a_remote_host():
    with pytest.raises(tls.TlsConfigError, match="cannot be turned off"):
        tls.build_ssl_context({"verify_tls": False}, url="https://collector.example.com")


def test_verification_may_be_disabled_for_loopback_development():
    context = tls.build_ssl_context({"verify_tls": False}, url="http://127.0.0.1:8000")
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_NONE and context.check_hostname is False


@pytest.mark.parametrize("value", ["0", "false", "no", "off", False])
def test_string_and_boolean_false_are_both_honoured(value):
    with pytest.raises(tls.TlsConfigError):
        tls.build_ssl_context({"verify_tls": value}, url="https://collector.example.com")


def test_custom_ca_context_is_strict(authority):
    context = tls.build_ssl_context({"ca_bundle": str(authority["ca"])})
    assert isinstance(context, ssl.SSLContext)
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_missing_ca_bundle_is_reported_clearly(tmp_path):
    with pytest.raises(tls.TlsConfigError, match="CA bundle file not found"):
        tls.build_ssl_context({"ca_bundle": str(tmp_path / "absent.pem")})


def test_missing_client_certificate_is_reported_clearly(tmp_path):
    with pytest.raises(tls.TlsConfigError, match="Client certificate file not found"):
        tls.build_ssl_context({"client_cert": str(tmp_path / "absent.pem")})


def test_unreadable_certificate_content_is_reported(tmp_path):
    junk = tmp_path / "client.pem"
    junk.write_text("not a certificate")
    with pytest.raises(tls.TlsConfigError, match="Failed to load client certificate"):
        tls.build_ssl_context({"client_cert": str(junk)})


def test_describe_reports_the_effective_posture(authority):
    posture = tls.describe({"ca_bundle": str(authority["ca"])}, url="https://server.example")
    assert posture["url_scheme"] == "https"
    assert posture["certificate_verification"] is True
    assert posture["hostname_checked"] is True
    assert posture["custom_ca_bundle"] is True
    assert posture["mutual_tls"] is False
    weak = tls.describe({"verify_tls": False}, url="http://127.0.0.1:8000")
    assert weak["certificate_verification"] is False


def test_proxy_is_passed_through():
    assert tls.transport_options({"proxy": "http://proxy.example:3128"})["proxy"] == \
        "http://proxy.example:3128"
    assert "proxy" not in tls.transport_options({})


# -- real handshake -----------------------------------------------------------

def test_untrusted_certificate_is_rejected_by_the_agent(tls_server):
    with AgentClient(tls_server.url, "token") as client:
        with pytest.raises(httpx.HTTPError):
            client._get_client().get("/")


def test_agent_accepts_the_certificate_when_given_the_ca(tls_server, authority):
    with AgentClient(tls_server.url, "token",
                     **tls.transport_options({"ca_bundle": str(authority["ca"])})) as client:
        response = client._get_client().get("/")
    assert response.status_code == 200 and response.json() == {"ok": True}


def test_certificate_for_the_wrong_name_is_rejected(authority):
    """A trusted CA is not enough; the name has to match the requested host."""
    wrong = write_certificate(authority["certificate"].parent, authority["ca"], authority["key"],
                              common_name="other.example", name="wrong.pem")
    listener = TlsListener(wrong)
    try:
        with AgentClient(listener.url, "token",
                         **tls.transport_options({"ca_bundle": str(authority["ca"])})) as client:
            with pytest.raises(httpx.HTTPError):
                client._get_client().get("/")
    finally:
        listener.stop()


def test_mutual_tls_is_negotiated(authority, tmp_path):
    """The listener demands a client certificate, and refuses without one."""
    certificate = write_certificate(tmp_path, authority["ca"], authority["key"],
                                    common_name="endpoint-agent", name="agent-cert.pem")
    listener = TlsListener(authority["certificate"], client_ca=authority["ca"])
    try:
        options = tls.transport_options({"ca_bundle": str(authority["ca"]),
                                         "client_cert": str(certificate)})
        with AgentClient(listener.url, "token", **options) as client:
            assert client._get_client().get("/").status_code == 200
        # Without a client certificate the same listener refuses the connection.
        with AgentClient(listener.url, "token",
                         **tls.transport_options({"ca_bundle": str(authority["ca"])})) as client:
            with pytest.raises(httpx.HTTPError):
                client._get_client().get("/")
    finally:
        listener.stop()


def test_sync_and_async_clients_use_identical_transport(authority):
    with AgentClient("https://server.example", "token",
                     **tls.transport_options({"ca_bundle": str(authority["ca"])})) as client:
        kwargs = client._transport_kwargs()
        assert client._get_client() is not None
        assert client._get_async_client() is not None
        assert kwargs == {"verify": client._verify}
        assert client._verify is kwargs["verify"]


def test_updater_uses_the_same_policy(tmp_path, authority):
    updater = StagedUpdater(tmp_path, server_url="https://server.example",
                            **tls.transport_options({"ca_bundle": str(authority["ca"])}))
    assert isinstance(updater._transport_options["verify"], ssl.SSLContext)
    with pytest.raises(tls.TlsConfigError):
        StagedUpdater(tmp_path, server_url="http://collector.example.com")


# -- configuration plumbing ---------------------------------------------------

def test_default_config_declares_the_tls_keys(tmp_path):
    config = Config(tmp_path / "agent_config.json")
    config.load()
    assert config.get("tls.verify_tls") is True
    assert config.get("tls.ca_bundle") is None
    assert config.get("tls.client_cert") is None
    assert config.get("tls.allow_insecure_http") is False


def test_tls_keys_survive_a_config_round_trip(tmp_path):
    path = tmp_path / "agent_config.json"
    config = Config(path)
    config.set("tls.ca_bundle", "/etc/pki/forensic-ca.pem")
    config.set("tls.verify_tls", True)
    config.save()
    reloaded = Config(path)
    assert reloaded.load() is True
    assert reloaded.get("tls.ca_bundle") == "/etc/pki/forensic-ca.pem"
    assert reloaded.get("tls.verify_tls") is True


def test_installer_style_config_is_no_longer_ignored(tmp_path, authority):
    """The keys the platform installers write must actually reach the client."""
    path = tmp_path / "agent_config.json"
    config = Config(path)
    config.set("server_url", "https://collector.example.com")
    config.set("tls.ca_bundle", str(authority["ca"]))
    config.set("tls.proxy", "http://proxy.example:3128")
    config.save()

    loaded = Config(path)
    assert loaded.load() is True
    options = tls.transport_options(loaded.get("tls", {}), url=loaded.get("server_url"))
    assert isinstance(options["verify"], ssl.SSLContext)
    assert options["proxy"] == "http://proxy.example:3128"


def test_legacy_flat_installer_keys_are_still_honoured(tmp_path, authority):
    """An older installer wrote these keys flat; they must not be ignored."""
    path = tmp_path / "agent_config.json"
    path.write_text(json.dumps({
        "server_url": "https://collector.example.com",
        "ca_bundle": str(authority["ca"]),
        "proxy": "http://proxy.example:3128",
        "verify_tls": True,
    }), encoding="utf-8")
    loaded = Config(path)
    assert loaded.load() is True
    settings = tls.settings_from_config(loaded.data)
    assert settings["ca_bundle"] == str(authority["ca"])
    assert settings["proxy"] == "http://proxy.example:3128"
    options = tls.transport_options(settings, url=loaded.get("server_url"))
    assert isinstance(options["verify"], ssl.SSLContext)
    assert options["proxy"] == "http://proxy.example:3128"


def test_nested_section_wins_over_a_legacy_flat_key(authority):
    settings = tls.settings_from_config({
        "tls": {"ca_bundle": str(authority["ca"])},
        "ca_bundle": "/stale/path.pem",
    })
    assert settings["ca_bundle"] == str(authority["ca"])


def test_legacy_key_is_used_when_the_nested_value_is_unset():
    """The merge fills the nested section with None defaults, so None must lose."""
    settings = tls.settings_from_config({
        "tls": {"verify_tls": True, "ca_bundle": None, "proxy": None},
        "ca_bundle": "/etc/pki/legacy-ca.pem",
        "proxy": "http://legacy-proxy:3128",
    })
    assert settings["ca_bundle"] == "/etc/pki/legacy-ca.pem"
    assert settings["proxy"] == "http://legacy-proxy:3128"


def test_settings_from_config_handles_a_missing_section():
    assert tls.settings_from_config({}) == {}
    assert tls.settings_from_config(None) == {}
    assert tls.settings_from_config({"tls": None}) == {}


# -- configuration isolation --------------------------------------------------

def test_one_config_cannot_leak_into_another(tmp_path):
    """A set() on one Config must not rewrite the shared defaults.

    The defaults used to be copied shallowly, so the nested sections were shared
    objects and one agent's CA bundle path appeared in every later Config in the
    process.
    """
    from endpoint_agent.config import DEFAULT_CONFIG

    first = Config(tmp_path / "first.json")
    first.set("tls.ca_bundle", "/private/agent-a-ca.pem")
    first.set("tls.verify_tls", True)
    first.set("collectors.usb", True)

    second = Config(tmp_path / "second.json")
    assert second.get("tls.ca_bundle") is None
    assert second.get("collectors.usb") is None
    assert DEFAULT_CONFIG["tls"]["ca_bundle"] is None
    assert DEFAULT_CONFIG["collectors"] == {}


def test_loading_does_not_mutate_the_defaults(tmp_path):
    from endpoint_agent.config import DEFAULT_CONFIG

    path = tmp_path / "agent_config.json"
    path.write_text(json.dumps({"tls": {"ca_bundle": "/private/ca.pem"}}), encoding="utf-8")
    assert Config(path).load() is True
    assert DEFAULT_CONFIG["tls"]["ca_bundle"] is None


def test_a_loopback_development_config_still_works(tmp_path):
    """The documented default dev setup must not be broken by the new policy."""
    path = tmp_path / "agent_config.json"
    config = Config(path)
    config.set("server_url", "http://localhost:8000")
    config.set("tls.allow_insecure_http", True)
    config.save()
    loaded = Config(path)
    loaded.load()
    with AgentClient(loaded.get("server_url"), "token",
                     allow_insecure_http=bool(loaded.get("tls.allow_insecure_http")),
                     **tls.transport_options(loaded.get("tls", {}), url=loaded.get("server_url"))) as client:
        assert client._server == "http://localhost:8000"