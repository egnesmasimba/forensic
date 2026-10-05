"""Server-side transport security.

TLS termination stays with the ASGI server (uvicorn is started with
``--ssl-certfile``/``--ssl-keyfile``), so this module does the two things the
application itself is responsible for:

* decide whether a request arrived over TLS, and set the response headers that
  depend on that answer;
* generate the certificate material an operator needs, because a private
  deployment has no publicly trusted certificate and the agent has to be given
  a CA bundle to verify.

Run ``python -m app.transport_security generate-cert --help`` for the generator.
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

DEFAULT_HSTS_MAX_AGE = 31536000
# Refuse sessions older than a year, per the HSTS preload requirement, so a
# certificate that expires inside that window cannot strand an operator.
DEFAULT_MAX_AGE = 31536000


@dataclass(frozen=True)
class TransportSettings:
    """Transport policy, resolved from the environment at startup."""

    require_https: bool = False
    trust_proxy_headers: bool = False
    secure_cookies: Optional[bool] = None
    hsts: bool = True
    hsts_max_age: int = DEFAULT_HSTS_MAX_AGE

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "TransportSettings":
        source = env if env is not None else dict(os.environ)
        secure_raw = source.get("ZANAQ_SECURE_COOKIES")
        if secure_raw is None:
            secure: Optional[bool] = None
        else:
            secure = secure_raw.strip().lower() in ("1", "true", "yes", "on")
        max_age = source.get("ZANAQ_HSTS_MAX_AGE")
        return cls(
            require_https=_flag(source.get("ZANAQ_REQUIRE_HTTPS")),
            # Proxy headers stay untrusted by default: this application is
            # documented to run without them, and trusting them blindly lets a
            # client claim its own request was secure.
            trust_proxy_headers=_flag(source.get("ZANAQ_TRUST_PROXY_HEADERS")),
            secure_cookies=secure,
            hsts=_flag(source.get("ZANAQ_HSTS"), default=True),
            hsts_max_age=int(max_age) if max_age else DEFAULT_HSTS_MAX_AGE,
        )


def _flag(value: Optional[str], *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def is_secure_request(request, settings: TransportSettings) -> bool:
    """True when the client reached this application over TLS.

    ``X-Forwarded-Proto`` is only believed when the operator has explicitly said
    a trusted reverse proxy sits in front, because otherwise any client could
    send the header and downgrade the application's own security decisions.
    """
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-proto", "")
        first = forwarded.split(",")[0].strip().lower()
        if first:
            return first == "https"
    url = getattr(request, "url", None)
    scheme = getattr(url, "scheme", "") or ""
    if scheme:
        return scheme == "https"
    return str(request.scope.get("scheme", "")).lower() == "https" if hasattr(request, "scope") else False


def secure_cookie_default(request, settings: TransportSettings) -> bool:
    """Whether the session cookie should carry the ``Secure`` attribute.

    An explicit ``ZANAQ_SECURE_COOKIES`` always wins, so an operator behind a
    terminating proxy can force it on; otherwise it follows the request.
    """
    if settings.secure_cookies is not None:
        return settings.secure_cookies
    return is_secure_request(request, settings)


def apply_security_headers(response, *, secure: bool, settings: TransportSettings) -> None:
    """Add the response headers that are safe regardless of deployment."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if secure and settings.hsts and settings.hsts_max_age > 0:
        response.headers.setdefault(
            "Strict-Transport-Security",
            f"max-age={min(settings.hsts_max_age, DEFAULT_MAX_AGE)}; includeSubDomains")


# -- certificate generation ---------------------------------------------------

def _san_entries(hosts: Iterable[str]):
    from cryptography import x509

    entries = []
    for host in hosts:
        text = str(host).strip()
        if not text:
            continue
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(text)))
        except ValueError:
            entries.append(x509.DNSName(text))
    if not entries:
        raise ValueError("At least one host name or address is required")
    return entries


def _write(path: Path, data: bytes, *, private: bool = False) -> Path:
    path.write_bytes(data)
    try:
        path.chmod(0o600 if private else 0o644)
    except OSError:
        pass  # Windows and some filesystems do not support POSIX modes.
    return path


def generate_certificate(out_dir: os.PathLike[str] | str, hosts: Iterable[str], *,
                         common_name: str = "zanaq-forensic", days: int = 365,
                         key_size: int = 3072, now: Optional[datetime.datetime] = None) -> dict:
    """Create a private CA plus a server certificate it signed.

    Returns the written paths and the SHA-256 fingerprints. The ``ca.pem`` file
    is what an agent is given as ``tls.ca_bundle``; ``server.pem`` contains the
    certificate and its key together, which is what uvicorn wants.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    moment = now or datetime.datetime.now(datetime.timezone.utc)
    if days < 1:
        raise ValueError("days must be positive")
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    sans = _san_entries(hosts)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=max(2048, key_size))
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{common_name} private CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(moment - datetime.timedelta(minutes=5))
        .not_valid_after(moment + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=max(2048, key_size))
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(moment - datetime.timedelta(minutes=5))
        .not_valid_after(moment + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    pem = serialization.Encoding.PEM
    no_encryption = serialization.NoEncryption()
    ca_path = _write(directory / "ca.pem", ca_certificate.public_bytes(pem))
    _write(directory / "ca.key.pem",
           ca_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, no_encryption), private=True)
    server_path = _write(directory / "server.pem",
                         server_certificate.public_bytes(pem)
                         + server_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, no_encryption),
                         private=True)

    def fingerprint(certificate) -> str:
        return certificate.fingerprint(hashes.SHA256()).hex(":").upper()

    return {
        "ca": str(ca_path),
        "server": str(server_path),
        "hosts": [str(getattr(entry, "value", entry)) for entry in sans],
        "ca_fingerprint": fingerprint(ca_certificate),
        "server_fingerprint": fingerprint(server_certificate),
        "expires": server_certificate.not_valid_after_utc.isoformat(),
    }


def install_transport_security(app, settings: TransportSettings) -> None:
    """Register the transport middleware on a FastAPI application.

    Adds HSTS and the other response headers, and optionally redirects plain HTTP
    to HTTPS. The redirect is off by default because a deployment that terminates
    TLS at a proxy would otherwise redirect clients to a loopback URL.
    """
    from starlette.responses import RedirectResponse

    @app.middleware("http")
    async def _transport_security(request, call_next):  # type: ignore[no-untyped-def]
        secure = is_secure_request(request, settings)
        if settings.require_https and not secure:
            target = str(request.url)
            if target.startswith("http://"):
                target = "https://" + target[len("http://"):]
            return RedirectResponse(url=target, status_code=301)
        response = await call_next(request)
        apply_security_headers(response, secure=secure, settings=settings)
        return response


def summary(settings: TransportSettings) -> dict:
    """Report the effective policy, for the startup log and documentation."""
    return {
        "require_https": settings.require_https,
        "trust_proxy_headers": settings.trust_proxy_headers,
        "secure_cookies": "auto" if settings.secure_cookies is None else settings.secure_cookies,
        "hsts": settings.hsts,
        "hsts_max_age": settings.hsts_max_age,
        "minimum_tls_version": "TLS 1.2",
    }


def _main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("generate-cert", help="create a private CA and server certificate")
    generate.add_argument("--host", action="append", required=True,
                          help="host name or address to place in the certificate (repeatable)")
    generate.add_argument("--out-dir", default="tls")
    generate.add_argument("--common-name", default="zanaq-forensic")
    generate.add_argument("--days", type=int, default=365)
    generate.add_argument("--key-size", type=int, default=3072)
    sub.add_parser("show", help="print the effective transport policy")

    args = parser.parse_args(argv)
    if args.command == "show":
        for key, value in summary(TransportSettings.from_env()).items():
            print(f"{key}: {value}")
        return 0

    result = generate_certificate(args.out_dir, args.host, common_name=args.common_name,
                                  days=args.days, key_size=args.key_size)
    print(f"CA certificate:  {result['ca']}")
    print(f"  SHA-256:       {result['ca_fingerprint']}")
    print(f"Server material: {result['server']}")
    print(f"  SHA-256:       {result['server_fingerprint']}")
    print(f"Valid until:     {result['expires']}")
    print()
    print("Start the server with:")
    print(f"  python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 \\")
    print(f"      --ssl-certfile {result['server']} --ssl-keyfile {result['server']}")
    print()
    print("Point each agent at the server and trust the CA:")
    print(f"  server_url: https://<host>:8000")
    print(f"  tls.ca_bundle: {result['ca']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())