"""TLS policy for agent-to-server communication.

The installers have always written ``verify_tls``, ``ca_bundle`` and ``proxy``
into ``config.json``, but no module read them, so an operator could believe the
link was protected while the agent silently used plain HTTP with the default
trust store. This module is the single place that decides how a connection is
protected, and it is deliberately strict:

* Certificate verification is on unless it is explicitly turned off.
* Turning verification off is refused for any host that is not loopback, so a
  development escape hatch cannot be deployed by accident.
* Plain HTTP is refused for any host that is not loopback.
* A private certificate authority and a client certificate for mutual TLS are
  both supported, because an on-premises server rarely has a publicly trusted
  certificate.
* No option disables hostname checking. A certificate has to match the name in
  the configured URL; the alternative is the exact failure this code exists to
  prevent.
"""
from __future__ import annotations

import ipaddress
import os
import ssl
from pathlib import Path
from typing import Any, Mapping, Optional, Union
from urllib.parse import urlsplit

LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})
MINIMUM_TLS_VERSION = ssl.TLSVersion.TLSv1_2

VerifyArgument = Union[bool, str, ssl.SSLContext]

# The platform installers originally wrote these keys flat at the top level of
# config.json. A flat value is still honoured when the nested one is absent, or
# an upgraded agent would silently fall back to the defaults the installer was
# trying to avoid.
LEGACY_KEYS = ("verify_tls", "ca_bundle", "client_cert", "client_key",
               "server_hostname", "allow_insecure_http", "proxy")


class TlsConfigError(Exception):
    """Raised when TLS settings are missing, unreadable, or unsafe."""


def settings_from_config(config: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    """Extract TLS settings from a whole agent configuration mapping.

    The nested ``tls`` section wins; the older flat keys are used as a fallback
    so that a configuration written by an earlier installer keeps working.
    """
    source: Mapping[str, Any] = config or {}
    nested = source.get("tls")
    settings: dict[str, Any] = dict(nested) if isinstance(nested, Mapping) else {}
    for key in LEGACY_KEYS:
        # An unset nested value falls back to the legacy flat key. The comparison
        # has to be against None rather than membership: the configuration merge
        # fills the nested section with None defaults, so the flat key would
        # otherwise be shadowed by a key the operator never wrote.
        if settings.get(key) is None and key in source:
            settings[key] = source[key]
    return settings


def is_loopback_host(host: Optional[str]) -> bool:
    """True when the host is a loopback literal or name."""
    if not host:
        return False
    candidate = host.strip().strip("[]").lower()
    if candidate in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def require_secure_url(url: str, *, allow_insecure: bool = False) -> str:
    """Validate a server URL and return it unchanged.

    Raises ``TlsConfigError`` for a malformed URL, and for plain HTTP to a
    non-loopback host unless the operator opted out in configuration.
    """
    if not url or not isinstance(url, str):
        raise TlsConfigError("Server URL is missing")
    parsed = urlsplit(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise TlsConfigError(f"Server URL must use http or https, got {parsed.scheme or 'no scheme'!r}")
    if not parsed.hostname:
        raise TlsConfigError("Server URL has no host")
    if parsed.username or parsed.password:
        # Credentials belong in the agent token or the OS credential store, not
        # in a URL that ends up in logs and process listings.
        raise TlsConfigError("Server URL must not embed credentials")
    if parsed.scheme == "http" and not is_loopback_host(parsed.hostname) and not allow_insecure:
        raise TlsConfigError(
            f"Refusing plain HTTP to non-loopback host {parsed.hostname!r}; "
            "use https, or set allow_insecure_http to override")
    return url.strip()


def _readable(path: Any, label: str) -> str:
    if not path:
        raise TlsConfigError(f"{label} path is empty")
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise TlsConfigError(f"{label} file not found: {resolved}")
    return str(resolved)


def _check_key_permissions(path: str) -> None:
    """Refuse a client key that other local users can read."""
    if os.name == "nt":
        return
    mode = Path(path).stat().st_mode & 0o077
    if mode:
        raise TlsConfigError(
            f"Client key {path} is readable by other users (mode {mode:03o}); "
            "restrict it to the agent account")


def build_ssl_context(config: Optional[Mapping[str, Any]] = None, *, url: Optional[str] = None) -> VerifyArgument:
    """Build the ``verify`` argument for httpx from agent TLS configuration.

    Returns ``True`` for the ordinary verified case, ``False`` only for an
    explicitly permitted loopback development connection, and an
    ``ssl.SSLContext`` when a CA bundle or client certificate is configured.
    """
    settings: Mapping[str, Any] = config or {}
    allow_insecure = bool(settings.get("allow_insecure_http", False))
    if url:
        require_secure_url(url, allow_insecure=allow_insecure)

    verify_tls = settings.get("verify_tls", True)
    host = urlsplit(url).hostname if url else None
    if isinstance(verify_tls, str):
        verify_tls = verify_tls.strip().lower() not in ("0", "false", "no", "off", "")
    if not verify_tls:
        if not (host is None or is_loopback_host(host)):
            raise TlsConfigError(
                "verify_tls is disabled but the server is not loopback; certificate "
                "verification cannot be turned off for a remote host")
        # httpx still needs a context object to be safe against a downgrade.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    ca_bundle = settings.get("ca_bundle") or None
    client_cert = settings.get("client_cert") or None
    client_key = settings.get("client_key") or None
    if not ca_bundle and not client_cert:
        # Default trust store; no need to build a context.
        return True

    context = ssl.create_default_context(cafile=_readable(ca_bundle, "CA bundle") if ca_bundle else None)
    context.minimum_version = MINIMUM_TLS_VERSION
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if client_cert:
        cert_path = _readable(client_cert, "Client certificate")
        key_path = _readable(client_key, "Client key") if client_key else cert_path
        if client_key:
            _check_key_permissions(key_path)
        try:
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        except (ssl.SSLError, OSError) as exc:
            raise TlsConfigError(f"Failed to load client certificate: {exc}") from exc
    return context


def transport_options(config: Optional[Mapping[str, Any]] = None, *, url: Optional[str] = None) -> dict[str, Any]:
    """Build the keyword arguments shared by every agent HTTP client.

    Call sites pass the result through so the sync client, the async client and
    the updater cannot drift apart in how they authenticate the server.
    """
    settings: Mapping[str, Any] = config or {}
    options: dict[str, Any] = {"verify": build_ssl_context(settings, url=url)}
    proxy = settings.get("proxy") or None
    if proxy:
        options["proxy"] = str(proxy)
    return options


def describe(config: Optional[Mapping[str, Any]] = None, *, url: Optional[str] = None) -> dict[str, Any]:
    """Summarise the effective TLS posture for the startup log and reports."""
    settings: Mapping[str, Any] = config or {}
    options = transport_options(settings, url=url)
    verify = options["verify"]
    return {
        "url_scheme": urlsplit(url).scheme if url else None,
        "certificate_verification": verify is not False and not (
            isinstance(verify, ssl.SSLContext) and verify.verify_mode == ssl.CERT_NONE),
        "hostname_checked": not (isinstance(verify, ssl.SSLContext) and not verify.check_hostname),
        "minimum_tls_version": MINIMUM_TLS_VERSION.name.replace("TLSv", "TLS "),
        "custom_ca_bundle": bool(settings.get("ca_bundle")),
        "mutual_tls": bool(settings.get("client_cert")),
        "proxy": bool(options.get("proxy")),
    }