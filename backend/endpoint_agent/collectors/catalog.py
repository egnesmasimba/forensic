"""The single inventory of collectors the agent knows how to run.

The worker previously imported three collectors inline, which meant sixteen
implemented collectors were never constructed and never appeared in any status
report. Anything added here is registered automatically and shows up in
``endpoint-agent doctor``, whether or not it can actually collect.

Imports are deliberately local so that importing this module does not pull in
every collector (and therefore every optional dependency) eagerly.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)


#: module path -> attribute holding the Collector subclass
_COLLECTOR_CLASSES: tuple[tuple[str, str], ...] = (
    ("endpoint_agent.collectors.biometrics", "BiometricCollector"),
    ("endpoint_agent.collectors.agentlog", "AgentLogCollector"),
    ("endpoint_agent.collectors.browser_downloads", "BrowserDownloadCollector"),
    ("endpoint_agent.collectors.citrix", "CitrixCollector"),
    ("endpoint_agent.collectors.clipboard", "ClipboardCollector"),
    ("endpoint_agent.collectors.fileops", "FileOpsCollector"),
    ("endpoint_agent.collectors.fschange", "FSChangeCollector"),
    ("endpoint_agent.collectors.idle", "IdleCollector"),
    ("endpoint_agent.collectors.incognito", "IncognitoCollector"),
    ("endpoint_agent.collectors.mail_capture", "MailCollector"),
    ("endpoint_agent.collectors.print", "PrintCollector"),
    ("endpoint_agent.collectors.process", "ProcessCollector"),
    ("endpoint_agent.collectors.procforensics", "ProcForensicsCollector"),
    ("endpoint_agent.collectors.rdp", "RDPCollector"),
    ("endpoint_agent.collectors.registry", "RegistryCollector"),
    ("endpoint_agent.collectors.screenshot", "ScreenshotCollector"),
    ("endpoint_agent.collectors.transfers", "TransferCollector"),
    ("endpoint_agent.collectors.usb", "USBCollector"),
    ("endpoint_agent.collectors.usb_command", "UsbCommandCollector"),
    ("endpoint_agent.collectors.window", "WindowCollector"),
)


def iter_collector_classes() -> Iterator[tuple[Optional[type], Optional[str]]]:
    """Yield ``(class, error)`` for every known collector.

    A module that fails to import yields ``(None, message)`` instead of
    aborting the whole inventory, so one broken collector cannot hide the rest.
    """
    for module_path, attr in _COLLECTOR_CLASSES:
        try:
            module = importlib.import_module(module_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Collector module %s failed to import: %s", module_path, exc)
            yield None, f"{module_path}: {type(exc).__name__}: {exc}"
            continue
        cls = getattr(module, attr, None)
        if cls is None:
            yield None, f"{module_path}: missing attribute {attr}"
            continue
        yield cls, None


def load_collector_classes() -> tuple[list[type], dict[str, str]]:
    """Return ``(classes, errors)`` for every collector that could be imported."""
    classes: list[type] = []
    errors: dict[str, str] = {}
    for cls, err in iter_collector_classes():
        if cls is None:
            key = err.split(":", 1)[0] if err else "unknown"
            errors[key] = err or "unknown error"
        else:
            classes.append(cls)
    return classes, errors


def sensitive_collector_names() -> set[str]:
    """Names of collectors that capture content requiring explicit opt-in."""
    names: set[str] = set()
    for cls, _ in iter_collector_classes():
        if cls is not None and getattr(cls, "sensitive", False):
            names.add(getattr(cls, "name", ""))
    return names


def catalog_report() -> dict[str, Any]:
    """Availability matrix for every known collector."""
    classes, errors = load_collector_classes()
    from . import Collector, dependencies

    entries: list[dict[str, Any]] = []
    for cls in classes:
        missing = dependencies.missing_modules(cls.effective_requires())
        entries.append({
            "name": cls.name,
            "available": cls.is_available(),
            "enabled_by_default": not cls.sensitive,
            "sensitive": cls.sensitive,
            "requires": list(cls.effective_requires()),
            "missing_dependencies": list(missing),
            "unavailable_reason": cls.unavailable_reason(),
            "interval_seconds": cls.default_interval_seconds,
        })
    entries.sort(key=lambda e: e["name"])
    return {
        "registered": len(classes),
        "collectors": entries,
        "import_errors": errors,
        "dependencies": dependencies.dependency_report(),
    }