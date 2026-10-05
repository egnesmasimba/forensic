"""Explicit inventory of the agent's optional third-party dependencies.

Every collector that depends on something outside the standard library declares
it via ``Collector.requires``. This module turns those declarations into a
machine-readable report so an examiner can tell the difference between:

* a collector that is switched off by configuration,
* a collector that cannot run on this operating system, and
* a collector that is silently inert because an import is missing.

The third case is the dangerous one. A forensic collector that quietly returns
no events looks identical to a host where nothing happened, so the gap has to be
reported rather than logged and forgotten.
"""

from __future__ import annotations

import functools
import importlib
import importlib.util
import platform
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Sequence


@dataclass(frozen=True)
class Dependency:
    """A third-party module some collectors need in order to collect anything."""

    module: str
    pip_name: str
    platforms: tuple[str, ...] = ()
    purpose: str = ""
    #: Import names of the concrete collectors that cannot work without it.
    collectors: tuple[str, ...] = field(default_factory=tuple)

    def available(self) -> bool:
        return module_available(self.module)

    def version(self) -> Optional[str]:
        return module_version(self.module)

    def status(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "pip_name": self.pip_name,
            "available": self.available(),
            "version": self.version(),
            "platforms": list(self.platforms),
            "purpose": self.purpose,
            "collectors": list(self.collectors),
        }


OPTIONAL_DEPENDENCIES: tuple[Dependency, ...] = (
    Dependency(module="pynput", pip_name="pynput", purpose="Opt-in aggregate typing timing and mouse movement capture.", collectors=("biometrics",)),
    Dependency(
        module="psutil",
        pip_name="psutil",
        platforms=("windows", "linux", "macos"),
        purpose="Process enumeration and resource metrics.",
        collectors=("process", "procforensics", "fileops", "incognito", "citrix", "usb", "window"),
    ),
    Dependency(
        module="win32api",
        pip_name="pywin32",
        platforms=("windows",),
        purpose="Windows session idle time and USB arrival notifications.",
        collectors=("idle", "usb"),
    ),
    Dependency(
        module="win32gui",
        pip_name="pywin32",
        platforms=("windows",),
        purpose="Window titles and clipboard access.",
        collectors=("window", "clipboard"),
    ),
    Dependency(
        module="win32process",
        pip_name="pywin32",
        platforms=("windows",),
        purpose="Window-to-PID mapping.",
        collectors=("window",),
    ),
    Dependency(
        module="win32con",
        pip_name="pywin32",
        platforms=("windows",),
        purpose="Win32 constants for USB device notifications.",
        collectors=("usb",),
    ),
    Dependency(
        module="win32print",
        pip_name="pywin32",
        platforms=("windows",),
        purpose="Spooler print job enumeration.",
        collectors=("print",),
    ),
    Dependency(
        module="pythoncom",
        pip_name="pywin32",
        platforms=("windows",),
        purpose="COM/WMI access for USB and RDP session detail.",
        collectors=("usb", "rdp"),
    ),
    Dependency(
        module="wmi",
        pip_name="pywin32",
        platforms=("windows",),
        purpose="WMI queries for USB and RDP session detail.",
        collectors=("usb", "rdp"),
    ),
    Dependency(
        module="winreg",
        pip_name="",
        platforms=("windows",),
        purpose="Windows registry persistence locations.",
        collectors=("registry",),
    ),
    Dependency(
        module="PIL",
        pip_name="Pillow",
        platforms=("windows", "linux", "macos"),
        purpose="Screen capture on Windows and macOS.",
        collectors=("screenshot",),
    ),
    Dependency(
        module="mss",
        pip_name="mss",
        platforms=("linux",),
        purpose="Screen capture on Linux, where ImageGrab is unavailable.",
        collectors=("screenshot",),
    ),
    Dependency(
        module="pyperclip",
        pip_name="pyperclip",
        platforms=("windows", "linux", "macos"),
        purpose="Clipboard history capture.",
        collectors=("clipboard",),
    ),
    Dependency(
        module="watchdog",
        pip_name="watchdog",
        platforms=("windows", "linux", "macos"),
        purpose="Filesystem change notification.",
        collectors=("fschange", "fileops"),
    ),
    Dependency(
        module="Quartz",
        pip_name="pyobjc",
        platforms=("macos",),
        purpose="macOS idle time, frontmost window and USB enumeration.",
        collectors=("idle", "window", "clipboard", "usb"),
    ),
    Dependency(
        module="pyudev",
        pip_name="pyudev",
        platforms=("linux",),
        purpose="Linux USB device arrival via udev.",
        collectors=("usb",),
    ),
    Dependency(
        module="objc",
        pip_name="pyobjc",
        platforms=("macos",),
        purpose="macOS IOKit USB enumeration.",
        collectors=("usb",),
    ),
)

_BY_MODULE: dict[str, Dependency] = {dep.module: dep for dep in OPTIONAL_DEPENDENCIES}


def known_dependencies() -> tuple[Dependency, ...]:
    return OPTIONAL_DEPENDENCIES


def find(module: str) -> Optional[Dependency]:
    """Return the registry entry for an import name, if one is declared."""
    return _BY_MODULE.get(module)


@functools.lru_cache(maxsize=None)
def module_available(module: str) -> bool:
    """True when ``module`` can be imported.

    ``find_spec`` is used rather than a real import so that probing never
    executes third-party code, and results are cached because availability
    cannot change while the agent is running.
    """
    if module in sys.modules:
        return True
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError, AttributeError):
        return False


@functools.lru_cache(maxsize=None)
def module_version(module: str) -> Optional[str]:
    """Best-effort installed version for a module, or None if unknown."""
    dep = find(module)
    dist = dep.pip_name if dep and dep.pip_name else module
    try:
        from importlib import metadata
    except ImportError:  # pragma: no cover - Python < 3.8
        return None
    try:
        return metadata.version(dist)
    except Exception:  # noqa: BLE001 - metadata raises many unrelated errors
        try:
            mod = importlib.import_module(module)
        except Exception:  # noqa: BLE001
            return None
        return getattr(mod, "__version__", None)


def missing_modules(modules: Iterable[str]) -> tuple[str, ...]:
    """Return the subset of ``modules`` that cannot be imported, preserving order."""
    return tuple(m for m in modules if not module_available(m))


def pip_names(modules: Iterable[str]) -> tuple[str, ...]:
    """Map import names to installable distribution names, de-duplicated."""
    out: list[str] = []
    for module in modules:
        dep = find(module)
        name = dep.pip_name if dep else module
        if name and name not in out:
            out.append(name)
    return tuple(out)


def install_command(modules: Sequence[str]) -> str:
    """Build the pip command that would satisfy ``modules``."""
    names = pip_names(modules)
    return f"pip install {' '.join(names)}" if names else ""


def unavailable_reason(modules: Iterable[str], *, platform_supported: bool = True) -> Optional[str]:
    """Explain, in one sentence, why a collector cannot run - or return None."""
    missing = missing_modules(modules)
    if missing:
        return (
            f"missing optional dependencies: {', '.join(missing)} "
            f"(install with: {install_command(missing)})"
        )
    if not platform_supported:
        return "not supported on this platform"
    return None


def applies_here(dep: Dependency, os_tag: Optional[str] = None) -> bool:
    """True when a dependency is relevant to the given platform.

    An empty ``platforms`` tuple means the dependency is cross-platform. This
    keeps ``pyobjc`` out of the suggested install line on a Windows endpoint,
    where its absence is expected and harmless.
    """
    if not dep.platforms:
        return True
    tag = os_tag or current_os_tag()
    return tag in dep.platforms


def current_os_tag() -> str:
    """Normalized operating system tag used by the dependency registry."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "macos"
    if system.startswith("linux"):
        return "linux"
    return system or "unknown"


def dependency_report(os_tag: Optional[str] = None) -> dict[str, Any]:
    """Inventory of optional dependencies and their availability.

    ``missing`` lists every absent module for the record; ``missing_relevant``
    narrows that to modules this platform could actually use, which is what an
    operator should act on.
    """
    deps = [dep.status() for dep in OPTIONAL_DEPENDENCIES]
    missing = sorted({dep.module for dep in OPTIONAL_DEPENDENCIES if not dep.available()})
    relevant = sorted(
        {
            dep.module
            for dep in OPTIONAL_DEPENDENCIES
            if not dep.available() and applies_here(dep, os_tag)
        }
    )
    return {
        "python": sys.version.split()[0],
        "platform": os_tag or current_os_tag(),
        "dependencies": deps,
        "missing": missing,
        "missing_relevant": relevant,
        "install_command": install_command(relevant),
        "install_command_all_platforms": install_command(missing),
        "complete": not missing,
        "complete_for_platform": not relevant,
    }