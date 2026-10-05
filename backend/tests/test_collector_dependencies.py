from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

import pytest

from endpoint_agent.collectors import Collector, CollectorManager, NoopCollector
from endpoint_agent.collectors import dependencies
from endpoint_agent.collectors.catalog import catalog_report, load_collector_classes


class _FakeCollector(Collector):
    name = "fake"
    requires = ("definitely_not_installed_module",)

    @classmethod
    def supports_current_os(cls) -> bool:
        return True

    def _collect(self) -> Iterable[dict[str, Any]]:
        return [{"type": "fake"}]


class _NeedyCollector(_FakeCollector):
    name = "needy"
    requires = ("also_absent_module",)


class _OptionalCollector(_FakeCollector):
    name = "optional"
    requires = ()

    @classmethod
    def effective_requires(cls) -> tuple[str, ...]:
        # Stands in for a platform-conditional collector such as idle.
        return ("absent_on_this_platform",) if sys.platform == "win32" else ()


def test_missing_dependency_is_reported_not_just_logged() -> None:
    missing = _FakeCollector.missing_requirements()
    assert missing == ("definitely_not_installed_module",)
    assert _FakeCollector.is_available() is False
    status = _FakeCollector({}).status()
    assert status["available"] is False
    assert status["missing_dependencies"] == ["definitely_not_installed_module"]
    assert "definitely_not_installed_module" in status["unavailable_reason"]
    assert "pip install" in status["install_command"]


def test_unavailable_dependency_stops_collection() -> None:
    collector = _FakeCollector()
    assert collector.enabled is False
    # An inert collector must not be able to tick, or it would look healthy.
    assert collector.tick_if_due() == []
    assert collector.status()["events_collected"] == 0


def test_collector_without_requirements_is_available() -> None:
    expected = ("absent_on_this_platform",) if sys.platform == "win32" else ()
    assert _OptionalCollector.missing_requirements() == expected
    assert _OptionalCollector.is_available() is (not expected)

    class _Clean(_FakeCollector):
        name = "clean"
        requires = ()

        @classmethod
        def effective_requires(cls) -> tuple[str, ...]:
            return ()

    assert _Clean.is_available() is True
    assert _Clean.unavailable_reason() is None
    assert _Clean({}).status()["available"] is True


def test_platform_restriction_is_distinct_from_missing_dependency() -> None:
    class _WindowsOnly(_FakeCollector):
        name = "win_only"
        requires = ()
        platforms = ("windows",)

    reason = _WindowsOnly.unavailable_reason()
    if sys.platform == "win32":
        assert _WindowsOnly.platform_supported() is True
        assert _WindowsOnly.is_available() is True
        assert reason is None
    else:
        assert _WindowsOnly.platform_supported() is False
        assert _WindowsOnly.is_available() is False
        assert "not supported on" in reason


def test_sensitive_collectors_are_opt_in() -> None:
    class _Surveillance(_FakeCollector):
        name = "surveillance"
        sensitive = True
        requires = ()

        @classmethod
        def effective_requires(cls) -> tuple[str, ...]:
            return ()

    # Registering every collector must not silently switch on capture.
    assert _Surveillance().enabled is False
    assert _Surveillance().status()["enabled"] is False
    # ...but an explicit opt-in still works.
    assert _Surveillance({"enabled": True}).enabled is True
    assert _Surveillance({"enabled": False}).enabled is False


def test_manager_registers_every_known_collector() -> None:
    classes, errors = load_collector_classes()
    assert errors == {}, f"collector modules failed to import: {errors}"
    assert classes, "catalog resolved no collectors"

    mgr = CollectorManager({}, collectors=classes)
    status = mgr.status()
    assert status["registered"] == len(classes)
    assert status["init_errors"] == {}
    names = set(status["collectors"])
    # The original defect was a hardcoded three-collector subset; these must
    # always be present regardless of what else the catalog grows to include.
    assert {"process", "usb", "window", "clipboard", "screenshot", "print"} <= names


def test_catalog_covers_every_collector_module_on_disk() -> None:
    """Guards the original defect: an implemented collector that no inventory
    references, and which therefore never appears in any status report."""
    import endpoint_agent.collectors as pkg
    from endpoint_agent.collectors.catalog import _COLLECTOR_CLASSES

    listed = {path.rsplit(".", 1)[-1] for path, _ in _COLLECTOR_CLASSES}
    helpers = {"__init__", "catalog", "dependencies", "capture_state"}
    on_disk = {
        p.stem for p in Path(pkg.__file__).parent.glob("*.py")
        if p.stem not in helpers and not p.stem.startswith("_")
    }
    missing = on_disk - listed
    assert not missing, f"collector modules absent from the catalog: {sorted(missing)}"

    classes, errors = load_collector_classes()
    assert errors == {}
    assert len(classes) == len(_COLLECTOR_CLASSES)


def test_manager_status_surfaces_inert_collectors() -> None:
    mgr = CollectorManager({}, collectors=[NoopCollector, _FakeCollector])
    status = mgr.status()
    assert "fake" in status["inert"]
    assert status["missing_dependencies"] == ["definitely_not_installed_module"]
    assert "pip install" in status["install_command"]
    assert status["collectors"]["noop"]["available"] is True


def test_manager_records_initialization_failures() -> None:
    class _Broken(NoopCollector):
        name = "broken"

        def __init__(self, config=None):  # type: ignore[no-untyped-def]
            raise RuntimeError("cannot build")

    mgr = CollectorManager({}, collectors=[NoopCollector, _Broken])
    status = mgr.status()
    # A collector that cannot even be constructed must still be visible.
    assert "cannot build" in status["init_errors"]["broken"]
    assert status["registered"] == 1


def test_catalog_report_matches_runtime_availability() -> None:
    report = catalog_report()
    assert report["registered"] == len(load_collector_classes()[0])
    assert report["import_errors"] == {}
    for entry in report["collectors"]:
        if entry["missing_dependencies"] and not entry["unavailable_reason"]:
            pytest.fail(
                f"{entry['name']} reports missing dependencies "
                f"{entry['missing_dependencies']} with no reason"
            )
        if not entry["available"] and not entry["unavailable_reason"]:
            pytest.fail(f"{entry['name']} is unavailable without an explanation")


def test_catalog_marks_capture_collectors_opt_in() -> None:
    entries = {e["name"]: e for e in catalog_report()["collectors"]}
    for name in ("clipboard", "screenshot", "window", "usb"):
        assert entries[name]["sensitive"] is True
        assert entries[name]["enabled_by_default"] is False
    assert entries["process"]["sensitive"] is False


def test_every_import_name_maps_to_a_real_distribution() -> None:
    for module, dep in dependencies._BY_MODULE.items():
        if not dep.pip_name:
            # Only stdlib/platform modules may omit a distribution name.
            assert module == "winreg", f"{module} needs a pip_name"
            continue
        assert dep.pip_name in {
            "psutil", "pywin32", "Pillow", "mss", "pyperclip", "watchdog",
            "pyobjc", "pyudev", "pynput",
        }, f"{module} maps to unexpected distribution {dep.pip_name}"


def test_install_command_deduplicates_shared_distributions() -> None:
    # win32gui/win32api/win32print all ship in pywin32.
    cmd = dependencies.install_command(("win32gui", "win32api", "win32print"))
    assert cmd == "pip install pywin32"


def test_dependency_report_separates_relevant_from_all_missing() -> None:
    report = dependencies.dependency_report()
    assert report["platform"] in {"windows", "linux", "macos"}
    assert set(report["missing"]) >= set(report["missing_relevant"])
    if report["missing_relevant"]:
        assert report["install_command"]
        assert report["complete_for_platform"] is False
    # macOS-only modules are never actionable on a Windows endpoint.
    if report["platform"] == "windows":
        assert "Quartz" not in report["missing_relevant"]
        assert "pyudev" not in report["missing_relevant"]


def test_module_available_uses_find_spec_without_importing() -> None:
    assert dependencies.module_available("json") is True
    assert dependencies.module_available("no_such_module_anywhere") is False


def test_doctor_command_reports_and_gates_exit_code() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "endpoint_agent", "doctor"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0
    assert "Collectors usable:" in proc.stdout

    strict = subprocess.run(
        [sys.executable, "-m", "endpoint_agent", "doctor", "--strict"],
        capture_output=True, text=True,
    )
    usable = catalog_report()["collectors"]
    expected = 0 if all(e["available"] for e in usable) else 1
    assert strict.returncode == expected


def test_doctor_json_output_is_machine_readable() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "endpoint_agent", "doctor", "--json"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0
    report = json.loads(proc.stdout)
    assert report["registered"] == len(load_collector_classes()[0])
    assert report["dependencies"]["python"]
    assert isinstance(report["collectors"], list)
