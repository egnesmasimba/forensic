from __future__ import annotations

import logging
import subprocess
import platform
from pathlib import Path
from typing import Any, Iterable, Optional

from ..print_policy import PrintContentPolicy
from . import Collector, current_os_tag
from .transfers import inspect_file

logger = logging.getLogger(__name__)


def _windows_print_available() -> bool:
    try:
        import win32print  # noqa: F401
        return True
    except ImportError:
        return False


def _cups_available() -> bool:
    os_tag = current_os_tag()
    if os_tag in ("linux", "macos"):
        try:
            subprocess.run(["lpstat", "-W", "all"], capture_output=True, timeout=2)
            return True
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            return False
    return False


#: DEVMODE duplex codes, per the Windows DEVMODE structure.
_DUPLEX_MODES = {1: "simplex", 2: "duplex", 3: "tumble"}


def _devmode_fields(devmode: Any) -> dict[str, Any]:
    """Read copies/colour/duplex from a pywin32 DEVMODE.

    ``EnumJobs`` does not return a per-job DEVMODE, so these fields are
    best-effort: whatever cannot be read is reported as ``None`` rather than
    guessed. Requires pywin32 and therefore a real spooler to validate.
    """
    out: dict[str, Any] = {"copies": None, "color": None, "duplex": None}
    if devmode is None:
        return out
    for attr, key, caster in (
        ("Copies", "copies", int),
        ("Color", "color", bool),
        ("Duplex", "duplex", int),
    ):
        value = getattr(devmode, attr, None)
        if value is None and isinstance(devmode, dict):
            value = devmode.get(key)
        if value is None:
            continue
        try:
            out[key] = caster(value)
        except (TypeError, ValueError):
            continue
    if out["duplex"] is not None:
        out["duplex"] = _DUPLEX_MODES.get(out["duplex"], "unknown")
    return out


def _job_devmode(job: dict[str, Any]) -> dict[str, Any]:
    """Extract a per-job DEVMODE from whichever key pywin32 supplied."""
    for key in ("pDevMode", "DevMode", "pDevmode"):
        if job.get(key):
            return _devmode_fields(job[key])
    return _devmode_fields(None)


def _printer_location(handle: Any) -> str:
    """Printer location string from the printer's level-2 info, if present."""
    try:
        import win32print

        info = win32print.GetPrinter(handle, 2)
        return str(info.get("pLocation") or "")[:200]
    except Exception:  # noqa: BLE001 - location is optional metadata
        return ""


class PrintCollector(Collector):
    name = "print"
    default_interval_seconds = 15.0
    requires = ("win32print",)
    # CUPS is implemented in ``_scan_cups`` and carries no win32print
    # dependency, so the collector must not advertise Windows-only support.
    platforms = ("windows", "linux", "macos")

    @classmethod
    def effective_requires(cls) -> tuple[str, ...]:
        # win32print only applies to the Windows spooler.
        return cls.requires if current_os_tag() == "windows" else ()

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._seen_jobs: set[str] = set()
        self.policy = PrintContentPolicy(self._config.get("content_policy"))

    def status(self) -> dict[str, Any]:
        return {**super().status(), "content_policy": self.policy.status()}

    @classmethod
    def supports_current_os(cls) -> bool:
        os_tag = current_os_tag()
        if os_tag == "windows":
            if not _windows_print_available():
                logger.info("print unsupported on windows: pywin32 win32print not installed")
                return False
            return True
        if os_tag in ("linux", "macos"):
            if not _cups_available():
                logger.info("print unsupported: CUPS lpstat not available on %s", os_tag)
                return False
            return True
        logger.info("print unsupported: platform %s", platform.system())
        return False

    def _scan_windows(self) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = []
        try:
            import win32print
            printers = win32print.EnumPrinters(2)
            for prn in printers:
                prn_name = prn[2]
                try:
                    h = win32print.OpenPrinter(prn_name)
                    try:
                        location = _printer_location(h)
                        raw = win32print.EnumJobs(h, 0, -1, 1)
                        for job in raw:
                            jid = f"{prn_name}-{job.get('JobId', 0)}"
                            entry = {
                                "job_key": jid,
                                "printer": prn_name,
                                "printer_location": location,
                                "job_id": int(job.get("JobId", 0) or 0),
                                "user": str(job.get("pUserName", "") or ""),
                                "document": str(job.get("pDocument", "") or ""),
                                "status": str(job.get("Status", "") or ""),
                                "pages": int(job.get("TotalPages", 0) or 0),
                                "size": int(job.get("Size", 0) or 0),
                            }
                            entry.update(_job_devmode(job))
                            jobs.append(entry)
                    finally:
                        win32print.ClosePrinter(h)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("win32print enum %s failed: %s", prn_name, exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("print windows scan failed: %s", exc)
        return jobs

    def _scan_cups(self) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = []
        try:
            out = subprocess.check_output(["lpstat", "-W", "all", "-l"], text=True, timeout=5)
            current: Optional[dict[str, Any]] = None
            for line in out.splitlines():
                line = line.rstrip()
                if not line:
                    continue
                if line.startswith(" ") and current:
                    current["_raw"] = current.get("_raw", "") + "\n" + line.strip()
                    continue
                if ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip().lower()
                    val = val.strip()
                    if key == "job" and "-" in val:
                        if current:
                            jobs.append(current)
                        parts = val.split("-", 1)
                        current = {
                            "job_key": val,
                            "printer": parts[0],
                            "job_id": int(parts[1]) if parts[1].isdigit() else 0,
                            "document": "",
                            "user": "",
                            "status": "",
                            "pages": 0,
                            "size": 0,
                            "_raw": val,
                        }
                    elif current:
                        if key.startswith("owner"):
                            current["user"] = val
                        elif key.startswith("name") or key == "title":
                            current["document"] = val
                        elif key.startswith("status"):
                            current["status"] = val
                        elif key.startswith("size"):
                            try:
                                current["size"] = int(val.split()[0])
                            except (ValueError, IndexError):
                                pass
                        elif key.startswith("pages"):
                            try:
                                current["pages"] = int(val.split()[0])
                            except (ValueError, IndexError):
                                pass
            if current:
                jobs.append(current)
            for j in jobs:
                j.pop("_raw", None)
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
            logger.warning("print cups scan failed: %s", exc)
        return jobs

    def _scan(self) -> list[dict[str, Any]]:
        os_tag = current_os_tag()
        if os_tag == "windows":
            return self._scan_windows()
        return self._scan_cups()

    def _normalise_job(self, job: dict[str, Any]) -> dict[str, Any]:
        """Give every platform's job the same metadata keys.

        CUPS exposes neither per-job DEVMODE nor a location string, so those
        fields are reported as ``None`` rather than omitted: an examiner can
        tell "not reported by this platform" from "missing".
        """
        entry = {k: v for k, v in job.items() if k != "job_key"}
        for key, default in (
            ("printer_location", None),
            ("copies", None),
            ("color", None),
            ("duplex", None),
        ):
            entry.setdefault(key, default)
        return entry

    def _capture_candidates(self, jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Retain a bounded copy of sources that matched the print policy."""
        events: list[dict[str, Any]] = []
        if not self.policy.active:
            return events
        # Expire on the collection tick: the server's retention job can expire
        # the event but has no way to reach bytes held on the endpoint.
        try:
            self.policy.expire_artifacts(dry_run=False)
        except OSError as exc:
            logger.warning("print artifact retention pass failed: %s", exc)
        captured = 0
        for job in jobs:
            if captured >= self.policy.max_per_pass:
                # Reported as a skip: nothing was retained, and the server
                # treats "capture" as grounds for a sensitive-print alert.
                events.append({
                    "type": "print_document",
                    "severity": "low",
                    "payload": {
                        "decision": "skip",
                        "reason": "per_pass_limit_reached",
                        "printer": job.get("printer", ""),
                        "document": job.get("document", ""),
                        "user": job.get("user", ""),
                    },
                })
                break
            decision = self.policy.evaluate(job)
            if not decision.capture:
                # Declining is recorded, so an absent capture is explainable
                # rather than indistinguishable from a missed print.
                events.append({
                    "type": "print_document",
                    "severity": "low",
                    "payload": {
                        "decision": "skip",
                        "reason": decision.reason,
                        "printer": job.get("printer", ""),
                        "printer_location": job.get("printer_location"),
                        "document": job.get("document", ""),
                        "user": job.get("user", ""),
                        "pages": job.get("pages", 0),
                        "copies": job.get("copies"),
                        "color": job.get("color"),
                        "duplex": job.get("duplex"),
                    },
                })
                continue
            source = Path(decision.source_path) if decision.source_path else None
            scan: dict[str, Any] = {}
            retained: dict[str, Any] = {"retained": False, "reason": "source_not_resolved"}
            if source is not None:
                try:
                    if source.stat().st_size > self.policy.max_capture_bytes:
                        scan = {"partial": True, "size": source.stat().st_size,
                                "notes": ["Source exceeds the configured capture limit; not retained"]}
                        retained = {"retained": False, "reason": "source_exceeds_capture_limit"}
                    else:
                        scan = inspect_file(source)
                        store = self.policy.store
                        if store is None:
                            # No artifact directory configured: the policy
                            # matched but nothing is being kept, which the
                            # payload must say rather than imply a capture.
                            retained = {"retained": False, "reason": "artifact_store_not_configured"}
                        else:
                            retained = store.retain(source, job=job)
                            if not retained.get("retained"):
                                scan.setdefault("notes", []).append(
                                    "Source matched policy but was not retained: "
                                    + str(retained.get("reason"))
                                )
                except OSError as exc:
                    scan = {"error": f"{type(exc).__name__}: {exc}"}
                    retained = {"retained": False, "reason": f"source_unreadable: {type(exc).__name__}"}
            captured += 1
            events.append({
                "type": "print_document",
                "severity": "high",
                "payload": {
                    "decision": "capture",
                    "reason": decision.reason,
                    "matched_terms": list(decision.matched_terms),
                    "printer": job.get("printer", ""),
                    "printer_location": job.get("printer_location"),
                    "document": job.get("document", ""),
                    "source_path": decision.source_path,
                    "user": job.get("user", ""),
                    "pages": job.get("pages", 0),
                    "copies": job.get("copies"),
                    "color": job.get("color"),
                    "duplex": job.get("duplex"),
                    "file_scan": scan,
                    "retained_copy": retained,
                },
            })
        return events

    def _collect(self) -> Iterable[dict[str, Any]]:
        jobs = self._scan()
        events: list[dict[str, Any]] = []
        fresh: list[dict[str, Any]] = []
        for job in jobs:
            key = str(job.get("job_key", ""))
            if key and key not in self._seen_jobs:
                self._seen_jobs.add(key)
                fresh.append(job)
                payload = self._normalise_job(job)
                sev = "high" if (job.get("pages") or 0) >= 20 else "medium"
                events.append({"type": "print_job", "severity": sev, "payload": payload})
        if len(self._seen_jobs) > 5000:
            self._seen_jobs = set(list(self._seen_jobs)[-2000:])
        events.extend(self._capture_candidates(fresh))
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "print_job",
            "severity": "medium",
            "payload": {
                "printer": "HP-LaserJet",
                "job_id": 42,
                "user": "alice",
                "document": "quarterly-report.pdf",
                "status": "PRINTING",
                "pages": 12,
                "size": 245760,
            },
        }
