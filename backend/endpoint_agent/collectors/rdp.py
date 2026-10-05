from __future__ import annotations

import logging
import subprocess
from typing import Any, Iterable, Optional

from . import Collector, current_os_tag

logger = logging.getLogger(__name__)


def _windows_rdp_available() -> bool:
    try:
        import pythoncom  # noqa: F401
        import wmi  # noqa: F401
        return True
    except ImportError:
        try:
            import win32com.client  # noqa: F401
            return True
        except ImportError:
            return False


def _linux_loginctl_available() -> bool:
    try:
        subprocess.run(["loginctl", "list-sessions"], capture_output=True, timeout=2)
        return True
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return False


class RDPCollector(Collector):
    name = "rdp"
    default_interval_seconds = 15.0
    #: macOS has no standard remote-session query; previously this collector
    #: reported success there while collecting nothing at all.
    platforms = ("windows", "linux")

    @classmethod
    def effective_requires(cls) -> tuple[str, ...]:
        # Either WMI or the pywin32 COM fallback is enough on Windows, and the
        # Linux path shells out to loginctl, so nothing is strictly mandatory.
        return ()

    @classmethod
    def unavailable_reason(cls) -> Optional[str]:
        if cls.is_available():
            return None
        if current_os_tag() == "windows":
            return (
                "no usable RDP query backend: requires pywin32 (pythoncom/wmi) "
                "or win32com.client"
            )
        if current_os_tag() == "linux":
            return "no usable RDP query backend: requires the loginctl binary"
        return "no standard remote session query available on this platform"

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._active_sessions: dict[str, dict[str, Any]] = {}

    @classmethod
    def supports_current_os(cls) -> bool:
        os_tag = current_os_tag()
        if os_tag == "windows":
            if not _windows_rdp_available():
                logger.info("rdp unsupported on windows: wmi/pywin32 not available")
                return False
            return True
        if os_tag == "linux":
            if not _linux_loginctl_available():
                logger.info("rdp unsupported on linux: loginctl not available")
                return False
            return True
        if os_tag == "macos":
            logger.info("rdp no-op on macos (no standard session query)")
            return True
        logger.info("rdp no-op on %s", os_tag)
        return True

    def _scan_windows(self) -> dict[str, dict[str, Any]]:
        sessions: dict[str, dict[str, Any]] = {}
        try:
            try:
                import pythoncom
                import wmi
                pythoncom.CoInitialize()
                try:
                    c = wmi.WMI()
                    for s in c.Win32_LogonSession():
                        try:
                            stype = int(s.LogonType or 0)
                            remote = stype in (10,)  # 10 = RemoteInteractive
                            sid = str(s.LogonId or "")
                            if not sid:
                                continue
                            entry = {
                                "session_id": sid,
                                "logon_type": stype,
                                "remote": bool(remote),
                                "authentication_package": str(s.AuthenticationPackage or ""),
                                "start_time": str(s.StartTime or ""),
                            }
                            for owner in s.associators(wmi_association_class="Win32_LoggedOnUser"):
                                try:
                                    entry["user"] = str(getattr(owner, "Name", "") or "")
                                    entry["domain"] = str(getattr(owner, "Domain", "") or "")
                                except Exception:  # noqa: BLE001
                                    pass
                            sessions[sid] = entry
                        except Exception:  # noqa: BLE001
                            continue
                finally:
                    pythoncom.CoUninitialize()
            except ImportError:
                import win32com.client
                loc = win32com.client.Dispatch("WbemScripting.SWbemLocator")
                svc = loc.ConnectServer(".", "root\\cimv2")
                for s in svc.ExecQuery("SELECT * FROM Win32_LogonSession"):
                    try:
                        stype = int(s.LogonType or 0)
                        remote = stype == 10
                        sid = str(s.LogonId or "")
                        if not sid:
                            continue
                        sessions[sid] = {
                            "session_id": sid,
                            "logon_type": stype,
                            "remote": bool(remote),
                        }
                    except Exception:  # noqa: BLE001
                        continue
        except Exception as exc:  # noqa: BLE001
            logger.warning("rdp windows scan failed: %s", exc)
        return sessions

    def _scan_linux(self) -> dict[str, dict[str, Any]]:
        sessions: dict[str, dict[str, Any]] = {}
        try:
            out = subprocess.check_output(
                ["loginctl", "list-sessions", "--no-legend", "--no-pager"],
                text=True, timeout=5,
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                sid, user, seat = parts[0], parts[1], parts[2] if len(parts) >= 3 else ""
                remote = any(s in seat.lower() for s in ("rdp", "vnc", "xrdp", "nx", "nomachine"))
                try:
                    show = subprocess.check_output(
                        ["loginctl", "show-session", sid, "--no-pager", "-p", "Type", "-p", "Remote", "-p", "Service"],
                        text=True, timeout=3,
                    )
                    stype = ""
                    is_remote = False
                    for ln in show.splitlines():
                        if "=" in ln:
                            k, v = ln.split("=", 1)
                            if k.strip() == "Type":
                                stype = v.strip()
                            elif k.strip() == "Remote":
                                is_remote = v.strip().lower() in ("1", "true", "yes")
                    sessions[sid] = {
                        "session_id": sid,
                        "user": user,
                        "seat": seat,
                        "type": stype,
                        "remote": bool(is_remote or remote),
                    }
                except (subprocess.SubprocessError, OSError):
                    sessions[sid] = {
                        "session_id": sid,
                        "user": user,
                        "seat": seat,
                        "remote": bool(remote),
                    }
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
            logger.warning("rdp linux scan failed: %s", exc)
        return sessions

    def _scan(self) -> dict[str, dict[str, Any]]:
        os_tag = current_os_tag()
        if os_tag == "windows":
            return self._scan_windows()
        if os_tag == "linux":
            return self._scan_linux()
        return {}

    def _collect(self) -> Iterable[dict[str, Any]]:
        current = self._scan()
        events: list[dict[str, Any]] = []
        prev = self._active_sessions
        for sid, info in current.items():
            if sid not in prev and info.get("remote"):
                payload = dict(info)
                sev = "high" if info.get("logon_type") == 10 else "medium"
                events.append({"type": "rdp_connect", "severity": sev, "payload": payload})
        for sid, info in prev.items():
            if sid not in current and info.get("remote"):
                payload = dict(info)
                events.append({"type": "rdp_disconnect", "severity": "low", "payload": payload})
        self._active_sessions = current
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "rdp_connect",
            "severity": "high",
            "payload": {
                "session_id": "4",
                "logon_type": 10,
                "remote": True,
                "user": "alice",
                "domain": "CORP",
                "authentication_package": "Kerberos",
                "start_time": "20261003080000.000000+120",
            },
        }
