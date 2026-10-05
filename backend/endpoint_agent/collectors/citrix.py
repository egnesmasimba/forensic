from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import sys
from typing import Any

from endpoint_agent.collectors import Collector


logger = logging.getLogger(__name__)


class CitrixCollector(Collector):
    name = "citrix"
    default_interval_seconds = 10.0
    requires = ("psutil",)

    _WIN_PROCS = ("wfica32.exe", "wfcrun32.exe", "cdviewer.exe", "concentr.exe", "receiver.exe", "selfservice.exe")
    _NIX_PROCS = ("wfica", "wfcrun", "ctxusbd", "ctxhidsvc", "ctxcwalogd")
    _DRIVE_LETTERS = tuple(f"{chr(c)}:\\" for c in range(ord("A"), ord("Z") + 1))

    @classmethod
    def supports_current_os(cls) -> bool:
        return True

    def _scan_processes(self) -> list[dict[str, Any]]:
        try:
            import psutil  # type: ignore
        except Exception:
            return []
        hits: list[dict[str, Any]] = []
        target = self._WIN_PROCS if platform.system().lower() == "windows" else self._NIX_PROCS
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
            try:
                info = proc.info or {}
                nm = (info.get("name") or "").lower()
                if any(nm.startswith(p[:8]) for p in target) or any(p in nm for p in target):
                    hits.append({
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "exe": info.get("exe"),
                        "cmdline": " ".join(info.get("cmdline") or [])[:500],
                        "username": info.get("username"),
                    })
            except Exception:
                continue
        return hits

    def _mapped_client_drives(self) -> list[str]:
        r"""Windows only: look for \\client\$C style network drives or Client drives."""
        if platform.system().lower() != "windows":
            return []
        try:
            import ctypes
            import string
            drives = []
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    root = f"{letter}:\\"
                    try:
                        name_buf = ctypes.create_unicode_buffer(256)
                        fs_buf = ctypes.create_unicode_buffer(256)
                        ok = ctypes.windll.kernel32.GetVolumeInformationW(
                            ctypes.c_wchar_p(root), name_buf, 256, None, None, None, fs_buf, 256
                        )
                        label = name_buf.value if ok else ""
                        if "client" in label.lower() or label.lower().startswith(("client ", "$client")):
                            drives.append(f"{letter}:\\ ({label})")
                    except Exception:
                        pass
                bitmask >>= 1
            return drives
        except Exception:
            return []

    def _collect(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        procs = self._scan_processes()
        for p in procs:
            events.append({
                "type": "citrix_start",
                "severity": "medium",
                "payload": {
                    "kind": "process",
                    "pid": p["pid"],
                    "process_name": p["name"],
                    "exe": p["exe"],
                    "cmdline": p["cmdline"],
                    "username": p["username"],
                },
            })
        drives = self._mapped_client_drives()
        if drives:
            events.append({
                "type": "citrix_window",
                "severity": "low",
                "payload": {"kind": "mapped_drives", "drives": drives},
            })
        if procs:
            events.append({
                "type": "citrix_clipboard",
                "severity": "low",
                "payload": {"kind": "channel_hint", "processes": [p["name"] for p in procs],
                            "notes": "Citrix client present; clipboard channel may be active"},
            })
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "citrix_start",
            "severity": "medium",
            "payload": {"kind": "process", "pid": 0, "process_name": "wfica32.exe",
                        "exe": "C:\\Program Files (x86)\\Citrix\\ICA Client\\wfica32.exe",
                        "cmdline": "wfica32.exe", "username": "user"},
        }
