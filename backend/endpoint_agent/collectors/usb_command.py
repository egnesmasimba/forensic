from __future__ import annotations

import logging
import platform
import shutil
import subprocess
from typing import Any

from endpoint_agent.collectors import Collector


logger = logging.getLogger(__name__)


class UsbCommandCollector(Collector):
    """Command-driven collector: executes block_usb / unblock_usb actions requested by server.

    Not scheduled like tick collectors; invoked via CollectorManager.accept_command(...).
    Still emits endpoint events for auditability.
    """
    name = "usb_command"
    default_interval_seconds = 0.0  # disabled as a tick collector by default

    @classmethod
    def supports_current_os(cls) -> bool:
        return True

    def _collect(self) -> list[dict[str, Any]]:
        return []

    def execute(self, command: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        """Return list of events describing the action result."""
        events: list[dict[str, Any]] = []
        if command == "block_usb":
            ok, detail = self._block_usb(args)
            events.append({
                "type": "usb_block_attempt",
                "severity": "high" if not ok else "medium",
                "payload": {"action": "block", "success": bool(ok), "detail": detail, "args": args},
            })
        elif command == "unblock_usb":
            ok, detail = self._unblock_usb(args)
            events.append({
                "type": "usb_block_attempt",
                "severity": "medium",
                "payload": {"action": "unblock", "success": bool(ok), "detail": detail, "args": args},
            })
        return events

    # ----- platform actions -----

    def _run(self, cmd: list[str]) -> tuple[int, str]:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            return res.returncode, (res.stdout or "") + (res.stderr or "")
        except Exception as e:
            return -1, f"subprocess error: {e}"

    def _block_usb(self, args: dict[str, Any]) -> tuple[bool, str]:
        sysname = platform.system().lower()
        if sysname == "windows":
            # Best-effort: disable USBSTOR service via registry + sc config
            cmds = [
                ["reg", "add",
                 "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
                 "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f"],
                ["sc.exe", "config", "USBSTOR", "start=", "disabled"],
            ]
            outs = []
            for c in cmds:
                rc, out = self._run(c)
                outs.append(f"{c[0]} rc={rc}")
                if rc != 0:
                    return False, "; ".join(outs) + f" | cmd_output: {out[:400]}"
            return True, "; ".join(outs)
        if sysname == "linux":
            driver = shutil.which("udevadm") or ""
            rule = 'SUBSYSTEM=="usb", MODE="0000"'
            rule_path = args.get("rule_path", "/etc/udev/rules.d/99-zanaq-block-usb.rules")
            try:
                with open(rule_path, "w") as fh:
                    fh.write(rule + "\n")
            except Exception as e:
                return False, f"write rule failed: {e}"
            if driver:
                rc, out = self._run([driver, "control", "--reload-rules"])
                return rc == 0, f"wrote {rule_path}; udevadm rc={rc} out={out[:300]}"
            return True, f"wrote {rule_path}; no udevadm to reload"
        if sysname == "darwin":
            try:
                script = ('do shell script "kextunload -b com.apple.driver.AppleUSBOHCI '
                          '-b com.apple.driver.AppleUSBEHCI -b com.apple.driver.AppleUSBXHCI" with administrator privileges')
                rc, out = self._run(["osascript", "-e", script])
                return rc == 0, f"osascript rc={rc} out={out[:300]}"
            except Exception as e:
                return False, str(e)
        return False, f"unsupported os: {sysname}"

    def _unblock_usb(self, args: dict[str, Any]) -> tuple[bool, str]:
        sysname = platform.system().lower()
        if sysname == "windows":
            cmds = [
                ["reg", "add",
                 "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
                 "/v", "Start", "/t", "REG_DWORD", "/d", "3", "/f"],
                ["sc.exe", "config", "USBSTOR", "start=", "demand"],
            ]
            outs = []
            for c in cmds:
                rc, out = self._run(c)
                outs.append(f"{c[0]} rc={rc}")
                if rc != 0:
                    return False, "; ".join(outs) + f" | {out[:400]}"
            return True, "; ".join(outs)
        if sysname == "linux":
            rule_path = args.get("rule_path", "/etc/udev/rules.d/99-zanaq-block-usb.rules")
            import os as _os
            try:
                if _os.path.exists(rule_path):
                    _os.remove(rule_path)
            except Exception as e:
                return False, f"remove rule failed: {e}"
            driver = shutil.which("udevadm") or ""
            if driver:
                rc, out = self._run([driver, "control", "--reload-rules"])
                return True, f"removed {rule_path}; udevadm rc={rc} out={out[:300]}"
            return True, f"removed {rule_path}"
        if sysname == "darwin":
            script = ('do shell script "kextload -b com.apple.driver.AppleUSBOHCI '
                      '-b com.apple.driver.AppleUSBEHCI -b com.apple.driver.AppleUSBXHCI" with administrator privileges')
            rc, out = self._run(["osascript", "-e", script])
            return rc == 0, f"osascript rc={rc} out={out[:300]}"
        return False, f"unsupported os: {sysname}"

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "usb_block_attempt",
            "severity": "medium",
            "payload": {"action": "block", "success": True,
                        "detail": "USBSTOR Start=4 written", "args": {}},
        }
