from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

from . import Collector, current_os_tag

logger = logging.getLogger(__name__)

_RUN_PATHS: list[tuple[str, str]] = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]


def _winreg_available() -> bool:
    try:
        import winreg  # noqa: F401
        return True
    except ImportError:
        return False


class RegistryCollector(Collector):
    name = "registry"
    default_interval_seconds = 60.0
    requires = ("winreg",)
    platforms = ("windows",)

    @classmethod
    def effective_requires(cls) -> tuple[str, ...]:
        # winreg exists only on Windows; elsewhere this collector is inert for
        # platform reasons, not because a module is missing.
        return cls.requires if current_os_tag() == "windows" else ()

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        extra = self._config.get("watch_keys") or []
        self._watch_keys: list[tuple[str, str]] = list(_RUN_PATHS)
        for item in extra:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                self._watch_keys.append((str(item[0]), str(item[1])))
            elif isinstance(item, str) and "\\" in item:
                hive, _, sub = item.partition("\\")
                self._watch_keys.append((hive, sub))
        self._baseline: dict[str, dict[str, Any]] = {}
        self._baseline_ready = False

    @classmethod
    def supports_current_os(cls) -> bool:
        os_tag = current_os_tag()
        if os_tag == "windows":
            if not _winreg_available():
                logger.info("registry unsupported on windows: winreg not available")
                return False
            return True
        logger.info("registry no-op on %s (Windows-only collector)", os_tag)
        return True

    def _hive_to_const(self, hive: str):
        import winreg
        hive_u = hive.upper()
        if hive_u in ("HKLM", "HKEY_LOCAL_MACHINE"):
            return winreg.HKEY_LOCAL_MACHINE
        if hive_u in ("HKCU", "HKEY_CURRENT_USER"):
            return winreg.HKEY_CURRENT_USER
        if hive_u in ("HKU", "HKEY_USERS"):
            return winreg.HKEY_USERS
        if hive_u in ("HKCR", "HKEY_CLASSES_ROOT"):
            return winreg.HKEY_CLASSES_ROOT
        if hive_u in ("HKCC", "HKEY_CURRENT_CONFIG"):
            return winreg.HKEY_CURRENT_CONFIG
        return None

    def _read_key(self, hive_str: str, subkey: str) -> dict[str, Any]:
        import winreg
        result: dict[str, Any] = {}
        hive = self._hive_to_const(hive_str)
        if hive is None:
            return result
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(k, i)
                        result[name] = {"value": str(value), "type": int(vtype)}
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            return result
        except PermissionError as exc:
            logger.debug("registry cannot read %s\\%s: %s", hive_str, subkey, exc)
            return result
        except OSError as exc:
            logger.debug("registry read error %s\\%s: %s", hive_str, subkey, exc)
            return result
        return result

    def _collect(self) -> Iterable[dict[str, Any]]:
        os_tag = current_os_tag()
        if os_tag != "windows":
            return []
        current: dict[str, dict[str, Any]] = {}
        for hive, sub in self._watch_keys:
            current[f"{hive}\\{sub}"] = self._read_key(hive, sub)

        events: list[dict[str, Any]] = []
        if self._baseline_ready:
            for key_path in sorted(set(self._baseline) | set(current)):
                prev_vals = self._baseline.get(key_path, {})
                cur_vals = current.get(key_path, {})
                all_names = set(prev_vals) | set(cur_vals)
                for name in sorted(all_names):
                    before = prev_vals.get(name)
                    after = cur_vals.get(name)
                    if before == after:
                        continue
                    payload: dict[str, Any] = {
                        "key": key_path,
                        "value_name": name,
                        "before": before,
                        "after": after,
                    }
                    if before is None:
                        payload["change"] = "added"
                    elif after is None:
                        payload["change"] = "removed"
                    else:
                        payload["change"] = "modified"
                    sev = "high" if any(
                        m in str(after or before or "").lower()
                        for m in ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "regsvr32", "rundll32")
                    ) else "medium"
                    events.append({"type": "registry_change", "severity": sev, "payload": payload})
        self._baseline = current
        self._baseline_ready = True
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "registry_change",
            "severity": "medium",
            "payload": {
                "key": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "MaliciousStarter",
                "change": "added",
                "before": None,
                "after": {"value": "C:\\Users\\alice\\evil.exe --hidden", "type": 1},
            },
        }
