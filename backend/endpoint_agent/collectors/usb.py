from __future__ import annotations

import logging
import platform
from typing import Any, Iterable, Optional

from . import Collector, current_os_tag, dependencies

logger = logging.getLogger(__name__)


def _windows_wmi_available() -> bool:
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


def _windows_pywin32_available() -> bool:
    try:
        import win32api  # noqa: F401
        import win32con  # noqa: F401
        return True
    except ImportError:
        return False


def _linux_pyudev_available() -> bool:
    try:
        import pyudev  # noqa: F401
        return True
    except ImportError:
        return False


def _macos_pyobjc_available() -> bool:
    try:
        import objc  # noqa: F401
        from Quartz import IOServiceGetMatchingService, IOServiceMatching  # noqa: F401
        return True
    except ImportError:
        return False


class USBCollector(Collector):
    name = "usb"
    default_interval_seconds = 10.0
    sensitive = True

    @classmethod
    def effective_requires(cls) -> tuple[str, ...]:
        os_tag = current_os_tag()
        if os_tag == "linux":
            return ("pyudev",)
        if os_tag == "macos":
            return ("objc", "Quartz")
        # On Windows either pywin32 or WMI suffices, so nothing is mandatory.
        return ()

    @classmethod
    def unavailable_reason(cls) -> Optional[str]:
        if cls.is_available():
            return None
        os_tag = current_os_tag()
        alternatives = {
            "windows": ("pywin32", "pywin32 (win32api/win32con) or WMI"),
            "linux": ("pyudev", "pyudev"),
            "macos": ("pyobjc", "pyobjc (objc/Quartz IOKit)"),
        }.get(os_tag, ("pywin32", "pywin32 or WMI"))
        install = dependencies.install_command((alternatives[0],))
        return (
            f"no usable USB backend for {os_tag}: requires {alternatives[1]} "
            f"(install with: {install})"
        )

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._known_devices: dict[str, dict[str, Any]] = {}

    @classmethod
    def supports_current_os(cls) -> bool:
        os_tag = current_os_tag()
        if os_tag == "windows":
            if not _windows_wmi_available() and not _windows_pywin32_available():
                logger.info("usb unsupported on windows: wmi/pywin32 not installed")
                return False
            return True
        if os_tag == "linux":
            if not _linux_pyudev_available():
                logger.info("usb unsupported on linux: pyudev not installed")
                return False
            return True
        if os_tag == "macos":
            if not _macos_pyobjc_available():
                logger.info("usb unsupported on macos: pyobjc (Quartz/IOKit) not installed")
                return False
            return True
        logger.info("usb unsupported: unknown platform %s", platform.system())
        return False

    def _scan_windows_wmi(self) -> dict[str, dict[str, Any]]:
        devices: dict[str, dict[str, Any]] = {}
        try:
            try:
                import pythoncom
                import wmi
                pythoncom.CoInitialize()
                try:
                    c = wmi.WMI()
                    for disk in c.Win32_DiskDrive():
                        if "USB" in (disk.InterfaceType or ""):
                            devid = str(disk.DeviceID or "")
                            if not devid:
                                continue
                            devices[devid] = {
                                "device_id": devid,
                                "model": str(disk.Model or ""),
                                "serial": str(disk.SerialNumber or ""),
                                "size": int(disk.Size or 0),
                                "interface": "USB",
                            }
                finally:
                    pythoncom.CoUninitialize()
            except ImportError:
                import win32com.client
                strComputer = "."
                objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
                objSWbemServices = objWMIService.ConnectServer(strComputer, "root\\cimv2")
                colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'")
                for item in colItems:
                    devid = str(item.DeviceID or "")
                    if not devid:
                        continue
                    devices[devid] = {
                        "device_id": devid,
                        "model": str(item.Model or ""),
                        "serial": str(item.SerialNumber or ""),
                        "size": int(item.Size or 0),
                        "interface": "USB",
                    }
        except Exception as exc:  # noqa: BLE001
            logger.warning("usb WMI scan failed: %s", exc)
        return devices

    def _scan_linux_pyudev(self) -> dict[str, dict[str, Any]]:
        devices: dict[str, dict[str, Any]] = {}
        try:
            import pyudev
            ctx = pyudev.Context()
            for dev in ctx.list_devices(subsystem="block", DEVTYPE="disk"):
                bus = dev.get("ID_BUS", "")
                if bus != "usb":
                    continue
                key = dev.device_path
                devices[key] = {
                    "device_id": key,
                    "model": dev.get("ID_MODEL", ""),
                    "serial": dev.get("ID_SERIAL", ""),
                    "vendor": dev.get("ID_VENDOR", ""),
                    "devnode": dev.device_node,
                }
        except Exception as exc:  # noqa: BLE001
            logger.warning("usb pyudev scan failed: %s", exc)
        return devices

    def _scan_macos_iokit(self) -> dict[str, dict[str, Any]]:
        devices: dict[str, dict[str, Any]] = {}
        try:
            from Quartz import (
                IOServiceGetMatchingServices,
                IOServiceMatching,
                IOIteratorNext,
                IORegistryEntryCreateCFProperty,
                kCFAllocatorDefault,
                kIORegistryIterateRecursively,
            )
            import ctypes
            matching = IOServiceMatching("IOUSBDevice")
            if matching is None:
                return devices
            iter_ptr = ctypes.c_void_p(0)
            kr = IOServiceGetMatchingServices(0, matching, ctypes.byref(iter_ptr))
            if kr != 0:
                return devices
            while True:
                service = IOIteratorNext(iter_ptr)
                if not service:
                    break
                try:
                    name_prop = IORegistryEntryCreateCFProperty(
                        service, "USB Product Name", kCFAllocatorDefault, 0
                    )
                    serial_prop = IORegistryEntryCreateCFProperty(
                        service, "USB Serial Number", kCFAllocatorDefault, 0
                    )
                    vendor_prop = IORegistryEntryCreateCFProperty(
                        service, "USB Vendor Name", kCFAllocatorDefault, 0
                    )
                    devid = str(serial_prop or name_prop or f"usb-{service}")
                    devices[devid] = {
                        "device_id": devid,
                        "model": str(name_prop or ""),
                        "serial": str(serial_prop or ""),
                        "vendor": str(vendor_prop or ""),
                    }
                except Exception:  # noqa: BLE001
                    pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("usb IOKit scan failed: %s", exc)
        return devices

    def _scan(self) -> dict[str, dict[str, Any]]:
        os_tag = current_os_tag()
        if os_tag == "windows":
            return self._scan_windows_wmi()
        if os_tag == "linux":
            return self._scan_linux_pyudev()
        if os_tag == "macos":
            return self._scan_macos_iokit()
        return {}

    def _collect(self) -> Iterable[dict[str, Any]]:
        current = self._scan()
        events: list[dict[str, Any]] = []
        prev = self._known_devices
        for key, info in current.items():
            if key not in prev:
                payload = dict(info)
                payload["action"] = "insert"
                events.append({"type": "usb_insert", "severity": "medium", "payload": payload})
        for key, info in prev.items():
            if key not in current:
                payload = dict(info)
                payload["action"] = "remove"
                events.append({"type": "usb_remove", "severity": "low", "payload": payload})
        self._known_devices = current
        return events

    def produce_event(self) -> dict[str, Any]:
        return {
            "type": "usb_insert",
            "severity": "medium",
            "payload": {
                "device_id": "USB\\VID_1234&PID_5678\\SERIAL001",
                "model": "Flash Drive",
                "serial": "SERIAL001",
                "size": 16 * 1024 * 1024 * 1024,
                "interface": "USB",
                "action": "insert",
            },
        }
