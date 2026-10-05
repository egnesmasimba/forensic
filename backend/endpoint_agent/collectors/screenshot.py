from __future__ import annotations

import base64
import io
import logging
from typing import Any, Iterable, Optional

from . import Collector, current_os_tag

logger = logging.getLogger(__name__)

_TARGET_W = 1280
_TARGET_H = 720
_JPEG_QUALITY = 75


def _pil_available() -> bool:
    try:
        from PIL import ImageGrab, Image  # noqa: F401
        return True
    except ImportError:
        return False


def _mss_available() -> bool:
    try:
        import mss  # noqa: F401
        return True
    except ImportError:
        return False


class ScreenshotCollector(Collector):
    name = "screenshot"
    default_interval_seconds = 60.0
    sensitive = True

    @classmethod
    def effective_requires(cls) -> tuple[str, ...]:
        # Pillow is needed on every path: the mss backend still decodes and
        # re-encodes through PIL.Image. Linux additionally has no working
        # ImageGrab, so mss becomes mandatory there.
        if current_os_tag() == "linux":
            return ("PIL", "mss")
        return ("PIL",)

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._target_w = int(self._config.get("max_width", _TARGET_W))
        self._target_h = int(self._config.get("max_height", _TARGET_H))
        self._quality = int(self._config.get("jpeg_quality", _JPEG_QUALITY))
        self._pending_capture = False

    @classmethod
    def supports_current_os(cls) -> bool:
        if not _pil_available() and not _mss_available():
            logger.info("screenshot unsupported: neither Pillow nor mss installed")
            return False
        return True

    def capture_now(self) -> Optional[dict[str, Any]]:
        try:
            img = None
            if _pil_available():
                from PIL import ImageGrab
                try:
                    grabbed = ImageGrab.grab(all_screens=True)
                    if grabbed:
                        img = grabbed
                except Exception:  # noqa: BLE001
                    img = None
            if img is None and _mss_available():
                import mss
                from PIL import Image
                try:
                    with mss.mss() as sct:
                        monitor = sct.monitors[0]
                        raw = sct.grab(monitor)
                        img = Image.frombytes("RGB", raw.size, raw.rgb)
                except Exception:  # noqa: BLE001
                    img = None
            if img is None:
                return None
            w, h = img.size
            ratio = min(self._target_w / w, self._target_h / h, 1.0)
            if ratio < 1.0:
                new_w = max(1, int(w * ratio))
                new_h = max(1, int(h * ratio))
                from PIL import Image
                img = img.resize((new_w, new_h), Image.LANCZOS)
            if img.mode != "RGB":
                img = img.convert("RGB")
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=self._quality, optimize=True)
            data = buf.getvalue()
            payload: dict[str, Any] = {
                "width": img.size[0],
                "height": img.size[1],
                "size_bytes": len(data),
                "mime": "image/jpeg",
                "encoding": "base64",
                "image_b64": base64.b64encode(data).decode("ascii"),
            }
            return {"type": "screenshot", "severity": "low", "payload": payload}
        except Exception as exc:  # noqa: BLE001
            logger.warning("screenshot capture failed: %s", exc)
            return None

    def schedule_capture(self) -> None:
        self._pending_capture = True

    def _collect(self) -> Iterable[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if self._pending_capture or self.enabled:
            ev = self.capture_now()
            if ev is not None:
                events.append(ev)
        self._pending_capture = False
        return events

    def produce_event(self) -> dict[str, Any]:
        tiny = base64.b64encode(
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c"
            b"\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c"
            b" $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00\x0b\x08\x00\x01\x00"
            b"\x01\x01\x01\x11\x00\xff\xc4\x00\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\n\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x08\x01\x01"
            b"\x00\x00?\x00\xd2\xcf \xff\xd9"
        ).decode("ascii")
        return {
            "type": "screenshot",
            "severity": "low",
            "payload": {
                "width": 1280,
                "height": 720,
                "size_bytes": 65536,
                "mime": "image/jpeg",
                "encoding": "base64",
                "image_b64": tiny,
            },
        }
