from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from . import tls

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)


class UpdateError(Exception):
    pass


@dataclass
class UpdateManifest:
    version: str
    url: str
    sha256: str
    size: int = 0
    min_version: str = ""
    release_notes: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UpdateManifest":
        try:
            return cls(
                version=str(data["version"]),
                url=str(data["url"]),
                sha256=str(data.get("sha256", "")).lower(),
                size=int(data.get("size", 0) or 0),
                min_version=str(data.get("min_version", "") or ""),
                release_notes=str(data.get("release_notes", "") or ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise UpdateError(f"Invalid update manifest: {exc}") from exc


class StagedUpdater:
    def __init__(
        self,
        target_dir: os.PathLike[str] | str,
        *,
        server_url: str = "",
        agent_token: str = "",
        current_version: str = "0.0.0",
        download_timeout: float = 600.0,
        verify: tls.VerifyArgument = True,
        proxy: Optional[str] = None,
        allow_insecure_http: bool = False,
        staging_dir: Optional[os.PathLike[str] | str] = None,
        backup_dir: Optional[os.PathLike[str] | str] = None,
    ) -> None:
        if httpx is None:
            raise UpdateError("httpx is not available")
        self._target = Path(target_dir).resolve()
        self._server = tls.require_secure_url(server_url, allow_insecure=allow_insecure_http).rstrip("/") if server_url else ""
        self._token = agent_token
        self._current_version = current_version
        self._timeout = download_timeout
        self._transport_options: dict[str, Any] = {"verify": verify}
        if proxy:
            self._transport_options["proxy"] = str(proxy)
        self._staging = (
            Path(staging_dir).resolve()
            if staging_dir
            else self._target.with_name(self._target.name + ".staging")
        )
        self._backup = (
            Path(backup_dir).resolve()
            if backup_dir
            else self._target.with_name(self._target.name + ".backup")
        )
        self._manifest_path = self._target.parent / "update_manifest.json"

    @property
    def target_dir(self) -> Path:
        return self._target

    @property
    def staging_dir(self) -> Path:
        return self._staging

    @property
    def backup_dir(self) -> Path:
        return self._backup

    def _cleanup_dir(self, path: Path) -> None:
        if path.exists():
            try:
                shutil.rmtree(path)
            except OSError as exc:
                logger.warning("Failed to clean up %s: %s", path, exc)

    def _ensure_parent(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

    def check_for_updates(
        self,
        manifest_url: str = "",
        channel: str = "stable",
    ) -> Optional[UpdateManifest]:
        url = manifest_url or (f"{self._server}/api/agent/releases?channel={channel}" if self._server else "")
        if not url:
            raise UpdateError("No manifest URL or server URL configured")
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._token:
            headers["X-Agent-Token"] = self._token
        try:
            with httpx.Client(timeout=min(60.0, self._timeout), **self._transport_options) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code != 200:
                    raise UpdateError(f"Manifest fetch HTTP {resp.status_code}")
                data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise UpdateError(f"Failed to fetch manifest: {exc}") from exc
        if isinstance(data, list):
            candidates = [UpdateManifest.from_dict(x) for x in data if isinstance(x, dict)]
        else:
            if "releases" in data and isinstance(data["releases"], list):
                candidates = [
                    UpdateManifest.from_dict(x) for x in data["releases"] if isinstance(x, dict)
                ]
            else:
                candidates = [UpdateManifest.from_dict(data)]
        if not candidates:
            return None
        current_parts = self._parse_version(self._current_version)
        best: Optional[UpdateManifest] = None
        best_parts: Optional[tuple[int, ...]] = None
        for m in candidates:
            m_parts = self._parse_version(m.version)
            if not self._version_greater(m_parts, current_parts):
                continue
            if m.min_version:
                min_parts = self._parse_version(m.min_version)
                if not self._version_greater_equal(current_parts, min_parts):
                    continue
            if best_parts is None or self._version_greater(m_parts, best_parts):
                best = m
                best_parts = m_parts
        return best

    @staticmethod
    def _parse_version(v: str) -> tuple[int, ...]:
        out: list[int] = []
        for chunk in v.split("."):
            num = ""
            for ch in chunk:
                if ch.isdigit():
                    num += ch
                else:
                    break
            if num:
                try:
                    out.append(int(num))
                except ValueError:
                    out.append(0)
            else:
                out.append(0)
        while len(out) < 3:
            out.append(0)
        return tuple(out)

    @staticmethod
    def _version_greater(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
        n = max(len(a), len(b))
        ap = a + (0,) * (n - len(a))
        bp = b + (0,) * (n - len(b))
        return ap > bp

    @staticmethod
    def _version_greater_equal(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
        return not StagedUpdater._version_greater(b, a)

    def download(self, manifest: UpdateManifest, progress: Optional[Callable[[int, int], None]] = None) -> Path:
        if not manifest.sha256:
            raise UpdateError("Manifest is missing sha256 hash, refusing download")
        self._cleanup_dir(self._staging)
        self._ensure_parent(self._staging)
        self._staging.mkdir(parents=True, exist_ok=True)
        headers: dict[str, str] = {"Accept": "application/zip,application/octet-stream,*/*"}
        if manifest.url.startswith(self._server) and self._token:
            headers["X-Agent-Token"] = self._token
        download_name = Path(manifest.url.split("?", 1)[0]).name or "update.bin"
        download_path = self._staging / download_name
        hasher = hashlib.sha256()
        total = 0
        expected = manifest.size or 0
        try:
            with httpx.Client(timeout=self._timeout, **self._transport_options) as client:
                with client.stream("GET", manifest.url, headers=headers) as resp:
                    if resp.status_code != 200:
                        raise UpdateError(f"Download HTTP {resp.status_code}")
                    expected = manifest.size or int(resp.headers.get("Content-Length", "0") or 0)
                    with download_path.open("wb") as fh:
                        for chunk in resp.iter_bytes(chunk_size=64 * 1024):
                            if not chunk:
                                continue
                            fh.write(chunk)
                            hasher.update(chunk)
                            total += len(chunk)
                            if progress is not None:
                                try:
                                    progress(total, expected)
                                except Exception:  # noqa: BLE001
                                    pass
                        fh.flush()
                        try:
                            os.fsync(fh.fileno())
                        except (AttributeError, OSError):
                            pass
        except httpx.HTTPError as exc:
            raise UpdateError(f"Download failed: {exc}") from exc
        digest = hasher.hexdigest().lower()
        if digest != manifest.sha256.lower():
            self._cleanup_dir(self._staging)
            raise UpdateError(
                f"SHA256 mismatch: expected {manifest.sha256} got {digest}"
            )
        if expected and total != expected:
            logger.warning("Download size mismatch: expected %d got %d", expected, total)
        return download_path

    def extract_package(self, archive_path: Path) -> Path:
        self._ensure_parent(self._staging)
        extract_dir = self._staging / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        suffix = archive_path.suffix.lower()
        try:
            if suffix in (".zip",):
                import zipfile
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(extract_dir)
            elif suffix in (".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz"):
                import tarfile
                mode_map = {
                    ".tar": "r:",
                    ".gz": "r:gz",
                    ".tgz": "r:gz",
                    ".bz2": "r:bz2",
                    ".tbz2": "r:bz2",
                    ".xz": "r:xz",
                    ".txz": "r:xz",
                }
                mode = mode_map.get(suffix, "r:*")
                with tarfile.open(archive_path, mode) as tf:
                    tf.extractall(extract_dir)
            else:
                raise UpdateError(f"Unsupported archive format: {suffix}")
        except (shutil.ReadError, ValueError, OSError) as exc:
            raise UpdateError(f"Failed to extract package: {exc}") from exc
        package_root = self._find_package_root(extract_dir)
        return package_root

    @staticmethod
    def _find_package_root(extract_dir: Path) -> Path:
        files = [p for p in extract_dir.iterdir() if p.name not in ("__MACOSX",)]
        if len(files) == 1 and files[0].is_dir():
            return files[0]
        return extract_dir

    def stage_apply(self, package_root: Path, manifest: UpdateManifest) -> None:
        if not self._target.exists():
            self._target.mkdir(parents=True, exist_ok=True)
        self._cleanup_dir(self._backup)
        self._ensure_parent(self._backup)
        backup_path = self._backup
        try:
            shutil.copytree(package_root, self._staging / "applied", symlinks=True)
        except OSError as exc:
            raise UpdateError(f"Failed to stage package: {exc}") from exc
        if self._target.exists():
            try:
                shutil.copytree(self._target, backup_path, symlinks=True)
            except OSError as exc:
                logger.warning("Failed to create full backup: %s", exc)
                if not backup_path.exists():
                    backup_path.mkdir(parents=True, exist_ok=True)

    def atomic_swap(self, manifest: UpdateManifest) -> None:
        applied = self._staging / "applied"
        if not applied.exists():
            raise UpdateError("Staged payload not found at %s" % applied)
        if not self._target.exists():
            self._target.mkdir(parents=True, exist_ok=True)
        swap_tmp = self._target.with_name(self._target.name + ".swap." + str(int(time.time())))
        try:
            try:
                if swap_tmp.exists():
                    shutil.rmtree(swap_tmp)
            except OSError:
                pass
            shutil.copytree(applied, swap_tmp, symlinks=True)
            self._persist_manifest(manifest)
            backup_real = self._backup
            if self._target.exists():
                try:
                    if backup_real.exists():
                        shutil.rmtree(backup_real)
                except OSError:
                    pass
                try:
                    os.replace(self._target, backup_real)
                except OSError:
                    shutil.move(str(self._target), str(backup_real))
            try:
                os.replace(swap_tmp, self._target)
            except OSError:
                shutil.move(str(swap_tmp), str(self._target))
        except OSError as exc:
            try:
                if swap_tmp.exists():
                    shutil.rmtree(swap_tmp)
            except OSError:
                pass
            self._rollback_after_failure()
            raise UpdateError(f"Atomic swap failed: {exc}") from exc

    def _rollback_after_failure(self) -> None:
        if not self._backup.exists():
            return
        try:
            if self._target.exists():
                broken = self._target.with_name(self._target.name + ".broken." + str(int(time.time())))
                try:
                    shutil.move(str(self._target), str(broken))
                except OSError:
                    try:
                        shutil.rmtree(self._target)
                    except OSError:
                        pass
            shutil.move(str(self._backup), str(self._target))
            logger.warning("Rolled back to backup after failure")
        except OSError as exc:
            logger.critical("Rollback failed: %s", exc)

    def rollback(self) -> bool:
        if not self._backup.exists():
            return False
        try:
            broken = self._target.with_name(self._target.name + ".broken." + str(int(time.time())))
            if self._target.exists():
                try:
                    shutil.move(str(self._target), str(broken))
                except OSError:
                    try:
                        shutil.rmtree(self._target)
                    except OSError:
                        pass
            shutil.move(str(self._backup), str(self._target))
            return True
        except OSError as exc:
            logger.error("Rollback failed: %s", exc)
            return False

    def _persist_manifest(self, manifest: UpdateManifest) -> None:
        try:
            self._ensure_parent(self._manifest_path)
            data = {
                "version": manifest.version,
                "url": manifest.url,
                "sha256": manifest.sha256,
                "size": manifest.size,
                "applied_at": int(time.time()),
            }
            tmp = self._manifest_path.with_suffix(self._manifest_path.suffix + ".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(tmp, self._manifest_path)
        except OSError as exc:
            logger.warning("Failed to persist manifest: %s", exc)

    def load_applied_manifest(self) -> Optional[dict[str, Any]]:
        if not self._manifest_path.exists():
            return None
        try:
            return json.loads(self._manifest_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return None

    def full_update(self, manifest: UpdateManifest, progress: Optional[Callable[[int, int], None]] = None) -> str:
        archive = self.download(manifest, progress=progress)
        root = self.extract_package(archive)
        self.stage_apply(root, manifest)
        self.atomic_swap(manifest)
        self._cleanup_dir(self._staging)
        return manifest.version
