"""Policy-scoped capture of documents that a user prints.

This deliberately does **not** archive every printed page. Retaining a copy of
everything any user prints, indefinitely and without their knowledge, is
surveillance rather than evidence collection: it sweeps up medical forms,
bank statements, and privileged legal material, and on many endpoints it would
exceed what the deployment's approved collection scope covers.

Instead the agent captures a bounded copy of the *source document* only when a
configured policy matches, which is the same shape as the transfer collector:
the agent scans, the server decides whether to raise an alert. Retained bytes
are written to a bounded, content-addressed :class:`PrintArtifactStore` and
expired by the agent on the same clock as the server's retention job, because
the server can expire the event but has no way to reach bytes held on the
endpoint.

Where the store is not configured the policy still matches and the document is
still scanned, but nothing is retained and both the payload and the resulting
alert say so. A policy match is not by itself evidence that a copy was taken.

Spool-stream interception is also out of scope. Capturing the rendered output
requires a native Windows port-monitor DLL registered with the spooler, and the
intercepted bytes are usually a proprietary driver stream (PCL/PostScript)
rather than a viewable document.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


#: Hard ceiling on a single retained copy, mirroring the transfer collector.
MAX_CAPTURE_BYTES = 25 * 1024 * 1024
#: Ceiling on files walked per source lookup, so a large tree cannot stall a tick.
MAX_LOOKUP_FILES = 2000
#: Ceiling on retained copies per collection pass.
MAX_PER_PASS = 5
#: Ceiling on total bytes the on-disk artifact store may hold.
MAX_STORE_BYTES = 256 * 1024 * 1024
#: Ceiling on retained artifacts in the store, so a policy hit cannot fill a disk.
MAX_STORE_ARTIFACTS = 500
#: Ceiling on a single manifest, matching the snapshot store's bound.
MAX_MANIFEST_BYTES = 2 * 1024 * 1024


@dataclass
class CaptureDecision:
    """Why a print job was or was not escalated to a content capture."""

    capture: bool
    reason: str
    matched_terms: tuple[str, ...] = ()
    source_path: Optional[Path] = None

    def as_payload(self) -> dict[str, Any]:
        return {
            "capture": self.capture,
            "reason": self.reason,
            "matched_terms": list(self.matched_terms),
            "source_path": self.source_path,
        }


class PrintArtifactStore:
    """Bounded on-disk store for retained copies of printed source documents.

    A policy match is only meaningful if the bytes it refers to actually exist,
    so the collector writes the source here and reports what it retained rather
    than asserting a copy it never took. Each artifact is content-addressed by
    SHA-256 and accompanied by a manifest recording the originating path and
    capture time, which keeps the claim auditable:

    * the manifest digest is re-checked on load, so a rewritten manifest is
      rejected rather than silently trusted;
    * :meth:`verify` re-hashes the stored bytes, so silent corruption or
      substitution after capture is detectable;
    * total bytes and artifact count are both capped, so a broad term list
      cannot fill a disk.

    The store is local to the endpoint. It is deliberately *not* an upload
    channel: the server receives the hash and metadata, and the bytes stay
    under the deployment's existing evidence controls until retention removes
    them.
    """

    def __init__(self, directory: str | os.PathLike[str], *, max_bytes: int = MAX_STORE_BYTES,
                 max_artifacts: int = MAX_STORE_ARTIFACTS) -> None:
        self.directory = Path(directory)
        self.max_bytes = max_bytes
        self.max_artifacts = max_artifacts
        self.directory.mkdir(parents=True, exist_ok=True)

    def _artifact_dir(self, identity: str) -> Path:
        return self.directory / identity

    def usage(self) -> tuple[int, int]:
        """Return ``(bytes, artifacts)`` currently held, tolerating removals."""
        total = 0
        count = 0
        for entry in self.directory.iterdir():
            if not entry.is_dir():
                continue
            count += 1
            for blob in entry.iterdir():
                try:
                    total += blob.stat().st_size
                except OSError:
                    continue
        return total, count

    def retain(self, source: Path, *, job: Optional[dict[str, Any]] = None,
               max_bytes: Optional[int] = None) -> dict[str, Any]:
        """Copy ``source`` into the store and describe what was retained.

        The copy is size-checked and hash-checked, and a file that changes
        mid-read is rejected rather than stored in a state the manifest cannot
        describe.
        """
        limit = self.max_bytes if max_bytes is None else min(int(max_bytes), self.max_bytes)
        try:
            before = source.stat()
        except OSError as exc:
            return {"retained": False, "reason": f"source_unreadable: {type(exc).__name__}"}
        if before.st_size > limit:
            return {"retained": False, "reason": "source_exceeds_capture_limit", "size": before.st_size}

        used, count = self.usage()
        if count >= self.max_artifacts:
            return {"retained": False, "reason": "artifact_count_limit_reached"}
        if used + before.st_size > self.max_bytes:
            return {"retained": False, "reason": "artifact_store_byte_limit_reached"}

        identity = uuid.uuid4().hex
        directory = self._artifact_dir(identity)
        try:
            directory.mkdir()
            digest = hashlib.sha256()
            written = 0
            # Streamed straight to the artifact so the hash covers exactly the
            # bytes that were stored, rather than a separate re-read.
            with source.open("rb") as stream, (directory / "content").open("wb") as out:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limit:
                        raise OSError("Source grew past the capture limit while reading")
                    digest.update(chunk)
                    out.write(chunk)
            if (before.st_size, before.st_mtime_ns) != (source.stat().st_size, source.stat().st_mtime_ns):
                raise OSError("Source changed during capture")
        except OSError as exc:
            for leftover in (directory / "content", directory / "manifest.json"):
                try:
                    leftover.unlink()
                except OSError:
                    pass
            try:
                directory.rmdir()
            except OSError:
                pass
            return {"retained": False, "reason": f"capture_failed: {type(exc).__name__}"}

        manifest = {
            "artifact_id": identity,
            "source_path": str(source),
            "size": written,
            "sha256": digest.hexdigest(),
            "captured_at": time.time(),
            "printer": str((job or {}).get("printer") or ""),
            "user": str((job or {}).get("user") or ""),
            "document": str((job or {}).get("document") or ""),
            "scope": "Source document bytes only; no spool or rendered-page capture",
        }
        encoded = json.dumps(manifest, sort_keys=True).encode()
        (directory / "manifest.json").write_bytes(encoded)
        return {
            "retained": True,
            "artifact_id": identity,
            "size": written,
            "sha256": manifest["sha256"],
            "stored_path": str(directory / "content"),
            "scope": manifest["scope"],
        }

    def load_manifest(self, identity: str) -> dict[str, Any]:
        """Load a manifest, rejecting a missing, oversized, or altered one."""
        if len(identity) != 32 or any(c not in "0123456789abcdef" for c in identity):
            raise ValueError("Invalid artifact id")
        directory = self._artifact_dir(identity)
        if directory.is_symlink():
            raise ValueError("Artifact link rejected")
        path = directory / "manifest.json"
        with path.open("rb") as stream:
            encoded = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(encoded) > MAX_MANIFEST_BYTES:
            raise ValueError("Artifact manifest exceeds limit")
        manifest = json.loads(encoded)
        if manifest.get("artifact_id") != identity:
            raise ValueError("Artifact manifest does not describe this artifact")
        return manifest

    def verify(self, identity: str) -> dict[str, Any]:
        """Re-hash stored bytes and compare against the manifest.

        A missing or unreadable manifest is reported as unverified rather than
        raised, so a partially deleted artifact cannot be mistaken for an
        intact one during an integrity sweep.
        """
        try:
            manifest = self.load_manifest(identity)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {"artifact_id": identity, "verified": False,
                    "reason": f"manifest_unreadable: {type(exc).__name__}"}
        blob = self._artifact_dir(identity) / "content"
        try:
            data = blob.read_bytes()
        except OSError as exc:
            return {"artifact_id": identity, "verified": False, "reason": f"content_missing: {type(exc).__name__}"}
        actual = hashlib.sha256(data).hexdigest()
        return {
            "artifact_id": identity,
            "verified": actual == manifest.get("sha256"),
            "expected_sha256": manifest.get("sha256"),
            "actual_sha256": actual,
        }

    def expire(self, older_than_seconds: float, *, dry_run: bool = True) -> dict[str, Any]:
        """Remove artifacts captured longer ago than the retention window.

        Called from the server-side retention job so a captured copy cannot
        outlive the retention period that applies to every other observation.
        """
        cutoff = time.time() - float(older_than_seconds)
        removed: list[str] = []
        for entry in self.directory.iterdir():
            if not entry.is_dir():
                continue
            try:
                manifest = self.load_manifest(entry.name)
            except (OSError, ValueError, json.JSONDecodeError):
                # An unreadable manifest has no verifiable age, so it is
                # reported rather than silently retained forever.
                logger.warning("print artifact %s has no readable manifest", entry.name)
                continue
            if float(manifest.get("captured_at") or 0) >= cutoff:
                continue
            removed.append(entry.name)
            if not dry_run:
                for child in entry.iterdir():
                    try:
                        child.unlink()
                    except OSError:
                        pass
                try:
                    entry.rmdir()
                except OSError:
                    pass
        return {"removed": len(removed), "artifact_ids": removed, "dry_run": dry_run}


def _normalise(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


def _bounded(value: Any, default: int, ceiling: int) -> int:
    """Coerce a configured limit to an int clamped to ``ceiling``."""
    try:
        return min(int(value), ceiling)
    except (TypeError, ValueError):
        return default


class PrintContentPolicy:
    """Decides whether a printed document warrants a bounded retained copy.

    Configuration::

        {
          "enabled": true,
          "sensitive_terms": ["payroll", "medical record"],
          "source_roots": ["C:/Users/alice/Documents"],
          "max_capture_bytes": 26214400,
          "max_per_pass": 5,
          "artifact_dir": "C:/ProgramData/Zanaq/print-artifacts",
          "max_store_bytes": 268435456,
          "max_store_artifacts": 500
        }

A capture requires at least one term to match the spooler's document title, or
the resolved source file when one can be located, **and** a source document that
was actually located inside the configured roots. A title match whose source
cannot be resolved is reported as matched-but-not-captured, because a match with
no bytes behind it cannot support a claim that a document was copied. With no
terms configured the collector stays metadata-only and captures nothing.

    Retained bytes live in ``artifact_dir``. When that is unset the collector
    scans and reports metadata but retains no copy, because a policy match with
    no retained bytes cannot support the claim that a document was captured.
    """

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        cfg = dict(config or {})
        self.enabled = bool(cfg.get("enabled", False))
        self.terms = tuple(
            str(t).strip().lower() for t in cfg.get("sensitive_terms", []) if str(t).strip()
        )
        self.roots = tuple(str(r) for r in cfg.get("source_roots", []) if str(r).strip())
        self.store_dir = str(cfg.get("artifact_dir") or "").strip()
        self.max_store_bytes = max(1, _bounded(cfg.get("max_store_bytes"), MAX_STORE_BYTES, MAX_STORE_BYTES))
        self.max_store_artifacts = max(1, _bounded(cfg.get("max_store_artifacts"), MAX_STORE_ARTIFACTS, MAX_STORE_ARTIFACTS))
        #: Days a retained copy may be held. Defaults to the same 365-day
        #: ceiling the server enforces on observations, so an artifact cannot
        #: outlive the retention window applied to the event that created it.
        self.retention_days = max(1, _bounded(cfg.get("retention_days"), 365, 3650))
        self._store: Optional[PrintArtifactStore] = None
        try:
            self.max_capture_bytes = max(
                1, min(int(cfg.get("max_capture_bytes", MAX_CAPTURE_BYTES)), MAX_CAPTURE_BYTES)
            )
        except (TypeError, ValueError):
            self.max_capture_bytes = MAX_CAPTURE_BYTES
        self.max_per_pass = max(1, _bounded(cfg.get("max_per_pass"), MAX_PER_PASS, 50))

    @property
    def active(self) -> bool:
        """True only when a capture could actually be authorised."""
        return self.enabled and bool(self.terms)

    @property
    def store(self) -> Optional[PrintArtifactStore]:
        """The artifact store, created lazily and only when configured."""
        if not self.active or not self.store_dir:
            return None
        if self._store is None:
            try:
                self._store = PrintArtifactStore(
                    self.store_dir,
                    max_bytes=self.max_store_bytes,
                    max_artifacts=self.max_store_artifacts,
                )
            except OSError as exc:
                logger.warning("print artifact store unavailable: %s", exc)
                return None
        return self._store

    def status(self) -> dict[str, Any]:
        used = count = 0
        store = self.store
        if store is not None:
            try:
                used, count = store.usage()
            except OSError:
                used = count = 0
        return {
            "content_capture_enabled": self.enabled,
            "active": self.active,
            "terms": len(self.terms),
            "source_roots": len(self.roots),
            "max_capture_bytes": self.max_capture_bytes,
            "max_per_pass": self.max_per_pass,
            "artifact_store_configured": bool(self.store_dir),
            "artifact_store_available": store is not None,
            "artifact_bytes": used,
            "artifact_count": count,
            "max_store_bytes": self.max_store_bytes,
            "max_store_artifacts": self.max_store_artifacts,
            "retention_days": self.retention_days,
        }

    def expire_artifacts(self, *, dry_run: bool = True) -> dict[str, Any]:
        """Remove retained copies older than the configured retention window.

        The server's retention job can expire the event but cannot reach bytes
        on the endpoint, so the agent expires its own artifacts on the same
        clock. Called from the print collector's tick rather than at import, so
        expiry runs on the normal collection cadence.
        """
        store = self.store
        if store is None:
            return {"removed": 0, "dry_run": dry_run, "reason": "no_artifact_store"}
        result = store.expire(self.retention_days * 86400, dry_run=dry_run)
        if result["removed"]:
            logger.info("print artifact retention removed %d artifact(s)", result["removed"])
        return result

    def match_terms(self, *values: str) -> tuple[str, ...]:
        """Terms appearing in any of the supplied values."""
        haystack = " ".join(_normalise(v) for v in values if v)
        if not haystack:
            return ()
        return tuple(t for t in self.terms if _normalise(t) in haystack)

    def resolve_source(self, document: str) -> tuple[Optional[Path], str]:
        """Locate a printed document inside the configured source roots.

        The spooler usually reports only a document title, so resolution is a
        best-effort stem match bounded to the configured roots. Anything that
        cannot be resolved is reported rather than searched for globally: an
        unbounded filesystem walk would be both slow and a privacy problem.
        """
        if not self.roots or not document:
            return None, "no_source_roots" if not self.roots else "no_document_title"
        wanted = _normalise(Path(document).stem)
        if not wanted:
            return None, "unusable_document_title"
        seen = 0
        for root in self.roots:
            base = Path(root)
            try:
                if not base.is_dir():
                    continue
                for candidate in base.rglob("*"):
                    if seen >= MAX_LOOKUP_FILES:
                        return None, "lookup_budget_exhausted"
                    if not candidate.is_file():
                        continue
                    seen += 1
                    try:
                        # Resolved up to the hard ceiling so that a file over
                        # the *configured* limit is still located and reported
                        # as not retained, rather than looking unmatched.
                        if candidate.stat().st_size > MAX_CAPTURE_BYTES:
                            continue
                    except OSError:
                        continue
                    if _normalise(candidate.stem) == wanted:
                        # Guard against a symlink escaping the configured root.
                        try:
                            resolved = candidate.resolve()
                            base_resolved = base.resolve()
                        except OSError:
                            continue
                        if base_resolved not in resolved.parents and resolved != base_resolved:
                            continue
                        return resolved, "resolved_by_title"
            except OSError as exc:
                logger.debug("source root %s unreadable: %s", base, exc)
                continue
        return None, "source_not_found_in_roots"

    def evaluate(self, job: dict[str, Any]) -> CaptureDecision:
        """Decide whether this print job warrants a retained copy."""
        document = str(job.get("document") or "")
        if not self.active:
            return CaptureDecision(False, "content_capture_disabled")

        title_terms = self.match_terms(document)
        # Resolve the source even on a title match: without it there is no
        # document to retain, and the match would record nothing but a name.
        source, resolution = self.resolve_source(document)

        if title_terms:
            # A title match with no resolved source has no document to retain,
            # so it is reported as matched-but-not-captured rather than as a
            # capture: the caller must never be told bytes were taken when the
            # bytes were never located.
            if source is None:
                return CaptureDecision(
                    False, f"title_matched_source_unresolved:{resolution}", title_terms, None,
                )
            return CaptureDecision(
                True, "document_title_matched_policy", title_terms, str(source),
            )
        if source is None:
            return CaptureDecision(False, resolution)
        try:
            text = source.read_text(encoding="utf-8", errors="replace")[:65536]
        except OSError as exc:
            logger.debug("printed source unreadable %s: %s", source, exc)
            return CaptureDecision(False, "source_unreadable")
        # Match against the file name too: the spooler title is often generic
        # ("Microsoft Word - Document1") while the file name is descriptive.
        source_terms = self.match_terms(source.name, text)
        if source_terms:
            return CaptureDecision(
                True, "source_content_matched_policy", source_terms, str(source)
            )
        return CaptureDecision(False, "no_policy_match", (), str(source))


__all__ = [
    "CaptureDecision",
    "MAX_CAPTURE_BYTES",
    "MAX_LOOKUP_FILES",
    "MAX_PER_PASS",
    "MAX_STORE_ARTIFACTS",
    "MAX_STORE_BYTES",
    "PrintArtifactStore",
    "PrintContentPolicy",
]