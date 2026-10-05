#!/usr/bin/env python3
"""Build a release manifest for all .pyz bundles in the packages/ directory.

Scans packages/*.pyz, computes SHA256, size, and published timestamp,
then writes manifest.json matching the server schema expected by
StagedUpdater.check_for_updates() (version, os, arch, filename, sha256,
size, published_at, download_url, release_notes, active).

Usage:
    python tools/build_manifest.py \
        --version 1.2.3 \
        --base-url https://update.example.com/downloads \
        [--packages-dir packages] \
        [--output packages/manifest.json] \
        [--notes "Release notes for this version"] \
        [--os linux --arch x86_64] \
        [--channel stable]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


ARCH_MAP = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86-64": "x86_64",
    "x86_64": "x86_64",
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "arm64": "arm64",
    "aarch64": "arm64",
    "armv7": "armv7",
    "armv7l": "armv7",
    "armhf": "armv7",
    "arm": "armv6",
    "armv6": "armv6",
    "universal2": "universal2",
    "universal": "universal",
}

OS_MAP = {
    "windows": "windows",
    "win": "windows",
    "win32": "windows",
    "nt": "windows",
    "linux": "linux",
    "manylinux": "linux",
    "debian": "linux",
    "ubuntu": "linux",
    "darwin": "macos",
    "macos": "macos",
    "osx": "macos",
    "mac": "macos",
    "apple": "macos",
}


_FILENAME_RE = re.compile(
    r"^(?P<prefix>[a-zA-Z0-9_.-]+?)"
    r"(?:[-_](?P<os>windows|win|linux|darwin|macos|osx|mac|manylinux|debian|ubuntu|nt))?"
    r"(?:[-_](?P<arch>amd64|x64|x86[_-]?64|x86|i386|i686|arm64|aarch64|armv7l?|armhf|armv6|arm|universal2|universal))?"
    r"(?:[-_](?P<version>\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.]+)?))?"
    r"(?P<ext>\.pyz)$",
    re.IGNORECASE,
)


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def normalize_os(raw: Optional[str]) -> str:
    if not raw:
        return "any"
    key = raw.lower()
    for cand, norm in OS_MAP.items():
        if cand in key or key == cand:
            return norm
    return raw.lower()


def normalize_arch(raw: Optional[str]) -> str:
    if not raw:
        return "any"
    key = raw.lower().replace("-", "_")
    return ARCH_MAP.get(key, raw.lower())


def parse_filename(name: str) -> dict[str, Any]:
    m = _FILENAME_RE.match(name)
    if not m:
        return {"prefix": Path(name).stem, "os": "any", "arch": "any", "version": None}
    return {
        "prefix": m.group("prefix") or Path(name).stem,
        "os": normalize_os(m.group("os")),
        "arch": normalize_arch(m.group("arch")),
        "version": m.group("version"),
    }


def load_release_notes(notes_arg: Optional[str], packages_dir: Path) -> str:
    if notes_arg:
        notes_path = Path(notes_arg)
        if notes_path.is_file():
            try:
                return notes_path.read_text(encoding="utf-8").strip()
            except OSError:
                pass
        return notes_arg
    md_files = [
        packages_dir.parent / "RELEASE_NOTES.md",
        packages_dir.parent / "CHANGELOG.md",
        packages_dir / "RELEASE_NOTES.md",
    ]
    for p in md_files:
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8").strip()
            except OSError:
                continue
    return ""


def build_release_entry(
    pyz: Path,
    *,
    version: str,
    base_url: str,
    release_notes: str,
    published_at: str,
    force_os: Optional[str] = None,
    force_arch: Optional[str] = None,
    active: bool = True,
) -> dict[str, Any]:
    parsed = parse_filename(pyz.name)
    pkg_os = force_os if force_os else parsed["os"]
    pkg_arch = force_arch if force_arch else parsed["arch"]
    pkg_version = parsed["version"] or version
    filename = pyz.name
    download_url = base_url.rstrip("/") + "/" + filename
    sha = sha256_file(pyz)
    size = pyz.stat().st_size

    return {
        "version": pkg_version,
        "os": pkg_os,
        "arch": pkg_arch,
        "filename": filename,
        "sha256": sha,
        "size": size,
        "published_at": published_at,
        "download_url": download_url,
        "url": download_url,
        "release_notes": release_notes,
        "active": bool(active),
    }


def write_manifest(
    packages_dir: Path,
    output: Path,
    *,
    version: str,
    base_url: str,
    channel: str,
    notes: Optional[str],
    force_os: Optional[str],
    force_arch: Optional[str],
    active: bool = True,
) -> dict[str, Any]:
    pyz_files = sorted(p for p in packages_dir.glob("*.pyz") if p.is_file())
    if not pyz_files:
        print(f"[!] No .pyz files found in {packages_dir}", file=sys.stderr)
        raise SystemExit(2)

    published_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    release_notes = load_release_notes(notes, packages_dir)

    releases: list[dict[str, Any]] = []
    for pyz in pyz_files:
        entry = build_release_entry(
            pyz,
            version=version,
            base_url=base_url,
            release_notes=release_notes,
            published_at=published_at,
            force_os=force_os,
            force_arch=force_arch,
            active=active,
        )
        releases.append(entry)
        print(
            f"[+] {entry['filename']:<45} "
            f"os={entry['os']:<7} arch={entry['arch']:<10} "
            f"v={entry['version']:<10} sha256={entry['sha256'][:12]}... "
            f"size={entry['size']:,}"
        )

    envelope: dict[str, Any] = {
        "schema_version": 1,
        "channel": channel,
        "generated_at": published_at,
        "generated_by_epoch": int(time.time()),
        "base_url": base_url.rstrip("/"),
        "version": version,
        "release_notes": release_notes,
        "active": bool(active),
        "releases": releases,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    tmp.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, output)
    print(f"[+] Wrote manifest with {len(releases)} release(s) -> {output}")
    return envelope


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Build manifest.json for .pyz bundles")
    p.add_argument("--version", required=True, help="Semantic release version (e.g. 1.2.3)")
    p.add_argument(
        "--base-url",
        required=True,
        help="Public download URL prefix (filename appended), e.g. https://u.example.com/dl",
    )
    p.add_argument(
        "--packages-dir",
        default=str(Path(__file__).resolve().parent.parent / "packages"),
        help="Directory containing .pyz files (default: ../packages)",
    )
    p.add_argument(
        "--output",
        default=None,
        help="Output manifest path (default: <packages-dir>/manifest.json)",
    )
    p.add_argument("--notes", default=None, help="Release notes string OR path to a text/markdown file")
    p.add_argument("--os", default=None, help="Override OS for all files (windows|linux|macos)")
    p.add_argument("--arch", default=None, help="Override arch for all files (x86_64|arm64|...)")
    p.add_argument("--channel", default="stable", help="Release channel (default: stable)")
    p.add_argument("--inactive", action="store_true", help="Mark all releases as active=false")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    packages_dir = Path(args.packages_dir).resolve()
    if not packages_dir.is_dir():
        print(f"[!] Packages dir not found: {packages_dir}", file=sys.stderr)
        return 2
    output = Path(args.output).resolve() if args.output else packages_dir / "manifest.json"
    write_manifest(
        packages_dir,
        output,
        version=args.version,
        base_url=args.base_url,
        channel=args.channel,
        notes=args.notes,
        force_os=args.os,
        force_arch=args.arch,
        active=not args.inactive,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
