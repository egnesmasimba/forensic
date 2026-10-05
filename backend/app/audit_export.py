"""Formatted, schedulable export of the compliance audit log.

The audit log was only ever downloadable as CSV with a column subset, which is
not what a SIEM or an auditor consumes. This adds SIEM-ready framing (CEF and
RFC 5424 syslog), newline-delimited JSON, an operator-supplied template, and a
schedule so the export happens without someone remembering to fetch it.

Three limits are deliberate:

**Export only. Nothing is transmitted.** This writes a file to a directory the
operator names. Forwarding to a remote collector remains the separate, still
unimplemented, integration recorded under 11.1 — bundling a network sender here
would turn a reporting feature into an exfiltration path that nobody reviewed.

**Exports are incremental.** Each run records the highest audit id it has
written and resumes from there, so a scheduled export does not re-send the
whole history every interval and a gap can be detected by comparing watermarks.

**Templates cannot execute anything.** A template is a ``{field}`` substitution
over the audit columns, with strict escaping, not a format string with
attributes. An operator cannot turn an audit export into an outbound request by
mistyping it.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import socket
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterable, Optional

from app.models import utcnow

logger = logging.getLogger(__name__)

#: Supported output framings.
FORMATS = ("csv", "jsonl", "cef", "syslog")
#: Ceiling on rows written by one run, so a large backlog cannot exhaust memory.
EXPORT_LIMIT = 5000
#: Ceiling on the bytes of a single export file.
MAX_EXPORT_BYTES = 32 * 1024 * 1024
#: Only a plain file name may be configured; the directory is chosen separately.
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

#: CEF severities keyed by the audit action they most resemble.
_CEF_SEVERITY = {
    "erasure_applied": 8,
    "erasure_refused": 7,
    "access_requested": 5,
    "access_exported": 5,
    "portability_export": 5,
    "legal_hold_set": 6,
    "legal_hold_cleared": 6,
    "retention_applied": 6,
    "raw_access": 8,
    "consent_withdrawn": 6,
}
_SYSLOG_SEVERITY = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warning",
    5: "notice", 6: "info", 7: "debug",
}

#: Vendor identity written into the CEF header, so a collector can identify us.
CEF_VENDOR = "Zanaq"
CEF_PRODUCT = "ForensicCenter"
CEF_VERSION = "1"
#: syslog facility: local0 (16).
_SYSLOG_FACILITY = 16


def _severity(action: str) -> int:
    """Map an audit action onto a CEF 0-10 severity."""
    for key, value in _CEF_SEVERITY.items():
        if key in action:
            return value
    if "delete" in action or "denied" in action or "refus" in action:
        return 7
    return 3


def _cef_header(value: str) -> str:
    """Escape a CEF header field: backslash then pipe."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_value(value: str) -> str:
    """Escape a CEF extension value: backslash, equals, and newlines."""
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", "\\r").replace("\n", "\\n"))


def _cef_message(value: str) -> str:
    """Escape a CEF message body: backslash and newlines."""
    return str(value).replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")


def cef_line(row: dict[str, Any], template: str = "") -> str:
    """Render one audit row as an ArcSight/HP CEF record.

    Layout is ``CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions``.
    """
    action = str(row.get("action") or "")
    name = str(row.get("action") or "audit")
    severity = _severity(action)
    extension = " ".join(
        f"{key}={_cef_value(row.get(key, ''))}" for key in sorted(row)
    )
    body = template.format(**row) if template else _cef_message(row.get("detail", ""))
    # The message body belongs in the extension's msg= field, last, and must
    # not contain the unescaped pipes that would break the header parse.
    head = "|".join([
        "CEF:0", _cef_header(CEF_VENDOR), _cef_header(CEF_PRODUCT), CEF_VERSION,
        _cef_header(action or "audit"), _cef_header(name), str(severity),
    ])
    return f"{head}|{extension} msg={_cef_value(body)}"


def syslog_line(row: dict[str, Any], hostname: str = "", template: str = "") -> str:
    """Render one audit row as an RFC 5424 syslog message."""
    severity = _severity(str(row.get("action") or ""))
    pri = _SYSLOG_FACILITY * 8 + min(severity, 7)
    stamp = str(row.get("created_at") or "")
    host = hostname or socket.gethostname()
    body = template.format(**row) if template else json.dumps(row, sort_keys=True)
    # Newlines would forge additional syslog records.
    body = str(body).replace("\r", " ").replace("\n", " ")
    return f"<{pri}>1 {stamp} {host} {CEF_PRODUCT} - audit - - {body}"


def render(rows: list[dict[str, Any]], columns: list[str], fmt: str,
           template: str = "") -> str:
    """Render audit rows in the requested framing."""
    if fmt not in FORMATS:
        raise ValueError(f"Unsupported audit export format {fmt!r}")
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
        return buffer.getvalue()
    if fmt == "jsonl":
        return "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    if fmt == "cef":
        return "".join(cef_line(row, template) + "\n" for row in rows)
    return "".join(syslog_line(row, template=template) + "\n" for row in rows)


def validate_template(template: str, columns: Iterable[str]) -> str:
    """Reject a template that references anything but the audit columns.

    A template is data, not code: only ``{column}`` placeholders are allowed,
    and an unknown one is refused at configuration time rather than raising
    during a scheduled run nobody is watching.
    """
    template = (template or "").strip()
    if not template:
        return ""
    allowed = set(columns)
    for name in re.findall(r"\{([^{}]*)\}", template):
        if name not in allowed:
            raise ValueError(f"Template references unknown audit field {name!r}")
    # A stray brace would raise at render time.
    try:
        template.format(**{column: "" for column in allowed})
    except (IndexError, KeyError, ValueError) as error:
        raise ValueError(f"Invalid template: {error}") from error
    return template


def validate_filename(name: str) -> str:
    """Only a plain file name is accepted, so a schedule cannot write anywhere."""
    if not _NAME_RE.match(name or ""):
        raise ValueError("Export name must be a plain file name")
    return name


def audit_rows_since(db, after_id: int, columns: list[str], limit: int = EXPORT_LIMIT):
    """Return audit rows newer than ``after_id``, ascending, and the new watermark.

    Ascending order matters: a batch written in descending id order would drop
    rows whenever the limit is reached part-way through a backlog.
    """
    from app.compliance import AUDIT_COLUMNS

    chosen = [column for column in columns if column in AUDIT_COLUMNS] or list(AUDIT_COLUMNS)
    records = (
        db.query(_audit_model())
        .filter(_audit_model().id > after_id)
        .order_by(_audit_model().id.asc())
        .limit(min(int(limit), EXPORT_LIMIT))
        .all()
    )
    rows = []
    for record in records:
        item = {
            "id": record.id,
            "actor": record.actor,
            "action": record.action,
            "detail": record.detail,
            "created_at": record.created_at.isoformat() if record.created_at else "",
        }
        rows.append({column: item[column] for column in chosen})
    watermark = records[-1].id if records else after_id
    return chosen, rows, watermark


def _audit_model():
    from app.privacy_models import PrivacyAudit

    return PrivacyAudit


def write_export(directory: str, filename: str, body: str, *, overwrite: bool = False) -> dict[str, Any]:
    """Write one export file atomically, refusing to clobber anything else.

    The file is written to a temporary name in the same directory and renamed
    into place, so a consumer never reads a half-written export and a failed
    run cannot truncate the previous one.
    """
    validate_filename(filename)
    target = Path(directory).expanduser()
    target.mkdir(parents=True, exist_ok=True)
    path = target / filename
    if path.exists() and not overwrite:
        raise ValueError(f"{filename} already exists; archiving is required before re-export")
    encoded = body.encode("utf-8")
    if len(encoded) > MAX_EXPORT_BYTES:
        raise ValueError("Audit export exceeds the configured size limit")
    temp = path.with_suffix(path.suffix + ".partial")
    try:
        temp.write_bytes(encoded)
        os.replace(temp, path)
    except OSError:
        temp.unlink(missing_ok=True)
        raise
    return {"path": str(path), "bytes": len(encoded)}


def run_due_exports(db, now=None, only: int | None = None) -> int:
    """Write every enabled schedule whose interval has elapsed.

    ``only`` restricts the run to a single schedule id, which is what the
    administrator "run now" endpoint needs: asking for one schedule must not
    also fire every other schedule that happened to be due.
    """
    from app.models import AuditExportSchedule

    now = now or utcnow()
    written = 0
    query = (db.query(AuditExportSchedule)
             .filter(AuditExportSchedule.enabled.is_(True),
                     AuditExportSchedule.next_run <= now))
    if only is not None:
        query = query.filter(AuditExportSchedule.id == only)
    due = query.order_by(AuditExportSchedule.id).all()
    for schedule in due:
        schedule.next_run = now + timedelta(seconds=schedule.interval_seconds)
        try:
            columns, rows, watermark = audit_rows_since(
                db, schedule.last_id, json.loads(schedule.columns))
            if not rows:
                continue
            body = render(rows, columns, schedule.format, schedule.template)
            # Each run gets its own file, and the name carries the watermark so
            # two runs inside the same second cannot collide and silently
            # overwrite the earlier export.
            stamp = now.strftime("%Y%m%dT%H%M%S")
            filename = f"{Path(schedule.filename).stem}-{stamp}-{watermark}.log"
            written_at = write_export(schedule.directory, filename, body)
            forwarded = None
            if getattr(schedule, "forward_to_siem", False):
                from app.siem import siem_forwarder

                forwarded = siem_forwarder().forward(rows, schedule.template)
                if not forwarded.sent:
                    # The watermark is deliberately left un-advanced so the next
                    # run retries the forward. That re-exports the same rows
                    # locally, which duplicates a file rather than silently
                    # dropping the SIEM copy: for an audit trail, a duplicate
                    # export is recoverable and a lost one is not.
                    logger.warning(
                        "audit export schedule %s: SIEM forward failed (%s); "
                        "watermark held at %s for retry",
                        schedule.id, forwarded.detail, schedule.last_id)
                    continue
            schedule.last_id = watermark
            schedule.last_run = now
            schedule.last_path = written_at["path"]
            schedule.last_rows = len(rows)
            written += 1
        except (ValueError, OSError) as error:
            # One broken schedule must not stop the others, and the failure is
            # logged rather than raised inside the collect loop.
            logger.warning("audit export schedule %s failed: %s", schedule.id, error)
    return written


__all__ = [
    "CEF_PRODUCT",
    "CEF_VENDOR",
    "EXPORT_LIMIT",
    "FORMATS",
    "MAX_EXPORT_BYTES",
    "audit_rows_since",
    "cef_line",
    "render",
    "run_due_exports",
    "syslog_line",
    "validate_filename",
    "validate_template",
    "write_export",
]