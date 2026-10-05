"""Parse investigator-supplied files, tables, layouts, and queue messages."""

import hashlib
import json
import re
import sqlite3
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.ingest import ACTIONS, FIELDS, MAX_BYTES, MAX_ROWS, events_from_rows, read_csv_events, store_events
from app.models import CollectedArtifact, CollectionSource, LayoutDefinition, QueueMessage

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
LOG_LINE = re.compile(
    r"^(?P<occurred_at>\S+)\s+(?P<user>\S+)\s+"
    rf"(?P<action>{'|'.join(ACTIONS)})\s+"
    r"(?P<destination>\S*)\s+(?P<bytes>\d+)\s+(?P<records>\d+)\s*$"
)
PRINTABLE = re.compile(rb"[\x20-\x7e]{4,80}")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def remember_artifact(db: Session, raw: bytes, filename: str, kind: str, summary: str, username: str) -> dict:
    key = digest(raw)
    existing = db.query(CollectedArtifact).filter(CollectedArtifact.sha256 == key).one_or_none()
    if existing is not None:
        return {"duplicate": True, "artifact_id": existing.id, "kind": existing.kind, "summary": existing.summary}
    row = CollectedArtifact(
        sha256=key,
        filename=Path(filename).name[:255] or "upload",
        kind=kind,
        size=len(raw),
        summary=summary[:4000],
        imported_by=username,
    )
    db.add(row)
    db.flush()
    return {"duplicate": False, "artifact_id": row.id, "kind": kind, "summary": row.summary}


def parse_text_or_binary(raw: bytes) -> dict:
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, "File must be at most 2 MB")
    if b"\x00" in raw[:8192]:
        strings = [item.decode("ascii") for item in PRINTABLE.findall(raw)[:100]]
        return {"kind": "binary", "summary": "\n".join(strings) or "No printable text."}
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        strings = [item.decode("ascii") for item in PRINTABLE.findall(raw)[:100]]
        return {"kind": "binary", "summary": "\n".join(strings) or "No printable text."}
    lines = text.splitlines()
    preview = "\n".join(lines[:20])[:2000]
    return {"kind": "text", "summary": f"{len(lines)} lines\n{preview}", "text": text}


def log_rows(text: str) -> tuple[list[dict], int]:
    rows = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        match = LOG_LINE.match(line.strip())
        if match is None:
            skipped += 1
            continue
        row = match.groupdict()
        row["event_id"] = hashlib.sha256(line.strip().encode()).hexdigest()[:40]
        rows.append(row)
    return rows, skipped


def parse_xml_events(raw: bytes):
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, "Activity file must be at most 2 MB")
    lowered = raw[:200].lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise HTTPException(422, "XML entity declarations are not accepted")
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        raise HTTPException(422, "Upload a valid XML file")
    nodes = root.findall("event") if root.tag == "events" else [root] if root.tag == "event" else []
    if not nodes:
        raise HTTPException(422, "XML must contain an events/event list")
    rows = []
    for node in nodes:
        rows.append({name: (node.findtext(name) or "").strip() for name in FIELDS})
    return events_from_rows(rows)


def parse_layout(text: str, layout: LayoutDefinition) -> list[dict]:
    try:
        spec = json.loads(layout.spec)
    except json.JSONDecodeError:
        raise HTTPException(422, "Layout specification is not valid JSON")
    rows = []
    if layout.mode == "fixed":
        fields = spec.get("fields") or []
        if not fields:
            raise HTTPException(422, "Fixed layout needs fields")
        for line in text.splitlines():
            if not line.strip():
                continue
            rows.append({item["name"]: line[int(item["start"]): int(item["start"]) + int(item["length"])].strip() for item in fields})
    elif layout.mode == "delimited":
        names = spec.get("columns") or []
        delimiter = layout.delimiter or ","
        if not names:
            raise HTTPException(422, "Delimited layout needs columns")
        for line in text.splitlines():
            if not line.strip():
                continue
            parts = line.split(delimiter)
            if len(parts) < len(names):
                raise HTTPException(422, "A layout row has fewer columns than the definition")
            rows.append({name: parts[index].strip() for index, name in enumerate(names)})
    else:
        raise HTTPException(422, "Unknown layout mode")
    if not rows:
        raise HTTPException(422, "Layout file has no records")
    if len(rows) > MAX_ROWS:
        raise HTTPException(413, "Activity file must contain at most 5,000 rows")
    return rows


def read_sqlite_table(path: Path, table: str) -> list[dict]:
    if not IDENT.fullmatch(table):
        raise HTTPException(422, "Table name must be a simple identifier")
    uri = path.resolve().as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        raise HTTPException(422, "Could not open that SQLite file")
    try:
        names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        if table not in names or table.startswith("sqlite_"):
            raise HTTPException(422, "Table not found")
        columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
        missing = [name for name in FIELDS if name not in columns]
        if missing:
            raise HTTPException(422, "Table is missing columns: " + ", ".join(missing))
        selected = ", ".join(FIELDS)
        fetched = connection.execute(f"SELECT {selected} FROM {table} LIMIT ?", (MAX_ROWS + 1,)).fetchall()
    except sqlite3.Error:
        raise HTTPException(422, "Could not read that table")
    finally:
        connection.close()
    if len(fetched) > MAX_ROWS:
        raise HTTPException(413, "Activity file must contain at most 5,000 rows")
    return [dict(zip(FIELDS, ["" if value is None else str(value) for value in row])) for row in fetched]


def inbox_path(root: Path, name: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    candidate = (root / Path(name).name).resolve()
    if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():
        raise HTTPException(404, "File is not in the collection inbox")
    if candidate.parent.resolve() != root.resolve():
        raise HTTPException(404, "File is not in the collection inbox")
    return candidate


def _take(db: Session, raw: bytes, filename: str, kind: str, summary: str, username: str) -> dict | None:
    marker = remember_artifact(db, raw, filename, kind, summary, username)
    if marker["duplicate"]:
        return marker
    return None


def accept_upload(db: Session, raw: bytes, filename: str, source: str, username: str) -> dict:
    suffix = Path(filename).suffix.lower()
    if suffix == ".csv":
        events = read_csv_events(raw)
        marker = _take(db, raw, filename, "csv", f"{len(events)} events", username)
        if marker:
            return marker
        stored = store_events(db, events, source, username)
        stored["kind"] = "csv"
        return stored
    if suffix == ".xml":
        events = parse_xml_events(raw)
        marker = _take(db, raw, filename, "xml", f"{len(events)} events", username)
        if marker:
            return marker
        stored = store_events(db, events, source, username)
        stored["kind"] = "xml"
        return stored
    if suffix == ".log":
        text = raw.decode("utf-8-sig")
        rows, skipped = log_rows(text)
        if not rows:
            raise HTTPException(422, "Log file has no activity lines")
        events = events_from_rows(rows)
        marker = _take(db, raw, filename, "log", f"{len(events)} events, {skipped} other lines", username)
        if marker:
            return marker
        stored = store_events(db, events, source, username)
        stored["kind"] = "log"
        stored["skipped_lines"] = skipped
        return stored
    parsed = parse_text_or_binary(raw)
    marker = remember_artifact(db, raw, filename, parsed["kind"], parsed["summary"], username)
    if not marker["duplicate"]:
        db.commit()
    return marker


def accept_layout(db: Session, raw: bytes, filename: str, layout: LayoutDefinition, source: str, username: str) -> dict:
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, "File must be at most 2 MB")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(422, "Layout files must be UTF-8 text")
    rows = parse_layout(text, layout)
    if set(FIELDS) <= set(rows[0]):
        events = events_from_rows(rows)
        marker = _take(db, raw, filename, "layout", f"{len(events)} events", username)
        if marker:
            return marker
        stored = store_events(db, events, source, username)
        stored["kind"] = "layout"
        return stored
    summary = json.dumps(rows[:20])[:4000]
    marker = remember_artifact(db, raw, filename, "layout", summary, username)
    if not marker["duplicate"]:
        db.commit()
    marker["rows"] = len(rows)
    return marker


def enqueue(db: Session, body: dict, username: str) -> dict:
    encoded = json.dumps(body)
    try:
        events = events_from_rows([body], start_line=1)
    except HTTPException as error:
        db.add(QueueMessage(body=encoded, status="failed", detail=str(error.detail)[:500]))
        db.commit()
        raise
    stored = store_events(db, events, "message queue", username)
    db.add(QueueMessage(body=encoded, status="stored", detail=f"Accepted {stored['accepted']}"))
    db.commit()
    stored["kind"] = "queue"
    return stored


def scan_inbox(db: Session, root: Path, username: str) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    done = root / "done"
    done.mkdir(exist_ok=True)
    accepted = 0
    for path in sorted(root.iterdir()):
        if not path.is_file() or path.suffix.lower() not in {".csv", ".xml", ".log", ".txt", ".bin", ".dat"}:
            continue
        raw = path.read_bytes()
        if len(raw) > MAX_BYTES:
            continue
        result = accept_upload(db, raw, path.name, path.stem[:80] or "inbox", username)
        target = done / path.name
        if target.exists():
            target = done / f"{path.stem}-{digest(raw)[:8]}{path.suffix}"
        path.replace(target)
        accepted += 0 if result.get("duplicate") else result.get("accepted", 1)
    for source in db.query(CollectionSource).filter(CollectionSource.enabled.is_(True), CollectionSource.kind == "sqlite"):
        when = source.last_run_at
        if when is not None and (datetime.now(timezone.utc) - _as_utc(when)).total_seconds() < source.interval_seconds:
            continue
        try:
            path = inbox_path(root, source.filename)
            rows = read_sqlite_table(path, source.table_name)
            stored = store_events(db, events_from_rows(rows), source.name[:80], username)
            source.last_status = f"Accepted {stored['accepted']}"
            accepted += stored["accepted"]
        except HTTPException as error:
            source.last_status = str(error.detail)[:200]
        source.last_run_at = datetime.now(timezone.utc)
        db.add(source)
        db.commit()
    return {"accepted": accepted}


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
