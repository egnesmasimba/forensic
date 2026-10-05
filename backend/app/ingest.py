"""Shared activity-event validation, storage, and alert correlation."""

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Alert, EventCorrelation, ImportedEvent

FIELDS = ["event_id", "occurred_at", "user", "action", "destination", "bytes", "records"]
MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 5000
LARGE_TRANSFER = 10 * 1024 * 1024
RULE_DEFAULTS = {
    "large-external-transfer": ("Large transfer to removable or cloud storage", LARGE_TRANSFER, 80),
    "network-share": ("Large transfer to a network share", LARGE_TRANSFER, 75),
    "browser-download": ("Large browser download", LARGE_TRANSFER, 75),
    "cloud-sync": ("Large cloud sync transfer", LARGE_TRANSFER, 80),
    "archive": ("Large archive created", LARGE_TRANSFER, 65),
    "encryption": ("Large encrypted file", LARGE_TRANSFER, 75),
    "bulk-export": ("Bulk data export", 1000, 70),
    "login-failures": ("Repeated login failures", 3, 60),
    "external-recipient": ("Message to a public mail domain", 1, 70),
    "large-attachment": ("Large email attachment", LARGE_TRANSFER, 75),
    "encrypted-attachment": ("Encrypted email attachment", 1, 75),
    "attachment-context": ("Encrypted attachment to a public mail domain", 1, 75),
    "unusual-protocol": ("Unusual protocol", 1, 60),
    "bandwidth-heavy": ("Bandwidth-heavy flow", 100 * 1024 * 1024, 70),
    "repeated-connections": ("Repeated connections in one flow", 100, 65),
}
ACTIONS = (
    "file_transfer",
    "data_export",
    "login_success",
    "login_failure",
    "browser_download",
    "cloud_sync",
    "archive",
    "encrypt",
)
REMOVABLE = {"usb", "removable"}
CLOUD = {"cloud", "onedrive", "dropbox", "google drive", "googledrive", "gdrive", "box"}
SHARES = {"share", "network", "smb", "unc"}


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    event_id: str = Field(min_length=1, max_length=120)
    occurred_at: datetime
    user: str = Field(min_length=1, max_length=120)
    action: Literal["file_transfer", "data_export", "login_success", "login_failure", "browser_download", "cloud_sync", "archive", "encrypt"]
    destination: str = Field(max_length=200)
    bytes: int = Field(ge=0, le=10**15)
    records: int = Field(ge=0, le=10**12)

    @field_validator("occurred_at")
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")
        return value.astimezone(timezone.utc)


def load_rules(db: Session) -> dict:
    from app.models import DetectionSetting

    stored = {row.rule_id: row for row in db.query(DetectionSetting).all()}
    loaded = {}
    for rule_id, (label, threshold, score) in RULE_DEFAULTS.items():
        row = stored.get(rule_id)
        if row is None:
            loaded[rule_id] = (True, threshold, score, label)
        else:
            loaded[rule_id] = (bool(row.enabled), int(row.threshold), int(row.score), row.label)
    return loaded


def _hit(rules: dict, rule_id: str, matched: bool):
    enabled, _threshold, score, label = rules[rule_id]
    if enabled and matched:
        return label, score, rule_id
    return None


def detection(event: Event, rules: dict | None = None):
    rules = rules or load_rules_from_defaults()
    destination = " ".join(event.destination.lower().split())
    checks = []
    if event.action == "file_transfer" and destination in REMOVABLE | CLOUD:
        checks.append(_hit(rules, "large-external-transfer", event.bytes >= rules["large-external-transfer"][1]))
    if event.action == "file_transfer" and destination in SHARES:
        checks.append(_hit(rules, "network-share", event.bytes >= rules["network-share"][1]))
    if event.action == "browser_download":
        checks.append(_hit(rules, "browser-download", event.bytes >= rules["browser-download"][1]))
    if event.action == "cloud_sync" and destination in CLOUD:
        checks.append(_hit(rules, "cloud-sync", event.bytes >= rules["cloud-sync"][1]))
    if event.action == "archive":
        checks.append(_hit(rules, "archive", event.bytes >= rules["archive"][1]))
    if event.action == "encrypt":
        checks.append(_hit(rules, "encryption", event.bytes >= rules["encryption"][1]))
    if event.action == "data_export":
        checks.append(_hit(rules, "bulk-export", event.records >= rules["bulk-export"][1]))
    return next((item for item in checks if item), None)


def load_rules_from_defaults() -> dict:
    return {rule_id: (True, threshold, score, label) for rule_id, (label, threshold, score) in RULE_DEFAULTS.items()}


def read_csv_dicts(raw: bytes, fields: list[str]) -> list[dict]:
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, "Activity file must be at most 2 MB")
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")), strict=True)
        if reader.fieldnames is None or len(reader.fieldnames) != len(fields) or set(reader.fieldnames) != set(fields):
            raise HTTPException(422, "CSV must have these columns: " + ", ".join(fields))
        return list(reader)
    except (UnicodeDecodeError, csv.Error):
        raise HTTPException(422, "Upload a valid UTF-8 CSV file")


def read_csv_events(raw: bytes) -> list[Event]:
    return events_from_rows(read_csv_dicts(raw, FIELDS))


def events_from_rows(rows: list[dict], start_line: int = 2, model=Event):
    events = []
    for offset, row in enumerate(rows):
        if len(events) >= MAX_ROWS:
            raise HTTPException(413, "Activity file must contain at most 5,000 rows")
        try:
            events.append(model.model_validate(row))
        except ValidationError as error:
            issue = error.errors()[0]
            line = start_line + offset
            raise HTTPException(422, f"Row {line}: {'.'.join(map(str, issue['loc']))}: {issue['msg']}")
    if not events:
        raise HTTPException(422, "Activity file has no events")
    return events


def store_events(db: Session, events: list[Event], source: str, username: str) -> dict:
    accepted = duplicates = 0
    alert_ids = []
    correlations = []
    fresh = []
    rules = load_rules(db)
    try:
        for event in events:
            key = hashlib.sha256(json.dumps([source, event.event_id]).encode()).hexdigest()
            payload = json.dumps(event.model_dump(mode="json"), sort_keys=True)
            existing = db.get(ImportedEvent, key)
            if existing:
                if existing.payload != payload:
                    raise HTTPException(409, f"Event {event.event_id} already exists with different data")
                duplicates += 1
                continue
            rule = detection(event, rules)
            alert = None
            if rule:
                title, score, rule_id = rule
                alert = Alert(
                    title=title,
                    score=score,
                    status="open",
                    entity_type="user",
                    entity_ref=event.user,
                    channel=source,
                    description=(
                        f"Rule: {rule_id}. Event: {event.event_id}. Time: {event.occurred_at.isoformat()}. "
                        f"Destination: {event.destination or 'unspecified'}. Bytes: {event.bytes}. Records: {event.records}."
                    ),
                )
                db.add(alert)
                db.flush()
                alert_ids.append(alert.id)
            db.add(
                ImportedEvent(
                    key=key,
                    source=source,
                    event_id=event.event_id,
                    payload=payload,
                    imported_by=username,
                    alert_id=alert.id if alert else None,
                )
            )
            db.flush()
            correlations.extend(_correlate(db, key, event.user))
            fresh.append(event)
            accepted += 1
        enabled, threshold, score, label = rules["login-failures"]
        if enabled:
            counts: dict[str, int] = {}
            for event in fresh:
                if event.action == "login_failure":
                    counts[event.user] = counts.get(event.user, 0) + 1
            for user, count in counts.items():
                if count < threshold:
                    continue
                alert = Alert(
                    title=label,
                    score=score,
                    status="open",
                    entity_type="user",
                    entity_ref=user,
                    channel=source,
                    description=f"Rule: login-failures. User: {user}. Failures in this import: {count}.",
                )
                db.add(alert)
                db.flush()
                alert_ids.append(alert.id)
        from app.analytics import evaluate_rules, note_activity
        note_activity(db, fresh, source)
        alert_ids.extend(evaluate_rules(db, {("user", event.user) for event in fresh}))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Another import used the same event IDs. Retry this file.")
    except HTTPException:
        db.rollback()
        raise
    return {
        "accepted": accepted,
        "duplicates": duplicates,
        "alerts_created": len(alert_ids),
        "alert_ids": alert_ids,
        "correlations": correlations,
    }


def store_observations(db: Session, items: list[tuple[dict, list[tuple]]], source: str, username: str) -> dict:
    accepted = duplicates = 0
    alert_ids = []
    correlations = []
    try:
        for payload, rules in items:
            event_id = payload["event_id"]
            key = hashlib.sha256(json.dumps([source, event_id]).encode()).hexdigest()
            encoded = json.dumps(payload, sort_keys=True)
            existing = db.get(ImportedEvent, key)
            if existing:
                if existing.payload != encoded:
                    raise HTTPException(409, f"Event {event_id} already exists with different data")
                duplicates += 1
                continue
            alert = None
            if rules:
                title, score, _rule_id = max(rules, key=lambda item: item[1])
                rule_ids = ", ".join(rule_id for _title, _score, rule_id in rules)
                alert = Alert(
                    title=title,
                    score=score,
                    status="open",
                    entity_type="user",
                    entity_ref=payload["user"],
                    channel=source,
                    description=(
                        f"Rule: {rule_ids}. Event: {event_id}. Time: {payload['occurred_at']}. "
                        f"Action: {payload['action']}."
                    ),
                )
                db.add(alert)
                db.flush()
                alert_ids.append(alert.id)
            db.add(
                ImportedEvent(
                    key=key,
                    source=source,
                    event_id=event_id,
                    payload=encoded,
                    imported_by=username,
                    alert_id=alert.id if alert else None,
                )
            )
            db.flush()
            correlations.extend(_correlate(db, key, payload["user"]))
            accepted += 1
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Another import used the same event IDs. Retry this file.")
    except HTTPException:
        db.rollback()
        raise
    return {
        "accepted": accepted,
        "duplicates": duplicates,
        "alerts_created": len(alert_ids),
        "alert_ids": alert_ids,
        "correlations": correlations,
    }


def _correlate(db: Session, event_key: str, user: str) -> list[dict]:
    matches = (
        db.query(Alert)
        .filter(Alert.entity_ref.ilike(user))
        .order_by(Alert.id.desc())
        .limit(20)
        .all()
    )
    found = []
    for alert in matches:
        row = EventCorrelation(
            event_key=event_key,
            alert_id=alert.id,
            case_id=alert.case_id,
            entity_ref=alert.entity_ref,
            channel=alert.channel or "",
        )
        db.add(row)
        found.append(
            {
                "alert_id": alert.id,
                "case_id": alert.case_id,
                "entity_ref": alert.entity_ref,
                "channel": alert.channel or "",
            }
        )
    if found:
        db.flush()
    return found
