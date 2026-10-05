"""Local compliance records over stored investigation data. Not a certification."""
import csv
import hashlib
import io
import json
import re
from datetime import timedelta

from fastapi import HTTPException

from app.dlp import dlp_setting, inspect_text
from app.models import Alert, Case, Fact, utcnow
from app.privacy import audit, setting
from app.privacy_models import (
    ArchiveRecord, DisclosureRecord, ImpactAssessment, PrivacyAudit, SubjectConsent, SubjectRequest, SupervisionReview,
)

NOTICE = "Local record of stored investigation data. This is not a GDPR, CCPA, HIPAA, PCI-DSS, SOC 2, or FINRA certification."
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
MRN = re.compile(r"\bmrn[:\s#-]*[A-Za-z0-9]{4,}\b", re.IGNORECASE)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)")
AUDIT_COLUMNS = ("id", "actor", "action", "detail", "created_at")


def held(db, entity_ref: str) -> bool:
    return db.query(Alert.id).join(Case, Alert.case_id == Case.id).filter(
        Alert.entity_ref == entity_ref, Case.status != "closed").first() is not None


def _facts(db, entity_ref: str):
    return db.query(Fact).filter_by(entity_ref=entity_ref).order_by(Fact.id).limit(500).all()


def _package(db, entity_ref: str) -> dict:
    facts = [{"occurred_at": row.occurred_at, "name": row.name, "text_value": row.text_value, "numeric_value": row.numeric_value} for row in _facts(db, entity_ref)]
    alerts = [{"id": row.id, "title": row.title, "status": row.status, "case_id": row.case_id} for row in db.query(Alert).filter_by(entity_ref=entity_ref).order_by(Alert.id).limit(200)]
    consents = [{"purpose": row.purpose, "granted": row.granted, "created_at": row.created_at.isoformat()} for row in db.query(SubjectConsent).filter_by(entity_ref=entity_ref).order_by(SubjectConsent.id).limit(100)]
    disclosures = [{"recipient": row.recipient, "purpose": row.purpose, "created_at": row.created_at.isoformat()} for row in db.query(DisclosureRecord).filter_by(entity_ref=entity_ref).order_by(DisclosureRecord.id).limit(100)]
    return {"entity_ref": entity_ref, "facts": facts, "alerts": alerts, "consents": consents, "disclosures": disclosures, "notice": NOTICE}


def disclose(db, entity_ref: str, recipient: str, purpose: str, actor: str):
    db.add(DisclosureRecord(entity_ref=entity_ref, recipient=recipient[:120], purpose=purpose[:200], actor=actor))


def fulfill(db, kind: str, regime: str, entity_ref: str, actor: str) -> SubjectRequest:
    request = SubjectRequest(regime=regime, kind=kind, entity_ref=entity_ref, actor=actor)
    if kind in ("access", "portability"):
        disclose(db, entity_ref, actor, kind, actor)
        request.package = json.dumps(_package(db, entity_ref))
        request.status = "fulfilled"
        audit(db, actor, f"subject_{kind}", entity_ref=entity_ref, regime=regime)
    elif kind == "erasure":
        if held(db, entity_ref):
            request.status = "refused"
            request.reason = "An open case holds an alert for this entity"
        else:
            rows = [row for row in _facts(db, entity_ref) if row.text_value != "[erased]"]
            for row in rows:
                row.text_value = "[erased]"
                row.numeric_value = 0
            archives = db.query(ArchiveRecord).filter_by(entity_ref=entity_ref).limit(500).all()
            for archive in archives:
                archive.body = json.dumps({"entity_ref": entity_ref, "text_value": "[erased]"}, sort_keys=True, separators=(",", ":"))
                archive.sha256 = _digest(archive.body)
            request.package = json.dumps({"facts_redacted": len(rows), "archives_redacted": len(archives), "notice": NOTICE})
            request.status = "fulfilled"
            audit(db, actor, "subject_erasure", entity_ref=entity_ref, facts=len(rows))
    elif kind == "opt_out":
        request.status = "fulfilled"
        request.package = json.dumps({"notice": "Opt-out is recorded. Live collectors are unchanged."})
        audit(db, actor, "subject_opt_out", entity_ref=entity_ref, regime=regime)
    else:
        raise HTTPException(422, "Choose access, portability, erasure, or opt_out")
    db.add(request)
    db.flush()
    return request


def review_text(db, text: str) -> dict:
    if len(text) > 20000:
        raise HTTPException(422, "Review text is limited to 20,000 characters")
    ssns = SSN.findall(text)
    inspected = inspect_text(text, dlp_setting(db))
    return {
        "phi": {
            "ssn": len(ssns),
            "mrn": len(MRN.findall(text)),
            "email": len(EMAIL.findall(text)),
            "phone": len(PHONE.findall(text)),
            "samples": [f"SSN ending {item[-4:]}" for item in ssns[:5]],
        },
        "cards": inspected["cards"],
        "notice": "Pattern review of submitted text. Not a HIPAA or PCI certification.",
    }


def _body(row: Fact) -> str:
    payload = {
        "source_key": row.source_key, "occurred_at": row.occurred_at, "entity_type": row.entity_type,
        "entity_ref": row.entity_ref, "name": row.name, "numeric_value": row.numeric_value, "text_value": row.text_value,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _digest(body: str) -> str:
    return hashlib.sha256(body.encode()).hexdigest()


def age_facts(db, actor: str, dry_run: bool = True) -> dict:
    months = setting(db).online_months
    result = {"months": months, "facts": 0, "held": 0, "dry_run": dry_run, "notice": NOTICE}
    if not 6 <= months <= 12:
        result["skipped"] = "Set an online retention of 6 to 12 months before aging facts"
        return result
    cutoff = (utcnow() - timedelta(days=months * 30)).isoformat()
    rows = db.query(Fact).filter(Fact.occurred_at < cutoff, Fact.text_value.notin_(("[archived]", "[erased]"))).order_by(Fact.id).limit(500).all()
    for row in rows:
        if held(db, row.entity_ref):
            result["held"] += 1
            continue
        result["facts"] += 1
        if dry_run:
            continue
        body = _body(row)
        db.add(ArchiveRecord(source_table="facts", source_id=row.id, entity_ref=row.entity_ref, sha256=_digest(body), body=body, actor=actor))
        row.text_value = "[archived]"
        row.numeric_value = 0
    if not dry_run and result["facts"]:
        audit(db, actor, "facts_archived", **{key: value for key, value in result.items() if key != "notice"})
    return result


def archive_payload(row: ArchiveRecord) -> dict:
    if _digest(row.body) != row.sha256:
        raise HTTPException(409, "Archive hash does not match the stored body")
    return {"id": row.id, "entity_ref": row.entity_ref, "sha256": row.sha256, "body": json.loads(row.body), "created_at": row.created_at.isoformat()}


def audit_rows(db, columns: list[str]):
    chosen = [column for column in columns if column in AUDIT_COLUMNS] or list(AUDIT_COLUMNS)
    rows = []
    for row in db.query(PrivacyAudit).order_by(PrivacyAudit.id.desc()).limit(500):
        item = {"id": row.id, "actor": row.actor, "action": row.action, "detail": row.detail, "created_at": row.created_at.isoformat()}
        rows.append({column: item[column] for column in chosen})
    return chosen, rows


def audit_csv(columns: list[str], rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


CONTROLS = {
    "notice": NOTICE,
    "security": ["Role checks on API routes", "CSRF header on signed-in requests", "Administrator-only compliance changes"],
    "availability": ["Queued capture drops are counted", "Retention and aging are explicit administrator actions unless automatic retention is enabled"],
    "integrity": ["Attachment SHA-256", "Archive SHA-256 checked on retrieval"],
    "confidentiality": ["Privacy mode withholds raw routes from non-administrators", "Card numbers are stored as last four in DLP review"],
    "privacy": ["Subject access, portability, erasure, consent, opt-out, and impact notes are local records"],
    "gaps": ["No certification", "No vulnerability scanner", "No live network blocking", "Transmission to a remote compliance service is not implemented"],
}
