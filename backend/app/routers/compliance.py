import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.audit_export import (
    FORMATS as AUDIT_FORMATS,
    run_due_exports as run_audit_exports,
    validate_filename as validate_audit_filename,
    validate_template as validate_audit_template,
)
from app.auth import administrator, get_db
from app.compliance import (
    AUDIT_COLUMNS, CONTROLS, age_facts, archive_payload, audit_csv, audit_rows, fulfill, review_text,
)
from app.models import AuditExportSchedule, utcnow
from app.siem import siem_config
from app.privacy import audit, setting
from app.privacy_models import (
    ArchiveRecord, ImpactAssessment, SubjectConsent, SubjectRequest, SupervisionReview,
)

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


class RequestInput(BaseModel):
    entity_ref: str = Field(min_length=1, max_length=120)
    kind: Literal["access", "portability", "erasure", "opt_out"]
    regime: Literal["gdpr", "ccpa", "other"] = "other"


class ConsentInput(BaseModel):
    entity_ref: str = Field(min_length=1, max_length=120)
    purpose: str = Field(min_length=1, max_length=300)
    granted: bool


class AssessmentInput(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    scope: str = Field(min_length=1, max_length=2000)
    risks: str = Field(min_length=1, max_length=2000)
    mitigations: str = Field(default="", max_length=2000)
    status: Literal["draft", "accepted"] = "draft"


class ReviewInput(BaseModel):
    entity_ref: str = Field(min_length=1, max_length=120)
    decision: Literal["approved", "exception", "escalate"]
    note: str = Field(default="", max_length=1000)


class InspectInput(BaseModel):
    text: str = Field(min_length=1, max_length=20000)


class RetentionInput(BaseModel):
    online_months: int = Field(ge=6, le=12)


def _request(row: SubjectRequest) -> dict:
    return {"id": row.id, "regime": row.regime, "kind": row.kind, "entity_ref": row.entity_ref,
            "status": row.status, "reason": row.reason, "package": json.loads(row.package or "{}"),
            "actor": row.actor, "created_at": row.created_at.isoformat()}


@router.get("/controls")
def controls(user=Depends(administrator)):
    return CONTROLS


@router.post("/requests", status_code=201)
def create_request(data: RequestInput, user=Depends(administrator), db=Depends(get_db)):
    row = fulfill(db, data.kind, data.regime, data.entity_ref, user.username)
    db.commit()
    return _request(row)


@router.get("/requests")
def list_requests(user=Depends(administrator), db=Depends(get_db)):
    return [_request(row) for row in db.query(SubjectRequest).order_by(SubjectRequest.id.desc()).limit(100)]


@router.post("/consents", status_code=201)
def consent(data: ConsentInput, user=Depends(administrator), db=Depends(get_db)):
    row = SubjectConsent(entity_ref=data.entity_ref, purpose=data.purpose, granted=data.granted, actor=user.username)
    db.add(row)
    audit(db, user.username, "subject_consent", entity_ref=data.entity_ref, granted=data.granted)
    db.commit()
    return {"id": row.id, "granted": row.granted}


@router.get("/consents")
def consents(entity_ref: str = "", user=Depends(administrator), db=Depends(get_db)):
    query = db.query(SubjectConsent).order_by(SubjectConsent.id.desc())
    if entity_ref:
        query = query.filter_by(entity_ref=entity_ref)
    return [{"id": row.id, "entity_ref": row.entity_ref, "purpose": row.purpose, "granted": row.granted, "created_at": row.created_at.isoformat()} for row in query.limit(100)]


@router.post("/assessments", status_code=201)
def assessment(data: AssessmentInput, user=Depends(administrator), db=Depends(get_db)):
    row = ImpactAssessment(title=data.title, scope=data.scope, risks=data.risks, mitigations=data.mitigations, status=data.status, actor=user.username)
    db.add(row)
    audit(db, user.username, "impact_assessment", title=data.title, status=data.status)
    db.commit()
    return {"id": row.id, "status": row.status}


@router.get("/assessments")
def assessments(user=Depends(administrator), db=Depends(get_db)):
    return [{"id": row.id, "title": row.title, "status": row.status, "scope": row.scope, "risks": row.risks, "mitigations": row.mitigations} for row in db.query(ImpactAssessment).order_by(ImpactAssessment.id.desc()).limit(50)]


@router.post("/reviews", status_code=201)
def review(data: ReviewInput, user=Depends(administrator), db=Depends(get_db)):
    row = SupervisionReview(entity_ref=data.entity_ref, decision=data.decision, note=data.note, actor=user.username)
    db.add(row)
    audit(db, user.username, "supervision_review", entity_ref=data.entity_ref, decision=data.decision)
    db.commit()
    return {"id": row.id, "decision": row.decision}


@router.post("/inspect")
def inspect(data: InspectInput, user=Depends(administrator), db=Depends(get_db)):
    result = review_text(db, data.text)
    audit(db, user.username, "pattern_review", ssn=result["phi"]["ssn"], cards=len(result["cards"]))
    db.commit()
    return result


@router.put("/retention")
def retention(data: RetentionInput, user=Depends(administrator), db=Depends(get_db)):
    row = setting(db)
    row.online_months = data.online_months
    audit(db, user.username, "online_retention", months=data.online_months)
    db.commit()
    return {"online_months": row.online_months, "endpoint_retention_days": row.retention_days}


@router.post("/aging")
def aging(dry_run: bool = True, user=Depends(administrator), db=Depends(get_db)):
    result = age_facts(db, user.username, dry_run)
    db.commit()
    return result


@router.get("/archive")
def archives(user=Depends(administrator), db=Depends(get_db)):
    return [{"id": row.id, "entity_ref": row.entity_ref, "sha256": row.sha256, "created_at": row.created_at.isoformat()} for row in db.query(ArchiveRecord).order_by(ArchiveRecord.id.desc()).limit(100)]


@router.get("/archive/{record_id}")
def archive(record_id: int, user=Depends(administrator), db=Depends(get_db)):
    row = db.get(ArchiveRecord, record_id)
    if row is None:
        raise HTTPException(404, "Archive record not found")
    return archive_payload(row)


@router.post("/archive/{record_id}/verify")
def verify(record_id: int, user=Depends(administrator), db=Depends(get_db)):
    row = db.get(ArchiveRecord, record_id)
    if row is None:
        raise HTTPException(404, "Archive record not found")
    archive_payload(row)
    return {"id": row.id, "verified": True}


@router.get("/audit-export")
def export_audit(format: Literal["json", "csv"] = "json", columns: str = "", user=Depends(administrator), db=Depends(get_db)):
    chosen, rows = audit_rows(db, [part.strip() for part in columns.split(",") if part.strip()])
    audit(db, user.username, "audit_exported", format=format, columns=chosen)
    db.commit()
    if format == "csv":
        return Response(audit_csv(chosen, rows), media_type="text/csv")
    return {"columns": chosen, "rows": rows, "available_columns": list(AUDIT_COLUMNS)}


class AuditExportIn(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    format: Literal["csv", "jsonl", "cef", "syslog"] = "cef"
    columns: list[str] = Field(default_factory=lambda: list(AUDIT_COLUMNS))
    template: str = Field(default="", max_length=500)
    directory: str = Field(min_length=1, max_length=300)
    filename: str = Field(default="audit-export.log", max_length=80)
    interval_seconds: int = Field(default=3600, ge=300, le=86400)
    # A schedule can be defined paused, so it can be pointed at a directory or
    # volume that is not ready yet and switched on deliberately later.
    enabled: bool = True
    # Also forward each run to the SIEM described by the environment. Ignored
    # (and reported as not sent) when no SIEM is configured.
    forward_to_siem: bool = False


@router.get("/audit-exports")
def list_audit_exports(user=Depends(administrator), db=Depends(get_db)):
    rows = db.query(AuditExportSchedule).order_by(AuditExportSchedule.id).all()
    return {
        "schedules": [{"id": r.id, "name": r.name, "format": r.format, "directory": r.directory,
                       "filename": r.filename, "interval_seconds": r.interval_seconds,
                       "enabled": r.enabled, "forward_to_siem": r.forward_to_siem,
                       "last_run": r.last_run.isoformat() if r.last_run else None,
                       "last_rows": r.last_rows, "last_path": r.last_path} for r in rows],
        "formats": list(AUDIT_FORMATS),
        "available_columns": list(AUDIT_COLUMNS),
        # Reports whether forwarding is configured in the environment and where
        # it would go. The credential is deliberately absent: it never enters
        # the database, so it can never be returned from here.
        "siem": siem_config().public_status(),
        "scope": "Exports are written locally; forwarding happens only for a schedule "
                 "with forward_to_siem and only when the SIEM is configured in the environment",
    }


@router.post("/audit-exports", status_code=201)
def create_audit_export(body: AuditExportIn, user=Depends(administrator), db=Depends(get_db)):
    chosen = [column for column in body.columns if column in AUDIT_COLUMNS] or list(AUDIT_COLUMNS)
    try:
        template = validate_audit_template(body.template, chosen)
        filename = validate_audit_filename(body.filename)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    row = AuditExportSchedule(
        name=body.name, format=body.format, columns=json.dumps(chosen), template=template,
        directory=body.directory, filename=filename, interval_seconds=body.interval_seconds,
        next_run=utcnow(), enabled=bool(body.enabled),
        forward_to_siem=bool(body.forward_to_siem),
    )
    db.add(row)
    audit(db, user.username, "audit_export_scheduled", name=row.name, export_format=row.format,
          directory=row.directory, interval_seconds=row.interval_seconds)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "format": row.format, "columns": chosen}


@router.post("/audit-exports/{schedule_id}/run", status_code=201)
def run_audit_export_now(schedule_id: int, user=Depends(administrator), db=Depends(get_db)):
    row = db.get(AuditExportSchedule, schedule_id)
    if row is None:
        raise HTTPException(404, "Audit export schedule not found")
    if not row.enabled:
        # A disabled schedule is a deliberate pause. Running it anyway would
        # contradict that, and reporting "written: 0" would look like a
        # successful run that produced nothing.
        raise HTTPException(409, "Audit export schedule is disabled")
    # Only this schedule is run, so an operator asking for one export does not
    # also fire every other schedule that happened to be due.
    before = row.last_id
    row.next_run = utcnow()
    written = run_audit_exports(db, only=row.id)
    db.commit()
    return {"id": row.id, "written": written, "last_id": row.last_id, "was": before}


@router.delete("/audit-exports/{schedule_id}")
def delete_audit_export(schedule_id: int, user=Depends(administrator), db=Depends(get_db)):
    row = db.get(AuditExportSchedule, schedule_id)
    if row is None:
        raise HTTPException(404, "Audit export schedule not found")
    audit(db, user.username, "audit_export_removed", name=row.name,
          note="Exported files are left on disk for archival")
    db.delete(row)
    db.commit()
    return {"id": schedule_id, "deleted": True, "note": "Files already written are not deleted"}
