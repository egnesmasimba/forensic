import json
from typing import Literal

from fastapi import APIRouter, Depends, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.auth import administrator, current_user, get_db, writer
from app.mail_analysis import mail_policy, store_mail
from app.mail_models import MailEvidence, MailPolicy
from endpoint_agent.content_scan import MAX_FILE, normalize_domain, parse_email, scan_bytes


router = APIRouter(prefix="/api/mail", tags=["email capture"], dependencies=[Depends(current_user)])


class PolicyInput(BaseModel):
    internal_domains: list[str] = Field(default_factory=list, max_length=100)
    sensitive_terms: list[str] = Field(default_factory=list, max_length=100)


@router.get("/policy")
def policy(db=Depends(get_db)):
    return mail_policy(db)


@router.put("/policy")
def update_policy(data: PolicyInput, user=Depends(administrator), db=Depends(get_db)):
    try:
        domains = sorted(set(normalize_domain(d) for d in data.internal_domains))
    except ValueError as error:
        raise HTTPException(422, str(error))
    terms = list(dict.fromkeys(term.strip() for term in data.sensitive_terms))
    if any(not term or len(term) > 80 for term in terms):
        raise HTTPException(422, "Use non-empty sensitive terms of at most 80 characters")
    row = db.get(MailPolicy, 1)
    if row is None:
        row = MailPolicy(id=1)
        db.add(row)
    row.internal_domains, row.sensitive_terms = json.dumps(domains), json.dumps(terms)
    db.commit()
    return mail_policy(db)


def summary(row):
    report = json.loads(row.report)
    return {"id": row.id, "client": row.client, "subject": row.subject, "sender": report["sender"],
            "direction": report["direction"], "occurred_at": report["occurred_at"], "agent_id": row.agent_id,
            "recipient_domains": report["recipient_domains"], "attachments": len(report["attachments"]),
            "findings": report["findings"], "partial": report["partial"], "alert_id": row.alert_id}


@router.post("/eml", status_code=201)
async def import_message(file: UploadFile, direction: Literal["incoming", "outgoing", "unknown"] = Form("unknown"),
                         user=Depends(writer), db=Depends(get_db)):
    raw = await file.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise HTTPException(413, "Message must be at most 8 MB")
    if b":" not in raw.split(b"\n\n", 1)[0] or not raw.strip():
        raise HTTPException(422, "Upload an RFC 5322 email message")
    try:
        report = parse_email(raw, client="eml", direction=direction)
        row, duplicate = store_mail(db, report, captured_by=user.username, raw=raw)
    except ValueError as error:
        db.rollback()
        raise HTTPException(422, str(error))
    db.commit()
    return {**summary(row), "duplicate": duplicate}


@router.post("/scan")
async def scan_attachment(file: UploadFile, user=Depends(writer)):
    data = await file.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise HTTPException(413, "Scanning input must be at most 8 MB")
    return scan_bytes(data, file.filename or "attachment.bin")


@router.get("/messages")
def messages(limit: int = Query(30, ge=1, le=100), before_id: int | None = Query(None, ge=1), db=Depends(get_db)):
    query = db.query(MailEvidence)
    if before_id:
        query = query.filter(MailEvidence.id < before_id)
    return [summary(row) for row in query.order_by(MailEvidence.id.desc()).limit(limit)]


@router.get("/messages/{message_id}")
def message(message_id: int, db=Depends(get_db)):
    row = db.get(MailEvidence, message_id)
    if row is None:
        raise HTTPException(404, "Email record not found")
    return {**summary(row), "report": json.loads(row.report), "captured_by": row.captured_by,
            "event_id": row.event_id, "original_message_retained": row.raw is not None}
