from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.auth import current_user, get_db, writer
from app.audit_export import (
    FORMATS as AUDIT_FORMATS,
    run_due_exports as run_audit_exports,
    validate_filename as validate_audit_filename,
    validate_template as validate_audit_template,
)
from app.automation import STEPS, TRIGGERS, delivery_service, escalate, run_playbook, template
from app.models import (
    AuditExportSchedule, AutomationAudit, AutomationRun, Delivery, Incident,
    LocalTrigger, Notice, OutboundRecipient, Playbook, Ticket, utcnow,
)

router = APIRouter(prefix="/api/automation", tags=["automation"], dependencies=[Depends(current_user)])


class PlaybookIn(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    trigger: str
    steps: str = Field(min_length=3, max_length=120)
    message: str = Field(default="", max_length=300)

    @field_validator("trigger")
    @classmethod
    def known_trigger(cls, value: str) -> str:
        if value not in TRIGGERS:
            raise ValueError("Choose download, upload, email, print, other, or dlp")
        return value

    @field_validator("steps")
    @classmethod
    def known_steps(cls, value: str) -> str:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if not parts or any(part not in STEPS for part in parts):
            raise ValueError("Steps are notify, email, sms, ticket, and incident")
        return ",".join(parts)


@router.get("/playbooks")
def playbooks(db=Depends(get_db)):
    rows = db.query(Playbook).order_by(Playbook.name).all()
    return [{"id": row.id, "name": row.name, "trigger": row.trigger, "steps": row.steps, "enabled": row.enabled} for row in rows]


@router.post("/playbooks", status_code=201)
def create_playbook(body: PlaybookIn, user=Depends(writer), db=Depends(get_db)):
    if db.query(Playbook).filter_by(name=body.name.strip()).one_or_none() is not None:
        raise HTTPException(409, "That playbook name already exists")
    row = Playbook(name=body.name.strip(), trigger=body.trigger, steps=body.steps, message=body.message.strip())
    db.add(row)
    db.add(AutomationAudit(actor=user.username, change=f"Playbook {row.name} for {row.trigger}."))
    db.commit()
    db.refresh(row)
    return {"id": row.id, "name": row.name}


class RunBody(BaseModel):
    alert_id: int = Field(ge=1)


@router.post("/playbooks/{playbook_id}/run", status_code=201)
def run_one(playbook_id: int, body: RunBody, user=Depends(writer), db=Depends(get_db)):
    from app.models import Alert
    playbook = db.get(Playbook, playbook_id)
    alert = db.get(Alert, body.alert_id)
    if playbook is None or alert is None:
        raise HTTPException(404, "Playbook or alert not found")
    done = run_playbook(db, playbook, alert) if playbook.enabled else []
    db.commit()
    return {"steps": done}


@router.get("/runs")
def runs(db=Depends(get_db)):
    rows = db.query(AutomationRun).order_by(AutomationRun.id.desc()).limit(30).all()
    return [{"playbook_id": row.playbook_id, "alert_id": row.alert_id, "steps_done": row.steps_done} for row in rows]


class NoticeIn(BaseModel):
    user: str = Field(min_length=1, max_length=120)
    message: str = Field(min_length=1, max_length=500)


@router.post("/notices", status_code=201)
def notify(body: NoticeIn, user=Depends(writer), db=Depends(get_db)):
    db.add(Notice(user=body.user.strip(), channel="app", subject="Review", body=body.message.strip()))
    db.add(AutomationAudit(actor=user.username, change=f"Notified {body.user.strip()}."))
    db.commit()
    return {"channel": "app"}


@router.get("/notices")
def notices(db=Depends(get_db)):
    rows = db.query(Notice).order_by(Notice.id.desc()).limit(30).all()
    return [{
        "id": row.id, "user": row.user, "channel": row.channel, "subject": row.subject,
        "body": row.body, "acknowledged": row.acknowledged, "escalation": row.escalation,
    } for row in rows]


@router.post("/notices/{notice_id}/acknowledge")
def acknowledge(notice_id: int, user=Depends(writer), db=Depends(get_db)):
    row = db.get(Notice, notice_id)
    if row is None:
        raise HTTPException(404, "Notice not found")
    row.acknowledged = True
    db.commit()
    return {"id": row.id, "acknowledged": True}


class TemplateUpdate(BaseModel):
    subject: str = Field(min_length=3, max_length=160)
    body: str = Field(min_length=3, max_length=500)
    throttle_minutes: int = Field(ge=0, le=1440)
    escalate_minutes: int = Field(ge=0, le=10080)


@router.get("/template")
def read_template(db=Depends(get_db)):
    row = template(db)
    return {
        "subject": row.subject, "body": row.body,
        "throttle_minutes": row.throttle_minutes, "escalate_minutes": row.escalate_minutes,
    }


@router.put("/template")
def update_template(body: TemplateUpdate, user=Depends(writer), db=Depends(get_db)):
    row = template(db)
    row.subject = body.subject.strip()
    row.body = body.body.strip()
    row.throttle_minutes = body.throttle_minutes
    row.escalate_minutes = body.escalate_minutes
    db.add(AutomationAudit(actor=user.username, change="Updated the alert template."))
    db.commit()
    return read_template(db)


@router.post("/escalate", status_code=201)
def run_escalation(user=Depends(writer), db=Depends(get_db)):
    created = escalate(db)
    db.commit()
    return {"created": created}


class IncidentIn(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    detail: str = Field(default="", max_length=500)
    alert_id: int | None = None


@router.post("/incidents", status_code=201)
def create_incident(body: IncidentIn, user=Depends(writer), db=Depends(get_db)):
    row = Incident(title=body.title.strip(), detail=body.detail.strip(), alert_id=body.alert_id)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "status": row.status}


class IncidentUpdate(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def known(cls, value: str) -> str:
        if value not in {"open", "updated", "resolved"}:
            raise ValueError("Choose open, updated, or resolved")
        return value


@router.put("/incidents/{incident_id}")
def update_incident(incident_id: int, body: IncidentUpdate, user=Depends(writer), db=Depends(get_db)):
    from app.models import Alert
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(404, "Incident not found")
    row.status = body.status
    if body.status == "resolved" and row.alert_id is not None:
        alert = db.get(Alert, row.alert_id)
        if alert is not None:
            alert.status = "closed"
    db.commit()
    return {"id": row.id, "status": row.status}


@router.get("/incidents")
def incidents(db=Depends(get_db)):
    rows = db.query(Incident).order_by(Incident.id.desc()).limit(30).all()
    return [{"id": row.id, "title": row.title, "status": row.status, "alert_id": row.alert_id} for row in rows]


class RecipientIn(BaseModel):
    channel: str
    address: str = Field(min_length=3, max_length=200)
    scope: str = Field(default="", max_length=40)

    @field_validator("channel")
    @classmethod
    def known_channel(cls, value: str) -> str:
        if value not in {"email", "sms"}:
            raise ValueError("Choose email or sms")
        return value

    @field_validator("address")
    @classmethod
    def plausible(cls, value: str) -> str:
        address = value.strip()
        if "@" not in address and not address.replace("+", "").isdigit():
            # Reject anything that is neither an email nor a phone number
            # rather than handing a typo to a relay.
            raise ValueError("Provide an email address or a phone number")
        return address


@router.get("/recipients")
def list_recipients(db=Depends(get_db)):
    rows = db.query(OutboundRecipient).order_by(OutboundRecipient.id).all()
    return {
        "recipients": [{"id": r.id, "channel": r.channel, "address": r.address,
                        "scope": r.scope, "enabled": r.enabled} for r in rows],
        "transport": delivery_service().status(),
    }


@router.post("/recipients", status_code=201)
def create_recipient(body: RecipientIn, user=Depends(writer), db=Depends(get_db)):
    row = OutboundRecipient(channel=body.channel, address=body.address, scope=body.scope.strip())
    db.add(row)
    db.add(AutomationAudit(actor=user.username, change=(
        f"Added outbound {row.channel} recipient {row.address}"
        + (f" scoped to {row.scope}" if row.scope else "")
        + ". Alert text will be delivered here.")))
    db.commit()
    db.refresh(row)
    return {"id": row.id, "channel": row.channel, "address": row.address}


class RecipientUpdate(BaseModel):
    enabled: bool


@router.put("/recipients/{recipient_id}")
def update_recipient(recipient_id: int, body: RecipientUpdate, user=Depends(writer), db=Depends(get_db)):
    row = db.get(OutboundRecipient, recipient_id)
    if row is None:
        raise HTTPException(404, "Recipient not found")
    row.enabled = body.enabled
    db.add(AutomationAudit(actor=user.username, change=(
        f"{'Enabled' if body.enabled else 'Disabled'} outbound {row.channel} recipient "
        f"{row.address}. {'Alert text may again be delivered here.' if body.enabled else 'No further alert text will be sent here.'}")))
    db.commit()
    return {"id": row.id, "enabled": row.enabled}


@router.get("/deliveries")
def deliveries(db=Depends(get_db)):
    rows = db.query(Delivery).order_by(Delivery.id.desc()).limit(500).all()
    return [{"id": r.id, "channel": r.channel, "recipient": r.recipient, "status": r.status,
             "detail": r.detail, "attempts": r.attempts, "alert_id": r.alert_id} for r in rows]


class TicketIn(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    alert_id: int | None = None
    #: Push to the configured external system straight away instead of leaving
    #: the ticket local only.
    push: bool = False


@router.post("/tickets", status_code=201)
def create_ticket(body: TicketIn, user=Depends(writer), db=Depends(get_db)):
    row = Ticket(system="custom", title=body.title.strip(), alert_id=body.alert_id)
    db.add(row)
    db.flush()
    result = None
    if body.push:
        result = _push_ticket(db, row)
    db.commit()
    db.refresh(row)
    payload = {"id": row.id, "system": row.system, "status": row.status,
               "external_id": row.external_id, "external_ref": row.external_ref,
               "last_error": row.last_error}
    if result is not None:
        payload["push"] = result.as_payload()
    return payload


def _push_ticket(db, row: Ticket):
    """Push one ticket outward, recording the outcome on the ticket itself.

    Idempotent: a ticket that already carries an external id is not created a
    second time, because a retried request must not leave the ITSM with
    duplicate incidents.
    """
    from app.ticketing import TicketResult, ticket_connector

    connector = ticket_connector()
    if not connector.config.enabled:
        result = TicketResult(pushed=False, detail="ticketing not configured")
        row.last_error = result.detail
        return result
    if row.external_id:
        # Idempotent: a retried request must not create a second incident in
        # the ITSM, which an investigator would then have to reconcile by hand.
        result = TicketResult(pushed=False, detail="already pushed",
                              external_id=row.external_id)
        return result
    result = connector.push(row)
    if result.pushed:
        row.system = connector.config.target
        row.external_id = result.external_id
        row.external_ref = result.external_url
        row.last_error = ""
        row.pushed_at = utcnow()
    else:
        # Recorded on the ticket: a silent failure here means an investigator
        # believes work was raised in the ITSM when it was not.
        row.last_error = result.detail[:300]
    return result


class TicketUpdate(BaseModel):
    status: str
    #: Also apply the status to the external ticket when one was pushed.
    push: bool = False

    @field_validator("status")
    @classmethod
    def known(cls, value: str) -> str:
        if value not in {"open", "pending", "closed"}:
            raise ValueError("Choose open, pending, or closed")
        return value


@router.put("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, body: TicketUpdate, user=Depends(writer), db=Depends(get_db)):
    row = db.get(Ticket, ticket_id)
    if row is None:
        raise HTTPException(404, "Ticket not found")
    row.status = body.status
    payload = {"id": row.id, "status": row.status, "last_error": row.last_error}
    if body.push and row.external_id:
        connector = ticket_connector()
        if connector.config.enabled:
            result = connector.set_status(row, body.status)
            if not result.pushed:
                row.last_error = result.detail[:300]
            else:
                row.last_error = ""
            payload["push"] = result.as_payload()
        else:
            payload["push"] = {"pushed": False, "detail": "ticketing not configured"}
    db.commit()
    payload["last_error"] = row.last_error
    return payload


class TriggerIn(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    detail: str = Field(default="", max_length=300)


@router.post("/triggers", status_code=201)
def create_trigger(body: TriggerIn, user=Depends(writer), db=Depends(get_db)):
    row = LocalTrigger(name=body.name.strip(), detail=body.detail.strip())
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "confirmed": False}


@router.post("/triggers/{trigger_id}/confirm")
def confirm_trigger(trigger_id: int, user=Depends(writer), db=Depends(get_db)):
    row = db.get(LocalTrigger, trigger_id)
    if row is None:
        raise HTTPException(404, "Trigger not found")
    row.confirmed = True
    row.confirmed_by = user.username
    db.add(AutomationAudit(actor=user.username, change=f"Confirmed trigger {row.name}."))
    db.commit()
    return {"id": row.id, "confirmed": True, "confirmed_by": row.confirmed_by}


@router.get("/audit")
def audit(db=Depends(get_db)):
    rows = db.query(AutomationAudit).order_by(AutomationAudit.id.desc()).limit(30).all()
    return [{"actor": row.actor, "change": row.change} for row in rows]
