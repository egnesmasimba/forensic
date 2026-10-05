from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.auth import current_user, get_db, writer
from app.automation import apply_new_alerts
from app.dlp import (
    dlp_setting, record_file_changes, record_permission, record_print, record_screenshot_attempt, record_usb,
    review_cloud, review_commands, review_text,
)
from app.models import (
    CloudAllow, CommandAudit, DlpAudit, FileChange, PermissionAllow, PermissionChange, PrintJob,
    ScreenshotAttempt, UsbActivity, UsbDevice,
)
from app.observations import require_timestamp

router = APIRouter(prefix="/api/dlp", tags=["dlp"], dependencies=[Depends(current_user)])


class TextReview(BaseModel):
    user: str = Field(default="", max_length=120)
    text: str = Field(min_length=1, max_length=100000)


@router.post("/inspect", status_code=201)
def inspect(body: TextReview, user=Depends(writer), db=Depends(get_db)):
    result = review_text(db, body.user.strip(), body.text, user.username)
    apply_new_alerts(db)
    db.commit()
    return result


class PolicyUpdate(BaseModel):
    min_matches: int = Field(ge=1, le=20)
    score: int = Field(ge=0, le=1000)
    ip_terms: str = Field(default="", max_length=300)
    customer_terms: str = Field(default="", max_length=300)
    financial_terms: str = Field(default="", max_length=300)


@router.get("/policy")
def policy(db=Depends(get_db)):
    row = dlp_setting(db)
    return {
        "min_matches": row.min_matches, "score": row.score, "ip_terms": row.ip_terms,
        "customer_terms": row.customer_terms, "financial_terms": row.financial_terms,
    }


@router.put("/policy")
def update_policy(body: PolicyUpdate, user=Depends(writer), db=Depends(get_db)):
    row = dlp_setting(db)
    row.min_matches = body.min_matches
    row.score = body.score
    row.ip_terms = body.ip_terms.strip()
    row.customer_terms = body.customer_terms.strip()
    row.financial_terms = body.financial_terms.strip()
    db.add(DlpAudit(actor=user.username, change=f"Policy min matches {body.min_matches}, score {body.score}."))
    apply_new_alerts(db)
    db.commit()
    return policy(db)


@router.get("/audit")
def audit(db=Depends(get_db)):
    rows = db.query(DlpAudit).order_by(DlpAudit.id.desc()).limit(30).all()
    return [{"actor": row.actor, "change": row.change, "created_at": row.created_at.isoformat()} for row in rows]


class UsbAllow(BaseModel):
    serial: str = Field(min_length=1, max_length=80)
    label: str = Field(default="", max_length=80)
    allowed: bool = True


@router.put("/usb")
def allow_usb(body: UsbAllow, user=Depends(writer), db=Depends(get_db)):
    row = db.query(UsbDevice).filter_by(serial=body.serial.strip()).one_or_none()
    if row is None:
        row = UsbDevice(serial=body.serial.strip(), label=body.label.strip(), allowed=body.allowed)
        db.add(row)
    else:
        row.label = body.label.strip()
        row.allowed = body.allowed
    apply_new_alerts(db)
    db.commit()
    return {"serial": row.serial, "allowed": row.allowed}


class UsbEvent(BaseModel):
    serial: str = Field(min_length=1, max_length=80)
    user: str = Field(min_length=1, max_length=120)
    action: str = Field(default="transfer", max_length=40)
    bytes: int = Field(default=0, ge=0, le=10**15)
    occurred_at: str

    @field_validator("occurred_at")
    @classmethod
    def known_time(cls, value: str) -> str:
        return require_timestamp(value)


@router.post("/usb/activity", status_code=201)
def usb_activity(body: UsbEvent, user=Depends(writer), db=Depends(get_db)):
    result = record_usb(db, body.serial.strip(), body.user.strip(), body.action.strip(), body.bytes, body.occurred_at)
    apply_new_alerts(db)
    db.commit()
    return result


@router.get("/usb/activity")
def usb_log(db=Depends(get_db)):
    rows = db.query(UsbActivity).order_by(UsbActivity.id.desc()).limit(50).all()
    return [{"serial": row.serial, "user": row.user, "action": row.action, "bytes": row.bytes, "occurred_at": row.occurred_at} for row in rows]


class CloudRule(BaseModel):
    host: str = Field(min_length=3, max_length=120)
    allowed: bool = True


@router.put("/cloud")
def allow_cloud(body: CloudRule, user=Depends(writer), db=Depends(get_db)):
    host = body.host.casefold().strip()
    row = db.query(CloudAllow).filter_by(host=host).one_or_none()
    if row is None:
        row = CloudAllow(host=host, allowed=body.allowed)
        db.add(row)
    else:
        row.allowed = body.allowed
    apply_new_alerts(db)
    db.commit()
    return {"host": row.host, "allowed": row.allowed}


class CloudEvent(BaseModel):
    host: str = Field(min_length=3, max_length=120)
    user: str = Field(min_length=1, max_length=120)
    bytes: int = Field(ge=0, le=10**15)


@router.post("/cloud/activity", status_code=201)
def cloud_activity(body: CloudEvent, user=Depends(writer), db=Depends(get_db)):
    result = review_cloud(db, body.host.strip(), body.user.strip(), body.bytes)
    apply_new_alerts(db)
    db.commit()
    return result


class FileEvent(BaseModel):
    action: str
    source: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=200)
    occurred_at: str

    @field_validator("action")
    @classmethod
    def known_action(cls, value: str) -> str:
        if value not in {"rename", "move"}:
            raise ValueError("Choose rename or move")
        return value

    @field_validator("occurred_at")
    @classmethod
    def known_time(cls, value: str) -> str:
        return require_timestamp(value)


class FileBatch(BaseModel):
    user: str = Field(min_length=1, max_length=120)
    changes: list[FileEvent] = Field(min_length=1, max_length=100)


@router.post("/files", status_code=201)
def files(body: FileBatch, user=Depends(writer), db=Depends(get_db)):
    result = record_file_changes(db, body.user.strip(), [change.model_dump() for change in body.changes])
    apply_new_alerts(db)
    db.commit()
    return result


@router.get("/files")
def file_log(db=Depends(get_db)):
    rows = db.query(FileChange).order_by(FileChange.id.desc()).limit(50).all()
    return [{"user": row.user, "action": row.action, "source": row.source, "target": row.target} for row in rows]


class AllowPrincipal(BaseModel):
    principal: str = Field(min_length=1, max_length=120)


@router.put("/permissions/allow")
def allow_principal(body: AllowPrincipal, user=Depends(writer), db=Depends(get_db)):
    principal = body.principal.strip()
    if db.query(PermissionAllow).filter_by(principal=principal).one_or_none() is None:
        db.add(PermissionAllow(principal=principal))
        apply_new_alerts(db)
    db.commit()
    return {"principal": principal}


class PermissionEvent(BaseModel):
    user: str = Field(min_length=1, max_length=120)
    path: str = Field(min_length=1, max_length=200)
    principal: str = Field(min_length=1, max_length=120)
    change: str
    occurred_at: str

    @field_validator("change")
    @classmethod
    def known_change(cls, value: str) -> str:
        if value not in {"grant", "revoke"}:
            raise ValueError("Choose grant or revoke")
        return value

    @field_validator("occurred_at")
    @classmethod
    def known_time(cls, value: str) -> str:
        return require_timestamp(value)


@router.post("/permissions", status_code=201)
def permissions(body: PermissionEvent, user=Depends(writer), db=Depends(get_db)):
    result = record_permission(db, body.user.strip(), body.path.strip(), body.principal.strip(), body.change, body.occurred_at)
    apply_new_alerts(db)
    db.commit()
    return result


@router.get("/permissions")
def permission_log(db=Depends(get_db)):
    rows = db.query(PermissionChange).order_by(PermissionChange.id.desc()).limit(50).all()
    return [{"user": row.user, "path": row.path, "principal": row.principal, "change": row.change} for row in rows]


class CommandBatch(BaseModel):
    user: str = Field(min_length=1, max_length=120)
    commands: list[str] = Field(min_length=1, max_length=200)


@router.post("/commands", status_code=201)
def commands(body: CommandBatch, user=Depends(writer), db=Depends(get_db)):
    cleaned = [command.strip()[:300] for command in body.commands if command.strip()]
    if not cleaned:
        raise HTTPException(422, "Enter a command")
    result = review_commands(db, body.user.strip(), cleaned)
    apply_new_alerts(db)
    db.commit()
    return result


class PrintEvent(BaseModel):
    model_config = {"extra": "forbid"}
    user: str = Field(min_length=1, max_length=120)
    printer: str = Field(min_length=1, max_length=120)
    document: str = Field(min_length=1, max_length=200)
    pages: int = Field(ge=0, le=100000)
    size: int = Field(ge=0, le=2_000_000_000)
    occurred_at: str

    @field_validator("occurred_at")
    @classmethod
    def known_time(cls, value: str) -> str:
        return require_timestamp(value)


@router.post("/print", status_code=201)
def print_job(body: PrintEvent, user=Depends(writer), db=Depends(get_db)):
    del user
    result = record_print(db, body.user.strip(), body.printer.strip(), body.document.strip(), body.pages, body.size, body.occurred_at)
    apply_new_alerts(db)
    db.commit()
    return result


@router.get("/print")
def print_log(db=Depends(get_db)):
    rows = db.query(PrintJob).order_by(PrintJob.id.desc()).limit(50).all()
    return [{"user": row.user, "printer": row.printer, "document": row.document, "pages": row.pages, "size": row.size} for row in rows]


class ScreenshotEvent(BaseModel):
    model_config = {"extra": "forbid"}
    user: str = Field(min_length=1, max_length=120)
    application: str = Field(min_length=1, max_length=120)
    occurred_at: str

    @field_validator("occurred_at")
    @classmethod
    def known_time(cls, value: str) -> str:
        return require_timestamp(value)


@router.post("/screenshots", status_code=201)
def screenshot_attempt(body: ScreenshotEvent, user=Depends(writer), db=Depends(get_db)):
    del user
    result = record_screenshot_attempt(db, body.user.strip(), body.application.strip(), body.occurred_at)
    apply_new_alerts(db)
    db.commit()
    return result


@router.get("/screenshots")
def screenshot_log(db=Depends(get_db)):
    rows = db.query(ScreenshotAttempt).order_by(ScreenshotAttempt.id.desc()).limit(50).all()
    return [{"user": row.user, "application": row.application, "occurred_at": row.occurred_at} for row in rows]


@router.get("/commands")
def command_log(db=Depends(get_db)):
    rows = db.query(CommandAudit).order_by(CommandAudit.id.desc()).limit(50).all()
    return [{"user": row.user, "command": row.command, "finding": row.finding} for row in rows]
