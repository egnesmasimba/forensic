import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.auth import current_user, get_db, writer
from app.models import (
    BusinessProcess,
    FieldAudit,
    ProcessStep,
    ScreenDefinition,
    ScreenField,
    ScreenHit,
    ScreenMarker,
)
from app.screens import FIELD_ACTIONS, extract_fields, identify_text, record_hit, screen_query, valid_field_name

router = APIRouter(dependencies=[Depends(current_user)])


class ScreenCreate(BaseModel):
    name: str = Field(min_length=3, max_length=80)

    @field_validator("name")
    @classmethod
    def trimmed(cls, value: str) -> str:
        text = value.strip()
        if len(text) < 3:
            raise ValueError("Enter a screen name")
        return text


class MarkerCreate(BaseModel):
    text: str = Field(min_length=1, max_length=80)
    line: int = Field(default=0, ge=0, le=200)

    @field_validator("text")
    @classmethod
    def trimmed(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("Enter the text that identifies the screen")
        return text


class FieldCreate(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    label: str = Field(min_length=1, max_length=80)
    line: int = Field(ge=1, le=200)
    start_column: int = Field(ge=1, le=400)
    length: int = Field(ge=1, le=120)
    action: str = "read"

    @field_validator("name")
    @classmethod
    def known_name(cls, value: str) -> str:
        text = value.strip()
        if not valid_field_name(text):
            raise ValueError("Use a short lowercase field name")
        return text

    @field_validator("label")
    @classmethod
    def trimmed_label(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("Enter a field label")
        return text

    @field_validator("action")
    @classmethod
    def known_action(cls, value: str) -> str:
        if value not in FIELD_ACTIONS:
            raise ValueError("Choose read, update, add, or delete")
        return value


class ProcessCreate(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    description: str = Field(default="", max_length=500)

    @field_validator("name", "description")
    @classmethod
    def trimmed(cls, value: str) -> str:
        return value.strip()


class StepCreate(BaseModel):
    screen_id: int


class TextBody(BaseModel):
    text: str = Field(min_length=1, max_length=20000)


class ApplyBody(BaseModel):
    texts: list[str] = Field(min_length=1, max_length=8)

    @field_validator("texts")
    @classmethod
    def sized(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip("\n")
            if not text.strip():
                raise ValueError("Each screen transcript needs text")
            if len(text) > 20000:
                raise ValueError("A screen transcript is limited to 20,000 characters")
            cleaned.append(text)
        return cleaned


def _screen_out(row: ScreenDefinition) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "markers": [{"id": marker.id, "text": marker.text, "line": marker.line} for marker in row.markers],
        "fields": [
            {
                "id": field.id,
                "name": field.name,
                "label": field.label,
                "line": field.line,
                "start_column": field.start_column,
                "length": field.length,
                "action": field.action,
            }
            for field in row.fields
        ],
    }


def _process_out(row: BusinessProcess) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "steps": [
            {"id": step.id, "position": step.position, "screen_id": step.screen_id, "screen_name": step.screen.name}
            for step in row.steps
        ],
    }


def _load_screen(db: Session, screen_id: int) -> ScreenDefinition:
    row = screen_query(db).filter(ScreenDefinition.id == screen_id).one_or_none()
    if row is None:
        raise HTTPException(404, "Screen not found")
    return row


def _load_process(db: Session, process_id: int) -> BusinessProcess:
    row = (
        db.query(BusinessProcess)
        .options(selectinload(BusinessProcess.steps).selectinload(ProcessStep.screen).selectinload(ScreenDefinition.fields))
        .filter(BusinessProcess.id == process_id)
        .one_or_none()
    )
    if row is None:
        raise HTTPException(404, "Process not found")
    return row


@router.get("/api/screens")
def list_screens(db: Session = Depends(get_db)):
    rows = screen_query(db).order_by(ScreenDefinition.name).all()
    return [_screen_out(row) for row in rows]


@router.post("/api/screens", status_code=201)
def create_screen(body: ScreenCreate, user=Depends(writer), db: Session = Depends(get_db)):
    row = ScreenDefinition(name=body.name, created_by=user.username)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A screen with that name already exists")
    db.refresh(row)
    return _screen_out(row)


@router.post("/api/screens/identify")
def identify(body: TextBody, db: Session = Depends(get_db)):
    screen, names = identify_text(db, body.text)
    if screen is None and not names:
        raise HTTPException(409, "No screen definition matches this text")
    if screen is None:
        raise HTTPException(409, "More than one screen matches: " + ", ".join(names))
    return {"screen_id": screen.id, "screen_name": screen.name, "fields": extract_fields(screen, body.text)}


@router.post("/api/screens/{screen_id}/markers", status_code=201)
def add_marker(screen_id: int, body: MarkerCreate, user=Depends(writer), db: Session = Depends(get_db)):
    row = _load_screen(db, screen_id)
    if len(row.markers) >= 8:
        raise HTTPException(422, "A screen can have up to 8 identifying strings")
    marker = ScreenMarker(screen_id=row.id, text=body.text, line=body.line)
    db.add(marker)
    db.commit()
    db.refresh(row)
    return _screen_out(row)


@router.post("/api/screens/{screen_id}/fields", status_code=201)
def add_field(screen_id: int, body: FieldCreate, user=Depends(writer), db: Session = Depends(get_db)):
    row = _load_screen(db, screen_id)
    if len(row.fields) >= 20:
        raise HTTPException(422, "A screen can have up to 20 fields")
    field = ScreenField(
        screen_id=row.id,
        name=body.name,
        label=body.label,
        line=body.line,
        start_column=body.start_column,
        length=body.length,
        action=body.action,
    )
    db.add(field)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "That field name is already on this screen")
    db.refresh(row)
    return _screen_out(row)


@router.get("/api/processes")
def list_processes(db: Session = Depends(get_db)):
    rows = (
        db.query(BusinessProcess)
        .options(selectinload(BusinessProcess.steps).selectinload(ProcessStep.screen))
        .order_by(BusinessProcess.name)
        .all()
    )
    return [_process_out(row) for row in rows]


@router.post("/api/processes", status_code=201)
def create_process(body: ProcessCreate, user=Depends(writer), db: Session = Depends(get_db)):
    if len(body.name) < 3:
        raise HTTPException(422, "Enter a process name")
    row = BusinessProcess(name=body.name, description=body.description, created_by=user.username)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A process with that name already exists")
    db.refresh(row)
    return _process_out(row)


@router.post("/api/processes/{process_id}/steps", status_code=201)
def add_step(process_id: int, body: StepCreate, user=Depends(writer), db: Session = Depends(get_db)):
    process = _load_process(db, process_id)
    if len(process.steps) >= 8:
        raise HTTPException(422, "A process can have up to 8 screens")
    screen = db.get(ScreenDefinition, body.screen_id)
    if screen is None:
        raise HTTPException(404, "Screen not found")
    step = ProcessStep(process_id=process.id, screen_id=screen.id, position=len(process.steps) + 1)
    db.add(step)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "That screen is already a step in this process")
    return _process_out(_load_process(db, process.id))


@router.post("/api/processes/{process_id}/apply", status_code=201)
def apply_process(process_id: int, body: ApplyBody, user=Depends(writer), db: Session = Depends(get_db)):
    process = _load_process(db, process_id)
    if not process.steps:
        raise HTTPException(422, "Add at least one screen to this process")
    if len(body.texts) != len(process.steps):
        raise HTTPException(422, "Submit one transcript for each screen in the navigation")
    identified = []
    for text in body.texts:
        screen, names = identify_text(db, text)
        if screen is None and not names:
            raise HTTPException(409, "No screen definition matches this text")
        if screen is None:
            raise HTTPException(409, "More than one screen matches: " + ", ".join(names))
        identified.append((screen, text))
    expected = [step.screen_id for step in process.steps]
    actual = [screen.id for screen, _text in identified]
    if actual != expected:
        raise HTTPException(422, "These transcripts do not follow the navigation for this process")
    occurrence_key = uuid.uuid4().hex
    for step, (screen, text) in zip(process.steps, identified):
        record_hit(
            db,
            screen,
            text,
            source="transcript",
            username=user.username,
            process_id=process.id,
            step_position=step.position,
            occurrence_key=occurrence_key,
        )
    db.commit()
    table = _audit_table(db, process)
    return {"occurrence_key": occurrence_key, "audit": table}


@router.get("/api/processes/{process_id}/audit")
def process_audit(process_id: int, db: Session = Depends(get_db)):
    process = _load_process(db, process_id)
    return _audit_table(db, process)


@router.get("/api/audit/fields")
def field_audit(db: Session = Depends(get_db)):
    rows = (
        db.query(FieldAudit, ScreenHit, ScreenDefinition)
        .join(ScreenHit, ScreenHit.id == FieldAudit.hit_id)
        .join(ScreenDefinition, ScreenDefinition.id == ScreenHit.screen_id)
        .order_by(FieldAudit.id.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "screen": screen.name,
            "field": audit.label,
            "name": audit.name,
            "action": audit.action,
            "value": audit.value,
            "source": hit.source,
            "recorded_by": hit.created_by,
            "when": hit.created_at.isoformat(),
        }
        for audit, hit, screen in rows
    ]


def _audit_table(db: Session, process: BusinessProcess) -> dict:
    columns = ["When", "Recorded by"]
    keys = []
    used = set()
    for step in process.steps:
        for field in step.screen.fields:
            header = field.label
            if header in used:
                header = f"{step.screen.name} / {field.label}"
            used.add(header)
            columns.append(header)
            keys.append((step.screen_id, field.name, header))
    hits = (
        db.query(ScreenHit)
        .options(selectinload(ScreenHit.audits))
        .filter(ScreenHit.process_id == process.id)
        .order_by(ScreenHit.created_at.asc(), ScreenHit.step_position.asc(), ScreenHit.id.asc())
        .all()
    )
    groups: dict[str, list[ScreenHit]] = {}
    for hit in hits:
        groups.setdefault(hit.occurrence_key, []).append(hit)
    rows = []
    for group in groups.values():
        values = {(hit.screen_id, audit.name): audit.value for hit in group for audit in hit.audits}
        first = group[0]
        row = {"When": first.created_at.isoformat(), "Recorded by": first.created_by}
        for screen_id, name, header in keys:
            row[header] = values.get((screen_id, name), "")
        rows.append(row)
    return {"process": process.name, "columns": columns, "rows": rows}
