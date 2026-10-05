import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError

from app.auth import administrator, current_user, get_db, writer
from app.collect import (
    accept_layout,
    accept_upload,
    enqueue,
    inbox_path,
    read_sqlite_table,
    scan_inbox,
)
from app.ingest import MAX_BYTES, events_from_rows, store_events
from app.models import CollectedArtifact, CollectionSource, EventCorrelation, LayoutDefinition

router = APIRouter(prefix="/api/collectors", tags=["collectors"], dependencies=[Depends(current_user)])


def _root(request: Request) -> Path:
    return request.app.state.collection_dir


class LayoutCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    mode: str
    delimiter: str = ""
    spec: dict

    @field_validator("mode")
    @classmethod
    def known_mode(cls, value: str) -> str:
        if value not in ("fixed", "delimited"):
            raise ValueError("Layout mode must be fixed or delimited")
        return value


class SourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    filename: str = Field(min_length=1, max_length=255)
    table_name: str = Field(min_length=1, max_length=64)
    interval_seconds: int = Field(default=60, ge=15, le=86400)


class QueueBody(BaseModel):
    message: dict


@router.post("/file", status_code=201)
async def collect_file(
    file: UploadFile,
    source: str = Form(min_length=1, max_length=80),
    user=Depends(writer),
    db=Depends(get_db),
):
    raw = await file.read(MAX_BYTES + 1)
    return accept_upload(db, raw, file.filename or "upload", source.strip(), user.username)


@router.post("/table", status_code=201)
async def collect_table(
    request: Request,
    file: UploadFile,
    table: str = Form(min_length=1, max_length=64),
    source: str = Form(min_length=1, max_length=80),
    user=Depends(writer),
    db=Depends(get_db),
):
    raw = await file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, "Database file must be at most 2 MB")
    root = _root(request)
    root.mkdir(parents=True, exist_ok=True)
    name = Path(file.filename or "table.sqlite").name
    if not name.lower().endswith((".sqlite", ".db")):
        raise HTTPException(422, "Upload a .sqlite or .db file")
    target = root / name
    target.write_bytes(raw)
    rows = read_sqlite_table(target, table.strip())
    return store_events(db, events_from_rows(rows), source.strip(), user.username)


@router.post("/layouts", status_code=201)
def create_layout(payload: LayoutCreate, user=Depends(writer), db=Depends(get_db)):
    row = LayoutDefinition(
        name=payload.name.strip(),
        mode=payload.mode,
        delimiter=payload.delimiter[:4],
        spec=json.dumps(payload.spec),
        created_by=user.username,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A layout with that name already exists")
    db.refresh(row)
    return {"id": row.id, "name": row.name, "mode": row.mode}


@router.get("/layouts")
def list_layouts(db=Depends(get_db)):
    rows = db.query(LayoutDefinition).order_by(LayoutDefinition.name).all()
    return [{"id": row.id, "name": row.name, "mode": row.mode, "delimiter": row.delimiter} for row in rows]


@router.post("/layouts/{layout_id}/apply", status_code=201)
async def apply_layout(
    layout_id: int,
    file: UploadFile,
    source: str = Form(min_length=1, max_length=80),
    user=Depends(writer),
    db=Depends(get_db),
):
    layout = db.get(LayoutDefinition, layout_id)
    if layout is None:
        raise HTTPException(404, "Layout not found")
    raw = await file.read(MAX_BYTES + 1)
    return accept_layout(db, raw, file.filename or "layout.txt", layout, source.strip(), user.username)


@router.post("/queue", status_code=201)
def post_queue(payload: QueueBody, user=Depends(writer), db=Depends(get_db)):
    return enqueue(db, payload.message, user.username)


@router.post("/sources", status_code=201)
def create_source(payload: SourceCreate, request: Request, user=Depends(administrator), db=Depends(get_db)):
    del user
    inbox_path(request.app.state.collection_dir, payload.filename)
    row = CollectionSource(
        name=payload.name.strip(),
        kind="sqlite",
        filename=Path(payload.filename).name,
        table_name=payload.table_name.strip(),
        interval_seconds=payload.interval_seconds,
        enabled=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "name": row.name, "interval_seconds": row.interval_seconds}


@router.get("/sources")
def list_sources(db=Depends(get_db)):
    rows = db.query(CollectionSource).order_by(CollectionSource.id).all()
    return [
        {
            "id": row.id,
            "name": row.name,
            "kind": row.kind,
            "filename": row.filename,
            "table_name": row.table_name,
            "interval_seconds": row.interval_seconds,
            "enabled": row.enabled,
            "last_status": row.last_status,
        }
        for row in rows
    ]


@router.post("/run", status_code=200)
def run_collection(request: Request, user=Depends(writer), db=Depends(get_db)):
    return scan_inbox(db, request.app.state.collection_dir, user.username)


@router.get("/artifacts")
def list_artifacts(db=Depends(get_db)):
    rows = db.query(CollectedArtifact).order_by(CollectedArtifact.id.desc()).limit(50).all()
    return [
        {"id": row.id, "filename": row.filename, "kind": row.kind, "size": row.size, "summary": row.summary, "imported_by": row.imported_by}
        for row in rows
    ]


@router.get("/correlations")
def list_correlations(db=Depends(get_db)):
    rows = db.query(EventCorrelation).order_by(EventCorrelation.id.desc()).limit(50).all()
    return [
        {"event_key": row.event_key, "alert_id": row.alert_id, "case_id": row.case_id, "entity_ref": row.entity_ref, "channel": row.channel}
        for row in rows
    ]
