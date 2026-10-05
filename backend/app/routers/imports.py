"""Bounded, atomic CSV ingestion with deterministic rules and deduplication."""
import json

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile

from app.auth import current_user, get_db, writer
from app.ingest import MAX_BYTES, load_rules, read_csv_events, store_events, store_observations
from app.models import ImportedEvent
from app.observations import email_items, traffic_items

router = APIRouter(prefix="/api/imports", tags=["activity imports"], dependencies=[Depends(current_user)])


@router.post("/csv", status_code=201)
async def import_csv(file: UploadFile, source: str = Form(min_length=1, max_length=80),
                     user=Depends(writer), db=Depends(get_db)):
    source = source.strip()
    if not source:
        raise HTTPException(422, "Source is required")
    events = read_csv_events(await file.read(MAX_BYTES + 1))
    return store_events(db, events, source, user.username)


@router.post("/email", status_code=201)
async def import_email(file: UploadFile, source: str = Form(min_length=1, max_length=80),
                       user=Depends(writer), db=Depends(get_db)):
    source = source.strip()
    if not source:
        raise HTTPException(422, "Source is required")
    return store_observations(db, email_items(await file.read(MAX_BYTES + 1), load_rules(db)), source, user.username)


@router.post("/traffic", status_code=201)
async def import_traffic(file: UploadFile, source: str = Form(min_length=1, max_length=80),
                         user=Depends(writer), db=Depends(get_db)):
    source = source.strip()
    if not source:
        raise HTTPException(422, "Source is required")
    return store_observations(db, traffic_items(await file.read(MAX_BYTES + 1), load_rules(db)), source, user.username)


@router.get("/events")
def recent_events(db=Depends(get_db)):
    rows = db.query(ImportedEvent).order_by(ImportedEvent.imported_at.desc()).limit(100).all()
    return [{"source": row.source, "event": json.loads(row.payload), "imported_by": row.imported_by,
             "imported_at": row.imported_at, "alert_id": row.alert_id} for row in rows]
