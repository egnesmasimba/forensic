from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.auth import current_user, get_db, writer
from app.models import Attachment, OcrReading, utcnow
from app.ocr import IMAGE_TYPES, LANGUAGES, recognize
from app.routers.attachments import _stored_path
from app.screens import note_image_reading
from app.search_models import SearchDocument

router = APIRouter(prefix="/api/ocr", tags=["ocr"], dependencies=[Depends(current_user)])


def readings_for(db: Session, attachment_ids: list[int]) -> dict[int, OcrReading]:
    if not attachment_ids:
        return {}
    rows = db.query(OcrReading).filter(OcrReading.attachment_id.in_(attachment_ids)).all()
    return {row.attachment_id: row for row in rows}


def _snippet(text: str, term: str) -> str:
    lowered = text.lower()
    at = lowered.find(term.lower())
    if at < 0:
        return text[:180]
    start = max(0, at - 40)
    return text[start:at + len(term) + 80]


@router.get("/languages")
def languages():
    return [{"code": code, "label": label} for code, label in LANGUAGES.items()]


@router.post("/attachments/{attachment_id}", status_code=201)
def read_attachment(
    attachment_id: int,
    request: Request,
    language: str = Query(default="eng"),
    user=Depends(writer),
    db: Session = Depends(get_db),
):
    row = db.get(Attachment, attachment_id)
    if row is None:
        raise HTTPException(404, "Attachment not found")
    if row.content_type not in IMAGE_TYPES:
        raise HTTPException(422, "OCR reads PNG and JPEG images attached to a case")
    path = _stored_path(Path(request.app.state.attachment_dir), row.stored_name)
    if not path.is_file():
        raise HTTPException(404, "Attachment not found")
    text, confidence = recognize(str(path), language)
    reading = db.query(OcrReading).filter_by(attachment_id=row.id).one_or_none()
    if reading is None:
        reading = OcrReading(attachment_id=row.id)
        db.add(reading)
    reading.language = language
    reading.engine = "tesseract"
    reading.text = text
    reading.confidence = confidence
    reading.created_by = user.username
    reading.created_at = utcnow()
    source_key = f"ocr:{row.id}"
    document = db.query(SearchDocument).filter_by(source_key=source_key).one_or_none()
    if document is None:
        document = SearchDocument(
            source_key=source_key,
            source_kind="ocr",
            source_id=str(row.id),
            platform="evidence",
            occurred_at=reading.created_at,
            title=row.original_name[:200],
            body=text,
            created_by=user.username,
        )
        db.add(document)
    else:
        document.title = row.original_name[:200]
        document.body = text
        document.occurred_at = reading.created_at
        document.updated_at = utcnow()
    note_image_reading(db, text, user.username, row.id)
    db.commit()
    db.refresh(reading)
    return {
        "attachment_id": row.id,
        "case_id": row.case_id,
        "filename": row.original_name,
        "language": reading.language,
        "engine": reading.engine,
        "text": reading.text,
        "confidence": reading.confidence,
    }


@router.get("/search")
def search_readings(q: str = Query(min_length=2, max_length=80), db: Session = Depends(get_db)):
    term = q.strip()
    if len(term) < 2:
        raise HTTPException(422, "Enter at least two characters")
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    rows = (
        db.query(OcrReading, Attachment)
        .join(Attachment, Attachment.id == OcrReading.attachment_id)
        .filter(OcrReading.text.ilike(f"%{escaped}%", escape="\\"))
        .order_by(OcrReading.id.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "attachment_id": attachment.id,
            "case_id": attachment.case_id,
            "filename": attachment.original_name,
            "language": reading.language,
            "engine": reading.engine,
            "confidence": reading.confidence,
            "snippet": _snippet(reading.text, term),
        }
        for reading, attachment in rows
    ]
