import hashlib
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.auth import current_user, writer
from app.models import Attachment, User
from app.routers.cases import _case_or_404, get_db, log_activity
from app.schemas import AttachmentOut

router = APIRouter(prefix="/api/cases", tags=["attachments"], dependencies=[Depends(current_user)])

ALLOWED = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


def _safe_name(filename: str | None) -> tuple[str, str]:
    raw = (filename or "attachment").replace("\\", "/").rsplit("/", 1)[-1].strip() or "attachment"
    suffix = Path(raw).suffix.lower()
    if suffix not in ALLOWED:
        raise HTTPException(status_code=400, detail="This file type is not allowed")
    return raw[:255], suffix


def _stored_path(root: Path, stored_name: str) -> Path:
    base = root.resolve()
    path = (base / stored_name).resolve()
    if not path.is_relative_to(base):
        raise HTTPException(status_code=404, detail="Attachment not found")
    return path


def _attachment_or_404(db: Session, case_id: int, attachment_id: int) -> Attachment:
    row = db.get(Attachment, attachment_id)
    if row is None or row.case_id != case_id:
        raise HTTPException(status_code=404, detail="Attachment not found")
    return row


@router.post("/{case_id}/attachments", response_model=AttachmentOut, status_code=201)
async def upload_attachment(
    case_id: int,
    request: Request,
    file: UploadFile,
    db: Session = Depends(get_db),
    user: User = Depends(writer),
):
    case = _case_or_404(db, case_id)
    original_name, suffix = _safe_name(file.filename)
    who = user.username
    root = Path(request.app.state.attachment_dir)
    limit = int(request.app.state.max_attachment_bytes)
    folder = root / str(case.id)
    folder.mkdir(parents=True, exist_ok=True)
    stored_name = f"{case.id}/{uuid.uuid4().hex}{suffix}"
    path = _stored_path(root, stored_name)
    size = 0
    digest = hashlib.sha256()
    try:
        with path.open("wb") as handle:
            while chunk := await file.read(64 * 1024):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(status_code=413, detail="File is larger than 10 MB")
                digest.update(chunk)
                handle.write(chunk)
    except HTTPException:
        path.unlink(missing_ok=True)
        raise
    if size == 0:
        path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="File is empty")

    row = Attachment(
        case_id=case.id,
        original_name=original_name,
        stored_name=stored_name,
        content_type=ALLOWED[suffix],
        size=size,
        sha256=digest.hexdigest(),
        uploaded_by=who,
    )
    db.add(row)
    log_activity(db, case, "attachment_added", f"File attached: {original_name}", who)
    db.commit()
    db.refresh(row)
    return AttachmentOut.model_validate(row, from_attributes=True)


@router.get("/{case_id}/attachments/{attachment_id}")
def download_attachment(
    case_id: int,
    attachment_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    row = _attachment_or_404(db, case_id, attachment_id)
    path = _stored_path(Path(request.app.state.attachment_dir), row.stored_name)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Attachment not found")
    return FileResponse(
        path,
        media_type=row.content_type,
        filename=row.original_name,
        content_disposition_type="attachment",
    )


@router.get("/{case_id}/attachments/{attachment_id}/integrity")
def attachment_integrity(case_id: int, attachment_id: int, request: Request, db: Session = Depends(get_db)):
    row = _attachment_or_404(db, case_id, attachment_id)
    path = _stored_path(Path(request.app.state.attachment_dir), row.stored_name)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Attachment not found")
    if not row.sha256:
        return {"sha256": "", "stored_sha256": "", "matches": False, "detail": "No hash was stored for this file"}
    current = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "sha256": current,
        "stored_sha256": row.sha256,
        "matches": current == row.sha256,
        "detail": "File matches the stored hash" if current == row.sha256 else "File does not match the stored hash",
    }


@router.delete("/{case_id}/attachments/{attachment_id}", status_code=204)
def delete_attachment(
    case_id: int,
    attachment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(writer),
):
    case = _case_or_404(db, case_id)
    row = _attachment_or_404(db, case_id, attachment_id)
    path = _stored_path(Path(request.app.state.attachment_dir), row.stored_name)
    path.unlink(missing_ok=True)
    name = row.original_name
    db.delete(row)
    log_activity(db, case, "attachment_removed", f"File removed: {name}", user.username)
    db.commit()
