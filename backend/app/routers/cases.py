from fastapi import APIRouter, Depends, HTTPException, Query, Request

import json

from app.auth import current_user, writer
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.constants import STATUS_LABELS, TRANSITIONS
from app.models import Activity, Alert, Attachment, Case, Note, User, utcnow
from app.structure import apply_field_values, choose_route, field_values
from app.schemas import (
    ActivityOut,
    AlertOut,
    AttachmentOut,
    CaseCreate,
    CaseDetail,
    CaseSummary,
    CaseUpdate,
    NoteCreate,
    NoteOut,
    ResponseActionOut,
    TransitionRequest,
)

router = APIRouter(prefix="/api/cases", tags=["cases"], dependencies=[Depends(current_user)])


def get_db(request: Request):
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def _case_or_404(db: Session, case_id: int) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


def _alert_count(db: Session, case_id: int) -> int:
    return db.query(Alert).filter(Alert.case_id == case_id).count()


def _summary(case: Case, alert_count: int) -> CaseSummary:
    return CaseSummary(
        id=case.id,
        title=case.title,
        case_type=case.case_type,
        status=case.status,
        risk=case.risk,
        score=case.score,
        assignee=case.assignee,
        summary=case.summary,
        alert_count=alert_count,
        created_at=case.created_at,
        updated_at=case.updated_at,
    )


def _detail(db: Session, case: Case) -> CaseDetail:
    alerts = (
        db.query(Alert)
        .filter(Alert.case_id == case.id)
        .order_by(Alert.score.desc(), Alert.id.desc())
        .all()
    )
    notes = (
        db.query(Note)
        .filter(Note.case_id == case.id)
        .order_by(Note.created_at.asc(), Note.id.asc())
        .all()
    )
    activities = (
        db.query(Activity)
        .filter(Activity.case_id == case.id)
        .order_by(Activity.created_at.asc(), Activity.id.asc())
        .all()
    )
    attachments = (
        db.query(Attachment)
        .filter(Attachment.case_id == case.id)
        .order_by(Attachment.created_at.asc(), Attachment.id.asc())
        .all()
    )
    # Containment actions belong on the timeline: a case that records the threat
    # but not the response leaves the reader unable to tell what was done to the
    # endpoint, by whom, and whether it worked.
    from app.response_models import ResponseAudit

    response_actions = (
        db.query(ResponseAudit)
        .filter(ResponseAudit.case_id == case.id)
        .order_by(ResponseAudit.occurred_at.asc(), ResponseAudit.id.asc())
        .all()
    )
    from app.routers.ocr import readings_for

    readings = readings_for(db, [row.id for row in attachments])
    attachment_rows = []
    for row in attachments:
        item = AttachmentOut.model_validate(row, from_attributes=True)
        reading = readings.get(row.id)
        if reading is not None:
            item = item.model_copy(update={
                "ocr_text": reading.text,
                "ocr_confidence": reading.confidence,
                "ocr_language": reading.language,
            })
        attachment_rows.append(item)
    summary = _summary(case, len(alerts))
    return CaseDetail(
        **summary.model_dump(),
        conclusion=case.conclusion,
        alerts=[AlertOut.model_validate(row, from_attributes=True) for row in alerts],
        fields=field_values(db, case),
        notes=[NoteOut.model_validate(row, from_attributes=True) for row in notes],
        activities=[ActivityOut.model_validate(row, from_attributes=True) for row in activities],
        attachments=attachment_rows,
        response_actions=[
            ResponseActionOut(
                id=row.id,
                agent_id=row.agent_id,
                command_id=row.command_id,
                action=row.action,
                actor=row.actor,
                detail=json.loads(row.detail),
                occurred_at=row.occurred_at,
            )
            for row in response_actions
        ],
    )


def log_activity(db: Session, case: Case, action: str, detail: str, actor: str) -> None:
    db.add(Activity(case_id=case.id, action=action, detail=detail, actor=actor))
    case.updated_at = utcnow()


def filtered_cases(
    db: Session,
    *,
    status: str | None = None,
    risk: str | None = None,
    min_score: int | None = None,
    q: str | None = None,
    sort: str = "score",
    order: str = "desc",
) -> list[Case]:
    query = db.query(Case)
    if status:
        query = query.filter(Case.status == status)
    if risk:
        query = query.filter(Case.risk == risk)
    if min_score is not None:
        query = query.filter(Case.score >= min_score)
    if q and q.strip():
        term = f"%{q.strip()}%"
        query = query.filter(
            or_(
                Case.title.ilike(term),
                Case.summary.ilike(term),
                Case.assignee.ilike(term),
                Case.case_type.ilike(term),
            )
        )
    sort_column = {"score": Case.score, "updated": Case.updated_at, "created": Case.created_at}[sort]
    if order == "asc":
        query = query.order_by(sort_column.asc(), Case.id.asc())
    else:
        query = query.order_by(sort_column.desc(), Case.id.desc())
    return query.all()


def summaries_for(db: Session, cases: list[Case]) -> list[CaseSummary]:
    if not cases:
        return []
    ids = [case.id for case in cases]
    count_rows = (
        db.query(Alert.case_id, func.count(Alert.id))
        .filter(Alert.case_id.in_(ids))
        .group_by(Alert.case_id)
        .all()
    )
    counts = {case_id: count for case_id, count in count_rows}
    return [_summary(case, counts.get(case.id, 0)) for case in cases]


@router.get("", response_model=list[CaseSummary])
def list_cases(
    status: str | None = None,
    risk: str | None = None,
    min_score: int | None = Query(default=None, ge=0, le=1000),
    q: str | None = None,
    sort: str = Query(default="score", pattern="^(score|updated|created)$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
):
    cases = filtered_cases(
        db,
        status=status,
        risk=risk,
        min_score=min_score,
        q=q,
        sort=sort,
        order=order,
    )
    return summaries_for(db, cases)


@router.post("", response_model=CaseDetail, status_code=201)
def create_case(payload: CaseCreate, db: Session = Depends(get_db), user: User = Depends(writer)):
    case = Case(
        title=payload.title.strip(),
        case_type=payload.case_type,
        risk=payload.risk,
        score=payload.score,
        assignee=payload.assignee.strip(),
        summary=payload.summary.strip(),
        status="new",
    )
    db.add(case)
    db.flush()
    apply_field_values(db, case, payload.fields)
    log_activity(db, case, "opened", "Case opened", user.username)
    if not case.assignee:
        rule = choose_route(db, case.case_type, case.risk)
        if rule is not None:
            case.assignee = rule.assignee
            log_activity(db, case, "routed", f"Routed by {rule.name} to {rule.assignee}", user.username)
    db.commit()
    db.refresh(case)
    return _detail(db, case)


@router.get("/aging")
def aging_cases(days: int = Query(default=7, ge=1, le=365), db: Session = Depends(get_db)):
    from datetime import timedelta
    cutoff = utcnow() - timedelta(days=days)
    rows = db.query(Case).filter(Case.status != "closed", Case.updated_at < cutoff).order_by(Case.updated_at, Case.id).limit(200).all()
    return [{"id": row.id, "title": row.title, "status": row.status, "updated_at": row.updated_at} for row in rows]


@router.get("/{case_id}", response_model=CaseDetail)
def get_case(case_id: int, db: Session = Depends(get_db)):
    return _detail(db, _case_or_404(db, case_id))


@router.patch("/{case_id}", response_model=CaseDetail)
def update_case(case_id: int, payload: CaseUpdate, db: Session = Depends(get_db), user: User = Depends(writer)):
    case = _case_or_404(db, case_id)
    changes = payload.model_dump(exclude_unset=True, exclude={"actor", "fields"})
    supplied_fields = "fields" in payload.model_fields_set
    if not changes and not supplied_fields:
        return _detail(db, case)
    for field, value in changes.items():
        if isinstance(value, str):
            value = value.strip()
        setattr(case, field, value)
    if supplied_fields or "case_type" in changes:
        apply_field_values(db, case, payload.fields or {})
    log_activity(db, case, "updated", "Case details updated", user.username)
    db.commit()
    db.refresh(case)
    return _detail(db, case)


@router.post("/{case_id}/notes", response_model=CaseDetail, status_code=201)
def add_note(case_id: int, payload: NoteCreate, db: Session = Depends(get_db), user: User = Depends(writer)):
    case = _case_or_404(db, case_id)
    db.add(Note(case_id=case.id, author=user.username, body=payload.body.strip()))
    log_activity(db, case, "note_added", "Investigation note added", user.username)
    db.commit()
    db.refresh(case)
    return _detail(db, case)


@router.post("/{case_id}/transition", response_model=CaseDetail)
def transition_case(case_id: int, payload: TransitionRequest, db: Session = Depends(get_db), user: User = Depends(writer)):
    case = _case_or_404(db, case_id)
    allowed = TRANSITIONS.get(case.status, [])
    if payload.status not in allowed:
        current = STATUS_LABELS.get(case.status, case.status)
        target = STATUS_LABELS.get(payload.status, payload.status)
        raise HTTPException(
            status_code=409,
            detail=f"Cannot move a case from {current} to {target}",
        )
    previous = STATUS_LABELS.get(case.status, case.status)
    target = STATUS_LABELS.get(payload.status, payload.status)
    case.status = payload.status
    detail = f"Status changed from {previous} to {target}"
    if payload.note.strip():
        detail = f"{detail}. {payload.note.strip()}"
    log_activity(db, case, "status_changed", detail, user.username)
    db.commit()
    db.refresh(case)
    return _detail(db, case)
