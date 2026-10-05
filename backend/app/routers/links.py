from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.auth import current_user, writer
from app.constants import ENTITY_TYPES
from app.models import Alert, Case, EntityMark, User

router = APIRouter(prefix="/api/links", tags=["links"], dependencies=[Depends(current_user)])


def get_db(request: Request):
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _day_bound(value: str | None, end: bool) -> datetime | None:
    if not value:
        return None
    try:
        day = datetime.fromisoformat(value).date()
    except ValueError:
        raise HTTPException(status_code=422, detail="Use a YYYY-MM-DD date")
    if end:
        return datetime(day.year, day.month, day.day, 23, 59, 59, tzinfo=timezone.utc)
    return datetime(day.year, day.month, day.day, tzinfo=timezone.utc)


class MarkRequest(BaseModel):
    entity_type: str
    entity_ref: str = Field(min_length=1, max_length=120)
    fraudulent: bool

    @field_validator("entity_type")
    @classmethod
    def known_entity(cls, value: str) -> str:
        if value not in ENTITY_TYPES:
            raise ValueError("Unknown entity type")
        return value

    @field_validator("entity_ref")
    @classmethod
    def ref_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("Entity reference is required")
        return text


@router.get("")
def link_graph(
    anchor_type: str | None = None,
    anchor_ref: str | None = None,
    depth: int = 2,
    start: str | None = None,
    end: str | None = None,
    db: Session = Depends(get_db),
):
    if depth < 1 or depth > 3:
        raise HTTPException(status_code=422, detail="Depth must be 1, 2, or 3")
    if anchor_type and anchor_type not in ENTITY_TYPES:
        raise HTTPException(status_code=422, detail="Unknown entity type")
    start_at = _day_bound(start, end=False)
    end_at = _day_bound(end, end=True)
    alerts = [row for row in db.query(Alert).all() if row.entity_ref.strip()]
    if start_at or end_at:
        kept = []
        for row in alerts:
            when = _as_utc(row.created_at)
            if start_at and when < start_at:
                continue
            if end_at and when > end_at:
                continue
            kept.append(row)
        alerts = kept

    cases = {row.id: row for row in db.query(Case).all()}
    marks = {
        (row.entity_type, row.entity_ref): row.fraudulent
        for row in db.query(EntityMark).all()
    }
    entity_cases: dict[tuple[str, str], set[int]] = {}
    case_entities: dict[int, set[tuple[str, str]]] = {}
    for alert in alerts:
        key = (alert.entity_type, alert.entity_ref.strip())
        entity_cases.setdefault(key, set())
        if alert.case_id and alert.case_id in cases:
            entity_cases[key].add(alert.case_id)
            case_entities.setdefault(alert.case_id, set()).add(key)

    anchor = None
    if anchor_ref and anchor_ref.strip():
        ref = anchor_ref.strip()
        matches = [key for key in entity_cases if key[1] == ref and (not anchor_type or key[0] == anchor_type)]
        if not matches:
            return {"nodes": [], "edges": [], "truncated": False}
        if len(matches) > 1:
            raise HTTPException(status_code=422, detail="That reference is used by more than one entity type")
        anchor = matches[0]

    if anchor is None:
        visible_entities = set(entity_cases)
        visible_cases = set(case_entities)
    else:
        visible_entities = {anchor}
        visible_cases: set[int] = set()
        frontier_entities = {anchor}
        frontier_cases: set[int] = set()
        for level in range(1, depth + 1):
            if level % 2 == 1:
                frontier_cases = set()
                for key in frontier_entities:
                    frontier_cases |= entity_cases.get(key, set())
                frontier_cases -= visible_cases
                visible_cases |= frontier_cases
            else:
                frontier_entities = set()
                for case_id in frontier_cases:
                    frontier_entities |= case_entities.get(case_id, set())
                frontier_entities -= visible_entities
                visible_entities |= frontier_entities

    nodes = []
    for key in sorted(visible_entities):
        entity_type, entity_ref = key
        related = [cases[case_id] for case_id in entity_cases.get(key, set()) if case_id in cases]
        nodes.append(
            {
                "id": f"entity:{entity_type}:{entity_ref}",
                "kind": "entity",
                "label": entity_ref,
                "entity_type": entity_type,
                "entity_ref": entity_ref,
                "fraudulent": bool(marks.get(key, False)),
                "investigating": any(case.status != "closed" for case in related),
            }
        )
    for case_id in sorted(visible_cases):
        case = cases[case_id]
        nodes.append(
            {
                "id": f"case:{case.id}",
                "kind": "case",
                "label": case.title,
                "case_id": case.id,
                "status": case.status,
                "risk": case.risk,
                "investigating": case.status != "closed",
            }
        )
    edges = []
    for case_id in sorted(visible_cases):
        for key in sorted(case_entities.get(case_id, set())):
            if key not in visible_entities:
                continue
            entity_type, entity_ref = key
            edges.append({"source": f"entity:{entity_type}:{entity_ref}", "target": f"case:{case_id}"})
    truncated = False
    if len(nodes) > 80:
        keep = {node["id"] for node in nodes[:80]}
        nodes = nodes[:80]
        edges = [edge for edge in edges if edge["source"] in keep and edge["target"] in keep]
        truncated = True
    return {"nodes": nodes, "edges": edges, "truncated": truncated}


@router.put("/marks")
def mark_entity(payload: MarkRequest, db: Session = Depends(get_db), user: User = Depends(writer)):
    row = (
        db.query(EntityMark)
        .filter(EntityMark.entity_type == payload.entity_type, EntityMark.entity_ref == payload.entity_ref)
        .one_or_none()
    )
    if row is None:
        row = EntityMark(entity_type=payload.entity_type, entity_ref=payload.entity_ref)
        db.add(row)
    row.fraudulent = payload.fraudulent
    row.updated_by = user.username
    db.commit()
    return {"entity_type": row.entity_type, "entity_ref": row.entity_ref, "fraudulent": row.fraudulent}
