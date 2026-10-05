from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from app.auth import current_user, writer
from sqlalchemy.orm import Session

from app.models import Alert, AlertPolicy, AlertRoute, Case, User, utcnow
import app.alert_policy  # Registers suppression and in-app routing.
from app.routers.cases import _case_or_404, get_db, log_activity
from app.schemas import AlertCreate, AlertOut, AlertUpdate

router = APIRouter(prefix="/api/alerts", tags=["alerts"], dependencies=[Depends(current_user)])


def _alert_or_404(db: Session, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


def _raise_case_score(case: Case, score: int) -> None:
    if score > case.score:
        case.score = score
    case.updated_at = utcnow()


@router.get("", response_model=list[AlertOut])
def list_alerts(
    case_id: int | None = None,
    status: str | None = None,
    min_score: int | None = Query(default=None, ge=0, le=1000),
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if case_id is not None:
        query = query.filter(Alert.case_id == case_id)
    if status:
        query = query.filter(Alert.status == status)
    if min_score is not None:
        query = query.filter(Alert.score >= min_score)
    rows = query.order_by(Alert.score.desc(), Alert.id.desc()).all()
    return [AlertOut.model_validate(row, from_attributes=True) for row in rows]


class PolicyIn(BaseModel):
    kind: str
    entity_ref: str = Field(default="", max_length=120)
    title: str = Field(default="", max_length=200)
    channel: str = Field(default="", max_length=80)

    @field_validator("kind")
    @classmethod
    def known_kind(cls, value: str) -> str:
        if value not in ("suppress", "whitelist"):
            raise ValueError("Choose suppress or whitelist")
        return value


class RouteIn(BaseModel):
    channel: str = Field(default="", max_length=80)
    min_score: int = Field(default=0, ge=0, le=1000)
    assignee: str = Field(min_length=1, max_length=120)
    delivery: str = Field(default="app", max_length=20)

    @field_validator("delivery")
    @classmethod
    def known_delivery(cls, value: str) -> str:
        if value not in ("app", "email", "sms", "mq"):
            raise ValueError("Choose app, email, sms, or mq")
        return value


def _policy_out(row: AlertPolicy) -> dict:
    return {"id": row.id, "kind": row.kind, "entity_ref": row.entity_ref, "title": row.title, "channel": row.channel, "enabled": row.enabled}


@router.get("/policies")
def list_policies(db: Session = Depends(get_db)):
    return [_policy_out(row) for row in db.query(AlertPolicy).order_by(AlertPolicy.id.desc()).limit(50)]


@router.post("/policies", status_code=201)
def create_policy(payload: PolicyIn, db: Session = Depends(get_db), user: User = Depends(writer)):
    del user
    if payload.kind == "whitelist" and not payload.entity_ref.strip():
        raise HTTPException(422, "A whitelist names an entity")
    if payload.kind == "suppress" and not (payload.entity_ref.strip() or payload.title.strip() or payload.channel.strip()):
        raise HTTPException(422, "A suppression rule names an entity, title, or channel")
    if db.query(AlertPolicy).count() >= 50:
        raise HTTPException(422, "Suppression rules are limited to 50")
    row = AlertPolicy(kind=payload.kind, entity_ref=payload.entity_ref.strip(), title=payload.title.strip(), channel=payload.channel.strip())
    db.add(row)
    db.commit()
    db.refresh(row)
    return _policy_out(row)


@router.delete("/policies/{policy_id}", status_code=204)
def delete_policy(policy_id: int, db: Session = Depends(get_db), user: User = Depends(writer)):
    del user
    row = db.get(AlertPolicy, policy_id)
    if row is None:
        raise HTTPException(404, "Suppression rule not found")
    db.delete(row)
    db.commit()


@router.get("/routes")
def list_routes(db: Session = Depends(get_db)):
    return [{"id": row.id, "channel": row.channel, "min_score": row.min_score, "assignee": row.assignee, "delivery": row.delivery, "enabled": row.enabled} for row in db.query(AlertRoute).order_by(AlertRoute.position, AlertRoute.id).limit(50)]


@router.post("/routes", status_code=201)
def create_route(payload: RouteIn, db: Session = Depends(get_db), user: User = Depends(writer)):
    del user
    if db.query(AlertRoute).count() >= 50:
        raise HTTPException(422, "Alert routes are limited to 50")
    row = AlertRoute(channel=payload.channel.strip(), min_score=payload.min_score, assignee=payload.assignee.strip(), delivery=payload.delivery, position=db.query(AlertRoute).count())
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "assignee": row.assignee}


@router.get("/groups")
def alert_groups(db: Session = Depends(get_db)):
    buckets: dict[str, list] = {}
    for row in db.query(Alert).filter(Alert.status.in_(("open", "linked"))).order_by(Alert.id).limit(500):
        if not row.entity_ref:
            continue
        buckets.setdefault(row.entity_ref, []).append({"id": row.id, "title": row.title, "status": row.status, "channel": row.channel, "score": row.score})
    return [{"entity_ref": entity, "alerts": items} for entity, items in buckets.items() if len(items) >= 2]


@router.post("", response_model=AlertOut, status_code=201)
def create_alert(payload: AlertCreate, db: Session = Depends(get_db), user: User = Depends(writer)):
    case = None
    status = "open"
    if payload.case_id is not None:
        case = _case_or_404(db, payload.case_id)
        status = "linked"
    alert = Alert(
        title=payload.title.strip(),
        description=payload.description.strip(),
        score=payload.score,
        status=status,
        entity_type=payload.entity_type,
        entity_ref=payload.entity_ref.strip(),
        channel=payload.channel.strip(),
        case_id=case.id if case else None,
    )
    db.add(alert)
    if case is not None:
        _raise_case_score(case, alert.score)
        log_activity(
            db,
            case,
            "alert_linked",
            f"Alert linked: {alert.title}",
            user.username,
        )
    db.commit()
    db.refresh(alert)
    return AlertOut.model_validate(alert, from_attributes=True)


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db), user: User = Depends(writer)):
    alert = _alert_or_404(db, alert_id)
    data = payload.model_dump(exclude_unset=True)
    actor = user.username

    if payload.status == "dismissed":
        previous_case_id = alert.case_id
        alert.status = "dismissed"
        alert.case_id = None
        if previous_case_id is not None:
            case = db.get(Case, previous_case_id)
            if case is not None:
                log_activity(db, case, "alert_unlinked", f"Alert dismissed: {alert.title}", actor)
    elif payload.clear_case:
        if alert.status == "dismissed":
            raise HTTPException(status_code=409, detail="Dismissed alerts stay closed until reopened")
        previous_case_id = alert.case_id
        alert.case_id = None
        if alert.status == "linked":
            alert.status = "open"
        if previous_case_id is not None:
            case = db.get(Case, previous_case_id)
            if case is not None:
                log_activity(db, case, "alert_unlinked", f"Alert removed: {alert.title}", actor)
    elif "case_id" in data and payload.case_id is not None:
        if alert.status == "dismissed":
            raise HTTPException(
                status_code=409,
                detail="Dismissed alerts must be reopened before they can be linked",
            )
        case = _case_or_404(db, payload.case_id)
        previous_case_id = alert.case_id
        alert.case_id = case.id
        alert.status = "linked"
        _raise_case_score(case, alert.score)
        log_activity(db, case, "alert_linked", f"Alert linked: {alert.title}", actor)
        if previous_case_id and previous_case_id != case.id:
            previous = db.get(Case, previous_case_id)
            if previous is not None:
                log_activity(db, previous, "alert_unlinked", f"Alert moved: {alert.title}", actor)

    for field in ("title", "description", "score", "entity_type", "entity_ref", "channel"):
        if field not in data:
            continue
        value = data[field]
        if isinstance(value, str):
            value = value.strip()
        setattr(alert, field, value)

    if payload.status == "open" and alert.status == "dismissed":
        alert.status = "open"
        alert.case_id = None

    if alert.case_id is not None and alert.score:
        case = db.get(Case, alert.case_id)
        if case is not None and alert.score > case.score:
            _raise_case_score(case, alert.score)

    db.commit()
    db.refresh(alert)
    return AlertOut.model_validate(alert, from_attributes=True)
