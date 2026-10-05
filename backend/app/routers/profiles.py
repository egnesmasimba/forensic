from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.auth import current_user, get_db, writer
from app.behavior import _stamp
from app.models import LibraryRule, Prediction, SyntheticProfile
from app.observations import require_timestamp
from app.profiles import (
    build_twin, group_profile, peers, record_profile, review_user, time_use, update_library,
)

router = APIRouter(prefix="/api/profiles", tags=["profiles"], dependencies=[Depends(current_user)])


def _moment(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    parsed = _stamp(require_timestamp(value))
    if parsed is None:
        raise HTTPException(422, "occurred_at must be a timestamp")
    return parsed


class RefreshBody(BaseModel):
    entity_ref: str = Field(min_length=1, max_length=120)
    as_of: str = ""


@router.get("/review")
def review(entity_ref: str, as_of: str = "", db=Depends(get_db)):
    return review_user(db, entity_ref.strip(), _moment(as_of))


@router.post("/refresh", status_code=201)
def refresh(body: RefreshBody, user=Depends(writer), db=Depends(get_db)):
    ids = record_profile(db, body.entity_ref.strip(), _moment(body.as_of))
    db.commit()
    return {"alerts_created": len(ids), "alert_ids": ids}


@router.get("/predictions")
def predictions(entity_ref: str = "", db=Depends(get_db)):
    query = db.query(Prediction).order_by(Prediction.id.desc())
    if entity_ref:
        query = query.filter_by(entity_ref=entity_ref.strip())
    rows = query.limit(50).all()
    return [{
        "id": row.id, "entity_ref": row.entity_ref, "kind": row.kind, "score": row.score,
        "detail": row.detail, "period_key": row.period_key, "outcome": row.outcome,
    } for row in rows]


@router.get("/predictions/accuracy")
def accuracy(db=Depends(get_db)):
    rows = db.query(Prediction).all()
    confirmed = sum(1 for row in rows if row.outcome == "confirmed")
    dismissed = sum(1 for row in rows if row.outcome == "dismissed")
    decided = confirmed + dismissed
    return {
        "confirmed": confirmed, "dismissed": dismissed, "open": sum(1 for row in rows if not row.outcome),
        "rate": confirmed / decided if decided else 0.0,
    }


class OutcomeBody(BaseModel):
    outcome: str

    @field_validator("outcome")
    @classmethod
    def known(cls, value: str) -> str:
        if value not in {"confirmed", "dismissed"}:
            raise ValueError("Choose confirmed or dismissed")
        return value


@router.post("/predictions/{prediction_id}/outcome")
def set_outcome(prediction_id: int, body: OutcomeBody, user=Depends(writer), db=Depends(get_db)):
    row = db.get(Prediction, prediction_id)
    if row is None:
        raise HTTPException(404, "Prediction not found")
    row.outcome = body.outcome
    db.commit()
    return {"id": row.id, "outcome": row.outcome}


@router.get("/time")
def time_report(entity_ref: str, as_of: str = "", db=Depends(get_db)):
    return time_use(db, entity_ref.strip(), _moment(as_of))


class TwinBody(BaseModel):
    entity_ref: str = Field(min_length=1, max_length=120)
    as_of: str = ""


@router.post("/synthetic", status_code=201)
def synthetic(body: TwinBody, user=Depends(writer), db=Depends(get_db)):
    result = build_twin(db, body.entity_ref.strip(), _moment(body.as_of))
    db.commit()
    return result


@router.get("/synthetic/{token}")
def read_synthetic(token: str, db=Depends(get_db)):
    row = db.query(SyntheticProfile).filter_by(token=token).one_or_none()
    if row is None:
        raise HTTPException(404, "Synthetic profile not found")
    import json
    return {"token": row.token, "indicators": json.loads(row.payload).get("indicators", [])}


@router.get("/peers")
def peer_report(entity_ref: str, as_of: str = "", db=Depends(get_db)):
    return peers(db, entity_ref.strip(), _moment(as_of))


@router.get("/groups")
def groups(entity_type: str, group: str, as_of: str = "", db=Depends(get_db)):
    if entity_type not in {"user", "account", "customer", "other"}:
        raise HTTPException(422, "Choose user, account, customer, or other")
    return group_profile(db, entity_type, group.strip(), _moment(as_of))


@router.get("/library")
def library(db=Depends(get_db)):
    rows = db.query(LibraryRule).order_by(LibraryRule.framework, LibraryRule.key).all()
    return [{
        "key": row.key, "framework": row.framework, "name": row.name, "fact_name": row.fact_name,
        "measure": row.measure, "threshold": row.threshold, "score": row.score,
        "enabled": row.enabled, "customized": row.customized, "window_days": row.window_days, "catalog_version": row.catalog_version, "origin": "first-party" if row.framework == "local" else "illustrative framework mapping",
    } for row in rows]


@router.post("/library/update")
def library_update(user=Depends(writer), db=Depends(get_db)):
    return {"added": update_library(db)}


class LibraryUpdate(BaseModel):
    enabled: bool
    threshold: float = Field(ge=0, le=100000000)
    score: int = Field(ge=0, le=1000)


@router.put("/library/{key}")
def customize_library(key: str, body: LibraryUpdate, user=Depends(writer), db=Depends(get_db)):
    row = db.query(LibraryRule).filter_by(key=key).one_or_none()
    if row is None:
        raise HTTPException(404, "Library rule not found")
    row.customized = row.customized or row.threshold != body.threshold or row.score != body.score
    row.enabled = body.enabled
    row.threshold = body.threshold
    row.score = body.score
    db.commit()
    return {"key": row.key, "enabled": row.enabled, "threshold": row.threshold, "customized": row.customized}


@router.post("/library/evaluate", status_code=201)
def library_evaluate(body: RefreshBody, user=Depends(writer), db=Depends(get_db)):
    from app.profiles import evaluate_library
    ids = evaluate_library(db, body.entity_ref.strip(), _moment(body.as_of))
    db.commit()
    return {"alerts_created": len(ids), "alert_ids": ids}

class AggregateRequest(BaseModel):
    subjects: list[str] = Field(min_length=5, max_length=200)

    @field_validator('subjects')
    @classmethod
    def valid_subjects(cls, values):
        if any(not value.strip() or len(value) > 120 for value in values): raise ValueError('Provide bounded subject references')
        return [value.strip() for value in values]


@router.post('/synthetic-aggregate')
def synthetic_aggregate(body: AggregateRequest, user=Depends(writer), db=Depends(get_db)):
    from app.synthetic_analytics import release
    from sqlalchemy.exc import IntegrityError
    try:
        result=release(db,body.subjects); db.commit()
    except IntegrityError:
        db.rollback(); raise HTTPException(409,'Concurrent aggregate release; retry to retrieve the cached result')
    return result
