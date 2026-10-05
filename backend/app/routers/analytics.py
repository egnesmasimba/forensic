import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.analytics import (
    AGGREGATIONS, COMPARATORS, ENTITY_TYPES, _entity, evaluate_rules,
    remember_fact, rule_options, score_threshold, test_rule,
)
from app.behavior import (
    CHANNELS, MEASURES, PERIODS, indicator_series, refresh_user, store_channel_events, unified_activity,
)
from app.behavior import baseline_settings as load_baseline_settings
from app.auth import current_user, get_db, writer
from app.models import AnalyticRule, BehaviorDeviation, BusinessEntity, Fact, IndicatorDefinition, RiskEvent, RiskSetting
from app.observations import require_timestamp
from sqlalchemy.exc import IntegrityError

router = APIRouter(prefix="/api/analytics", tags=["analytics"], dependencies=[Depends(current_user)])


class EntityUpdate(BaseModel):
    entity_type: str
    entity_ref: str = Field(min_length=1, max_length=120)
    attribute_key: str = Field(min_length=1, max_length=40)
    attribute_value: str = Field(max_length=80)

    @field_validator("entity_type")
    @classmethod
    def known_type(cls, value: str) -> str:
        if value not in ENTITY_TYPES:
            raise ValueError("Choose user, account, customer, or other")
        return value


class FactCreate(BaseModel):
    entity_type: str
    entity_ref: str = Field(min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=40)
    numeric_value: float = 0
    text_value: str = Field(default="", max_length=200)
    occurred_at: str

    @field_validator("entity_type")
    @classmethod
    def known_type(cls, value: str) -> str:
        if value not in ENTITY_TYPES:
            raise ValueError("Choose user, account, customer, or other")
        return value

    @field_validator("occurred_at")
    @classmethod
    def stamped(cls, value: str) -> str:
        return require_timestamp(value)


class RuleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    version: int = Field(ge=1, le=1000000)
    entity_type: str
    fact_name: str = Field(min_length=1, max_length=40)
    aggregation: str
    comparator: str = "gte"
    threshold: float = 0
    score: int = Field(default=70, ge=0, le=1000)
    attribute_key: str = Field(default="", max_length=40)
    attribute_value: str = Field(default="", max_length=80)
    kind: str = "aggregation"
    list_mode: str = "deny"
    list_values: str = Field(default="", max_length=500)
    pattern: str = Field(default="", max_length=80)
    start_hour: int = Field(default=8, ge=0, le=23)
    end_hour: int = Field(default=18, ge=0, le=24)
    steps: str = Field(default="", max_length=200)

    @field_validator("kind")
    @classmethod
    def known_kind(cls, value: str) -> str:
        allowed = {"aggregation", "what", "how", "when", "where", "time_correlation", "data_correlation", "process"}
        if value not in allowed:
            raise ValueError("Unknown rule type")
        return value

    @field_validator("list_mode")
    @classmethod
    def known_list(cls, value: str) -> str:
        if value not in {"deny", "allow"}:
            raise ValueError("Choose deny or allow")
        return value

    @field_validator("entity_type")
    @classmethod
    def known_type(cls, value: str) -> str:
        if value not in ENTITY_TYPES:
            raise ValueError("Choose user, account, customer, or other")
        return value

    @field_validator("aggregation")
    @classmethod
    def known_aggregation(cls, value: str) -> str:
        if value not in AGGREGATIONS:
            raise ValueError("Choose sum, count, min, or max")
        return value

    @field_validator("comparator")
    @classmethod
    def known_comparator(cls, value: str) -> str:
        if value not in COMPARATORS:
            raise ValueError("Choose gte or lte")
        return value


def _options(body: RuleCreate) -> str:
    return json.dumps({
        "kind": body.kind, "list_mode": body.list_mode, "list_values": body.list_values.strip(),
        "pattern": body.pattern.strip(), "start_hour": body.start_hour, "end_hour": body.end_hour,
        "steps": body.steps.strip(),
    })


def _rule_out(row: AnalyticRule) -> dict:
    options = rule_options(row)
    return {
        "id": row.id, "name": row.name, "version": row.version, "enabled": row.enabled,
        "entity_type": row.entity_type, "fact_name": row.fact_name, "aggregation": row.aggregation,
        "comparator": row.comparator, "threshold": row.threshold, "score": row.score,
        "attribute_key": row.attribute_key, "attribute_value": row.attribute_value,
        "kind": options.get("kind", "aggregation"), "options": options,
    }


@router.get("/entities")
def list_entities(db=Depends(get_db)):
    rows = db.query(BusinessEntity).order_by(BusinessEntity.entity_type, BusinessEntity.entity_ref).limit(100).all()
    return [{
        "id": row.id, "entity_type": row.entity_type, "entity_ref": row.entity_ref,
        "static_info": json.loads(row.static_info or "{}"),
        "dynamic_info": json.loads(row.dynamic_info or "{}"),
    } for row in rows]


@router.put("/entities")
def update_entity(body: EntityUpdate, user=Depends(writer), db=Depends(get_db)):
    row = _entity(db, body.entity_type, body.entity_ref.strip())
    static = json.loads(row.static_info or "{}")
    static[body.attribute_key.strip()] = body.attribute_value.strip()
    row.static_info = json.dumps(static)
    db.commit()
    return {"entity_type": row.entity_type, "entity_ref": row.entity_ref, "static_info": static}


@router.post("/facts", status_code=201)
def create_fact(body: FactCreate, user=Depends(writer), db=Depends(get_db)):
    remember_fact(
        db, source_key=f"manual:{body.entity_type}:{body.entity_ref}:{body.name}:{body.occurred_at}",
        source="manual", occurred_at=body.occurred_at, entity_type=body.entity_type,
        entity_ref=body.entity_ref.strip(), name=body.name.strip(), numeric_value=body.numeric_value,
        text_value=body.text_value.strip(),
    )
    ids = evaluate_rules(db, {(body.entity_type, body.entity_ref.strip())})
    if body.entity_type == "user":
        from app.behavior import _stamp
        from app.profiles import record_profile
        ids.extend(refresh_user(db, body.entity_ref.strip()))
        moment = _stamp(body.occurred_at)
        if moment is not None:
            ids.extend(record_profile(db, body.entity_ref.strip(), moment))
    db.commit()
    return {"alerts_created": len(ids)}


@router.get("/rules")
def list_rules(db=Depends(get_db)):
    rows = db.query(AnalyticRule).order_by(AnalyticRule.name, AnalyticRule.version).all()
    return [_rule_out(row) for row in rows]


@router.post("/rules", status_code=201)
def create_rule(body: RuleCreate, user=Depends(writer), db=Depends(get_db)):
    row = AnalyticRule(
        name=body.name.strip(), version=body.version, entity_type=body.entity_type, fact_name=body.fact_name.strip(),
        aggregation=body.aggregation, comparator=body.comparator, threshold=body.threshold, score=body.score,
        attribute_key=body.attribute_key.strip(), attribute_value=body.attribute_value.strip(),
        options=_options(body), created_by=user.username,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "That rule name and version already exists")
    db.refresh(row)
    return _rule_out(row)


@router.post("/rules/test")
def preview_rule(body: RuleCreate, user=Depends(writer), db=Depends(get_db)):
    draft = AnalyticRule(
        name=body.name.strip(), version=body.version, entity_type=body.entity_type, fact_name=body.fact_name.strip(),
        aggregation=body.aggregation, comparator=body.comparator, threshold=body.threshold, score=body.score,
        attribute_key=body.attribute_key.strip(), attribute_value=body.attribute_value.strip(), options=_options(body),
    )
    return {"matches": test_rule(db, draft)}


@router.get("/scores")
def scores(db=Depends(get_db)):
    rows = db.query(RiskEvent).order_by(RiskEvent.id.desc()).limit(50).all()
    latest = {}
    history = []
    for row in rows:
        history.append({
            "entity_type": row.entity_type, "entity_ref": row.entity_ref, "score": row.score,
            "delta": row.delta, "reason": row.reason, "created_at": row.created_at.isoformat(),
        })
        latest.setdefault((row.entity_type, row.entity_ref), row.score)
    return {
        "threshold": score_threshold(db),
        "current": [{"entity_type": key[0], "entity_ref": key[1], "score": value} for key, value in latest.items()],
        "history": history,
    }


class ThresholdUpdate(BaseModel):
    threshold: int = Field(ge=1, le=10000)


@router.put("/score-threshold")
def update_threshold(body: ThresholdUpdate, user=Depends(writer), db=Depends(get_db)):
    row = db.get(RiskSetting, 1)
    if row is None:
        row = RiskSetting(id=1, threshold=body.threshold)
        db.add(row)
    else:
        row.threshold = body.threshold
    db.commit()
    return {"threshold": row.threshold}


def _as_of(value: str):
    from datetime import datetime, timezone

    from app.behavior import _stamp

    if not value:
        return datetime.now(timezone.utc)
    checked = require_timestamp(value)
    parsed = _stamp(checked)
    if parsed is None:
        raise HTTPException(422, "occurred_at must be a timestamp")
    return parsed


class IndicatorCreate(BaseModel):
    key: str = Field(min_length=3, max_length=40, pattern=r"^[a-z0-9_]+$")
    label: str = Field(min_length=3, max_length=160)
    fact_name: str = Field(min_length=1, max_length=40)
    measure: str
    period: str
    window_days: int = Field(default=90, ge=7, le=366)

    @field_validator("measure")
    @classmethod
    def known_measure(cls, value: str) -> str:
        if value not in MEASURES:
            raise ValueError("Choose distinct, count, sum, or revert")
        return value

    @field_validator("period")
    @classmethod
    def known_period(cls, value: str) -> str:
        if value not in PERIODS:
            raise ValueError("Choose day, week, or month")
        return value


@router.get("/indicators")
def indicators(entity_ref: str, as_of: str = "", db=Depends(get_db)):
    moment = _as_of(as_of)
    rows = db.query(IndicatorDefinition).order_by(IndicatorDefinition.id).all()
    result = []
    for row in rows:
        series = indicator_series(db, row, entity_ref.strip(), moment)
        series.pop("series", None)
        result.append(series)
    return result


@router.post("/indicators", status_code=201)
def create_indicator(body: IndicatorCreate, user=Depends(writer), db=Depends(get_db)):
    if db.query(IndicatorDefinition).filter_by(key=body.key).one_or_none() is not None:
        raise HTTPException(409, "That indicator already exists")
    row = IndicatorDefinition(
        key=body.key, label=body.label.strip(), fact_name=body.fact_name.strip(),
        measure=body.measure, period=body.period, window_days=body.window_days, built_in=False,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"key": row.key, "label": row.label, "fact_name": row.fact_name, "measure": row.measure, "period": row.period}


class BaselineUpdate(BaseModel):
    sigma: float = Field(ge=0.5, le=10)
    minimum_periods: int = Field(ge=1, le=90)


@router.get("/baselines")
def baselines(entity_ref: str, as_of: str = "", db=Depends(get_db)):
    from app.behavior import _baseline_row

    moment = _as_of(as_of)
    settings = load_baseline_settings(db)
    rows = []
    for definition in db.query(IndicatorDefinition).order_by(IndicatorDefinition.id).all():
        series = indicator_series(db, definition, entity_ref.strip(), moment)
        rows.append(_baseline_row(series, settings.sigma, settings.minimum_periods))
    return {
        "sigma": settings.sigma,
        "minimum_periods": settings.minimum_periods,
        "indicators": rows,
        "recorded": [
            {
                "entity_ref": row.entity_ref, "indicator_key": row.indicator_key, "period_key": row.period_key,
                "latest": row.latest, "mean": row.mean,
            }
            for row in db.query(BehaviorDeviation).filter_by(entity_ref=entity_ref.strip()).order_by(BehaviorDeviation.id.desc()).limit(20)
        ],
    }


@router.put("/baseline-settings")
def update_baseline(body: BaselineUpdate, user=Depends(writer), db=Depends(get_db)):
    row = load_baseline_settings(db)
    row.sigma = body.sigma
    row.minimum_periods = body.minimum_periods
    db.commit()
    return {"sigma": row.sigma, "minimum_periods": row.minimum_periods}


class RefreshBody(BaseModel):
    entity_ref: str = Field(default="", max_length=120)
    as_of: str = ""


@router.post("/baselines/refresh", status_code=201)
def refresh_baselines(body: RefreshBody, user=Depends(writer), db=Depends(get_db)):
    moment = _as_of(body.as_of)
    refs = [body.entity_ref.strip()] if body.entity_ref.strip() else [
        row[0] for row in db.query(Fact.entity_ref).filter(Fact.entity_type == "user").distinct().all()
    ]
    ids = []
    for ref in refs:
        if ref:
            ids.extend(refresh_user(db, ref, moment))
    db.commit()
    return {"alerts_created": len(ids), "alert_ids": ids}


class ChannelEventIn(BaseModel):
    source_key: str = Field(min_length=1, max_length=200)
    channel: str
    user: str = Field(min_length=1, max_length=120)
    occurred_at: str
    action: str = Field(default="", max_length=40)
    reference: str = Field(default="", max_length=120)

    @field_validator("channel")
    @classmethod
    def known_channel(cls, value: str) -> str:
        if value not in CHANNELS:
            raise ValueError("Choose phone, email, chat, or system")
        return value

    @field_validator("occurred_at")
    @classmethod
    def known_time(cls, value: str) -> str:
        return require_timestamp(value)


class ChannelBatch(BaseModel):
    events: list[ChannelEventIn] = Field(min_length=1, max_length=100)


@router.post("/channels", status_code=201)
def create_channels(body: ChannelBatch, user=Depends(writer), db=Depends(get_db)):
    stored = store_channel_events(db, [event.model_dump() for event in body.events])
    db.commit()
    return {"stored": stored}


@router.get("/channels")
def list_channels(user: str, db=Depends(get_db)):
    return unified_activity(db, user.strip())


@router.post("/evaluate", status_code=201)
def evaluate(user=Depends(writer), db=Depends(get_db)):
    ids = evaluate_rules(db, None)
    db.commit()
    count = db.query(Fact).count()
    return {"facts": count, "alerts_created": len(ids), "alert_ids": ids}
