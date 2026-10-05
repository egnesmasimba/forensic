"""Custom case fields and routing rules."""

import re

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.constants import RISK_LEVELS
from app.models import Case, CaseField, CaseFieldValue, RouteRule

FIELD_KEY = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
RISK_RANK = {level: index for index, level in enumerate(RISK_LEVELS)}


def fields_for_type(db: Session, case_type: str) -> list[CaseField]:
    return (
        db.query(CaseField)
        .filter(CaseField.case_type == case_type)
        .order_by(CaseField.position.asc(), CaseField.id.asc())
        .all()
    )


def field_values(db: Session, case: Case) -> list[dict]:
    definitions = fields_for_type(db, case.case_type)
    stored = {
        row.field_id: row.value
        for row in db.query(CaseFieldValue).filter(CaseFieldValue.case_id == case.id)
    }
    return [
        {
            "key": item.key,
            "label": item.label,
            "value": stored.get(item.id, ""),
            "required": item.required,
        }
        for item in definitions
    ]


def apply_field_values(db: Session, case: Case, values: dict[str, str]) -> None:
    definitions = fields_for_type(db, case.case_type)
    known = {item.key: item for item in definitions}
    unknown = sorted(set(values) - set(known))
    if unknown:
        raise HTTPException(status_code=422, detail="Unknown case field: " + ", ".join(unknown))
    existing = {
        row.field_id: row
        for row in db.query(CaseFieldValue).filter(CaseFieldValue.case_id == case.id)
    }
    for key, raw in values.items():
        definition = known[key]
        text = raw.strip()
        if len(text) > 500:
            raise HTTPException(status_code=422, detail=f"{definition.label} is too long")
        row = existing.get(definition.id)
        if text == "":
            if row is not None:
                db.delete(row)
            continue
        if row is None:
            db.add(CaseFieldValue(case_id=case.id, field_id=definition.id, value=text))
        else:
            row.value = text
    db.flush()
    stored = {
        row.field_id: row.value
        for row in db.query(CaseFieldValue).filter(CaseFieldValue.case_id == case.id)
    }
    missing = [item.label for item in definitions if item.required and not stored.get(item.id)]
    if missing:
        raise HTTPException(status_code=422, detail="Required case fields: " + ", ".join(missing))


def choose_route(db: Session, case_type: str, risk: str) -> RouteRule | None:
    rank = RISK_RANK[risk]
    candidates = []
    for rule in db.query(RouteRule).filter(RouteRule.enabled.is_(True)).all():
        if rule.case_type and rule.case_type != case_type:
            continue
        if RISK_RANK.get(rule.min_risk, 0) > rank:
            continue
        candidates.append((1 if rule.case_type else 0, RISK_RANK.get(rule.min_risk, 0), rule.position, rule.id, rule))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], -item[1], item[2], item[3]))
    return candidates[0][4]


def check_field_key(key: str) -> str:
    if not FIELD_KEY.fullmatch(key):
        raise HTTPException(
            status_code=422,
            detail="Field key must start with a letter and use lowercase letters, digits, or underscores",
        )
    return key
