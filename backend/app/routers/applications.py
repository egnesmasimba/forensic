from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from app.auth import administrator, current_user, get_db
from app.applications import LIMIT
from app.models import ApplicationRule

router = APIRouter(prefix="/api/applications", tags=["applications"], dependencies=[Depends(current_user)])


class RuleInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    field: Literal["process", "window"]
    pattern: str = Field(min_length=2, max_length=80)
    score: int = Field(default=40, ge=1, le=100)

    def stored_pattern(self):
        return " ".join(self.pattern.casefold().split())


def payload(row):
    return {"id": row.id, "name": row.name, "field": row.field, "pattern": row.pattern, "score": row.score, "enabled": row.enabled}


@router.get("/rules")
def list_rules(db=Depends(get_db)):
    return [payload(row) for row in db.query(ApplicationRule).order_by(ApplicationRule.id).all()]


@router.post("/rules", status_code=201)
def create_rule(body: RuleInput, user=Depends(administrator), db=Depends(get_db)):
    if db.query(ApplicationRule).count() >= LIMIT:
        raise HTTPException(422, f"At most {LIMIT} application rules")
    pattern = body.stored_pattern()
    if len(pattern) < 2:
        raise HTTPException(422, "Pattern must contain at least two letters or digits")
    row = ApplicationRule(name=body.name.strip(), field=body.field, pattern=pattern, score=body.score, created_by=user.username)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "That process or window pattern is already defined")
    db.refresh(row)
    return payload(row)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, user=Depends(administrator), db=Depends(get_db)):
    row = db.get(ApplicationRule, rule_id)
    if row is None:
        raise HTTPException(404, "Application rule not found")
    db.delete(row)
    db.commit()
