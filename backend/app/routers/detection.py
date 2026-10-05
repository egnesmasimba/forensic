from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import administrator, get_db
from app.ingest import RULE_DEFAULTS, load_rules
from app.models import DetectionSetting

router = APIRouter(prefix="/api/detection", tags=["detection"], dependencies=[Depends(administrator)])


class SettingUpdate(BaseModel):
    threshold: int = Field(ge=1, le=10**15)
    score: int = Field(ge=0, le=1000)
    enabled: bool


def seed_detection(db):
    stored = {row.rule_id for row in db.query(DetectionSetting).all()}
    for rule_id, (label, threshold, score) in RULE_DEFAULTS.items():
        if rule_id not in stored:
            db.add(DetectionSetting(rule_id=rule_id, label=label, threshold=threshold, score=score, enabled=True))
    db.commit()


@router.get("/settings")
def list_settings(db=Depends(get_db)):
    seed_detection(db)
    rules = load_rules(db)
    return [
        {"rule_id": rule_id, "label": rules[rule_id][3], "threshold": rules[rule_id][1], "score": rules[rule_id][2], "enabled": rules[rule_id][0]}
        for rule_id in RULE_DEFAULTS
    ]


@router.put("/settings/{rule_id}")
def update_setting(rule_id: str, payload: SettingUpdate, db=Depends(get_db)):
    if rule_id not in RULE_DEFAULTS:
        raise HTTPException(404, "Rule not found")
    seed_detection(db)
    row = db.get(DetectionSetting, rule_id)
    row.threshold = payload.threshold
    row.score = payload.score
    row.enabled = payload.enabled
    db.commit()
    return {"rule_id": row.rule_id, "label": row.label, "threshold": row.threshold, "score": row.score, "enabled": row.enabled}
