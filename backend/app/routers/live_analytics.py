from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from app.auth import current_user, writer, get_db
from app.live_analytics import store_stream
from app.indicator_catalog import behavior_catalog, threat_catalog, CATALOG_VERSION

router = APIRouter(prefix='/api/analytics', tags=['live analytics'], dependencies=[Depends(current_user)])


class StreamEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=80)
    entity_type: Literal['user', 'account', 'customer', 'other'] = 'user'
    entity_ref: str = Field(min_length=1, max_length=120, pattern=r'\S')
    name: str = Field(min_length=1, max_length=40, pattern=r'^[a-z][a-z0-9_]*$')
    numeric_value: float = Field(default=1, allow_inf_nan=False)
    text_value: str = Field(default='', max_length=200)
    occurred_at: datetime

    @field_validator('occurred_at')
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None: raise ValueError('Observation time must include timezone')
        return value.astimezone(timezone.utc)


class StreamBatch(BaseModel):
    stream: str = Field(min_length=1, max_length=80, pattern=r'^[a-zA-Z0-9_.-]+$')
    events: list[StreamEvent] = Field(min_length=1, max_length=200)


@router.post('/stream', status_code=201)
def stream(data: StreamBatch, user=Depends(writer), db=Depends(get_db)):
    try:
        result = store_stream(db, f'{user.username}:{data.stream}', data.events); db.commit()
    except IntegrityError:
        db.rollback(); raise HTTPException(409, 'Concurrent stream delivery; retry the batch')
    return result


@router.get('/catalog')
def catalog():
    behavior = list(behavior_catalog()); threats = list(threat_catalog())
    return {'version': CATALOG_VERSION, 'origin': 'First-party documented definitions; published vendor catalogs were not supplied',
            'behavioral_measures': behavior, 'insider_threat_rules': threats,
            'note': '160 daily/weekly measures and 320 window/target rules over 80 named signals, plus existing definitions. Missing facts mean no observations, not evidence of normal behavior.'}
