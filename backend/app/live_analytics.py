"""Transactional evaluation of bounded observations from a live capture producer."""
import hashlib
import json
import math
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from app.analytics import remember_fact, evaluate_rules
from app.behavior import refresh_user
from app.profiles import evaluate_library
from app.analytic_models import LiveReceipt
from app.indicator_catalog import REQUIRED_FACTS


def store_stream(db, stream, events):
    accepted = duplicates = 0
    users = {}
    only = set()
    for event in events:
        data = event.model_dump(mode='json')
        key = hashlib.sha256(f'{stream}:{event.event_id}'.encode()).hexdigest()
        digest = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        old = db.get(LiveReceipt, key)
        if old:
            if old.fingerprint != digest: raise HTTPException(409, 'Stream event ID already has different content')
            duplicates += 1; continue
        db.add(LiveReceipt(key=key, fingerprint=digest))
        db.flush()
        remember_fact(db, source_key=f'live:{key}', source='live', occurred_at=event.occurred_at.isoformat(),
                      entity_type=event.entity_type, entity_ref=event.entity_ref, name=event.name,
                      numeric_value=event.numeric_value, text_value=event.text_value)
        only.add((event.entity_type, event.entity_ref))
        if event.entity_type == 'user': users[event.entity_ref] = max(users.get(event.entity_ref, event.occurred_at), event.occurred_at)
        accepted += 1
    db.flush()
    ids = evaluate_rules(db, only) if only else []
    for user, moment in users.items():
        ids.extend(refresh_user(db, user, moment)); ids.extend(evaluate_library(db, user, moment))
    return {'accepted': accepted, 'duplicates': duplicates, 'alerts_created': len(ids), 'alert_ids': ids}


def endpoint_observation(event):
    from app.routers.live_analytics import StreamEvent
    payload = json.loads(event.payload)
    if event.type == 'analytic_fact':
        body = {**payload, 'event_id': str(event.id), 'occurred_at': event.occurred_at.isoformat()}
        observation = StreamEvent.model_validate(body)
    elif event.type in REQUIRED_FACTS:
        observation = StreamEvent(event_id=str(event.id), entity_type='user', entity_ref=f'agent:{event.agent_id}',
                                 name=event.type, numeric_value=1, text_value=str(payload.get('target', ''))[:200], occurred_at=event.occurred_at)
    else:
        return None
    return observation
