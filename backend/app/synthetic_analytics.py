"""Bounded, one-release-per-UTC-day aggregate mechanism with cached noise."""
import hashlib
import json
import math
import secrets
from statistics import mean
from fastapi import HTTPException
from app.models import Fact, BusinessEntity, utcnow
from app.analytic_models import SyntheticAggregateRelease
from app.behavior import _stamp
from datetime import timedelta

FEATURES = ('account_access', 'dormant_account_access', 'beneficiary_change', 'customer_name_query', 'transfer')
EPSILON = 1.0
CLIP = 20


def release(db, subjects):
    selected = sorted(set(subjects))
    if len(selected) < 5: raise HTTPException(422, 'At least five distinct registered subjects are required')
    now = utcnow(); day = now.strftime('%Y-%m-%d')
    digest = hashlib.sha256(json.dumps(selected).encode()).hexdigest()
    existing = db.get(SyntheticAggregateRelease, day)
    if existing:
        if existing.cohort_digest != digest: raise HTTPException(429, 'Daily aggregate privacy budget is exhausted; reuse the existing release or wait for the next UTC day')
        return json.loads(existing.payload)
    registered = db.query(BusinessEntity).filter(BusinessEntity.entity_type == 'user', BusinessEntity.entity_ref.in_(selected)).count()
    if registered != len(selected): raise HTTPException(422, 'Every subject must belong to the registered cohort domain')
    start = now - timedelta(days=30)
    rows = db.query(Fact).filter(Fact.entity_type == 'user', Fact.entity_ref.in_(selected), Fact.name.in_(FEATURES)).all()
    totals = {subject: {feature: 0 for feature in FEATURES} for subject in selected}
    for row in rows:
        moment = _stamp(row.occurred_at)
        if moment and start <= moment <= now:
            totals[row.entity_ref][row.name] += 1
    scale = len(FEATURES)*CLIP/len(selected)/EPSILON
    values = []
    for feature in FEATURES:
        value = mean(min(CLIP, totals[subject][feature]) for subject in selected)
        u = (secrets.randbelow(2**53)+0.5)/(2**53)-0.5
        noise = -scale * math.copysign(1, u) * math.log1p(-2*abs(u))
        values.append({'measure':feature, 'synthetic_mean':round(max(0,min(CLIP,value+noise)),2)})
    result = {'release_id':secrets.token_hex(12), 'measures':values, 'epsilon':EPSILON, 'window_days':30,
              'clipping_per_subject':CLIP, 'noise_scale':scale,
              'notice':'No individual token, exact average, identity, label or timestamp is exported. Conditional on a fixed, public registered cohort domain: add/remove per-subject activity adjacency with L1-bounded contributions; cohort selection and membership require independent privacy review. One cached release per UTC day; cumulative releases compose across days. This is not a legal compliance certification.'}
    db.add(SyntheticAggregateRelease(day=day,cohort_digest=digest,payload=json.dumps(result))); db.flush()
    return result
