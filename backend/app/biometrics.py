"""Aggregate-only behavioral comparisons; a review aid, not an authentication factor."""
import json
import math
from statistics import mean, pstdev
from datetime import timedelta, timezone
from pydantic import BaseModel, ConfigDict, Field
from fastapi import HTTPException
from app.models import Alert, utcnow
from app.analytic_models import BiometricBinding, BiometricConsent, BiometricProfile, BiometricSample

METRICS = ('hold_mean_ms', 'hold_sd_ms', 'interval_mean_ms', 'interval_sd_ms', 'flight_mean_ms', 'mouse_speed_mean', 'mouse_turn_mean')
FLOORS = {'hold_mean_ms': 20, 'hold_sd_ms': 15, 'interval_mean_ms': 30, 'interval_sd_ms': 30, 'flight_mean_ms': 30, 'mouse_speed_mean': 100, 'mouse_turn_mean': 0.2}


class SampleInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    key_count: int = Field(ge=0, le=100000)
    mouse_count: int = Field(ge=0, le=100000)
    duration_seconds: float = Field(gt=0, le=3600, allow_inf_nan=False)
    hold_mean_ms: float = Field(ge=0, le=10000, allow_inf_nan=False)
    hold_sd_ms: float = Field(ge=0, le=10000, allow_inf_nan=False)
    interval_mean_ms: float = Field(ge=0, le=10000, allow_inf_nan=False)
    interval_sd_ms: float = Field(ge=0, le=10000, allow_inf_nan=False)
    flight_mean_ms: float = Field(ge=-10000, le=10000, allow_inf_nan=False)
    mouse_speed_mean: float = Field(ge=0, le=100000, allow_inf_nan=False)
    mouse_turn_mean: float = Field(ge=0, le=math.pi, allow_inf_nan=False)


def permitted(db, agent_id):
    from app.privacy_models import PrivacySetting
    settings = db.get(PrivacySetting, 1)
    if settings and settings.council_required and (not settings.council_reference or not settings.council_expires_at or settings.council_expires_at.replace(tzinfo=timezone.utc) <= utcnow()):
        return False
    binding = db.get(BiometricBinding, agent_id)
    latest = db.query(BiometricConsent).filter_by(agent_id=agent_id).order_by(BiometricConsent.id.desc()).first()
    return bool(binding and binding.enabled and latest and latest.granted and latest.expires_at.replace(tzinfo=timezone.utc) > utcnow())


def available_metrics(sample):
    keys = []
    if sample.get('key_count',0) >= 20: keys.extend(METRICS[:5])
    if sample.get('mouse_count',0) >= 20: keys.extend(METRICS[5:])
    return keys


def compare(data, profile):
    baseline = json.loads(profile.baseline)
    selected = [key for key in available_metrics(data) if key in baseline]
    if len(selected) < 3: return None, 'insufficient'
    distance = mean(abs(data[key]-baseline[key]['mean']) / max(baseline[key]['sd'], FLOORS[key]) for key in selected)
    return distance, 'consistent' if distance <= profile.threshold else 'suspicious'


def store_sample(db, event):
    if not permitted(db, event.agent_id): raise HTTPException(403, 'Biometric collection requires an enabled binding and current explicit endpoint consent')
    data = SampleInput.model_validate_json(event.payload).model_dump()
    binding = db.get(BiometricBinding, event.agent_id)
    profile = db.get(BiometricProfile, binding.subject)
    distance, status = compare(data, profile) if profile else (None, 'unenrolled')
    if not available_metrics(data): status = 'insufficient'
    row = BiometricSample(event_id=event.id, agent_id=event.agent_id, subject=binding.subject, metrics=json.dumps(data),
                          occurred_at=event.occurred_at, distance=distance, status=status)
    db.add(row); db.flush()
    if status != 'suspicious': return None
    cutoff = utcnow() - timedelta(minutes=10)
    # Server receipt time bounds prevent client-provided future timestamps from manufacturing overlap.
    recent = db.query(BiometricSample).filter(BiometricSample.subject == binding.subject, BiometricSample.id < row.id,
              BiometricSample.received_at >= cutoff).order_by(BiometricSample.id.desc()).limit(20).all()
    same_agent = [sample for sample in recent if sample.agent_id == event.agent_id]
    possible_takeover = bool(same_agent and same_agent[0].status == 'suspicious')
    possible_sharing = any(sample.agent_id != event.agent_id and sample.status == 'consistent' for sample in recent)
    if not (possible_takeover or possible_sharing): return None
    if any(sample.alert_id for sample in recent): return None
    title = 'Possible credential sharing' if possible_sharing else 'Possible account takeover'
    alert = Alert(title=title, description=f'Aggregate biometric deviation {distance:.2f}; enrolled threshold {profile.threshold:.2f}. Device, workload and accessibility changes can explain this signal; verify with independent evidence.',
                  score=75, entity_type='user', entity_ref=binding.subject, channel='biometrics')
    db.add(alert); db.flush(); row.alert_id = alert.id
    return alert


def enroll(db, subject, ids, actor, threshold):
    rows = db.query(BiometricSample).filter(BiometricSample.id.in_(ids), BiometricSample.subject == subject).all()
    if len(rows) != len(set(ids)) or len(rows) < 5: raise HTTPException(422, 'Select at least five samples belonging to this subject')
    if any(row.status in ('suspicious','expired') for row in rows): raise HTTPException(422, 'Suspicious samples cannot enroll a baseline')
    data = [json.loads(row.metrics) for row in rows]
    baseline = {}
    for key in METRICS:
        values = [item[key] for item in data if key in available_metrics(item)]
        if len(values) >= 5: baseline[key] = {'mean': mean(values), 'sd': pstdev(values)}
    if len(baseline) < 3: raise HTTPException(422, 'Insufficient comparable input activity across the selected samples')
    row = db.get(BiometricProfile, subject)
    if row is None:
        row = BiometricProfile(subject=subject, baseline='{}', sample_ids='[]', enrolled_by=actor); db.add(row)
    row.baseline=json.dumps(baseline); row.sample_ids=json.dumps(sorted(ids)); row.enrolled_by=actor; row.threshold=threshold; row.created_at=utcnow()
    return row
