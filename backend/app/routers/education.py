from typing import Literal
from urllib.parse import urlsplit
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel, Field, field_validator
from app.auth import current_user, administrator, get_db
from app.models import EndpointAgent, Notice, User
from app.privacy_models import EducationPolicy, PolicyWarning, EducationAudit
from app.education import policy, create_warning, deliveries, record, warning_payload
from app.routers.agents import _agent_from_token
from app.privacy import audit

router = APIRouter(prefix='/api/education', tags=['policy education'])


class PolicyInput(BaseModel):
    enabled: bool = True
    title: str = Field(default='Policy reminder', min_length=1, max_length=160)
    message: str = Field(default='This activity needs review. Please follow your organization policy.', min_length=1, max_length=2000)
    education: str = Field(default='Review the policy before repeating this activity.', max_length=2000)
    training_url: str = Field(default='', max_length=500)
    manager: str = Field(default='', max_length=120)
    escalation_count: int = Field(default=3, ge=1, le=100)
    reminder_minutes: int = Field(default=60, ge=1, le=10080)

    @field_validator('training_url')
    @classmethod
    def safe_link(cls, value):
        if value:
            parsed = urlsplit(value)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError('Training links must use HTTPS without embedded credentials')
        return value


@router.get('/policy')
def get_policy(user=Depends(administrator), db=Depends(get_db)):
    saved = policy(db); db.commit(); return {key: getattr(saved, key) for key in PolicyInput.model_fields}


@router.put('/policy')
def save_policy(data: PolicyInput, user=Depends(administrator), db=Depends(get_db)):
    if data.manager and not db.query(User).filter_by(username=data.manager, disabled=False).first():
        raise HTTPException(422, 'Manager must be an active application account')
    saved = policy(db)
    for key, value in data.model_dump().items(): setattr(saved, key, value)
    audit(db, user.username, 'education_policy_changed', **data.model_dump()); db.commit()
    return data


@router.post('/reminders/{agent_id}', status_code=201)
def remind(agent_id: int, user=Depends(administrator), db=Depends(get_db)):
    if not db.get(EndpointAgent, agent_id): raise HTTPException(404, 'Agent not found')
    row = create_warning(db, agent_id, actor=user.username, reminder=True)
    if row is None: raise HTTPException(409, 'Policy education is disabled')
    db.commit(); return warning_payload(row)


@router.get('/warnings')
def warnings(user=Depends(administrator), db=Depends(get_db)):
    return [warning_payload(row) for row in db.query(PolicyWarning).order_by(PolicyWarning.id.desc()).limit(100)]


@router.get('/inbox')
def inbox(user=Depends(current_user), db=Depends(get_db)):
    from app.privacy_models import PrivacySetting
    settings = db.get(PrivacySetting, 1)
    restricted = settings and settings.enabled and user.role != "administrator"
    return [{'id': row.id, 'subject': "Manager notification" if restricted else row.subject, 'body': "A policy notification requires review. Content is withheld in privacy mode." if restricted else row.body, 'acknowledged': row.acknowledged} for row in db.query(Notice).filter_by(user=user.username).order_by(Notice.id.desc()).limit(100)]


@router.post('/inbox/{notice_id}/ack')
def inbox_ack(notice_id: int, user=Depends(current_user), db=Depends(get_db)):
    row = db.get(Notice, notice_id)
    if not row or row.user != user.username: raise HTTPException(404, 'Notice not found')
    row.acknowledged = True; audit(db, user.username, 'manager_notice_acknowledged', notice_id=notice_id); db.commit()
    return {'acknowledged': True}


@router.get('/agent/warnings')
def agent_warnings(request: Request, db=Depends(get_db)):
    agent = _agent_from_token(request, db); result = deliveries(db, agent.id); db.commit()
    return {'warnings': result}


class Receipt(BaseModel):
    action: Literal['displayed', 'acknowledged', 'training_completed']


@router.post('/agent/warnings/{warning_id}/receipt')
def receipt(warning_id: int, data: Receipt, request: Request, db=Depends(get_db)):
    agent = _agent_from_token(request, db); row = db.get(PolicyWarning, warning_id)
    if not row or row.agent_id != agent.id: raise HTTPException(404, 'Warning not found')
    if data.action == 'training_completed':
        if row.training_state == 'none': raise HTTPException(409, 'No training assigned')
        if row.training_state not in ('completed', 'verified'):
            row.training_state = 'completed'; record(db, row, f'agent:{agent.id}', 'training_self_reported')
    elif data.action == 'acknowledged':
        if row.state != 'acknowledged':
            row.state = 'acknowledged'; record(db, row, f'agent:{agent.id}', data.action)
    else:
        if not db.query(EducationAudit).filter_by(warning_id=row.id, action='displayed').first(): record(db, row, f'agent:{agent.id}', data.action)
    db.commit(); return warning_payload(row)


@router.get('/audit')
def trail(user=Depends(administrator), db=Depends(get_db)):
    return [{'id': row.id, 'warning_id': row.warning_id, 'actor': row.actor, 'action': row.action, 'created_at': row.created_at} for row in db.query(EducationAudit).order_by(EducationAudit.id.desc()).limit(200)]

class TrainingCompletion(BaseModel):
    reference: str = Field(min_length=1, max_length=200)


@router.post('/training/{warning_id}/complete')
def verified_training(warning_id: int, data: TrainingCompletion, request: Request, db=Depends(get_db)):
    import os
    import hmac
    configured = os.environ.get('ZANAQ_TRAINING_WEBHOOK_TOKEN', '')
    supplied = request.headers.get('authorization', '')
    if not configured or len(configured) < 32 or not hmac.compare_digest(supplied.encode(), ('Bearer ' + configured).encode()):
        raise HTTPException(401, 'Training provider authentication required')
    row = db.get(PolicyWarning, warning_id)
    if not row or not row.training_url: raise HTTPException(404, 'Training assignment not found')
    if row.training_state != 'verified':
        row.training_state = 'verified'; record(db, row, 'training-provider', 'training_verified')
        audit(db, 'training-provider', 'training_verified', warning_id=warning_id, reference=data.reference)
    db.commit(); return {'verified': True, 'warning_id': warning_id}
