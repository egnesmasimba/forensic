import json
from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import func
from app.auth import administrator, current_user, get_db
from app.models import EndpointAgent, EndpointEvent, utcnow
from app.privacy_models import PrivacySetting, PrivacyConsent, PrivacyAudit
from app.privacy import setting, pseudonym, audit, masked_image, retention

router = APIRouter(prefix='/api/privacy', tags=['privacy'])


class SettingsInput(BaseModel):
    enabled: bool = False
    consent_required: bool = True
    council_required: bool = False
    council_reference: str = Field(default='', max_length=500)
    council_expires_at: datetime | None = None
    purpose: str = Field(default='', max_length=500)
    legal_basis: Literal['', 'consent', 'legal_obligation', 'legitimate_interest', 'public_interest', 'contract', 'vital_interest'] = ''
    retention_days: int = Field(default=30, ge=1, le=3650)
    automatic_retention: bool = False

    @model_validator(mode='after')
    def valid(self):
        if self.enabled and (not self.purpose.strip() or not self.legal_basis):
            raise ValueError('Specify the processing purpose and legal basis before enabling privacy mode')
        if self.council_expires_at and self.council_expires_at.tzinfo is None:
            raise ValueError('Approval expiry must have a timezone')
        if self.enabled and self.council_required and (not self.council_reference.strip() or not self.council_expires_at or self.council_expires_at <= utcnow()):
            raise ValueError('A current works council agreement reference and expiry are required')
        return self


def public_settings(row):
    return {key: getattr(row, key) for key in SettingsInput.model_fields}


@router.get('/status')
def status(user=Depends(current_user), db=Depends(get_db)):
    row = setting(db); db.commit()
    return {'enabled': row.enabled, 'raw_access': user.role == 'administrator', 'purpose': row.purpose,
            'consent_required': row.consent_required, 'notice': 'Restricted views are pseudonymized; they are not certified anonymous data.'}


@router.get('/settings')
def settings(user=Depends(administrator), db=Depends(get_db)):
    row = setting(db); db.commit(); return public_settings(row)


@router.put('/settings')
def save(data: SettingsInput, user=Depends(administrator), db=Depends(get_db)):
    row = setting(db)
    for key, value in data.model_dump().items(): setattr(row, key, value)
    audit(db, user.username, 'settings_changed', **data.model_dump(mode='json'))
    db.commit(); return public_settings(row)


@router.get('/dashboard')
def dashboard(user=Depends(current_user), db=Depends(get_db)):
    row = setting(db)
    # Only structured counts and aliases are projected; payloads, names, titles and exact times never leave this route.
    groups = db.query(EndpointEvent.agent_id, EndpointEvent.severity, func.count(EndpointEvent.id)).group_by(EndpointEvent.agent_id, EndpointEvent.severity).limit(1000).all()
    aggregates = []
    for severity, people, events in db.query(EndpointEvent.severity, func.count(func.distinct(EndpointEvent.agent_id)), func.count(EndpointEvent.id)).group_by(EndpointEvent.severity):
        if people >= 5:
            lower = events // 5 * 5
            aggregates.append({'severity': severity, 'event_range': f'{lower}-{lower+4}', 'minimum_subjects': 5})
    db.commit()
    return {'aggregates': aggregates, 'suppression': 'Aggregate cohorts with fewer than five endpoints are withheld. Counts are grouped in ranges of five.', 'subjects': [{'subject': pseudonym(row, f'agent:{agent}'), 'severity': severity, 'events': count} for agent, severity, count in groups],
            'privacy': 'Pseudonymized counts. Raw identities and free text are excluded.', 'limited': len(groups) == 1000}


@router.get('/media')
def media(user=Depends(current_user), db=Depends(get_db)):
    from app.response_models import ReplaySession
    return {'screenshots': [row.id for row in db.query(EndpointEvent).filter_by(type='screenshot').order_by(EndpointEvent.id.desc()).limit(30)],
            'recordings': [row.id for row in db.query(ReplaySession).order_by(ReplaySession.id.desc()).limit(30)]}


@router.get('/screenshots/{event_id}')
def screenshot(event_id: int, user=Depends(current_user), db=Depends(get_db)):
    import base64
    event = db.get(EndpointEvent, event_id)
    if not event or event.type != 'screenshot': raise HTTPException(404, 'Screenshot not found')
    try: image = masked_image(base64.b64decode(json.loads(event.payload).get('image_b64', ''), validate=True))
    except Exception: image = ''
    return {'event_id': event_id, 'image_base64': image, 'mask': 'All pixels covered; missing or invalid media is withheld'}


@router.get('/recordings/{session_id}/frames')
def recording(session_id: int, after: int = Query(-1, ge=-1), user=Depends(current_user), db=Depends(get_db)):
    from app.response_models import ReplayFrame, ReplaySession
    if not db.get(ReplaySession, session_id): raise HTTPException(404, 'Recording not found')
    output = []
    for frame in db.query(ReplayFrame).filter(ReplayFrame.session_id == session_id, ReplayFrame.sequence > after).order_by(ReplayFrame.sequence).limit(30):
        try: image = masked_image(frame.image) if frame.image else ''
        except Exception: image = ''
        output.append({'sequence': frame.sequence, 'text': '[withheld]', 'fields': {}, 'original_html': '', 'image_base64': image, 'mask': 'All pixels and text covered'})
    return output


class ConsentInput(BaseModel):
    granted: bool
    purpose: str = Field(min_length=1, max_length=500)
    expires_days: int = Field(default=30, ge=1, le=365)


@router.get('/agent/notice')
def consent_notice(request: Request, db=Depends(get_db)):
    from app.routers.agents import _agent_from_token
    agent = _agent_from_token(request, db); row = setting(db)
    latest = db.query(PrivacyConsent).filter_by(agent_id=agent.id).order_by(PrivacyConsent.id.desc()).first()
    db.commit()
    return {'purpose': row.purpose, 'legal_basis': row.legal_basis, 'enabled': row.enabled, 'consent_required': row.consent_required,
            'consent': {'granted': latest.granted, 'purpose': latest.purpose, 'expires_at': latest.expires_at} if latest else None}


@router.post('/agent/consent', status_code=201)
def consent(data: ConsentInput, request: Request, db=Depends(get_db)):
    from app.routers.agents import _agent_from_token
    agent = _agent_from_token(request, db); row = setting(db)
    if data.purpose != row.purpose: raise HTTPException(409, 'Processing purpose changed; read the current notice')
    consent = PrivacyConsent(agent_id=agent.id, purpose=data.purpose, granted=data.granted, expires_at=utcnow()+timedelta(days=data.expires_days), actor=f'agent:{agent.id}')
    db.add(consent); audit(db, f'agent:{agent.id}', 'consent_granted' if data.granted else 'consent_withdrawn', purpose=data.purpose)
    db.commit(); return {'id': consent.id, 'granted': consent.granted}


@router.get('/consents')
def consents(user=Depends(administrator), db=Depends(get_db)):
    return [{'id': row.id, 'agent_id': row.agent_id, 'purpose': row.purpose, 'granted': row.granted, 'expires_at': row.expires_at, 'created_at': row.created_at} for row in db.query(PrivacyConsent).order_by(PrivacyConsent.id.desc()).limit(100)]


@router.post('/retention')
def run_retention(dry_run: bool = True, user=Depends(administrator), db=Depends(get_db)):
    result = retention(db, user.username, dry_run); db.commit(); return result


@router.get('/audit')
def audits(user=Depends(administrator), db=Depends(get_db)):
    return [{'id': row.id, 'actor': row.actor, 'action': row.action, 'detail': json.loads(row.detail), 'created_at': row.created_at} for row in db.query(PrivacyAudit).order_by(PrivacyAudit.id.desc()).limit(100)]


def install_privacy(app):
    import re
    @app.middleware('http')
    async def privacy_boundary(request, call_next):
        path = request.url.path
        safe = (not path.startswith('/api/') or path.startswith(('/api/auth/', '/api/privacy/', '/api/education/', '/api/biometrics/agent/')) or path in {'/api/biometrics/summary', '/api/profiles/synthetic-aggregate', '/api/iam/me', '/api/iam/factors/sms', '/api/iam/factors/enroll', '/api/iam/factors/confirm', '/api/iam/pam/redeem'} or path in {'/api/health', '/api/meta', '/api/agents/register', '/api/agents/heartbeat', '/api/agents/events', '/api/agents/me', '/api/agents/packages/manifest', '/api/response/poll'} or re.fullmatch(r'/api/(?:replay/agent/sessions/\d+/frames|response/commands/\d+/result)', path))
        if not safe:
            with app.state.session_factory() as db:
                settings = db.get(PrivacySetting, 1)
                if settings and settings.enabled:
                    try: user = current_user(request, db)
                    except HTTPException as error: return JSONResponse({'detail': error.detail}, status_code=error.status_code)
                    if user.role != 'administrator' or request.headers.get('x-privacy-raw') != '1':
                        return JSONResponse({'detail': 'Privacy mode restricts this route. Use the privacy dashboard; administrators may explicitly enable raw access.'}, status_code=403)
                    audit(db, user.username, 'raw_access', path=path, method=request.method); db.commit()
        response = await call_next(request)
        if path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        return response
