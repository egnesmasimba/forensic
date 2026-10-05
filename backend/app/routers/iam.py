import base64
import json
import secrets
from datetime import timedelta, timezone
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import update

from app.auth import (current_user, administrator, get_db, session_for, reserve_login_attempt,
                       clear_sessions, Credentials)
from app.models import User, LoginSession, utcnow
from app.iam_models import (IdentityPolicy, IdentityFactor, FactorEnrollment, IdentitySession,
    IdentityAudit, IdentityChallenge, PrivilegedRequest, PrivilegedActivity, LoginSchedule, PrivilegedRecording)
from app.iam import (MODULES, audit, seal, unseal, matched_counter, verify_factor, password_valid,
                      issue_sms, verify_sms)

router = APIRouter(prefix='/api/iam', tags=['identity and access'])


class Proof(BaseModel):
    password: str = Field(default='', max_length=256)
    otp: str = Field(default='', max_length=10)
    challenge_id: str = Field(default='', max_length=64)


class Enrollment(Proof):
    kind: Literal['totp','hotp','sms'] = 'totp'
    hardware_secret: str = Field(default='', max_length=128)
    counter: int = Field(default=0, ge=0, le=2147483647)
    phone: str = Field(default='', max_length=20)


def proof(db, request, user, payload, require_factor=False, purpose='login'):
    reserve_login_attempt(db, request, user.username)
    if not password_valid(db, user, payload.password):
        raise HTTPException(401, 'Identity verification failed')
    factor = db.get(IdentityFactor, user.id)
    if (factor or require_factor) and not verify_factor(db, user.id, payload.otp, payload.challenge_id, purpose):
        raise HTTPException(401, 'A valid second factor is required')


@router.get('/me')
def me(request: Request, user=Depends(current_user), db=Depends(get_db)):
    factor = db.get(IdentityFactor, user.id)
    session = session_for(request, db)
    identity = db.get(IdentitySession, session.token_hash)
    return {'factor':factor.kind if factor else None, 'modules':request.state.iam_modules,
            'mfa_verified':bool(identity and identity.mfa_verified),
            'shared_account':identity.shared_user_id if identity else None,
            'privileged':user.role == 'administrator'}


@router.post('/factors/enroll')
def enroll(payload: Enrollment, request: Request, user=Depends(current_user), db=Depends(get_db)):
    proof(db, request, user, payload)
    secret, challenge = '', None
    if payload.kind == 'sms':
        import re
        if not re.fullmatch(r'\+[1-9][0-9]{7,14}', payload.phone):
            raise HTTPException(422, 'Use an international phone number beginning with +')
        secret = payload.phone
        challenge = issue_sms(db, user.id, secret, 'enroll')
    elif payload.kind == 'hotp':
        try:
            decoded = base64.b32decode(payload.hardware_secret.upper(), casefold=True)
            if not 20 <= len(decoded) <= 64: raise ValueError()
        except Exception:
            raise HTTPException(422, 'Provide the hardware token’s Base32 OATH secret (20–64 bytes)')
        secret = payload.hardware_secret.upper()
    else:
        secret = base64.b32encode(secrets.token_bytes(20)).decode()
    row = db.get(FactorEnrollment, user.id)
    if row is None:
        row = FactorEnrollment(user_id=user.id); db.add(row)
    row.kind, row.secret = payload.kind, seal(secret)
    row.counter = payload.counter-1 if payload.kind == 'hotp' else -1
    row.expires_at = utcnow()+timedelta(minutes=10)
    audit(db, user.username, 'factor_enrollment_started', kind=payload.kind)
    db.commit()
    result = {'kind':payload.kind, 'challenge_id':challenge, 'confirmation_required':True}
    if payload.kind == 'totp':
        result.update(secret=secret, uri=f'otpauth://totp/InvestigationCenter:{quote(user.username)}?secret={secret}&issuer=InvestigationCenter&digits=6&period=30')
    return result


@router.post('/factors/confirm')
def confirm(payload: Proof, request: Request, user=Depends(current_user), db=Depends(get_db)):
    reserve_login_attempt(db, request, user.username)
    row = db.get(FactorEnrollment, user.id)
    if not row or row.expires_at.replace(tzinfo=timezone.utc) <= utcnow():
        raise HTTPException(409, 'Start factor enrollment again')
    counter = None
    if row.kind == 'sms':
        valid = verify_sms(db, user.id, 'enroll', payload.challenge_id, payload.otp)
        counter = -1
    else:
        counter = matched_counter(row.kind, unseal(row.secret), payload.otp, row.counter)
        valid = counter is not None
    if not valid: raise HTTPException(401, 'Invalid confirmation code')
    # Consume this enrollment atomically before changing the factor.
    consumed = db.execute(update(FactorEnrollment).where(FactorEnrollment.user_id == user.id,
        FactorEnrollment.secret == row.secret, FactorEnrollment.expires_at > utcnow()).values(expires_at=utcnow()),
        execution_options={'synchronize_session':False})
    if consumed.rowcount != 1: raise HTTPException(409, 'Enrollment was already confirmed')
    factor = db.get(IdentityFactor, user.id)
    if factor is None:
        factor = IdentityFactor(user_id=user.id); db.add(factor)
    factor.kind, factor.secret, factor.counter = row.kind, row.secret, counter
    session = session_for(request, db)
    identity = db.get(IdentitySession, session.token_hash)
    if identity: identity.mfa_verified = True
    clear_sessions(db, user.id, session.token_hash)
    audit(db, user.username, 'factor_enrolled', kind=row.kind)
    db.commit()
    return {'enabled':True, 'kind':row.kind}


@router.post('/factors/sms')
def sms_code(payload: Credentials, request: Request, db=Depends(get_db)):
    # Password-gated pre-login endpoint; it never returns an OTP to the caller.
    reserve_login_attempt(db, request, payload.username)
    user = db.query(User).filter_by(username=payload.username).first()
    if not user or user.disabled or not password_valid(db, user, payload.password):
        raise HTTPException(401, 'Invalid credentials')
    policy = db.get(IdentityPolicy, user.id)
    if policy and policy.shared: raise HTTPException(403, 'Request the code for your personal account')
    factor = db.get(IdentityFactor, user.id)
    if not factor or factor.kind != 'sms': raise HTTPException(409, 'An SMS factor is not enrolled')
    return {'challenge_id':issue_sms(db, user.id, unseal(factor.secret), 'login')}


@router.delete('/factors/{user_id}', status_code=204)
def reset_factor(user_id: int, user=Depends(administrator), db=Depends(get_db)):
    if user_id == user.id: raise HTTPException(403, 'A different administrator must reset your factor')
    policy = db.get(IdentityPolicy, user_id)
    if policy and policy.mfa_required:
        raise HTTPException(409, 'Temporarily remove the mandatory-factor policy before recovery')
    db.query(IdentityFactor).filter_by(user_id=user_id).delete()
    db.query(FactorEnrollment).filter_by(user_id=user_id).delete()
    clear_sessions(db, user_id)
    audit(db, user.username, 'factor_reset', user_id=user_id); db.commit()


class PolicyInput(BaseModel):
    shared: bool = False
    members: list[int] = Field(default_factory=list, max_length=100)
    mfa_required: bool = False
    modules: list[str] = Field(default_factory=lambda:['*'], max_length=40)

    @model_validator(mode='after')
    def validate_policy(self):
        if set(self.modules) - MODULES - {'*'}: raise ValueError('Unknown access module')
        if '*' in self.modules and len(self.modules) != 1: raise ValueError('Use * alone for unrestricted access')
        if self.shared and not self.members: raise ValueError('Specify accountable personal members')
        return self


@router.get('/accounts')
def accounts(user=Depends(administrator), db=Depends(get_db)):
    rows = []
    for account in db.query(User).order_by(User.id):
        policy = db.get(IdentityPolicy, account.id)
        factor = db.get(IdentityFactor, account.id)
        rows.append({'id':account.id,'username':account.username,'role':account.role,
            'privileged':account.role == 'administrator', 'disabled':account.disabled,
            'factor':factor.kind if factor else None, 'shared':bool(policy and policy.shared),
            'members':json.loads(policy.members) if policy else [],
            'modules':json.loads(policy.modules) if policy else ['*'],
            'mfa_required':bool(policy and policy.mfa_required), 'directory':bool(policy and policy.directory_dn)})
    return {'accounts':rows, 'modules':sorted(MODULES)}


@router.put('/accounts/{user_id}/policy')
def set_policy(user_id: int, payload: PolicyInput, user=Depends(administrator), db=Depends(get_db)):
    account = db.get(User, user_id)
    if not account: raise HTTPException(404, 'Account not found')
    if account.role == 'administrator' and (payload.shared or payload.modules != ['*']):
        raise HTTPException(422, 'Administrative accounts must be individual and retain full administration access')
    if payload.mfa_required and not payload.shared and not db.get(IdentityFactor, user_id):
        raise HTTPException(409, 'Enroll and confirm a factor before requiring MFA')
    for member_id in payload.members:
        member = db.get(User, member_id); member_policy = db.get(IdentityPolicy, member_id)
        if not member or member.disabled or member_id == user_id or (member_policy and member_policy.shared):
            raise HTTPException(422, 'Each member must be an enabled individual account')
    policy = db.get(IdentityPolicy, user_id)
    if not policy: policy = IdentityPolicy(user_id=user_id); db.add(policy)
    for key in ('shared','mfa_required'): setattr(policy, key, getattr(payload,key))
    policy.members, policy.modules = json.dumps(payload.members), json.dumps(payload.modules)
    clear_sessions(db, user_id)
    audit(db, user.username, 'access_policy_changed', user_id=user_id, **payload.model_dump())
    db.commit(); return {'saved':True, 'sessions_revoked':True}


@router.get('/sessions')
def sessions(user=Depends(current_user), db=Depends(get_db)):
    query = db.query(IdentitySession, LoginSession).join(LoginSession, LoginSession.token_hash == IdentitySession.token_hash).filter(LoginSession.expires_at > utcnow())
    if user.role != 'administrator': query = query.filter(IdentitySession.user_id == user.id)
    return [{'id':row.token_hash, 'user_id':row.user_id,'shared_account':row.shared_user_id,
             'address':row.address,'terminal':row.terminal,'mfa_verified':row.mfa_verified,
             'started_at':row.created_at,'expires_at':login.expires_at} for row,login in query.limit(200)]


@router.delete('/sessions/{session_id}', status_code=204)
def revoke(session_id: str, user=Depends(current_user), db=Depends(get_db)):
    row = db.get(LoginSession, session_id)
    if not row or (row.user_id != user.id and user.role != 'administrator'):
        raise HTTPException(404, 'Session not found')
    db.delete(row); audit(db, user.username, 'session_revoked', user_id=row.user_id); db.commit()


class AccessInput(BaseModel):
    resource: str = Field(min_length=1, max_length=120, pattern=r'^[A-Za-z0-9_.:/-]+$')
    reason: str = Field(min_length=10, max_length=500)


class Decision(BaseModel):
    approve: bool
    minutes: int = Field(default=30, ge=1, le=240)


@router.post('/privileged/requests', status_code=201)
def request_access(payload: AccessInput, user=Depends(current_user), db=Depends(get_db)):
    if not db.get(IdentityFactor, user.id): raise HTTPException(409, 'Enroll a factor before requesting privileged access')
    policy = db.get(IdentityPolicy, user.id)
    if policy and policy.shared: raise HTTPException(403, 'An individual account is required')
    row = PrivilegedRequest(user_id=user.id, **payload.model_dump()); db.add(row); db.flush()
    audit(db, user.username, 'privileged_requested', request_id=row.id, resource=row.resource)
    db.commit(); return {'id':row.id, 'status':row.status}


@router.get('/privileged/requests')
def requests(user=Depends(current_user), db=Depends(get_db)):
    query = db.query(PrivilegedRequest)
    if user.role != 'administrator': query = query.filter_by(user_id=user.id)
    return [{'id':row.id,'user_id':row.user_id,'resource':row.resource,'reason':row.reason,
             'status':'expired' if row.expires_at and row.expires_at.replace(tzinfo=timezone.utc) <= utcnow() else row.status,
             'approved_by':row.approved_by,'expires_at':row.expires_at} for row in query.order_by(PrivilegedRequest.id.desc()).limit(200)]


@router.post('/privileged/requests/{request_id}/decision')
def decide(request_id: int, payload: Decision, user=Depends(administrator), db=Depends(get_db)):
    row = db.get(PrivilegedRequest, request_id)
    if not row: raise HTTPException(404, 'Request not found')
    if row.user_id == user.id: raise HTTPException(403, 'Another administrator must approve access')
    result = db.execute(update(PrivilegedRequest).where(PrivilegedRequest.id == request_id,
        PrivilegedRequest.status == 'pending').values(status='approved' if payload.approve else 'denied',
        approved_by=user.id, expires_at=utcnow()+timedelta(minutes=payload.minutes)), execution_options={'synchronize_session':False})
    if result.rowcount != 1: raise HTTPException(409, 'Request is no longer pending')
    audit(db, user.username, 'privileged_decision', request_id=request_id, approve=payload.approve)
    db.commit(); return {'saved':True}


@router.post('/privileged/requests/{request_id}/activate')
def activate(request_id: int, payload: Proof, request: Request, user=Depends(current_user), db=Depends(get_db)):
    proof(db, request, user, payload, require_factor=True, purpose=f'privileged:{request_id}')
    result = db.execute(update(PrivilegedRequest).where(PrivilegedRequest.id == request_id,
        PrivilegedRequest.user_id == user.id, PrivilegedRequest.status == 'approved',
        PrivilegedRequest.expires_at > utcnow()).values(status='active', activated_session=session_for(request,db).token_hash),
        execution_options={'synchronize_session':False})
    if result.rowcount != 1: raise HTTPException(403, 'No unexpired approved request for this identity')
    audit(db, user.username, 'privileged_activated', request_id=request_id); db.commit()
    return {'active':True, 'recording':'Application request metadata is recorded; native terminal/video requires the endpoint recorder.'}


@router.post('/privileged/requests/{request_id}/sms')
def privileged_sms(request_id: int, payload: Proof, request: Request, user=Depends(current_user), db=Depends(get_db)):
    reserve_login_attempt(db, request, user.username)
    row = db.get(PrivilegedRequest, request_id); factor = db.get(IdentityFactor, user.id)
    if not password_valid(db,user,payload.password) or not row or row.user_id != user.id or row.status != 'approved' or row.expires_at.replace(tzinfo=timezone.utc) <= utcnow():
        raise HTTPException(403, 'A current approval and valid password are required')
    if not factor or factor.kind != 'sms': raise HTTPException(409, 'SMS is not enrolled')
    return {'challenge_id':issue_sms(db,user.id,unseal(factor.secret),f'privileged:{request_id}')}


@router.delete('/privileged/requests/{request_id}', status_code=204)
def revoke_access(request_id: int, user=Depends(current_user), db=Depends(get_db)):
    row = db.get(PrivilegedRequest, request_id)
    if not row or (row.user_id != user.id and user.role != 'administrator'): raise HTTPException(404, 'Request not found')
    row.status='revoked'
    from app.response_models import ReplaySession, ResponseCommand
    for link in db.query(PrivilegedRecording).filter_by(request_id=request_id):
        recording=db.get(ReplaySession,link.replay_id)
        if recording and recording.status in ('requested','active'):
            recording.status='stopped';recording.expires_at=utcnow()
            db.add(ResponseCommand(agent_id=recording.agent_id,action='live_stop',arguments=json.dumps({'session_id':recording.id}),
                actor=user.username,reason=f'Privileged approval {request_id} revoked',state='queued',expires_at=utcnow()+timedelta(minutes=2)))
    audit(db,user.username,'privileged_revoked',request_id=request_id); db.commit()


@router.get('/pam/authorize')
def pam_authorize(request: Request, resource: str = Query(min_length=1,max_length=120), user=Depends(current_user), db=Depends(get_db)):
    session = session_for(request, db)
    row = db.query(PrivilegedRequest).filter_by(user_id=user.id, resource=resource,
        status='active', activated_session=session.token_hash).filter(PrivilegedRequest.expires_at > utcnow()).first()
    if not row: raise HTTPException(403, 'No active privileged approval for this resource and session')
    audit(db,user.username,'pam_authorized',resource=resource,request_id=row.id); db.commit()
    return {'authorized':True,'individual':user.username,'resource':resource,'expires_at':row.expires_at}


@router.get('/audit')
def audit_log(before_id: int | None = Query(default=None,ge=1), user=Depends(administrator), db=Depends(get_db)):
    query = db.query(IdentityAudit)
    if before_id: query = query.filter(IdentityAudit.id < before_id)
    return [{'id':row.id,'actor':row.actor,'action':row.action,'detail':json.loads(row.detail),'created_at':row.created_at}
            for row in query.order_by(IdentityAudit.id.desc()).limit(100)]


@router.get('/recordings/{session_id}')
def session_recording(session_id: str, after_id: int = Query(default=0,ge=0), user=Depends(administrator), db=Depends(get_db)):
    return [{'id':row.id,'actor':row.actor,'shared_account':row.shared_user_id,'method':row.method,
             'path':row.path,'status':row.status,'created_at':row.created_at} for row in db.query(PrivilegedActivity).filter(
             PrivilegedActivity.session_hash == session_id, PrivilegedActivity.id > after_id).order_by(PrivilegedActivity.id).limit(500)]


@router.post('/directory/sync')
def directory_sync(user=Depends(administrator), db=Depends(get_db)):
    from app.iam_directory import sync
    result = sync(db)
    audit(db,user.username,'directory_synced',**result); db.commit(); return result


@router.post('/pam/ticket')
def pam_ticket(request: Request, resource: str = Query(min_length=1,max_length=120), user=Depends(current_user), db=Depends(get_db)):
    import hashlib
    pam_authorize(request,resource,user,db)
    session = session_for(request,db)
    ticket = secrets.token_urlsafe(32)
    db.add(IdentityChallenge(id=hashlib.sha256(ticket.encode()).hexdigest(), user_id=user.id,
        purpose='pam:'+resource, digest=session.token_hash, expires_at=utcnow()+timedelta(seconds=60)))
    audit(db,user.username,'pam_ticket_issued',resource=resource); db.commit()
    return {'ticket':ticket,'expires_in':60,'individual':user.username}


class PamRedeem(BaseModel):
    username: str = Field(min_length=1,max_length=120)
    resource: str = Field(min_length=1,max_length=120)
    ticket: str = Field(min_length=20,max_length=100)


@router.post('/pam/redeem')
def pam_redeem(payload: PamRedeem, request: Request, db=Depends(get_db)):
    import os, hmac, hashlib
    try: expected = json.loads(os.environ.get('ZANAQ_PAM_KEYS','{}')).get(payload.resource,'')
    except (ValueError,AttributeError): expected=''
    if not isinstance(expected,str) or len(expected)<32 or not hmac.compare_digest(expected,request.headers.get('x-pam-key','')):
        raise HTTPException(401,'Invalid PAM service credentials')
    identifier=hashlib.sha256(payload.ticket.encode()).hexdigest()
    ticket=db.get(IdentityChallenge,identifier)
    user=db.get(User,ticket.user_id) if ticket else None
    session=db.get(LoginSession,ticket.digest) if ticket else None
    if (not ticket or ticket.used or ticket.purpose != 'pam:'+payload.resource or
        ticket.expires_at.replace(tzinfo=timezone.utc)<=utcnow() or not user or user.disabled or
        user.username != payload.username or not session or session.expires_at.replace(tzinfo=timezone.utc)<=utcnow()):
        raise HTTPException(403,'Ticket is invalid, expired, or belongs to another identity')
    from app.iam import enforce_scope
    request.state.actor = user.username
    enforce_scope(db, request, user, session)
    grant=db.query(PrivilegedRequest).filter_by(user_id=user.id,resource=payload.resource,status='active',
        activated_session=session.token_hash).filter(PrivilegedRequest.expires_at>utcnow()).first()
    if not grant: raise HTTPException(403,'Privileged approval is no longer active')
    consumed=db.execute(update(IdentityChallenge).where(IdentityChallenge.id==identifier,IdentityChallenge.used.is_(False)).values(used=True))
    if consumed.rowcount != 1: raise HTTPException(403,'Ticket has already been redeemed')
    audit(db,user.username,'pam_ticket_redeemed',resource=payload.resource,request_id=grant.id); db.commit()
    return {'authorized':True,'individual':user.username,'resource':payload.resource}


class ScheduleInput(BaseModel):
    start_hour_utc: int = Field(ge=0,le=23)
    end_hour_utc: int = Field(ge=0,le=24)


@router.put('/accounts/{user_id}/login-hours')
def login_hours(user_id: int, payload: ScheduleInput, user=Depends(administrator), db=Depends(get_db)):
    if not db.get(User,user_id): raise HTTPException(404,'Account not found')
    row=db.get(LoginSchedule,user_id)
    if not row: row=LoginSchedule(user_id=user_id);db.add(row)
    row.start_hour_utc,row.end_hour_utc=payload.start_hour_utc,payload.end_hour_utc
    audit(db,user.username,'login_hours_changed',user_id=user_id,**payload.model_dump());db.commit()
    return {'saved':True,'timezone':'UTC','response':'review alert; login is not blocked'}


class RoleInput(BaseModel):
    role: Literal['administrator','investigator','viewer']


@router.put('/accounts/{user_id}/role')
def change_role(user_id: int, payload: RoleInput, user=Depends(administrator), db=Depends(get_db)):
    account=db.get(User,user_id);policy=db.get(IdentityPolicy,user_id)
    if not account: raise HTTPException(404,'Account not found')
    if account.id==user.id: raise HTTPException(403,'Another administrator must change your role')
    if policy and policy.directory_dn: raise HTTPException(409,'Directory roles are managed by group mappings')
    if payload.role=='administrator' and policy and (policy.shared or json.loads(policy.modules)!=['*']):
        raise HTTPException(409,'Administrator must be an unrestricted individual account')
    if account.role=='administrator' and payload.role!='administrator' and not account.disabled:
        if db.query(User).filter_by(role='administrator',disabled=False).count()<=1:
            raise HTTPException(409,'Keep an enabled administrator')
    account.role=payload.role;clear_sessions(db,user_id)
    audit(db,user.username,'role_changed',user_id=user_id,role=payload.role);db.commit()
    return {'role':payload.role,'sessions_revoked':True}


@router.post('/privileged/requests/{request_id}/record', status_code=202)
def record_desktop(request_id: int, user=Depends(administrator), db=Depends(get_db)):
    from app.routers.response import queue_command, CommandInput
    row=db.get(PrivilegedRequest,request_id)
    if not row or row.status!='active' or not row.expires_at or row.expires_at.replace(tzinfo=timezone.utc)<=utcnow():
        raise HTTPException(409,'An active, unexpired approval is required')
    login=db.get(LoginSession,row.activated_session)
    if not login or login.expires_at.replace(tzinfo=timezone.utc)<=utcnow():
        raise HTTPException(409,'The privileged session is no longer active')
    import re
    matched=re.fullmatch(r'agent:([1-9][0-9]*)',row.resource)
    if not matched: raise HTTPException(422,'Desktop recording requires an approved resource named agent:<endpoint ID>')
    from app.iam import privileged_capture_allowed
    privileged_capture_allowed(db, int(matched[1]))
    duration=min(600,int((row.expires_at.replace(tzinfo=timezone.utc)-utcnow()).total_seconds()))
    if duration<30: raise HTTPException(409,'At least 30 seconds of approved time must remain')
    command=queue_command(int(matched[1]),CommandInput(action='live_start',arguments={'mode':'view','duration':duration},
        reason=f'Privileged request {row.id}: {row.reason}'[:500]),user,db)
    replay_id=command['arguments']['session_id']
    db.add(PrivilegedRecording(replay_id=replay_id,request_id=row.id))
    audit(db,user.username,'privileged_recording_requested',request_id=row.id,replay_id=replay_id)
    db.commit();return {'replay_id':replay_id,'command':command,'status':'requested; endpoint confirmation required'}


@router.get('/privileged/requests/{request_id}/recordings')
def recordings(request_id: int,user=Depends(administrator),db=Depends(get_db)):
    return [{'replay_id':row.replay_id,'frames_url':f'/api/replay/sessions/{row.replay_id}/frames'}
            for row in db.query(PrivilegedRecording).filter_by(request_id=request_id)]
