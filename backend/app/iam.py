"""Identity verification, replay-resistant OTPs and application access boundaries."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from datetime import timedelta, timezone

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException
from sqlalchemy import update

from app.models import Alert, LoginSession, User, utcnow
from app.iam_models import (IdentityPolicy, IdentityFactor, IdentityChallenge,
    IdentitySession, IdentityAudit, PrivilegedRequest, PrivilegedActivity, LoginSchedule)

MODULES = {'cases','reports','alerts','network','search','mail','replay','response',
           'agents','analytics','profiles','dlp','websites','processes','links',
           'automation','collectors','imports','structure','routes','detection',
           'foundation','compliance','biometrics','education','privacy'}


def audit(db, actor, action, **detail):
    db.add(IdentityAudit(actor=actor, action=action, detail=json.dumps(detail)))


def cipher():
    try:
        return Fernet(os.environ['ZANAQ_IAM_KEY'].encode())
    except (KeyError, ValueError):
        raise HTTPException(503, 'Configure a persistent ZANAQ_IAM_KEY before enrolling factors')


def seal(value):
    return cipher().encrypt(value.encode()).decode()


def unseal(value):
    try:
        return cipher().decrypt(value.encode()).decode()
    except InvalidToken:
        raise HTTPException(503, 'The configured IAM key cannot decrypt this factor')


def hotp(secret, counter, digits=6):
    key = base64.b32decode(secret.upper(), casefold=True)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset:offset+4], 'big') & 0x7fffffff
    return str(number % (10**digits)).zfill(digits)


def matched_counter(kind, secret, code, previous=-1):
    if not code or len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    center = int(time.time()) // 30
    counters = range(max(0, center-1), center+2) if kind == 'totp' else range(previous+1, previous+11)
    for counter in counters:
        if counter > previous and hmac.compare_digest(hotp(secret, counter), code):
            return counter
    return None


def challenge_digest(challenge_id, code):
    # HMAC prevents offline enumeration of six-digit codes from a database copy.
    return hmac.new(os.environ['ZANAQ_IAM_KEY'].encode(), f'{challenge_id}:{code}'.encode(), hashlib.sha256).hexdigest()


def send_sms(phone, code):
    sid = os.environ.get('TWILIO_ACCOUNT_SID', '')
    token = os.environ.get('TWILIO_AUTH_TOKEN', '')
    sender = os.environ.get('TWILIO_FROM', '')
    if not sid.startswith('AC') or len(sid) != 34 or not sid[2:].isalnum() or not token or not sender:
        raise HTTPException(503, 'SMS delivery is not configured')
    try:
        response = httpx.post(f'https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json',
                              auth=(sid, token), data={'To':phone, 'From':sender,
                              'Body':f'Your Investigation Center code is {code}. It expires in 5 minutes.'}, timeout=10)
        response.raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(503, 'SMS delivery failed')


def issue_sms(db, user_id, phone, purpose):
    cipher()  # Validate the encryption key before generating any challenge.
    # Callers reserve the persistent per-account/address rate limit first.
    db.query(IdentityChallenge).filter_by(user_id=user_id, purpose=purpose, used=False).update({'used':True})
    identifier, code = secrets.token_urlsafe(32), str(secrets.randbelow(1000000)).zfill(6)
    row = IdentityChallenge(id=identifier, user_id=user_id, purpose=purpose,
                            digest=challenge_digest(identifier, code), expires_at=utcnow()+timedelta(minutes=5))
    send_sms(phone, code)
    db.add(row); db.commit()
    return identifier


def verify_sms(db, user_id, purpose, challenge_id, code):
    cipher()
    if not challenge_id or not code:
        return False
    row = db.get(IdentityChallenge, challenge_id)
    if not row or row.user_id != user_id or row.purpose != purpose or row.used or row.expires_at.replace(tzinfo=timezone.utc) <= utcnow():
        return False
    if not hmac.compare_digest(row.digest, challenge_digest(challenge_id, code)):
        return False
    result = db.execute(update(IdentityChallenge).where(IdentityChallenge.id == row.id,
        IdentityChallenge.used.is_(False)).values(used=True), execution_options={'synchronize_session':False})
    return result.rowcount == 1


def verify_factor(db, user_id, code, challenge_id='', purpose='login'):
    factor = db.get(IdentityFactor, user_id)
    if not factor:
        return False
    if factor.kind == 'sms':
        return verify_sms(db, user_id, purpose, challenge_id, code)
    counter = matched_counter(factor.kind, unseal(factor.secret), code, factor.counter)
    if counter is None:
        return False
    result = db.execute(update(IdentityFactor).where(IdentityFactor.user_id == user_id,
        IdentityFactor.counter == factor.counter).values(counter=counter), execution_options={'synchronize_session':False})
    return result.rowcount == 1


def password_valid(db, user, password):
    from app.auth import verify_password
    policy = db.get(IdentityPolicy, user.id) if user else None
    if policy and policy.directory_dn:
        from app.iam_directory import authenticate
        return authenticate(policy.directory_dn, password)
    return verify_password(password, user.password_hash if user else '0'*32+'$'+'0'*64)


def login_identity(db, user, payload, request):
    """Shared credentials never replace the accountable person's permissions."""
    from app.auth import reserve_login_attempt
    policy = db.get(IdentityPolicy, user.id)
    shared_id = None
    if policy and policy.shared:
        personal = db.query(User).filter_by(username=payload.personal_username.strip().lower()).first()
        reserve_login_attempt(db, request, payload.personal_username.strip().lower())
        if (not personal or personal.disabled or personal.id not in json.loads(policy.members)
                or not password_valid(db, personal, payload.personal_password)):
            raise HTTPException(401, 'Personal identity verification failed')
        personal_policy = db.get(IdentityPolicy, personal.id)
        if personal_policy and personal_policy.shared:
            raise HTTPException(403, 'A shared account cannot identify an individual')
        shared_id, user = user.id, personal
        policy = personal_policy
    factor = db.get(IdentityFactor, user.id)
    required = bool(factor or shared_id or (policy and policy.mfa_required))
    if required and not verify_factor(db, user.id, payload.otp, payload.challenge_id):
        audit(db, user.username, 'factor_rejected', shared_account=shared_id)
        db.commit()
        raise HTTPException(401, 'A valid personal second factor is required')
    return user, shared_id, required


def record_session(db, request, user, session, shared_id, verified):
    from app.auth import client_address
    terminal = hashlib.sha256(request.headers.get('user-agent', '').encode()).hexdigest()
    address = client_address(request)
    schedule = db.get(LoginSchedule, user.id)
    if schedule:
        start, end, hour = schedule.start_hour_utc, schedule.end_hour_utc, utcnow().hour
        permitted = start <= hour < end if start < end else (hour >= start or hour < end)
        if not permitted:
            audit(db, user.username, 'unusual_login_time', hour_utc=hour)
            if not db.query(Alert).filter_by(title='Outside approved login hours',channel='identity',entity_ref=user.username,status='open').first():
                db.add(Alert(title='Outside approved login hours', description=f'Login outside the configured UTC window {start}:00–{end}:00. Review required.',
                             score=50,entity_type='user',entity_ref=user.username,channel='identity'))
    active = db.query(IdentitySession).join(LoginSession, LoginSession.token_hash == IdentitySession.token_hash).filter(
        IdentitySession.user_id == user.id, LoginSession.expires_at > utcnow()).all()
    different = any(row.terminal != terminal or row.address != address for row in active)
    if active:
        action = 'different_terminal' if different else 'simultaneous_login'
        audit(db, user.username, action, active_sessions=len(active), address=address)
        if different:
            title = 'Possible credential sharing' if shared_id else 'Possible account takeover'
            existing = db.query(Alert).filter_by(title=title, channel='identity', entity_ref=user.username, status='open').first()
            if not existing:
                db.add(Alert(title=title, description='Overlapping authenticated sessions have different address or browser metadata. Review is required; this does not prove who used the credentials.',
                    score=70, entity_type='user', entity_ref=user.username, channel='identity'))
    db.add(IdentitySession(token_hash=session.token_hash, user_id=user.id, shared_user_id=shared_id,
                           address=address, terminal=terminal, mfa_verified=verified))
    audit(db, user.username, 'session_started', shared_account=shared_id, mfa=verified)


def enforce_scope(db, request, user, session):
    policy = db.get(IdentityPolicy, user.id)
    detail = db.get(IdentitySession, session.token_hash)
    # Legacy/shared sessions must not survive conversion into a shared account.
    if policy and policy.shared:
        raise HTTPException(401, 'Sign in again with personal identity verification')
    if policy and policy.mfa_required and (not detail or not detail.mfa_verified):
        raise HTTPException(401, 'Sign in again with a second factor')
    module = request.url.path.split('/')[2] if request.url.path.startswith('/api/') else ''
    allowed = json.loads(policy.modules) if policy else ['*']
    if detail and detail.shared_user_id:
        shared = db.get(IdentityPolicy, detail.shared_user_id)
        account = db.get(User, detail.shared_user_id)
        if not shared or not shared.shared or not account or account.disabled or user.id not in json.loads(shared.members):
            raise HTTPException(401, 'Shared-account membership was revoked')
        shared_allowed = json.loads(shared.modules)
        if '*' not in shared_allowed:
            allowed = shared_allowed if '*' in allowed else list(set(allowed) & set(shared_allowed))
    if module not in ('auth','iam','meta') and '*' not in allowed and module not in allowed:
        raise HTTPException(403, 'Your access policy does not permit this data area')
    request.state.identity_session = session.token_hash
    request.state.shared_user_id = detail.shared_user_id if detail else None
    request.state.privileged = user.role == 'administrator' or db.query(PrivilegedRequest.id).filter(
        PrivilegedRequest.activated_session == session.token_hash, PrivilegedRequest.status == 'active',
        PrivilegedRequest.expires_at > utcnow()).first() is not None
    request.state.iam_modules = allowed


def record_activity(db, request, status):
    if getattr(request.state, 'identity_session', None) and (getattr(request.state, 'privileged', False) or getattr(request.state, 'shared_user_id', None)):
        db.add(PrivilegedActivity(session_hash=request.state.identity_session, actor=request.state.actor,
            shared_user_id=getattr(request.state, 'shared_user_id', None), method=request.method,
            path=request.url.path[:250], status=status))


def privileged_capture_allowed(db, agent_id):
    """Privileged recording always requires current endpoint consent."""
    from app.privacy import setting
    from app.privacy_models import PrivacyConsent
    settings = setting(db)
    now = utcnow()
    if settings.council_required and (not settings.council_reference or not settings.council_expires_at
            or settings.council_expires_at.replace(tzinfo=timezone.utc) <= now):
        raise HTTPException(403, 'Current works council approval is required')
    consent = db.query(PrivacyConsent).filter_by(agent_id=agent_id).order_by(PrivacyConsent.id.desc()).first()
    if (not consent or not consent.granted or consent.purpose != settings.purpose
            or consent.expires_at.replace(tzinfo=timezone.utc) <= now):
        raise HTTPException(403, 'Current endpoint consent is required for privileged recording')
