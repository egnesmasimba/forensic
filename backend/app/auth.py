import hashlib
import hmac
import os
import secrets
import math
from datetime import timedelta, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy import update

from app.models import AuthenticationAudit, LoginSession, LoginThrottle, User, utcnow
from app.transport_security import secure_cookie_default

router = APIRouter(prefix="/api/auth", tags=["accounts"])
LOGIN_WINDOW_SECONDS = 900
USERNAME_LOGIN_LIMIT = 5
ADDRESS_LOGIN_LIMIT = 20
API_WINDOW_SECONDS = 60
API_LIMIT = 300


def client_address(request):
    # Forwarded headers are handled only by the server's explicitly trusted proxy configuration.
    return (request.client.host if request.client else "unknown")[:200]


def audit_login(db, request, username, outcome):
    db.add(AuthenticationAudit(username=username, client_address=client_address(request), outcome=outcome))


def reserve_login_attempt(db, request, username):
    """Reserve both persistent limits with atomic updates before password hashing."""
    now = utcnow()
    cutoff = now - timedelta(seconds=LOGIN_WINDOW_SECONDS)
    for scope, value, limit in (("account", username, USERNAME_LOGIN_LIMIT),
                                ("address", client_address(request), ADDRESS_LOGIN_LIMIT)):
        key = hashlib.sha256(f"{scope}:{value}".encode()).hexdigest()
        if db.get(LoginThrottle, key) is None:
            try:
                with db.begin_nested():
                    db.add(LoginThrottle(key=key, window_start=now, attempts=0))
                    db.flush()
            except IntegrityError:
                pass  # A concurrent request inserted this bucket.
        db.execute(update(LoginThrottle).where(LoginThrottle.key == key, LoginThrottle.window_start <= cutoff)
                   .values(window_start=now, attempts=0), execution_options={"synchronize_session": False})
        result = db.execute(update(LoginThrottle).where(LoginThrottle.key == key, LoginThrottle.attempts < limit)
                            .values(attempts=LoginThrottle.attempts + 1), execution_options={"synchronize_session": False})
        if result.rowcount != 1:
            db.expire_all()
            bucket = db.get(LoginThrottle, key)
            retry = max(1, math.ceil((bucket.window_start.replace(tzinfo=timezone.utc)
                                    + timedelta(seconds=LOGIN_WINDOW_SECONDS) - now).total_seconds()))
            db.rollback()  # Do not consume the other bucket when already blocked.
            audit_login(db, request, username, "throttled")
            db.commit()
            raise HTTPException(429, "Too many sign-in attempts. Please try again later.",
                                headers={"Retry-After": str(retry)})
    db.commit()


def reserve_api_attempt(db, key_material: str):
    """Limit authenticated API use separately from the sign-in buckets."""
    now = utcnow()
    cutoff = now - timedelta(seconds=API_WINDOW_SECONDS)
    key = hashlib.sha256(f"api:{key_material}".encode()).hexdigest()
    if db.get(LoginThrottle, key) is None:
        try:
            with db.begin_nested():
                db.add(LoginThrottle(key=key, window_start=now, attempts=0))
                db.flush()
        except IntegrityError:
            pass
    db.execute(update(LoginThrottle).where(LoginThrottle.key == key, LoginThrottle.window_start <= cutoff)
               .values(window_start=now, attempts=0), execution_options={"synchronize_session": False})
    result = db.execute(update(LoginThrottle).where(LoginThrottle.key == key, LoginThrottle.attempts < API_LIMIT)
                        .values(attempts=LoginThrottle.attempts + 1), execution_options={"synchronize_session": False})
    if result.rowcount != 1:
        db.expire_all()
        bucket = db.get(LoginThrottle, key)
        retry = max(1, math.ceil((bucket.window_start.replace(tzinfo=timezone.utc)
                                + timedelta(seconds=API_WINDOW_SECONDS) - now).total_seconds()))
        db.rollback()
        raise HTTPException(429, "Too many requests. Please try again later.",
                            headers={"Retry-After": str(retry)})
    db.commit()


def reserve_registration_attempt(db, request, username):
    """Rate-limit registration separately from sign-in.

    These buckets are prefixed so registering cannot exhaust a real user's
    sign-in allowance, and use a longer window because registration is not
    something a legitimate user retries in a loop.
    """
    now = utcnow()
    cutoff = now - timedelta(seconds=REGISTRATION_WINDOW_SECONDS)
    for scope, value, limit in (("reg-account", username, USERNAME_REGISTRATION_LIMIT),
                                ("reg-address", client_address(request), ADDRESS_REGISTRATION_LIMIT)):
        key = hashlib.sha256(f"{scope}:{value}".encode()).hexdigest()
        if db.get(LoginThrottle, key) is None:
            try:
                with db.begin_nested():
                    db.add(LoginThrottle(key=key, window_start=now, attempts=0))
                    db.flush()
            except IntegrityError:
                pass  # A concurrent request inserted this bucket.
        db.execute(update(LoginThrottle).where(LoginThrottle.key == key, LoginThrottle.window_start <= cutoff)
                   .values(window_start=now, attempts=0), execution_options={"synchronize_session": False})
        result = db.execute(update(LoginThrottle).where(LoginThrottle.key == key, LoginThrottle.attempts < limit)
                            .values(attempts=LoginThrottle.attempts + 1), execution_options={"synchronize_session": False})
        if result.rowcount != 1:
            db.expire_all()
            bucket = db.get(LoginThrottle, key)
            retry = max(1, math.ceil((bucket.window_start.replace(tzinfo=timezone.utc)
                                    + timedelta(seconds=REGISTRATION_WINDOW_SECONDS) - now).total_seconds()))
            db.rollback()
            audit_login(db, request, username, "registration_throttled")
            db.commit()
            raise HTTPException(429, "Too many registration attempts. Please try again later.",
                                headers={"Retry-After": str(retry)})
    db.commit()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    salt, expected = stored.split("$")
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex()
    return hmac.compare_digest(actual, expected)


def get_db(request: Request):
    with request.app.state.session_factory() as db:
        yield db


def session_for(request, db):
    token = request.cookies.get("zanaq_session", "")
    session = db.get(LoginSession, hashlib.sha256(token.encode()).hexdigest()) if token else None
    if session is None or session.expires_at.replace(tzinfo=timezone.utc) <= utcnow():
        raise HTTPException(401, "Please sign in")
    return session


def current_user(request: Request, db=Depends(get_db)):
    session = session_for(request, db)
    user = db.get(User, session.user_id)
    if user is None or user.disabled:
        raise HTTPException(401, "Please sign in")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), session.csrf):
            raise HTTPException(403, "Invalid session verification")
    request.state.actor = user.username
    from app.iam import enforce_scope
    enforce_scope(db, request, user, session)
    return user


def writer(user=Depends(current_user)):
    if user.role not in ("administrator", "investigator"):
        raise HTTPException(403, "Your account has read-only access")
    return user


def administrator(user=Depends(current_user)):
    if user.role != "administrator":
        raise HTTPException(403, "Administrator access required")
    return user


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)
    otp: str = Field(default='', max_length=10)
    challenge_id: str = Field(default='', max_length=64)
    personal_username: str = Field(default='', max_length=120)
    personal_password: str = Field(default='', max_length=256)

    @field_validator("username")
    @classmethod
    def normalize(cls, value):
        value = value.strip().lower()
        if not value:
            raise ValueError("Username is required")
        return value


class AccountCreate(Credentials):
    password: str = Field(min_length=12, max_length=256)
    role: Literal["administrator", "investigator", "viewer"]


#: The only role self-registration can ever grant. A registrant must be promoted
#: by an administrator afterwards.
REGISTRATION_ROLE = "viewer"
REGISTRATION_PASSWORD_MINIMUM = 12
REGISTRATION_WINDOW_SECONDS = 3600
USERNAME_REGISTRATION_LIMIT = 3
ADDRESS_REGISTRATION_LIMIT = 10


class RegistrationCreate(BaseModel):
    """Self-registration input.

    Deliberately has no ``role`` field, so the granted role is a server decision
    rather than something a caller can ask for. Reusing :class:`Credentials` would
    have inherited the sign-in-only OTP fields, which are meaningless here.
    """

    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=REGISTRATION_PASSWORD_MINIMUM, max_length=256)

    #: A client that tries to pass ``role`` gets an explicit error instead of a
    #: silently downgraded account, so an escalation attempt cannot look like it
    #: succeeded. The default "ignore unknown fields" behaviour would accept the
    #: request and quietly discard the privilege.
    model_config = ConfigDict(extra="forbid")

    @field_validator("username")
    @classmethod
    def normalize(cls, value):
        value = value.strip().lower()
        if not value:
            raise ValueError("Username is required")
        return value


def registration_enabled(env: Optional[dict] = None) -> bool:
    """Registration is opt-in and off unless the operator explicitly enables it."""
    source = env if env is not None else dict(os.environ)
    return source.get("ZANAQ_ALLOW_REGISTRATION", "").strip().lower() in ("1", "true", "yes", "on")


def user_info(user):
    return {"id": user.id, "username": user.username, "role": user.role, "disabled": bool(user.disabled)}


def clear_sessions(db, user_id: int, keep_hash: str | None = None):
    query = db.query(LoginSession).filter_by(user_id=user_id)
    if keep_hash:
        query = query.filter(LoginSession.token_hash != keep_hash)
    query.delete(synchronize_session=False)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class AdminPassword(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class AccountUpdate(BaseModel):
    disabled: bool


@router.post("/login")
def login(payload: Credentials, request: Request, response: Response, db=Depends(get_db)):
    # Require same-origin browser requests; JSON bodies prevent cross-site form login.
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
        audit_login(db, request, payload.username, "origin_rejected")
        db.commit()
        raise HTTPException(403, "Invalid login origin")
    reserve_login_attempt(db, request, payload.username)
    user = db.query(User).filter_by(username=payload.username).first()
    from app.iam import password_valid, login_identity, record_session
    valid = password_valid(db, user, payload.password)
    if not user or not valid or user.disabled:
        audit_login(db, request, payload.username, "disabled" if user and valid and user.disabled else "invalid_credentials")
        db.commit()
        raise HTTPException(401, "Invalid username or password")
    user, shared_id, verified = login_identity(db, user, payload, request)
    old = request.cookies.get("zanaq_session")
    if old:
        previous = db.get(LoginSession, hashlib.sha256(old.encode()).hexdigest())
        if previous:
            db.delete(previous)
            db.flush()
    token = secrets.token_urlsafe(32)
    session = LoginSession(token_hash=hashlib.sha256(token.encode()).hexdigest(),
                           user_id=user.id, csrf=secrets.token_hex(32),
                           expires_at=utcnow() + timedelta(hours=8))
    db.add(session)
    record_session(db, request, user, session, shared_id, verified)
    audit_login(db, request, user.username, "signed_in")
    db.commit()
    response.set_cookie("zanaq_session", token, httponly=True, samesite="strict",
                        secure=secure_cookie_default(request, request.app.state.transport),
                        max_age=28800)
    response.headers["Cache-Control"] = "no-store"
    return {**user_info(user), "csrf": session.csrf}


@router.get("/me")
def me(request: Request, response: Response, user=Depends(current_user), db=Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    return {**user_info(user), "csrf": session_for(request, db).csrf}


@router.post("/logout")
def logout(request: Request, response: Response, user=Depends(current_user), db=Depends(get_db)):
    db.delete(session_for(request, db))
    audit_login(db, request, user.username, "signed_out")
    db.commit()
    response.delete_cookie("zanaq_session")
    return {"status": "signed_out"}


@router.get("/users")
def list_users(user=Depends(administrator), db=Depends(get_db)):
    return [user_info(row) for row in db.query(User).order_by(User.username).all()]


@router.post("/users", status_code=201)
def create_user(payload: AccountCreate, user=Depends(administrator), db=Depends(get_db)):
    account = User(username=payload.username, password_hash=hash_password(payload.password), role=payload.role)
    db.add(account)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Username already exists")
    return user_info(account)


@router.get("/registration")
def registration_status():
    """Report whether self-registration is available, so the UI can hide the form.

    Unauthenticated by design: a prospective user has no account to sign in with,
    and the only thing revealed is whether the operator opted in.
    """
    return {"enabled": registration_enabled(),
            "password_minimum": REGISTRATION_PASSWORD_MINIMUM,
            "role": REGISTRATION_ROLE}


@router.post("/register", status_code=201)
def register(payload: RegistrationCreate, request: Request, db=Depends(get_db)):
    """Create a read-only account from a self-service signup.

    Unauthenticated by necessity. The controls that matter here, because
    ``/api/auth/*`` is exempt from the general API throttle:
    """
    if not registration_enabled():
        # 404 rather than 403 so the disabled route does not advertise itself.
        raise HTTPException(404, "Not found")
    # Require same-origin browser requests, as sign-in does: a JSON body defeats
    # cross-site form submission, and this is an unauthenticated write.
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
        audit_login(db, request, payload.username, "registration_origin_rejected")
        db.commit()
        raise HTTPException(403, "Invalid registration origin")
    reserve_registration_attempt(db, request, payload.username)
    account = User(username=payload.username,
                   password_hash=hash_password(payload.password),
                   role=REGISTRATION_ROLE, disabled=False)
    db.add(account)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # A taken username is reported plainly because a signup form is useless
        # otherwise, but it is audited so enumeration attempts stay visible.
        audit_login(db, request, payload.username, "registration_duplicate")
        db.commit()
        raise HTTPException(409, "Username already exists")
    audit_login(db, request, account.username, "registered")
    db.commit()
    return {**user_info(account),
            "status": "registered",
            "message": "Account created. An administrator can grant further access."}


@router.post("/password")
def change_password(payload: PasswordChange, request: Request, user=Depends(current_user), db=Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(401, "Current password is incorrect")
    user.password_hash = hash_password(payload.new_password)
    clear_sessions(db, user.id, session_for(request, db).token_hash)
    db.commit()
    return user_info(user)


@router.post("/users/{user_id}/password")
def recover_password(user_id: int, payload: AdminPassword, request: Request, user=Depends(administrator), db=Depends(get_db)):
    account = db.get(User, user_id)
    if account is None:
        raise HTTPException(404, "Account not found")
    account.password_hash = hash_password(payload.password)
    keep = session_for(request, db).token_hash if account.id == user.id else None
    clear_sessions(db, account.id, keep)
    db.commit()
    return user_info(account)


@router.patch("/users/{user_id}")
def update_account(user_id: int, payload: AccountUpdate, user=Depends(administrator), db=Depends(get_db)):
    account = db.get(User, user_id)
    if account is None:
        raise HTTPException(404, "Account not found")
    if account.id == user.id and payload.disabled:
        raise HTTPException(409, "Another administrator must disable this account")
    if payload.disabled and account.role == "administrator" and not account.disabled:
        enabled = db.query(User).filter_by(role="administrator", disabled=False).count()
        if enabled <= 1:
            raise HTTPException(409, "Keep at least one enabled administrator")
    account.disabled = payload.disabled
    if payload.disabled:
        clear_sessions(db, account.id)
    db.commit()
    return user_info(account)


@router.get("/audit")
def authentication_audit(limit: int = Query(default=50, ge=1, le=100),
                         before_id: int | None = Query(default=None, ge=1),
                         user=Depends(administrator), db=Depends(get_db)):
    query = db.query(AuthenticationAudit)
    if before_id is not None:
        query = query.filter(AuthenticationAudit.id < before_id)
    rows = query.order_by(AuthenticationAudit.id.desc()).limit(limit).all()
    return [{"id": row.id, "username": row.username, "client_address": row.client_address,
             "outcome": row.outcome, "created_at": row.created_at.replace(tzinfo=timezone.utc).isoformat()}
            for row in rows]
