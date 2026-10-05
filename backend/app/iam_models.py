from datetime import datetime
from sqlalchemy import ForeignKey, String, Text, Integer, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base, utcnow


class IdentityPolicy(Base):
    __tablename__ = 'identity_policies'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    shared: Mapped[bool] = mapped_column(Boolean, default=False)
    members: Mapped[str] = mapped_column(Text, default='[]')
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False)
    modules: Mapped[str] = mapped_column(Text, default='["*"]')
    directory_dn: Mapped[str] = mapped_column(Text, default='')


class LoginSchedule(Base):
    __tablename__ = 'login_schedules'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    start_hour_utc: Mapped[int] = mapped_column(Integer)
    end_hour_utc: Mapped[int] = mapped_column(Integer)


class PrivilegedRecording(Base):
    __tablename__ = 'privileged_recordings'
    replay_id: Mapped[int] = mapped_column(ForeignKey('replay_sessions.id'), primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey('privileged_requests.id'), index=True)


class IdentityFactor(Base):
    __tablename__ = 'identity_factors'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    kind: Mapped[str] = mapped_column(String(10))
    secret: Mapped[str] = mapped_column(Text)
    counter: Mapped[int] = mapped_column(Integer, default=-1)


class FactorEnrollment(Base):
    __tablename__ = 'factor_enrollments'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    kind: Mapped[str] = mapped_column(String(10))
    secret: Mapped[str] = mapped_column(Text)
    counter: Mapped[int] = mapped_column(Integer, default=-1)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IdentityChallenge(Base):
    __tablename__ = 'identity_challenges'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    purpose: Mapped[str] = mapped_column(String(120))
    digest: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class IdentitySession(Base):
    __tablename__ = 'identity_sessions'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    shared_user_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    address: Mapped[str] = mapped_column(String(200))
    terminal: Mapped[str] = mapped_column(String(64))
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IdentityAudit(Base):
    __tablename__ = 'identity_audit'
    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(80), index=True)
    detail: Mapped[str] = mapped_column(Text, default='{}')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PrivilegedRequest(Base):
    __tablename__ = 'privileged_requests'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    resource: Mapped[str] = mapped_column(String(120))
    reason: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), default='pending')
    approved_by: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_session: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PrivilegedActivity(Base):
    __tablename__ = 'privileged_activity'
    id: Mapped[int] = mapped_column(primary_key=True)
    session_hash: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(120))
    shared_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    method: Mapped[str] = mapped_column(String(12))
    path: Mapped[str] = mapped_column(String(250))
    status: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
