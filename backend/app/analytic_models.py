from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Float, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base, utcnow


class LiveReceipt(Base):
    __tablename__ = 'live_analytic_receipts'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BiometricBinding(Base):
    __tablename__ = 'biometric_bindings'
    agent_id: Mapped[int] = mapped_column(ForeignKey('endpoint_agents.id'), primary_key=True)
    subject: Mapped[str] = mapped_column(String(120), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class BiometricConsent(Base):
    __tablename__ = 'biometric_consents'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey('endpoint_agents.id'), index=True)
    granted: Mapped[bool] = mapped_column(Boolean)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BiometricProfile(Base):
    __tablename__ = 'biometric_profiles'
    subject: Mapped[str] = mapped_column(String(120), primary_key=True)
    baseline: Mapped[str] = mapped_column(Text)
    sample_ids: Mapped[str] = mapped_column(Text)
    enrolled_by: Mapped[str] = mapped_column(String(120))
    threshold: Mapped[float] = mapped_column(Float, default=3.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BiometricSample(Base):
    __tablename__ = 'biometric_samples'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey('endpoint_events.id'), unique=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey('endpoint_agents.id'), index=True)
    subject: Mapped[str] = mapped_column(String(120), index=True)
    metrics: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default='unenrolled')
    distance: Mapped[float | None] = mapped_column(Float, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey('alerts.id'), nullable=True)

class SyntheticAggregateRelease(Base):
    __tablename__ = 'synthetic_aggregate_releases'
    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    cohort_digest: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
