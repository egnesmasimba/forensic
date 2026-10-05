from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from app.models import Base, utcnow


class PrivacySetting(Base):
    __tablename__ = 'privacy_settings'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    consent_required: Mapped[bool] = mapped_column(Boolean, default=True)
    council_required: Mapped[bool] = mapped_column(Boolean, default=False)
    council_reference: Mapped[str] = mapped_column(String(500), default='')
    council_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    purpose: Mapped[str] = mapped_column(String(500), default='')
    legal_basis: Mapped[str] = mapped_column(String(100), default='')
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    automatic_retention: Mapped[bool] = mapped_column(Boolean, default=False)
    online_months: Mapped[int] = mapped_column(Integer, default=0)
    secret: Mapped[str] = mapped_column(String(64))


class PrivacyConsent(Base):
    __tablename__ = 'privacy_consents'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey('endpoint_agents.id'), index=True)
    purpose: Mapped[str] = mapped_column(String(500))
    granted: Mapped[bool] = mapped_column(Boolean)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PrivacyAudit(Base):
    __tablename__ = 'privacy_audits'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[str] = mapped_column(Text, default='{}')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EducationPolicy(Base):
    __tablename__ = 'education_policies'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    title: Mapped[str] = mapped_column(String(160), default='Policy reminder')
    message: Mapped[str] = mapped_column(String(2000), default='This activity needs review. Please follow your organization policy.')
    education: Mapped[str] = mapped_column(String(2000), default='Review the policy before repeating this activity.')
    training_url: Mapped[str] = mapped_column(String(500), default='')
    manager: Mapped[str] = mapped_column(String(120), default='')
    escalation_count: Mapped[int] = mapped_column(Integer, default=3)
    reminder_minutes: Mapped[int] = mapped_column(Integer, default=60)


class PolicyWarning(Base):
    __tablename__ = 'policy_warnings'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey('endpoint_agents.id'), index=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey('endpoint_events.id'), nullable=True, unique=True)
    title: Mapped[str] = mapped_column(String(160))
    message: Mapped[str] = mapped_column(String(2000))
    education: Mapped[str] = mapped_column(String(2000))
    training_url: Mapped[str] = mapped_column(String(500), default='')
    manager: Mapped[str] = mapped_column(String(120), default='')
    level: Mapped[int] = mapped_column(Integer, default=1)
    state: Mapped[str] = mapped_column(String(20), default='queued')
    training_state: Mapped[str] = mapped_column(String(20), default='none')
    deliveries: Mapped[int] = mapped_column(Integer, default=0)
    next_delivery_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SubjectRequest(Base):
    __tablename__ = "subject_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    regime: Mapped[str] = mapped_column(String(20))
    kind: Mapped[str] = mapped_column(String(20))
    entity_ref: Mapped[str] = mapped_column(String(120), index=True)
    status: Mapped[str] = mapped_column(String(20), default="open")
    reason: Mapped[str] = mapped_column(String(300), default="")
    package: Mapped[str] = mapped_column(Text, default="{}")
    actor: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SubjectConsent(Base):
    __tablename__ = "subject_consents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_ref: Mapped[str] = mapped_column(String(120), index=True)
    purpose: Mapped[str] = mapped_column(String(300))
    granted: Mapped[bool] = mapped_column(Boolean)
    actor: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ImpactAssessment(Base):
    __tablename__ = "impact_assessments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(160))
    scope: Mapped[str] = mapped_column(String(2000))
    risks: Mapped[str] = mapped_column(String(2000))
    mitigations: Mapped[str] = mapped_column(String(2000), default="")
    status: Mapped[str] = mapped_column(String(20), default="draft")
    actor: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DisclosureRecord(Base):
    __tablename__ = "disclosure_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_ref: Mapped[str] = mapped_column(String(120), index=True)
    recipient: Mapped[str] = mapped_column(String(120))
    purpose: Mapped[str] = mapped_column(String(200))
    actor: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SupervisionReview(Base):
    __tablename__ = "supervision_reviews"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_ref: Mapped[str] = mapped_column(String(120), index=True)
    decision: Mapped[str] = mapped_column(String(20))
    note: Mapped[str] = mapped_column(String(1000), default="")
    actor: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ArchiveRecord(Base):
    __tablename__ = "archive_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_table: Mapped[str] = mapped_column(String(40))
    source_id: Mapped[int] = mapped_column(Integer, index=True)
    entity_ref: Mapped[str] = mapped_column(String(120), index=True)
    sha256: Mapped[str] = mapped_column(String(64))
    body: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EducationAudit(Base):
    __tablename__ = 'education_audits'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    warning_id: Mapped[int] = mapped_column(ForeignKey('policy_warnings.id'), index=True)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
