from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base, utcnow


class MailEvidence(Base):
    __tablename__ = "mail_evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("endpoint_agents.id"), nullable=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("endpoint_events.id"), nullable=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    client: Mapped[str] = mapped_column(String(40))
    subject: Mapped[str] = mapped_column(String(200))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    captured_by: Mapped[str] = mapped_column(String(120))
    report: Mapped[str] = mapped_column(Text)
    raw: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MailPolicy(Base):
    __tablename__ = "mail_policy"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    internal_domains: Mapped[str] = mapped_column(Text, default="[]")
    sensitive_terms: Mapped[str] = mapped_column(Text)


class AgentEventReceipt(Base):
    __tablename__ = "agent_event_receipts"
    agent_id: Mapped[int] = mapped_column(ForeignKey("endpoint_agents.id"), primary_key=True)
    event_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    event_id: Mapped[int] = mapped_column(ForeignKey("endpoint_events.id"))
