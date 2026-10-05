from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, LargeBinary, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base, utcnow

class ReplaySession(Base):
    __tablename__ = "replay_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    platform: Mapped[str] = mapped_column(String(40), index=True)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("endpoint_agents.id"), nullable=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True)
    mode: Mapped[str] = mapped_column(String(20), default="recorded")
    status: Mapped[str] = mapped_column(String(30), default="recorded")
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class ReplayFrame(Base):
    __tablename__ = "replay_frames"
    __table_args__ = (UniqueConstraint("session_id", "sequence"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("replay_sessions.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    text: Mapped[str] = mapped_column(Text, default="")
    fields: Mapped[str] = mapped_column(Text, default="{}")
    original_html: Mapped[str] = mapped_column(Text, default="")
    image: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    document_id: Mapped[int | None] = mapped_column(ForeignKey("search_documents.id"), nullable=True, index=True)

class ResponseCommand(Base):
    __tablename__ = "response_commands"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("endpoint_agents.id"), index=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(40))
    arguments: Mapped[str] = mapped_column(Text, default="{}")
    actor: Mapped[str] = mapped_column(String(120))
    reason: Mapped[str] = mapped_column(String(500))
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[str] = mapped_column(Text, default="{}")
    result_digest: Mapped[str] = mapped_column(String(64), default="")

class ResponseAudit(Base):
    __tablename__ = "response_audits"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("endpoint_agents.id"), index=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    command_id: Mapped[int | None] = mapped_column(ForeignKey("response_commands.id"), nullable=True)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(60))
    detail: Mapped[str] = mapped_column(Text, default="{}")
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
