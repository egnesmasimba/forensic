from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base, utcnow


class SearchDocument(Base):
    __tablename__ = "search_documents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_key: Mapped[str] = mapped_column(String(200), unique=True)
    source_kind: Mapped[str] = mapped_column(String(40), index=True)
    source_id: Mapped[str] = mapped_column(String(120), index=True)
    platform: Mapped[str] = mapped_column(String(40), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    title: Mapped[str] = mapped_column(String(200))
    headers: Mapped[str] = mapped_column(Text, default="[]")
    fields: Mapped[str] = mapped_column(Text, default="[]")
    captions_text: Mapped[str] = mapped_column(Text, default="")
    values_text: Mapped[str] = mapped_column(Text, default="")
    headers_text: Mapped[str] = mapped_column(Text, default="")
    body: Mapped[str] = mapped_column(Text)
    partial: Mapped[bool] = mapped_column(default=False)
    created_by: Mapped[str] = mapped_column(String(120), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SearchOutbox(Base):
    __tablename__ = "search_outbox"
    source_key: Mapped[str] = mapped_column(String(200), primary_key=True)
    revision: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
