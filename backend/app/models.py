from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    case_type: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(40), default="new", index=True)
    risk: Mapped[str] = mapped_column(String(20), default="medium")
    score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    assignee: Mapped[str] = mapped_column(String(120), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    conclusion: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    alerts: Mapped[list["Alert"]] = relationship(back_populates="case")
    notes: Mapped[list["Note"]] = relationship(back_populates="case")
    activities: Mapped[list["Activity"]] = relationship(back_populates="case")
    attachments: Mapped[list["Attachment"]] = relationship(back_populates="case")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    status: Mapped[str] = mapped_column(String(40), default="open", index=True)
    entity_type: Mapped[str] = mapped_column(String(40), default="other")
    entity_ref: Mapped[str] = mapped_column(String(120), default="")
    channel: Mapped[str] = mapped_column(String(80), default="")
    assignee: Mapped[str] = mapped_column(String(120), default="")
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case | None] = relationship(back_populates="alerts")


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    author: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="notes")


class Attachment(Base):
    __tablename__ = "attachments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    original_name: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(120))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    uploaded_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="attachments")


class OcrReading(Base):
    __tablename__ = "ocr_readings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attachment_id: Mapped[int] = mapped_column(ForeignKey("attachments.id"), unique=True, index=True)
    language: Mapped[str] = mapped_column(String(20))
    engine: Mapped[str] = mapped_column(String(40), default="tesseract")
    text: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(default=0.0)
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Activity(Base):
    __tablename__ = "activities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    action: Mapped[str] = mapped_column(String(40))
    detail: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="activities")


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(20))
    disabled: Mapped[bool] = mapped_column(default=False)


class ReportTemplate(Base):
    __tablename__ = "report_templates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    columns: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(40), default="")
    query: Mapped[str] = mapped_column(String(200), default="")
    min_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sort: Mapped[str] = mapped_column(String(20), default="score")
    order: Mapped[str] = mapped_column(String(4), default="desc")
    created_by: Mapped[str] = mapped_column(String(120), default="")


class ReportDefinition(Base):
    __tablename__ = "report_definitions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    definition: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionSetting(Base):
    __tablename__ = "detection_settings"
    rule_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    label: Mapped[str] = mapped_column(String(120))
    threshold: Mapped[int] = mapped_column(Integer)
    score: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(default=True)


class LoginSession(Base):
    __tablename__ = "login_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    csrf: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CaseField(Base):
    __tablename__ = "case_fields"
    __table_args__ = (UniqueConstraint("case_type", "key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_type: Mapped[str] = mapped_column(String(80), index=True)
    key: Mapped[str] = mapped_column(String(40))
    label: Mapped[str] = mapped_column(String(80))
    required: Mapped[bool] = mapped_column(default=False)
    position: Mapped[int] = mapped_column(Integer, default=0)


class CaseFieldValue(Base):
    __tablename__ = "case_field_values"
    __table_args__ = (UniqueConstraint("case_id", "field_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    field_id: Mapped[int] = mapped_column(ForeignKey("case_fields.id"), index=True)
    value: Mapped[str] = mapped_column(Text, default="")


class RouteRule(Base):
    __tablename__ = "route_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    case_type: Mapped[str] = mapped_column(String(80), default="")
    min_risk: Mapped[str] = mapped_column(String(20), default="low")
    assignee: Mapped[str] = mapped_column(String(120))
    position: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(default=True)


class EntityMark(Base):
    __tablename__ = "entity_marks"
    __table_args__ = (UniqueConstraint("entity_type", "entity_ref"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(40))
    entity_ref: Mapped[str] = mapped_column(String(120))
    fraudulent: Mapped[bool] = mapped_column(default=False)
    updated_by: Mapped[str] = mapped_column(String(120), default="")


class AlertPolicy(Base):
    __tablename__ = "alert_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(20))
    entity_ref: Mapped[str] = mapped_column(String(120), default="")
    title: Mapped[str] = mapped_column(String(200), default="")
    channel: Mapped[str] = mapped_column(String(80), default="")
    enabled: Mapped[bool] = mapped_column(default=True)


class AlertRoute(Base):
    __tablename__ = "alert_routes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    channel: Mapped[str] = mapped_column(String(80), default="")
    min_score: Mapped[int] = mapped_column(Integer, default=0)
    assignee: Mapped[str] = mapped_column(String(120))
    delivery: Mapped[str] = mapped_column(String(20), default="app")
    enabled: Mapped[bool] = mapped_column(default=True)
    position: Mapped[int] = mapped_column(Integer, default=0)


class EventCorrelation(Base):
    __tablename__ = "event_correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_key: Mapped[str] = mapped_column(String(64), index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True)
    entity_ref: Mapped[str] = mapped_column(String(120), default="")
    channel: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectedArtifact(Base):
    __tablename__ = "collected_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    filename: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(20))
    size: Mapped[int] = mapped_column(Integer)
    summary: Mapped[str] = mapped_column(Text, default="")
    imported_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LayoutDefinition(Base):
    __tablename__ = "layout_definitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    mode: Mapped[str] = mapped_column(String(20))
    delimiter: Mapped[str] = mapped_column(String(4), default="")
    spec: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(120), default="")


class QueueMessage(Base):
    __tablename__ = "queue_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectionSource(Base):
    __tablename__ = "collection_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(20))
    filename: Mapped[str] = mapped_column(String(255), default="")
    table_name: Mapped[str] = mapped_column(String(64), default="")
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(200), default="")


class ImportedEvent(Base):
    __tablename__ = "imported_events"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(80), index=True)
    event_id: Mapped[str] = mapped_column(String(120))
    payload: Mapped[str] = mapped_column(Text)
    imported_by: Mapped[str] = mapped_column(String(120))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)


class LoginThrottle(Base):
    __tablename__ = "login_throttles"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class ReportSchedule(Base):
    __tablename__ = "report_schedules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_id: Mapped[int] = mapped_column(ForeignKey("report_templates.id"), index=True)
    interval_seconds: Mapped[int] = mapped_column(Integer)
    next_run: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScheduledExport(Base):
    __tablename__ = "scheduled_exports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    schedule_id: Mapped[int] = mapped_column(ForeignKey("report_schedules.id"), unique=True)
    body: Mapped[str] = mapped_column(Text)
    row_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthenticationAudit(Base):
    __tablename__ = "authentication_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120))
    client_address: Mapped[str] = mapped_column(String(200))
    outcome: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccessLog(Base):
    __tablename__ = "access_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(120), default="")
    method: Mapped[str] = mapped_column(String(12))
    path: Mapped[str] = mapped_column(String(200))
    status: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NetworkCapture(Base):
    __tablename__ = "network_captures"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    imported_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sha256: Mapped[str] = mapped_column(String(64))
    raw: Mapped[bytes] = mapped_column(LargeBinary)
    report: Mapped[str] = mapped_column(Text)


class NetworkMessageLayout(Base):
    __tablename__ = "network_message_layouts"
    __table_args__ = (UniqueConstraint("name", "version"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    version: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(40))
    direction: Mapped[str] = mapped_column(String(10), default="both")
    offset: Mapped[int] = mapped_column(Integer, default=0)
    encoding: Mapped[str] = mapped_column(String(20), default="ascii")
    byteorder: Mapped[str] = mapped_column(String(10), default="big")
    declaration: Mapped[str] = mapped_column(Text)
    definition: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    enabled: Mapped[bool] = mapped_column(default=True)
    identify_field: Mapped[str] = mapped_column(String(80), default="")


class ApplicationRule(Base):
    __tablename__ = "application_rules"
    __table_args__ = (UniqueConstraint("field", "pattern"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    field: Mapped[str] = mapped_column(String(20))
    pattern: Mapped[str] = mapped_column(String(80))
    score: Mapped[int] = mapped_column(Integer, default=40)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SiteRule(Base):
    __tablename__ = "site_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(253), unique=True)
    category: Mapped[str] = mapped_column(String(80))
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SitePolicy(Base):
    __tablename__ = "site_policies"

    category: Mapped[str] = mapped_column(String(80), primary_key=True)
    denied: Mapped[bool] = mapped_column(default=False)


class SiteVisit(Base):
    __tablename__ = "site_visits"
    __table_args__ = (UniqueConstraint("source", "visit_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(80))
    visit_id: Mapped[str] = mapped_column(String(80))
    occurred_at: Mapped[str] = mapped_column(String(40))
    user: Mapped[str] = mapped_column(String(120), index=True)
    host: Mapped[str] = mapped_column(String(253))
    seconds: Mapped[int] = mapped_column(Integer, default=0)
    category: Mapped[str] = mapped_column(String(80), index=True)
    imported_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EndpointAgentGroup(Base):
    __tablename__ = "endpoint_agent_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    default_config: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EndpointAgent(Base):
    __tablename__ = "endpoint_agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    machine_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(200))
    os: Mapped[str] = mapped_column(String(20), index=True)
    os_version: Mapped[str] = mapped_column(String(80), default="")
    arch: Mapped[str] = mapped_column(String(20), default="")
    agent_version: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(20), default="registered", index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    tags: Mapped[str] = mapped_column(Text, default="[]")
    group_id: Mapped[int | None] = mapped_column(ForeignKey("endpoint_agent_groups.id"), nullable=True, index=True)
    stealth_mode: Mapped[bool] = mapped_column(default=False)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    fingerprint: Mapped[str] = mapped_column(String(256), default="")
    cpu_pct: Mapped[float] = mapped_column(default=0.0)
    memory_pct: Mapped[float] = mapped_column(default=0.0)
    disk_free_bytes: Mapped[int] = mapped_column(default=0)
    last_event_id: Mapped[int] = mapped_column(default=0)
    update_status: Mapped[str] = mapped_column(String(40), default="")
    pending_command: Mapped[str] = mapped_column(Text, default="")

    group: Mapped[EndpointAgentGroup | None] = relationship()
    events: Mapped[list["EndpointEvent"]] = relationship(back_populates="agent")
    tamper_events: Mapped[list["EndpointTamperEvent"]] = relationship(back_populates="agent")


class EndpointEvent(Base):
    __tablename__ = "endpoint_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("endpoint_agents.id"), index=True)
    type: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="low", index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=utcnow)
    payload: Mapped[str] = mapped_column(Text, default="{}")
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True, index=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    linked_by: Mapped[str] = mapped_column(String(120), default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    agent: Mapped[EndpointAgent] = relationship(back_populates="events")
    alert: Mapped[Alert | None] = relationship()
    case: Mapped[Case | None] = relationship()


class EndpointTamperEvent(Base):
    __tablename__ = "endpoint_tamper_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("endpoint_agents.id"), index=True)
    type: Mapped[str] = mapped_column(String(40), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    resolved: Mapped[bool] = mapped_column(default=False)

    agent: Mapped[EndpointAgent] = relationship(back_populates="tamper_events")


class ScreenDefinition(Base):
    __tablename__ = "screen_definitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    markers: Mapped[list["ScreenMarker"]] = relationship(back_populates="screen", order_by="ScreenMarker.id")
    fields: Mapped[list["ScreenField"]] = relationship(back_populates="screen", order_by="ScreenField.id")


class ScreenMarker(Base):
    __tablename__ = "screen_markers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    screen_id: Mapped[int] = mapped_column(ForeignKey("screen_definitions.id"), index=True)
    text: Mapped[str] = mapped_column(String(80))
    line: Mapped[int] = mapped_column(Integer, default=0)

    screen: Mapped[ScreenDefinition] = relationship(back_populates="markers")


class ScreenField(Base):
    __tablename__ = "screen_fields"
    __table_args__ = (UniqueConstraint("screen_id", "name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    screen_id: Mapped[int] = mapped_column(ForeignKey("screen_definitions.id"), index=True)
    name: Mapped[str] = mapped_column(String(40))
    label: Mapped[str] = mapped_column(String(80))
    line: Mapped[int] = mapped_column(Integer)
    start_column: Mapped[int] = mapped_column(Integer)
    length: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(20), default="read")

    screen: Mapped[ScreenDefinition] = relationship(back_populates="fields")


class BusinessProcess(Base):
    __tablename__ = "business_processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    steps: Mapped[list["ProcessStep"]] = relationship(back_populates="process", order_by="ProcessStep.position")


class ProcessStep(Base):
    __tablename__ = "process_steps"
    __table_args__ = (
        UniqueConstraint("process_id", "position"),
        UniqueConstraint("process_id", "screen_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    process_id: Mapped[int] = mapped_column(ForeignKey("business_processes.id"), index=True)
    screen_id: Mapped[int] = mapped_column(ForeignKey("screen_definitions.id"), index=True)
    position: Mapped[int] = mapped_column(Integer)

    process: Mapped[BusinessProcess] = relationship(back_populates="steps")
    screen: Mapped[ScreenDefinition] = relationship()


class ScreenHit(Base):
    __tablename__ = "screen_hits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurrence_key: Mapped[str] = mapped_column(String(32), index=True)
    process_id: Mapped[int | None] = mapped_column(ForeignKey("business_processes.id"), nullable=True, index=True)
    screen_id: Mapped[int] = mapped_column(ForeignKey("screen_definitions.id"), index=True)
    step_position: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(20))
    attachment_id: Mapped[int | None] = mapped_column(ForeignKey("attachments.id"), nullable=True)
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    screen: Mapped[ScreenDefinition] = relationship()
    audits: Mapped[list["FieldAudit"]] = relationship(back_populates="hit", order_by="FieldAudit.id")


class FieldAudit(Base):
    __tablename__ = "field_audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hit_id: Mapped[int] = mapped_column(ForeignKey("screen_hits.id"), index=True)
    name: Mapped[str] = mapped_column(String(40))
    label: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(String(500), default="")

    hit: Mapped[ScreenHit] = relationship(back_populates="audits")


class BusinessEntity(Base):
    __tablename__ = "business_entities"
    __table_args__ = (UniqueConstraint("entity_type", "entity_ref"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(40))
    entity_ref: Mapped[str] = mapped_column(String(120))
    static_info: Mapped[str] = mapped_column(Text, default="{}")
    dynamic_info: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Fact(Base):
    __tablename__ = "facts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_key: Mapped[str] = mapped_column(String(200), unique=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    occurred_at: Mapped[str] = mapped_column(String(40))
    entity_type: Mapped[str] = mapped_column(String(40), index=True)
    entity_ref: Mapped[str] = mapped_column(String(120), index=True)
    name: Mapped[str] = mapped_column(String(40), index=True)
    numeric_value: Mapped[float] = mapped_column(default=0.0)
    text_value: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalyticRule(Base):
    __tablename__ = "analytic_rules"
    __table_args__ = (UniqueConstraint("name", "version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    version: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(default=True)
    entity_type: Mapped[str] = mapped_column(String(40))
    fact_name: Mapped[str] = mapped_column(String(40))
    aggregation: Mapped[str] = mapped_column(String(10))
    comparator: Mapped[str] = mapped_column(String(10))
    threshold: Mapped[float] = mapped_column(default=0.0)
    score: Mapped[int] = mapped_column(Integer, default=70)
    attribute_key: Mapped[str] = mapped_column(String(40), default="")
    attribute_value: Mapped[str] = mapped_column(String(80), default="")
    options: Mapped[str] = mapped_column(Text, default="{}")
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RiskSetting(Base):
    __tablename__ = "risk_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    threshold: Mapped[int] = mapped_column(Integer, default=100)


class RiskEvent(Base):
    __tablename__ = "risk_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(40), index=True)
    entity_ref: Mapped[str] = mapped_column(String(120), index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    delta: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IndicatorDefinition(Base):
    __tablename__ = "indicator_definitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(40), unique=True)
    label: Mapped[str] = mapped_column(String(160))
    fact_name: Mapped[str] = mapped_column(String(40))
    measure: Mapped[str] = mapped_column(String(20))
    period: Mapped[str] = mapped_column(String(10))
    window_days: Mapped[int] = mapped_column(Integer, default=90)
    built_in: Mapped[bool] = mapped_column(Boolean, default=False)


class BaselineSetting(Base):
    __tablename__ = "baseline_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sigma: Mapped[float] = mapped_column(Float, default=3.0)
    minimum_periods: Mapped[int] = mapped_column(Integer, default=4)


class BehaviorDeviation(Base):
    __tablename__ = "behavior_deviations"
    __table_args__ = (UniqueConstraint("entity_ref", "indicator_key", "period_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_ref: Mapped[str] = mapped_column(String(120), index=True)
    indicator_key: Mapped[str] = mapped_column(String(40))
    period_key: Mapped[str] = mapped_column(String(20))
    latest: Mapped[float] = mapped_column(Float, default=0.0)
    mean: Mapped[float] = mapped_column(Float, default=0.0)
    deviation: Mapped[float] = mapped_column(Float, default=0.0)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChannelEvent(Base):
    __tablename__ = "channel_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_key: Mapped[str] = mapped_column(String(200), unique=True)
    channel: Mapped[str] = mapped_column(String(20), index=True)
    user: Mapped[str] = mapped_column(String(120), index=True)
    occurred_at: Mapped[str] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(40), default="")
    reference: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Prediction(Base):
    __tablename__ = "predictions"
    __table_args__ = (UniqueConstraint("entity_ref", "kind", "period_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_ref: Mapped[str] = mapped_column(String(120), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    score: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[str] = mapped_column(String(200), default="")
    period_key: Mapped[str] = mapped_column(String(20))
    outcome: Mapped[str] = mapped_column(String(20), default="")
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SyntheticSalt(Base):
    __tablename__ = "synthetic_salts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret: Mapped[str] = mapped_column(String(64))


class SyntheticProfile(Base):
    __tablename__ = "synthetic_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True)
    entity_ref: Mapped[str] = mapped_column(String(120))
    payload: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LibraryRule(Base):
    __tablename__ = "library_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(40), unique=True)
    framework: Mapped[str] = mapped_column(String(20))
    name: Mapped[str] = mapped_column(String(120))
    fact_name: Mapped[str] = mapped_column(String(40))
    measure: Mapped[str] = mapped_column(String(20))
    threshold: Mapped[float] = mapped_column(Float, default=0.0)
    score: Mapped[int] = mapped_column(Integer, default=70)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    customized: Mapped[bool] = mapped_column(Boolean, default=False)
    catalog_version: Mapped[int] = mapped_column(Integer, default=1)
    window_days: Mapped[int] = mapped_column(Integer, default=7)


class LibraryFinding(Base):
    __tablename__ = "library_findings"
    __table_args__ = (UniqueConstraint("rule_key", "entity_ref", "period_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_key: Mapped[str] = mapped_column(String(40))
    entity_ref: Mapped[str] = mapped_column(String(120), index=True)
    period_key: Mapped[str] = mapped_column(String(20))
    value: Mapped[float] = mapped_column(Float, default=0.0)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuleFinding(Base):
    __tablename__ = "rule_findings"
    __table_args__ = (UniqueConstraint("rule_id", "entity_type", "entity_ref"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("analytic_rules.id"), index=True)
    entity_type: Mapped[str] = mapped_column(String(40))
    entity_ref: Mapped[str] = mapped_column(String(120))
    value: Mapped[float] = mapped_column(default=0.0)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DlpSetting(Base):
    __tablename__ = "dlp_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    min_matches: Mapped[int] = mapped_column(Integer, default=1)
    score: Mapped[int] = mapped_column(Integer, default=70)
    ip_terms: Mapped[str] = mapped_column(Text, default="confidential,proprietary,trade secret")
    customer_terms: Mapped[str] = mapped_column(Text, default="customer")
    financial_terms: Mapped[str] = mapped_column(Text, default="account number,routing number")


class DlpAudit(Base):
    __tablename__ = "dlp_audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(120), default="")
    change: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UsbDevice(Base):
    __tablename__ = "usb_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    serial: Mapped[str] = mapped_column(String(80), unique=True)
    label: Mapped[str] = mapped_column(String(80), default="")
    allowed: Mapped[bool] = mapped_column(Boolean, default=False)


class UsbActivity(Base):
    __tablename__ = "usb_activity"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    serial: Mapped[str] = mapped_column(String(80), index=True)
    user: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(40), default="")
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    occurred_at: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CloudAllow(Base):
    __tablename__ = "cloud_allows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(120), unique=True)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)


class FileChange(Base):
    __tablename__ = "file_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str] = mapped_column(String(120), index=True)
    action: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(String(200), default="")
    target: Mapped[str] = mapped_column(String(200), default="")
    occurred_at: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PermissionAllow(Base):
    __tablename__ = "permission_allows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    principal: Mapped[str] = mapped_column(String(120), unique=True)


class PermissionChange(Base):
    __tablename__ = "permission_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str] = mapped_column(String(120), default="")
    path: Mapped[str] = mapped_column(String(200), default="")
    principal: Mapped[str] = mapped_column(String(120), default="")
    change: Mapped[str] = mapped_column(String(20), default="")
    occurred_at: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PrintJob(Base):
    __tablename__ = "print_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str] = mapped_column(String(120), default="")
    printer: Mapped[str] = mapped_column(String(120), default="")
    document: Mapped[str] = mapped_column(String(200), default="")
    pages: Mapped[int] = mapped_column(Integer, default=0)
    size: Mapped[int] = mapped_column(Integer, default=0)
    occurred_at: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScreenshotAttempt(Base):
    __tablename__ = "screenshot_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str] = mapped_column(String(120), default="")
    application: Mapped[str] = mapped_column(String(120), default="")
    occurred_at: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CommandAudit(Base):
    __tablename__ = "command_audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str] = mapped_column(String(120), default="")
    command: Mapped[str] = mapped_column(String(300), default="")
    finding: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    trigger: Mapped[str] = mapped_column(String(20))
    steps: Mapped[str] = mapped_column(String(120), default="notify")
    message: Mapped[str] = mapped_column(String(300), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AutomationRun(Base):
    __tablename__ = "automation_runs"
    __table_args__ = (UniqueConstraint("playbook_id", "alert_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    playbook_id: Mapped[int] = mapped_column(ForeignKey("playbooks.id"), index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    steps_done: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NoticeTemplate(Base):
    __tablename__ = "notice_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject: Mapped[str] = mapped_column(String(160), default="Review {title}")
    body: Mapped[str] = mapped_column(String(500), default="{user}: {title} scored {score}.")
    throttle_minutes: Mapped[int] = mapped_column(Integer, default=15)
    escalate_minutes: Mapped[int] = mapped_column(Integer, default=60)


class Notice(Base):
    __tablename__ = "notices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str] = mapped_column(String(120), index=True)
    channel: Mapped[str] = mapped_column(String(20), default="app")
    subject: Mapped[str] = mapped_column(String(160), default="")
    body: Mapped[str] = mapped_column(String(500), default="")
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    escalation: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(20), default="open")
    detail: Mapped[str] = mapped_column(String(500), default="")
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OutboundRecipient(Base):
    """An address an outbound alert may be delivered to.

    Delivery targets are never inferred from the alert being delivered. An
    alert's ``entity_ref`` is the subject of the investigation — a compromised
    host, or a malicious sender — so sending alert text to whatever address
    that happens to be would hand the attacker a live feed and, on a spoofed
    channel, exfiltrate the finding. Targets are therefore configured here,
    explicitly, by an operator.
    """

    __tablename__ = "outbound_recipients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: ``email`` or ``sms``.
    channel: Mapped[str] = mapped_column(String(20), index=True)
    address: Mapped[str] = mapped_column(String(200), index=True)
    #: Optional routing hint; a delivery only goes to a recipient whose scope
    #: is blank or matches the alert channel.
    scope: Mapped[str] = mapped_column(String(40), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditExportSchedule(Base):
    """A scheduled, formatted export of the compliance audit log.

    Exports are incremental: ``last_id`` is the highest audit id already
    written, so each run emits only what is new. The target is a directory on
    the local host, never a remote endpoint.
    """

    __tablename__ = "audit_export_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    #: ``csv``, ``jsonl``, ``cef`` or ``syslog``.
    format: Mapped[str] = mapped_column(String(20), default="cef")
    #: JSON-encoded subset of audit columns to include.
    columns: Mapped[str] = mapped_column(String(300), default='["id","actor","action","detail","created_at"]')
    #: Optional ``{field}`` template; validated against the chosen columns.
    template: Mapped[str] = mapped_column(String(500), default="")
    directory: Mapped[str] = mapped_column(String(300))
    #: Also forward each run to the configured SIEM. Off by default: a local
    #: export must never start leaving the deployment because a collector
    #: happened to be configured in the environment.
    forward_to_siem: Mapped[bool] = mapped_column(Boolean, default=False)
    filename: Mapped[str] = mapped_column(String(80), default="audit-export.log")
    interval_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    next_run: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_id: Mapped[int] = mapped_column(default=0)
    last_rows: Mapped[int] = mapped_column(default=0)
    last_path: Mapped[str] = mapped_column(String(300), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Delivery(Base):
    """One recorded attempt to deliver an alert outside the deployment."""

    __tablename__ = "deliveries"
    __table_args__ = (UniqueConstraint("message_id", "recipient", name="uq_delivery_target"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Stable key so a retried playbook run cannot double-send.
    message_id: Mapped[str] = mapped_column(String(32), index=True)
    channel: Mapped[str] = mapped_column(String(20), default="")
    recipient: Mapped[str] = mapped_column(String(200))
    notice_id: Mapped[int | None] = mapped_column(ForeignKey("notices.id"), nullable=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="failed", index=True)
    detail: Mapped[str] = mapped_column(String(300), default="")
    attempts: Mapped[int] = mapped_column(default=1)
    permanent: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Ticket(Base):
    __tablename__ = "tickets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system: Mapped[str] = mapped_column(String(20), default="custom")
    title: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(20), default="open")
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    #: Identifier the external system assigned (ServiceNow ``sys_id``, Jira
    #: ``key``, or the bridge's own id). Indexed rather than unique so that
    #: many un-pushed local tickets can share an empty value; uniqueness of a
    #: populated pair is enforced when pushing.
    external_id: Mapped[str] = mapped_column(String(120), default="", index=True)
    #: Human-facing reference the external system showed the user.
    external_ref: Mapped[str] = mapped_column(String(120), default="")
    #: Last push or status-update failure, so a sync problem is visible on the
    #: ticket instead of only in a log the investigator never sees.
    last_error: Mapped[str] = mapped_column(String(300), default="")
    pushed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LocalTrigger(Base):
    __tablename__ = "local_triggers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    detail: Mapped[str] = mapped_column(String(300), default="")
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    confirmed_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AutomationAudit(Base):
    __tablename__ = "automation_audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(120), default="")
    change: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentPackageManifest(Base):
    __tablename__ = "agent_package_manifests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[str] = mapped_column(String(32), index=True)
    os: Mapped[str] = mapped_column(String(20), index=True)
    arch: Mapped[str] = mapped_column(String(20), default="any")
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(default=0)
    download_url: Mapped[str] = mapped_column(String(512), default="")
    release_notes: Mapped[str] = mapped_column(Text, default="")
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    active: Mapped[bool] = mapped_column(default=True, index=True)
