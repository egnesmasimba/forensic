from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_serializer, field_validator

from app.constants import ALERT_STATUSES, CASE_TYPES, ENTITY_TYPES, RISK_LEVELS, STATUSES


def _as_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    case_type: str
    risk: str = "medium"
    score: int = Field(default=0, ge=0, le=1000)
    assignee: str = Field(default="", max_length=120)
    summary: str = Field(default="", max_length=4000)
    fields: dict[str, str] = Field(default_factory=dict)
    actor: str = Field(default="Investigator", min_length=1, max_length=120)

    @field_validator("case_type")
    @classmethod
    def known_type(cls, value: str) -> str:
        if value not in CASE_TYPES:
            raise ValueError("Unknown case type")
        return value

    @field_validator("risk")
    @classmethod
    def known_risk(cls, value: str) -> str:
        if value not in RISK_LEVELS:
            raise ValueError("Unknown risk level")
        return value


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    case_type: str | None = None
    risk: str | None = None
    score: int | None = Field(default=None, ge=0, le=1000)
    assignee: str | None = Field(default=None, max_length=120)
    summary: str | None = Field(default=None, max_length=4000)
    conclusion: str | None = Field(default=None, max_length=4000)
    fields: dict[str, str] | None = None
    actor: str = Field(default="Investigator", min_length=1, max_length=120)

    @field_validator("case_type")
    @classmethod
    def known_type(cls, value: str | None) -> str | None:
        if value is not None and value not in CASE_TYPES:
            raise ValueError("Unknown case type")
        return value

    @field_validator("risk")
    @classmethod
    def known_risk(cls, value: str | None) -> str | None:
        if value is not None and value not in RISK_LEVELS:
            raise ValueError("Unknown risk level")
        return value


class TransitionRequest(BaseModel):
    status: str
    actor: str = Field(default="Investigator", min_length=1, max_length=120)
    note: str = Field(default="", max_length=4000)

    @field_validator("status")
    @classmethod
    def known_status(cls, value: str) -> str:
        if value not in STATUSES:
            raise ValueError("Unknown status")
        return value


class NoteCreate(BaseModel):
    author: str = Field(default="", max_length=120)
    body: str = Field(min_length=1, max_length=4000)


class NoteOut(BaseModel):
    id: int
    author: str
    body: str
    created_at: datetime

    @field_serializer("created_at")
    def ser_created(self, value: datetime) -> str:
        return _as_utc(value)


class ActivityOut(BaseModel):
    id: int
    action: str
    detail: str
    actor: str
    created_at: datetime

    @field_serializer("created_at")
    def ser_created(self, value: datetime) -> str:
        return _as_utc(value)


class AlertCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=4000)
    score: int = Field(default=0, ge=0, le=1000)
    entity_type: str = "other"
    entity_ref: str = Field(default="", max_length=120)
    channel: str = Field(default="", max_length=80)
    case_id: int | None = None
    actor: str = Field(default="Investigator", min_length=1, max_length=120)

    @field_validator("entity_type")
    @classmethod
    def known_entity(cls, value: str) -> str:
        if value not in ENTITY_TYPES:
            raise ValueError("Unknown entity type")
        return value


class AlertUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    score: int | None = Field(default=None, ge=0, le=1000)
    status: str | None = None
    entity_type: str | None = None
    entity_ref: str | None = Field(default=None, max_length=120)
    channel: str | None = Field(default=None, max_length=80)
    case_id: int | None = None
    clear_case: bool = False
    actor: str = Field(default="Investigator", min_length=1, max_length=120)

    @field_validator("status")
    @classmethod
    def known_status(cls, value: str | None) -> str | None:
        if value is not None and value not in ALERT_STATUSES:
            raise ValueError("Unknown alert status")
        return value

    @field_validator("entity_type")
    @classmethod
    def known_entity(cls, value: str | None) -> str | None:
        if value is not None and value not in ENTITY_TYPES:
            raise ValueError("Unknown entity type")
        return value


class AlertOut(BaseModel):
    id: int
    title: str
    description: str
    score: int
    status: str
    entity_type: str
    entity_ref: str
    channel: str
    assignee: str = ""
    case_id: int | None
    created_at: datetime

    @field_serializer("created_at")
    def ser_created(self, value: datetime) -> str:
        return _as_utc(value)


class CaseSummary(BaseModel):
    id: int
    title: str
    case_type: str
    status: str
    risk: str
    score: int
    assignee: str
    summary: str
    alert_count: int
    created_at: datetime
    updated_at: datetime

    @field_serializer("created_at", "updated_at")
    def ser_times(self, value: datetime) -> str:
        return _as_utc(value)


class AttachmentOut(BaseModel):
    id: int
    original_name: str
    content_type: str
    size: int
    sha256: str = ""
    uploaded_by: str
    created_at: datetime
    ocr_text: str = ""
    ocr_confidence: float | None = None
    ocr_language: str = ""

    @field_serializer("created_at")
    def ser_created(self, value: datetime) -> str:
        return _as_utc(value)


class FieldValueOut(BaseModel):
    key: str
    label: str
    value: str
    required: bool


class ResponseActionOut(BaseModel):
    id: int
    agent_id: int
    command_id: int | None
    action: str
    actor: str
    detail: dict
    occurred_at: datetime

    @field_serializer("occurred_at")
    def ser_occurred(self, value: datetime) -> str:
        return _as_utc(value)


class CaseDetail(CaseSummary):
    conclusion: str
    fields: list[FieldValueOut]
    alerts: list[AlertOut]
    notes: list[NoteOut]
    activities: list[ActivityOut]
    attachments: list[AttachmentOut]
    response_actions: list[ResponseActionOut] = []


EVENT_SEVERITIES = ("low", "medium", "high", "critical")
EVENT_TYPES = (
    "file_create", "file_read", "file_write", "file_delete", "file_rename",
    "usb_insert", "usb_remove", "usb_block_attempt",
    "clipboard_change",
    "print_job",
    "print_document",
    "screenshot",
    "process_start", "process_exit",
    "window_change", "window_active",
    "idle_start", "idle_end",
    "process_modules", "process_tree",
    "fschange",
    "registry_change",
    "rdp_connect", "rdp_disconnect",
    "citrix_start", "citrix_window", "citrix_clipboard",
    "incognito_detected",
    "agent_log", "tamper",
)
AGENT_OS = ("windows", "linux", "macos", "other")
AGENT_STATUSES = ("registered", "online", "offline", "suspended")
STALE_THRESHOLD_SECONDS = 90


class AgentRegister(BaseModel):
    machine_id: str = Field(min_length=4, max_length=64)
    hostname: str = Field(min_length=1, max_length=200)
    os: str
    os_version: str = Field(default="", max_length=80)
    arch: str = Field(default="", max_length=20)
    agent_version: str = Field(default="", max_length=32)
    public_fingerprint: str = Field(default="", max_length=256)
    tags: list[str] = Field(default_factory=list)

    @field_validator("os")
    @classmethod
    def normalize_os(cls, value: str) -> str:
        v = value.lower().strip()
        if v not in AGENT_OS:
            return "other"
        return v


class AgentHeartbeat(BaseModel):
    cpu_pct: float = Field(default=0.0, ge=0, le=100)
    memory_pct: float = Field(default=0.0, ge=0, le=100)
    disk_free_bytes: int = Field(default=0, ge=0)
    last_event_id: int = Field(default=0, ge=0)
    agent_version: str = Field(default="", max_length=32)
    collector_status: dict[str, str] = Field(default_factory=dict)
    update_status: str = Field(default="", max_length=40)
    tamper_events: list[dict] = Field(default_factory=list)


class AgentConfig(BaseModel):
    heartbeat_seconds: int = Field(default=60, ge=5, le=3600)
    event_flush_seconds: int = Field(default=10, ge=1, le=600)
    screenshot_interval_seconds: int = Field(default=60, ge=0, le=86400)
    idle_threshold_seconds: int = Field(default=30, ge=5, le=3600)
    watch_paths: list[str] = Field(default_factory=list)
    registry_watch_keys: list[str] = Field(default_factory=list)
    process_blacklist: list[str] = Field(default_factory=list)
    stealth_mode: bool = False
    update_channel: str = Field(default="stable", max_length=32)
    max_screenshot_resolution: tuple[int, int] = (1280, 720)
    screenshot_quality: int = Field(default=75, ge=30, le=100)


class AgentRegistered(BaseModel):
    agent_id: int
    agent_token: str
    config: AgentConfig
    server_time: str
    upgrade_instruction: str | None = None


class AgentOut(BaseModel):
    id: int
    machine_id: str
    hostname: str
    os: str
    os_version: str
    arch: str
    agent_version: str
    status: str
    registered_at: datetime
    last_seen_at: datetime | None
    tags: list[str] = []
    group_id: int | None = None
    stealth_mode: bool = False
    cpu_pct: float = 0.0
    memory_pct: float = 0.0
    disk_free_bytes: int = 0
    update_status: str = ""

    @field_serializer("registered_at", "last_seen_at")
    def ser_times(self, value: datetime | None) -> str | None:
        return _as_utc(value) if value else None

    @field_validator("tags", mode="before")
    @classmethod
    def load_tags(cls, value):
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                return json.loads(value) if value else []
            except Exception:
                return []
        return []


class EndpointEventCreate(BaseModel):
    type: str
    severity: str = "low"
    occurred_at: datetime | None = None
    payload: dict = Field(default_factory=dict)
    event_key: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @field_validator("occurred_at")
    @classmethod
    def timezone_required(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Event timestamps must include a timezone")
        return value.astimezone(timezone.utc) if value is not None else value

    @field_validator("severity")
    @classmethod
    def known_severity(cls, value: str) -> str:
        if value not in EVENT_SEVERITIES:
            raise ValueError(f"Unknown severity: {value}")
        return value


class EndpointEventBatch(BaseModel):
    events: list[EndpointEventCreate] = Field(min_length=1, max_length=1000)


class EndpointEventOut(BaseModel):
    id: int
    agent_id: int
    type: str
    severity: str
    occurred_at: datetime
    received_at: datetime
    payload: dict = {}
    alert_id: int | None = None
    case_id: int | None = None
    linked_by: str = ""

    @field_serializer("occurred_at", "received_at")
    def ser_evt_times(self, value: datetime) -> str:
        return _as_utc(value)

    @field_validator("payload", mode="before")
    @classmethod
    def load_payload(cls, value):
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                return json.loads(value) if value else {}
            except Exception:
                return {"_raw": value}
        return {}


class TamperEventOut(BaseModel):
    id: int
    agent_id: int
    type: str
    detail: str
    occurred_at: datetime
    resolved: bool

    @field_serializer("occurred_at")
    def ser_occurred(self, value: datetime) -> str:
        return _as_utc(value)


class GroupCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    description: str = Field(default="", max_length=4000)
    default_config: dict = Field(default_factory=dict)


class GroupOut(BaseModel):
    id: int
    name: str
    description: str
    created_at: datetime

    @field_serializer("created_at")
    def ser_created_at(self, value: datetime) -> str:
        return _as_utc(value)


class AgentUpdate(BaseModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=200)
    status: str | None = None
    tags: list[str] | None = None
    group_id: int | None = None
    stealth_mode: bool | None = None
    config_json: dict | None = None

    @field_validator("status")
    @classmethod
    def known_status(cls, value: str | None) -> str | None:
        if value is not None and value not in AGENT_STATUSES:
            raise ValueError(f"Unknown status: {value}")
        return value


class AgentCommand(BaseModel):
    command: str = Field(min_length=1, max_length=32)
    args: dict = Field(default_factory=dict)
    actor: str = Field(default="administrator", min_length=1, max_length=120)

    @field_validator("command")
    @classmethod
    def known_command(cls, value: str) -> str:
        known = ("screenshot_now", "flush_events", "force_update", "push_config",
                 "restart_agent", "block_usb", "unblock_usb", "send_test_event")
        if value not in known:
            raise ValueError(f"Unknown command: {value}")
        return value


class EventLink(BaseModel):
    case_id: int
    create_alert: bool = True
    alert_score: int = Field(default=50, ge=0, le=1000)
    alert_title: str = Field(default="", max_length=200)
    actor: str = Field(default="investigator", min_length=1, max_length=120)


class BulkEventLink(BaseModel):
    event_ids: list[int] = Field(min_length=1, max_length=500)
    case_id: int
    create_alert: bool = True
    alert_score: int = Field(default=50, ge=0, le=1000)
    actor: str = Field(default="investigator", min_length=1, max_length=120)


import json  # noqa: E402  (used inside validators)

