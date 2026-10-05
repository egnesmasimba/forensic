"""Review rules for investigator-supplied email metadata and traffic summaries."""

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.ingest import events_from_rows, read_csv_dicts

EMAIL_FIELDS = [
    "message_id",
    "occurred_at",
    "sender",
    "recipient_domain",
    "attachment_name",
    "attachment_bytes",
    "encrypted",
]
TRAFFIC_FIELDS = ["flow_id", "occurred_at", "user", "protocol", "application", "destination", "bytes", "connections"]
PUBLIC_MAIL = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "yahoo.co.uk",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
}
COMMON_PROTOCOLS = {"tcp", "udp", "icmp", "http", "https", "dns", "tls"}
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


class EmailRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    message_id: str = Field(min_length=1, max_length=120)
    occurred_at: str
    sender: str = Field(min_length=1, max_length=120)
    recipient_domain: str = Field(min_length=1, max_length=253)
    attachment_name: str = Field(default="", max_length=200)
    attachment_bytes: int = Field(ge=0, le=10**15)
    encrypted: bool

    @field_validator("occurred_at")
    @classmethod
    def timestamp(cls, value: str) -> str:
        return require_timestamp(value)

    @field_validator("recipient_domain")
    @classmethod
    def domain(cls, value: str) -> str:
        text = value.lower().strip(".")
        if DOMAIN.fullmatch(text) is None:
            raise ValueError("Recipient domain must be a hostname")
        return text

    @field_validator("encrypted", mode="before")
    @classmethod
    def flag(cls, value):
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"yes", "true", "1", "y"}:
            return True
        if text in {"no", "false", "0", "n", ""}:
            return False
        raise ValueError("encrypted must be yes or no")


class TrafficRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    flow_id: str = Field(min_length=1, max_length=120)
    occurred_at: str
    user: str = Field(min_length=1, max_length=120)
    protocol: str = Field(min_length=1, max_length=40)
    application: str = Field(default="", max_length=80)
    destination: str = Field(default="", max_length=200)
    bytes: int = Field(ge=0, le=10**15)
    connections: int = Field(ge=0, le=10**9)

    @field_validator("occurred_at")
    @classmethod
    def timestamp(cls, value: str) -> str:
        return require_timestamp(value)

    @field_validator("protocol")
    @classmethod
    def protocol_name(cls, value: str) -> str:
        return value.lower()


def require_timestamp(value: str) -> str:
    from pydantic import ValidationError

    from app.ingest import Event

    try:
        checked = Event.model_validate(
            {
                "event_id": "timestamp-check",
                "occurred_at": value,
                "user": "timestamp-check",
                "action": "login_success",
                "destination": "",
                "bytes": 0,
                "records": 0,
            }
        )
    except ValidationError as error:
        raise ValueError(error.errors()[0]["msg"]) from error
    return checked.occurred_at.isoformat()


def _public(domain: str) -> bool:
    return any(domain == name or domain.endswith("." + name) for name in PUBLIC_MAIL)


def _apply(rules: dict, rule_id: str, matched: bool, title: str | None = None):
    enabled, _threshold, score, label = rules[rule_id]
    if enabled and matched:
        return (title or label, score, rule_id)
    return None


def email_rules(record: EmailRecord, rules: dict) -> list[tuple]:
    found = [
        _apply(rules, "external-recipient", _public(record.recipient_domain)),
        _apply(rules, "large-attachment", record.attachment_bytes >= rules["large-attachment"][1]),
        _apply(rules, "encrypted-attachment", record.encrypted),
        _apply(rules, "attachment-context", bool(record.attachment_name) and record.encrypted and _public(record.recipient_domain)),
    ]
    return [item for item in found if item]


def traffic_rules(record: TrafficRecord, rules: dict) -> list[tuple]:
    application = record.application or record.protocol
    found = [
        _apply(rules, "unusual-protocol", record.protocol not in COMMON_PROTOCOLS),
        _apply(rules, "bandwidth-heavy", record.bytes >= rules["bandwidth-heavy"][1], f"{rules['bandwidth-heavy'][3]}: {application}"),
        _apply(rules, "repeated-connections", record.connections >= rules["repeated-connections"][1]),
    ]
    return [item for item in found if item]


def email_items(raw: bytes, rules: dict) -> list[tuple[dict, list[tuple]]]:
    items = []
    for record in events_from_rows(read_csv_dicts(raw, EMAIL_FIELDS), model=EmailRecord):
        data = record.model_dump(mode="json")
        payload = {
            "event_id": record.message_id,
            "occurred_at": record.occurred_at,
            "user": record.sender,
            "action": "email",
            "recipient_domain": data["recipient_domain"],
            "attachment_name": data["attachment_name"],
            "attachment_bytes": data["attachment_bytes"],
            "encrypted": data["encrypted"],
        }
        items.append((payload, email_rules(record, rules)))
    return items


def traffic_items(raw: bytes, rules: dict) -> list[tuple[dict, list[tuple]]]:
    items = []
    for record in events_from_rows(read_csv_dicts(raw, TRAFFIC_FIELDS), model=TrafficRecord):
        payload = {
            "event_id": record.flow_id,
            "occurred_at": record.occurred_at,
            "user": record.user,
            "action": f"traffic:{record.protocol}",
            "application": record.application,
            "destination": record.destination,
            "bytes": record.bytes,
            "connections": record.connections,
        }
        items.append((payload, traffic_rules(record, rules)))
    return items
