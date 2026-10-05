import hashlib
import json
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.ingest import load_rules
from app.mail_models import MailEvidence, MailPolicy
from app.models import Alert
from app.observations import PUBLIC_MAIL
from endpoint_agent.content_scan import DEFAULT_TERMS, MAX_TEXT, analyze_text, normalize_domain


class Recipient(BaseModel):
    kind: Literal["to", "cc", "bcc"] = "to"
    address: str = Field(max_length=320)

    @field_validator("address")
    @classmethod
    def valid_address(cls, value):
        if "@" not in value or any(c in value for c in "\r\n"):
            raise ValueError("Recipient must be an email address")
        normalize_domain(value.rsplit("@", 1)[1])
        return value


class AttachmentObservation(BaseModel):
    filename: str = Field(max_length=255)
    size: int = Field(ge=0, le=10**15)
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    format: str = Field(default="unknown", max_length=40)
    archive: bool = False
    encryption: Literal["confirmed", "probable", "unknown", "not_detected"] = "unknown"
    encryption_basis: str = Field(default="", max_length=300)
    text: str = Field(default="", max_length=MAX_TEXT)
    partial: bool = False
    notes: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("notes")
    @classmethod
    def bounded_notes(cls, values):
        return [v[:300] for v in values]


class MailObservation(BaseModel):
    message_id: str = Field(min_length=1, max_length=200)
    client: str = Field(min_length=1, max_length=40)
    direction: Literal["incoming", "outgoing", "unknown", "send_intent"] = "unknown"
    sender: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=200)
    recipients: list[Recipient] = Field(default_factory=list, max_length=200)
    occurred_at: datetime
    body: str = Field(default="", max_length=MAX_TEXT)
    attachments: list[AttachmentObservation] = Field(default_factory=list, max_length=30)
    encrypted_message: bool = False
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    partial: bool = False
    notes: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("occurred_at")
    @classmethod
    def valid_time(cls, value):
        if value.tzinfo is None:
            raise ValueError("Message time must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("notes")
    @classmethod
    def bounded_notes(cls, values):
        return [v[:300] for v in values]


def mail_policy(db):
    row = db.get(MailPolicy, 1)
    return {"internal_domains": json.loads(row.internal_domains) if row else [],
            "sensitive_terms": json.loads(row.sensitive_terms) if row else list(DEFAULT_TERMS)}


def analyze_mail(data, db):
    observation = MailObservation.model_validate(data)
    report = observation.model_dump(mode="json")
    settings = mail_policy(db)
    findings, domains = [], []
    for recipient in report["recipients"]:
        domain = normalize_domain(recipient["address"].rsplit("@", 1)[1])
        recipient["domain"] = domain
        internal = any(domain == allowed or domain.endswith("." + allowed) for allowed in settings["internal_domains"])
        classification = "internal" if internal else "external" if settings["internal_domains"] else "public_mail" if domain in PUBLIC_MAIL else "unclassified"
        recipient["classification"] = classification
        domains.append(domain)
    report["recipient_domains"] = sorted(set(domains))
    report["body_analysis"] = analyze_text(report["body"], settings["sensitive_terms"])
    report["capture_provenance"] = "Client observation; send intent is not delivery confirmation"
    rules = load_rules(db)
    risky = [r for r in report["recipients"] if r["classification"] in ("external", "public_mail")]
    outbound = observation.direction in ("outgoing", "send_intent")
    if risky and outbound and rules["external-recipient"][0]:
        findings.append({"rule": "external-recipient", "score": rules["external-recipient"][2], "reason": "Outbound recipient domains need review"})
    sensitive = bool(report["body_analysis"]["sensitive_terms"])
    for attachment in report["attachments"]:
        attachment["analysis"] = analyze_text(attachment["text"], settings["sensitive_terms"])
        sensitive |= bool(attachment["analysis"]["sensitive_terms"])
        if attachment["size"] >= rules["large-attachment"][1] and rules["large-attachment"][0]:
            findings.append({"rule": "large-attachment", "score": rules["large-attachment"][2], "reason": "Large attachment"})
        if attachment["encryption"] == "confirmed" and rules["encrypted-attachment"][0]:
            findings.append({"rule": "encrypted-attachment", "score": rules["encrypted-attachment"][2], "reason": "Attachment has a recognized encryption indicator"})
    if risky and outbound and sensitive:
        findings.append({"rule": "email-sensitive-content", "score": 85, "reason": "Sensitive content with an outbound recipient domain requiring review"})
    report["findings"] = list({f["rule"]: f for f in findings}.values())
    return observation, report


def store_mail(db, data, *, captured_by, agent_id=None, event_id=None, raw=None):
    observation, report = analyze_mail(data, db)
    fingerprint = hashlib.sha256((str(agent_id) + observation.client + observation.sha256 + observation.direction).encode()).hexdigest()
    existing = db.query(MailEvidence).filter_by(fingerprint=fingerprint).first()
    if existing:
        return existing, True
    row = MailEvidence(fingerprint=fingerprint, client=observation.client, subject=observation.subject,
                       occurred_at=observation.occurred_at, captured_by=captured_by, agent_id=agent_id,
                       event_id=event_id, report=json.dumps(report, ensure_ascii=False), raw=raw)
    if report["findings"]:
        alert = Alert(title="Email content or recipient review: " + (observation.subject or "Untitled message")[:140],
                      score=max(f["score"] for f in report["findings"]), channel="email",
                      entity_type="user", entity_ref=observation.sender[:120],
                      description="; ".join(f["reason"] for f in report["findings"]) +
                                  ". Direction: " + observation.direction + ". Domains: " + ", ".join(report["recipient_domains"])[:1000])
        db.add(alert)
        db.flush()
        row.alert_id = alert.id
    db.add(row)
    db.flush()
    return row, False
