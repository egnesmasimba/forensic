from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.delivery import DeliveryService, message_id
from app.models import (
    Alert, AutomationAudit, AutomationRun, Delivery, Incident, LocalTrigger, Notice,
    NoticeTemplate, OutboundRecipient, Playbook, Ticket,
)

TRIGGERS = ("download", "upload", "email", "print", "other", "dlp")
STEPS = ("notify", "email", "sms", "ticket", "incident")

#: Injected by tests; defaults to reading the environment on first use.
_service: DeliveryService | None = None


def delivery_service() -> DeliveryService:
    global _service
    if _service is None:
        _service = DeliveryService()
    return _service


def recipients(db: Session, channel: str, alert: Alert) -> list[str]:
    """Addresses this channel may deliver to, from the configured allowlist.

    An alert's own ``entity_ref`` is never used as a target: it identifies the
    subject of the investigation, so sending there would notify whoever is
    being investigated.
    """
    rows = db.query(OutboundRecipient).filter_by(channel=channel, enabled=True).all()
    return [row.address for row in rows if row.scope in ("", channel)]


def seed_automation(db: Session) -> None:
    if db.get(NoticeTemplate, 1) is None:
        db.add(NoticeTemplate(id=1))
        db.commit()


def template(db: Session) -> NoticeTemplate:
    row = db.get(NoticeTemplate, 1)
    if row is None:
        row = NoticeTemplate(id=1)
        db.add(row)
        db.flush()
    return row


def _text(pattern: str, alert: Alert) -> str:
    return pattern.format(user=alert.entity_ref or "unknown", title=alert.title, score=alert.score)


def matches(playbook: Playbook, alert: Alert) -> bool:
    title = alert.title.casefold()
    if playbook.trigger == "other":
        return True
    if playbook.trigger == "dlp":
        return alert.channel == "dlp"
    if playbook.trigger == "download":
        return "download" in title
    if playbook.trigger == "upload":
        return "cloud" in title or "disguise" in title or "upload" in title
    if playbook.trigger == "email":
        return alert.channel == "mail" or "email" in title or "mail" in title
    if playbook.trigger == "print":
        return "print" in title
    return False


def _recent_notice(db: Session, alert_id: int, channel: str, minutes: int) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    rows = db.query(Notice).filter_by(alert_id=alert_id, channel=channel, escalation=False).all()
    for row in rows:
        created = row.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created >= cutoff:
            return True
    return False


def _record_delivery(db: Session, alert: Alert, notice: Notice, channel: str,
                     recipient: str, key: str, result) -> Delivery:
    """Persist one delivery outcome, de-duplicating against a prior attempt.

    A playbook is idempotent per alert, but an operator re-running delivery
    must not silently send the same message twice, so an existing row for this
    message and recipient is returned unchanged.
    """
    existing = db.query(Delivery).filter_by(message_id=key, recipient=recipient).one_or_none()
    if existing is not None:
        return existing
    row = Delivery(
        message_id=key, channel=channel, recipient=recipient, notice_id=notice.id,
        alert_id=alert.id, status=result.status, detail=result.detail[:300],
        attempts=result.attempts, permanent=result.permanent,
    )
    db.add(row)
    return row


def _notify(db: Session, alert: Alert, channel: str, subject: str, body: str, escalation: bool = False) -> bool:
    """Record the message in-product, then attempt outbound delivery.

    The in-product notice is written first and unconditionally, so the message
    is durable even when no transport is configured. Delivery is attempted only
    for the channels that can leave the deployment, and a transport failure is
    recorded rather than raised: an unreachable relay must not abort the rest
    of the playbook.
    """
    saved = template(db)
    if channel in {"email", "sms"} and not escalation and _recent_notice(db, alert.id, channel, saved.throttle_minutes):
        return False
    notice = Notice(
        user=alert.entity_ref or "unknown", channel=channel, subject=subject[:160], body=body[:500],
        alert_id=alert.id, escalation=escalation,
    )
    db.add(notice)
    db.flush()
    if channel not in {"email", "sms"}:
        return True
    targets = recipients(db, channel, alert)
    service = delivery_service()
    if not targets:
        _record_delivery(db, alert, notice, channel, "", message_id(alert.id, channel, subject),
                         _NOT_CONFIGURED_RESULT)
        db.flush()
        return True
    key = message_id(alert.id, channel, subject)
    for target in targets:
        result = service.deliver(channel, target, subject, body)
        _record_delivery(db, alert, notice, channel, target, key, result)
    db.flush()
    return True


class _FixedResult:
    status = "not_configured"
    detail = "no outbound recipients configured for this channel"
    attempts = 1
    permanent = True


_NOT_CONFIGURED_RESULT = _FixedResult()


def run_playbook(db: Session, playbook: Playbook, alert: Alert) -> list[str]:
    if db.query(AutomationRun).filter_by(playbook_id=playbook.id, alert_id=alert.id).one_or_none() is not None:
        return []
    saved = template(db)
    done = []
    body = playbook.message or saved.body
    rendered = _text(body, alert)
    subject = _text(saved.subject, alert)
    for step in [part.strip() for part in playbook.steps.split(",") if part.strip()]:
        if step == "notify" and _notify(db, alert, "app", subject, rendered):
            done.append(step)
        elif step in {"email", "sms"} and _notify(db, alert, step, subject, rendered):
            done.append(step)
        elif step == "ticket":
            db.add(Ticket(system="custom", title=alert.title[:160], alert_id=alert.id))
            done.append(step)
        elif step == "incident":
            db.add(Incident(title=alert.title[:160], detail=alert.description[:500], alert_id=alert.id))
            done.append(step)
    db.add(AutomationRun(playbook_id=playbook.id, alert_id=alert.id, steps_done=",".join(done)))
    db.add(AutomationAudit(actor="playbook", change=f"Ran {playbook.name} on alert {alert.id}: {', '.join(done) or 'no steps'}."))
    return done


def apply_triggers(db: Session, alert: Alert) -> list[str]:
    done = []
    for playbook in db.query(Playbook).filter_by(enabled=True).all():
        if matches(playbook, alert):
            done.extend(run_playbook(db, playbook, alert))
    return done


def apply_new_alerts(db: Session) -> int:
    alerts = [row for row in list(db.new) if isinstance(row, Alert)]
    db.flush()
    count = 0
    for alert in alerts:
        if apply_triggers(db, alert):
            count += 1
    return count


def escalate(db: Session) -> int:
    saved = template(db)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=saved.escalate_minutes)
    created = 0
    for notice in db.query(Notice).filter_by(channel="app", acknowledged=False, escalation=False).all():
        if notice.alert_id is None:
            continue
        moment = notice.created_at if notice.created_at.tzinfo else notice.created_at.replace(tzinfo=timezone.utc)
        if moment > cutoff:
            continue
        if db.query(Notice).filter_by(alert_id=notice.alert_id, escalation=True).one_or_none() is not None:
            continue
        alert = db.get(Alert, notice.alert_id)
        if alert is None:
            continue
        _notify(db, alert, "app", f"Escalation: {alert.title}"[:160], notice.body, escalation=True)
        created += 1
    return created
