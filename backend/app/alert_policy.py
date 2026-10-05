"""Stored alert suppression and in-app routing. Notices are not sent outside the center."""
from sqlalchemy import event
from sqlalchemy.orm import object_session

from app.models import Alert, AlertPolicy, AlertRoute, Notice, utcnow


def _same(left: str, right: str) -> bool:
    return left.casefold() == right.casefold()


def suppressed(db, alert: Alert) -> bool:
    for rule in db.query(AlertPolicy).filter(AlertPolicy.enabled.is_(True)).all():
        if rule.kind == "whitelist":
            if rule.entity_ref and _same(rule.entity_ref, alert.entity_ref or ""):
                return True
            continue
        checks = []
        if rule.entity_ref:
            checks.append(_same(rule.entity_ref, alert.entity_ref or ""))
        if rule.title:
            checks.append(_same(rule.title, alert.title or ""))
        if rule.channel:
            checks.append(_same(rule.channel, alert.channel or ""))
        if checks and all(checks):
            return True
    return False


def matching_route(db, alert: Alert) -> AlertRoute | None:
    chosen = None
    for rule in db.query(AlertRoute).filter(AlertRoute.enabled.is_(True)).all():
        if rule.channel and not _same(rule.channel, alert.channel or ""):
            continue
        if alert.score < rule.min_score:
            continue
        if chosen is None or (rule.position, rule.id) < (chosen.position, chosen.id):
            chosen = rule
    return chosen


@event.listens_for(Alert, "before_insert")
def apply_alert_policy(mapper, connection, target: Alert) -> None:
    del mapper, connection
    db = object_session(target)
    if db is None or target.status != "open" or target.case_id is not None:
        return
    if suppressed(db, target):
        target.status = "suppressed"
        return
    rule = matching_route(db, target)
    if rule is None:
        return
    target.assignee = rule.assignee
    target._route_notice = True
    target._route_delivery = rule.delivery if rule.delivery in ("app", "email", "sms", "mq") else "app"


@event.listens_for(Alert, "after_insert")
def record_route_notice(mapper, connection, target: Alert) -> None:
    del mapper
    if not getattr(target, "_route_notice", False):
        return
    delivery = getattr(target, "_route_delivery", None) or "app"
    connection.execute(Notice.__table__.insert().values(
        user=target.assignee,
        channel=delivery,
        subject=f"Alert assigned: {target.title[:120]}",
        body=f"{target.entity_ref or 'unknown'}: {target.title} scored {target.score}. This notice stays in the center and is not sent.",
        alert_id=target.id,
        acknowledged=False,
        escalation=False,
        created_at=utcnow(),
    ))
