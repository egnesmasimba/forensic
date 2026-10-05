"""Match stored endpoint events to administrator-defined application names."""
from app.agent_alerts import make_alert_for
from app.models import ApplicationRule

LIMIT = 50


def observed(payload, field):
    keys = ("name", "exe", "executable", "process_name") if field == "process" else ("window_title",)
    return " ".join(str(payload.get(key) or "") for key in keys).casefold()


def match_application(db, event, payload):
    text_by_field = {}
    for rule in db.query(ApplicationRule).filter_by(enabled=True).order_by(ApplicationRule.id).limit(LIMIT):
        text = text_by_field.setdefault(rule.field, observed(payload, rule.field))
        if rule.pattern not in text:
            continue
        alert = make_alert_for(
            event,
            title=f"Application {rule.name}",
            score=rule.score,
            channel="application",
            description=f"Stored {event.type} matched the {rule.field} name {rule.pattern}.",
        )
        db.add(alert)
        db.flush()
        return alert
    return None
