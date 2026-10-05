from datetime import timedelta, timezone
from app.models import utcnow, Notice
from app.privacy_models import EducationPolicy, PolicyWarning, EducationAudit


def policy(db):
    row = db.get(EducationPolicy, 1)
    if row is None:
        row = EducationPolicy(id=1); db.add(row); db.flush()
    return row


def warning_payload(row):
    return {key: getattr(row, key) for key in ('id', 'agent_id', 'title', 'message', 'education', 'training_url', 'level', 'state', 'training_state', 'deliveries')}


def record(db, warning, actor, action):
    db.add(EducationAudit(warning_id=warning.id, actor=actor, action=action))


def create_warning(db, agent_id, event_id=None, actor='policy', reminder=False):
    saved = policy(db)
    if not saved.enabled: return None
    if event_id is not None:
        existing = db.query(PolicyWarning).filter_by(event_id=event_id).first()
        if existing: return existing
    count = db.query(PolicyWarning).filter(PolicyWarning.agent_id == agent_id, PolicyWarning.event_id.is_not(None), PolicyWarning.created_at >= utcnow()-timedelta(days=30)).count()
    level = 1 if reminder else min(3, 1 + count // saved.escalation_count)
    row = PolicyWarning(agent_id=agent_id, event_id=event_id, title=saved.title, message=saved.message,
                        education=saved.education, training_url=saved.training_url, manager=saved.manager,
                        training_state='assigned' if saved.training_url else 'none', level=level)
    db.add(row); db.flush(); record(db, row, actor, 'reminder_created' if reminder else 'warning_created')
    if row.training_url: record(db, row, actor, 'training_assigned')
    if row.level > 1 and row.manager:
        db.add(Notice(user=row.manager, channel='app', subject='Policy warning escalation', body=f'Endpoint policy warning {row.id} reached level {row.level}.', escalation=True))
        record(db, row, actor, 'manager_notified')
    return row


def deliveries(db, agent_id):
    saved = policy(db)
    if not saved.enabled: return []
    now = utcnow()
    rows = db.query(PolicyWarning).filter(PolicyWarning.agent_id == agent_id, PolicyWarning.state != 'acknowledged', PolicyWarning.next_delivery_at <= now).order_by(PolicyWarning.id).limit(5).all()
    for row in rows:
        if row.deliveries >= 2 and row.level < 3:
            row.level += 1; record(db, row, f'agent:{agent_id}', 'unacknowledged_escalation')
            if row.manager:
                db.add(Notice(user=row.manager, channel='app', subject='Unacknowledged policy warning', body=f'Endpoint policy warning {row.id} requires review.', escalation=True))
                record(db, row, 'policy', 'manager_notified')
        row.deliveries += 1; row.state = 'delivered'
        row.next_delivery_at = now + timedelta(minutes=saved.reminder_minutes)
        record(db, row, f'agent:{agent_id}', 'delivery_offered')
    return [warning_payload(row) for row in rows]
