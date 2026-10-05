"""Local foundation record: one environment, written decisions, and access logging."""
import csv
import os
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from cryptography.x509 import load_pem_x509_certificate
from sqlalchemy.orm import Session

from app.models import AccessLog, Alert

DECISIONS = (
    {"id": "ADR-1", "title": "One local application", "choice": "The Investigation Center is one FastAPI process. Separate microservices are not deployed."},
    {"id": "ADR-2", "title": "HTTP API", "choice": "Clients use the REST API. GraphQL and gRPC are not served."},
    {"id": "ADR-3", "title": "SQLite", "choice": "The local database is SQLite. PostgreSQL, MongoDB, and TimescaleDB are not connected."},
    {"id": "ADR-4", "title": "Local intake", "choice": "Activity arrives through authenticated uploads and the inbox folder. Kafka, RabbitMQ, and MQ Series are not connected."},
    {"id": "ADR-5", "title": "Single process", "choice": "There is no standby process or automatic failover."},
    {"id": "ADR-6", "title": "Branches", "choice": "Changes are reviewed on a branch before main. The application does not create branches."},
    {"id": "ADR-7", "title": "Secrets", "choice": "Secrets are read from the process environment. Vault and a cloud secrets manager are not connected."},
)

STANDARDS = (
    "Python for the application.",
    "Ruff selects pycodestyle and pyflakes errors.",
    "MD5 signatures are not created.",
    "Access logs store the actor, method, path, and status. Request bodies and query strings are not stored.",
)


def operations(db: Session, collection_dir: Path) -> dict:
    """Report this process only. There is no second node to fail over to."""
    import shutil

    from app.models import EndpointAgent, QueueMessage
    from app.response_models import ResponseCommand

    usage = shutil.disk_usage(collection_dir if collection_dir.is_dir() else collection_dir.parent)
    inbox = sum(1 for path in collection_dir.iterdir() if path.is_file()) if collection_dir.is_dir() else 0
    pending = db.query(QueueMessage).filter_by(status="pending").count()
    backlog = db.query(ResponseCommand).filter(ResponseCommand.state.in_(("queued", "dispatched"))).count()
    low_agents = db.query(EndpointAgent).filter(
        EndpointAgent.disk_free_bytes > 0, EndpointAgent.disk_free_bytes < 100 * 1024 * 1024
    ).count()
    return {
        "status": "low_disk" if usage.free < 100 * 1024 * 1024 else "ok",
        "database": "sqlite",
        "failover": False,
        "disk_free_bytes": usage.free,
        "disk_total_bytes": usage.total,
        "inbox_files": inbox,
        "pending_queue_messages": pending,
        "response_backlog": backlog,
        "response_backlog_limit": 100,
        "agents_below_100mb": low_agents,
    }


def notice_csv(db: Session) -> str:
    from app.models import Notice
    from app.reports import spreadsheet_safe

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "user", "channel", "subject", "body", "alert_id", "acknowledged"])
    for row in db.query(Notice).order_by(Notice.id).limit(500):
        writer.writerow([row.id, spreadsheet_safe(row.user), row.channel, spreadsheet_safe(row.subject),
                         spreadsheet_safe(row.body), row.alert_id or "", row.acknowledged])
    return output.getvalue()


def environment(raw: str | None = None) -> dict:
    if raw is None:
        raw = os.environ.get("ZANAQ_ENV", "local")
    name = raw.strip().lower() or "local"
    if name == "local":
        return {"name": "local", "accepted": True}
    return {"name": "local", "accepted": False, "rejected": name[:40]}


def record_access(db: Session, request, status: int) -> None:
    from app.iam import record_activity
    record_activity(db, request, status)
    path = request.url.path
    if not path.startswith("/api/") or path == "/api/health":
        return
    db.add(AccessLog(
        actor=getattr(request.state, "actor", "")[:120],
        method=request.method[:12],
        path=path[:200],
        status=status,
    ))
    db.flush()
    extra = db.query(AccessLog.id).order_by(AccessLog.id.desc()).offset(2000).limit(1).scalar()
    if extra is not None:
        db.query(AccessLog).filter(AccessLog.id <= extra).delete(synchronize_session=False)


def certificate_status(pem: bytes, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    try:
        cert = load_pem_x509_certificate(pem)
    except ValueError as error:
        raise ValueError("The certificate could not be read") from error
    expires = cert.not_valid_after_utc
    days = (expires - now).days
    return {"days_remaining": days, "expires": expires.isoformat(), "alert": days < 30}


def open_certificate_alert(db: Session, days: int) -> bool:
    existing = db.query(Alert).filter(Alert.title == "Certificate expiry", Alert.status == "open").one_or_none()
    if existing is not None:
        return False
    db.add(Alert(
        title="Certificate expiry",
        description=f"The certificate expires in {days} days.",
        score=40,
        entity_type="other",
        entity_ref="tls",
        channel="foundation",
    ))
    return True
