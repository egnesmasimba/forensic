import hashlib
import json
import os
import secrets
from datetime import timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_, desc
from pydantic import ValidationError
from app.mail_models import AgentEventReceipt

from app.auth import administrator, current_user, get_db, writer
from app.models import (
    Activity,
    AgentPackageManifest,
    Alert,
    Case,
    EndpointAgent,
    EndpointAgentGroup,
    EndpointEvent,
    EndpointTamperEvent,
    utcnow,
)
from app.schemas import (
    AGENT_OS,
    AGENT_STATUSES,
    EVENT_SEVERITIES,
    STALE_THRESHOLD_SECONDS,
    AgentCommand,
    AgentConfig,
    AgentHeartbeat,
    AgentOut,
    AgentRegister,
    AgentRegistered,
    AgentUpdate,
    BulkEventLink,
    EndpointEventBatch,
    EndpointEventOut,
    EventLink,
    GroupCreate,
    GroupOut,
    TamperEventOut,
    _as_utc,
)

MAX_EVENT_BATCH_BYTES = 5 * 1024 * 1024
router = APIRouter(prefix="/api/agents", tags=["endpoint-agents"])
PUBLIC_PATHS = {"/api/agents/register", "/api/agents/packages/manifest"}


def _is_public(request: Request) -> bool:
    return request.url.path in PUBLIC_PATHS or request.url.path.startswith("/api/agents/packages/")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _agent_from_token(request: Request, db):
    token = request.headers.get("x-agent-token", "")
    if not token:
        raise HTTPException(401, "X-Agent-Token missing")
    row = db.query(EndpointAgent).filter_by(token_hash=_hash_token(token)).first()
    if row is None:
        raise HTTPException(401, "Invalid agent token")
    if row.status == "suspended":
        raise HTTPException(403, "Agent suspended")
    return row


def _json_loads(text: str, default: Any = None) -> Any:
    if default is None:
        default = {}
    try:
        return json.loads(text) if text else default
    except Exception:
        return default


def _json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except Exception:
        return "{}"


def _stale_status(row: EndpointAgent) -> str:
    if row.status == "suspended":
        return "suspended"
    if row.last_seen_at is None:
        return "registered"
    age = (utcnow() - row.last_seen_at.replace(tzinfo=timezone.utc)).total_seconds()
    return "online" if age <= STALE_THRESHOLD_SECONDS else "offline"


def _upgrade_instruction(row: EndpointAgent, db) -> str | None:
    if not row.agent_version:
        return None
    newer = (
        db.query(AgentPackageManifest)
        .filter(
            AgentPackageManifest.active.is_(True),
            AgentPackageManifest.os == row.os,
            AgentPackageManifest.version > row.agent_version,
        )
        .order_by(desc(AgentPackageManifest.published_at))
        .first()
    )
    return newer.version if newer else None


@router.post("/register", status_code=201)
def register_agent(payload: AgentRegister, request: Request, db=Depends(get_db)):
    token = secrets.token_urlsafe(48)
    existing = db.query(EndpointAgent).filter_by(machine_id=payload.machine_id).first()
    if existing is not None:
        if existing.status == "suspended":
            raise HTTPException(403,"Agent is suspended")
        supplied=request.headers.get("x-agent-token","")
        if not supplied or not secrets.compare_digest(existing.token_hash,_hash_token(supplied)):
            raise HTTPException(409,"Machine already registered; its current agent token is required to renew registration")
        existing.token_hash = _hash_token(token)
        existing.hostname = payload.hostname
        existing.os = payload.os
        existing.os_version = payload.os_version
        existing.arch = payload.arch or existing.arch
        existing.agent_version = payload.agent_version
        existing.fingerprint = payload.public_fingerprint or existing.fingerprint
        existing.registered_at = utcnow()
        existing.tags = _json_dumps(payload.tags)
        db.commit()
        db.refresh(existing)
        row = existing
    else:
        row = EndpointAgent(
            machine_id=payload.machine_id,
            hostname=payload.hostname,
            os=payload.os,
            os_version=payload.os_version,
            arch=payload.arch,
            agent_version=payload.agent_version,
            token_hash=_hash_token(token),
            tags=_json_dumps(payload.tags),
            fingerprint=payload.public_fingerprint,
            status="registered",
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Machine ID or token collision")
        db.refresh(row)
    config = AgentConfig(**_json_loads(row.config_json, {}))
    return AgentRegistered(
        agent_id=row.id,
        agent_token=token,
        config=config,
        server_time=_as_utc(utcnow()),
        upgrade_instruction=_upgrade_instruction(row, db),
    )


@router.post("/heartbeat")
def agent_heartbeat(payload: AgentHeartbeat, request: Request, db=Depends(get_db)):
    if not _is_public(request):
        _ = Depends(current_user)  # type: ignore
    agent = _agent_from_token(request, db)
    agent.last_seen_at = utcnow()
    agent.status = "online"
    agent.cpu_pct = payload.cpu_pct
    agent.memory_pct = payload.memory_pct
    agent.disk_free_bytes = payload.disk_free_bytes
    agent.last_event_id = payload.last_event_id
    if payload.agent_version:
        agent.agent_version = payload.agent_version
    if payload.update_status:
        agent.update_status = payload.update_status
    for te in payload.tamper_events:
        db.add(EndpointTamperEvent(
            agent_id=agent.id,
            type=str(te.get("type", "tamper"))[:40],
            detail=str(te.get("detail", ""))[:4000],
        ))
    db.commit()
    command = agent.pending_command or ""
    if command:
        agent.pending_command = ""
        db.commit()
    config = AgentConfig(**_json_loads(agent.config_json, {}))
    from app.biometrics import permitted
    return {
        "biometrics_permitted": permitted(db, agent.id),
        "status": "ok",
        "computed_status": _stale_status(agent),
        "config": config.model_dump(),
        "upgrade_instruction": _upgrade_instruction(agent, db),
        "pending_command": _json_loads(command, None) if command else None,
        "server_time": _as_utc(utcnow()),
    }


@router.post("/events")
async def submit_events(payload: EndpointEventBatch, request: Request, db=Depends(get_db)):
    agent = _agent_from_token(request, db)
    if len(await request.body()) > MAX_EVENT_BATCH_BYTES:
        raise HTTPException(413, "Endpoint event batch must be at most 5 MB")
    duplicates = 0
    accepted = 0
    alerts_created = 0
    live_observations = []
    from app.agent_alerts import evaluate_agent_event
    last_id = 0
    for evt in payload.events:
        if evt.type == "screenshot":
            from app.privacy import capture_allowed
            capture_allowed(db, agent.id)
        fingerprint = hashlib.sha256(json.dumps({"type": evt.type, "severity": evt.severity, "payload": evt.payload,
            "occurred_at": evt.occurred_at.isoformat() if evt.occurred_at else None}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if evt.event_key:
            receipt = db.get(AgentEventReceipt, (agent.id, evt.event_key))
            if receipt:
                if receipt.fingerprint != fingerprint:
                    db.rollback()
                    raise HTTPException(409, "Event key already belongs to a different observation")
                duplicates += 1
                last_id = max(last_id, receipt.event_id)
                continue
        row = EndpointEvent(
            agent_id=agent.id,
            type=evt.type[:40],
            severity=evt.severity if evt.severity in EVENT_SEVERITIES else "low",
            occurred_at=(evt.occurred_at or utcnow()).replace(tzinfo=timezone.utc) if evt.occurred_at else utcnow(),
            payload=_json_dumps(evt.payload),
        )
        db.add(row)
        db.flush()
        last_id = row.id
        accepted += 1
        try:
            alert = evaluate_agent_event(db, row)
            from app.live_analytics import endpoint_observation
            observation = endpoint_observation(row)
            if observation is not None: live_observations.append(observation)
        except (ValidationError, ValueError) as error:
            db.rollback()
            raise HTTPException(422, "Invalid endpoint observation") from error
        if evt.event_key:
            db.add(AgentEventReceipt(agent_id=agent.id, event_key=evt.event_key, fingerprint=fingerprint, event_id=row.id))
            try:
                db.flush()
            except IntegrityError:
                db.rollback()
                raise HTTPException(409, "A concurrent delivery used this event key; retry the batch")
        if alert is not None:
            alerts_created += 1
            row.alert_id = alert.id
            from app.education import create_warning
            create_warning(db, agent.id, row.id)
    if live_observations:
        from app.live_analytics import store_stream
        live_result = store_stream(db, f"agent:{agent.id}", live_observations)
        alerts_created += live_result["alerts_created"]
    agent.last_event_id = max(agent.last_event_id, last_id)
    agent.last_seen_at = utcnow()
    agent.status = "online"
    db.commit()
    return {"accepted": accepted, "duplicates": duplicates, "alerts_created": alerts_created, "last_event_id": last_id}


@router.get("/packages/manifest")
def package_manifest(db=Depends(get_db)):
    rows = db.query(AgentPackageManifest).filter_by(active=True).all()
    result: dict[str, list[dict]] = {"packages": []}
    by_os: dict[str, dict] = {}
    for r in rows:
        key = f"{r.os}-{r.arch}"
        if key not in by_os or r.version > by_os[key]["version"]:
            by_os[key] = {
                "version": r.version,
                "os": r.os,
                "arch": r.arch,
                "filename": r.filename,
                "sha256": r.sha256,
                "size": r.size,
                "download_url": r.download_url or f"/api/agents/packages/{r.filename}",
                "release_notes": r.release_notes,
                "published_at": _as_utc(r.published_at),
            }
    result["latest"] = list(by_os.values())
    result["packages"] = [
        {
            "version": r.version,
            "os": r.os,
            "arch": r.arch,
            "filename": r.filename,
            "sha256": r.sha256,
            "size": r.size,
            "download_url": r.download_url or f"/api/agents/packages/{r.filename}",
            "published_at": _as_utc(r.published_at),
        }
        for r in rows
    ]
    return result


@router.get("/packages/{filename}")
def download_package(filename: str, db=Depends(get_db)):
    from fastapi.responses import FileResponse
    row = db.query(AgentPackageManifest).filter_by(filename=filename).first()
    if row is None:
        raise HTTPException(404, "Package not found")
    root = Path(__file__).resolve().parent.parent.parent / "endpoint_agent" / "packages"
    target = root / filename
    if not target.exists():
        raise HTTPException(404, "Package file missing on server")
    return FileResponse(target, filename=filename, media_type="application/octet-stream")


@router.get("/me")
def agent_me(request: Request, db=Depends(get_db)):
    agent = _agent_from_token(request, db)
    agent.last_seen_at = utcnow()
    db.commit()
    return AgentOut(
        id=agent.id,
        machine_id=agent.machine_id,
        hostname=agent.hostname,
        os=agent.os,
        os_version=agent.os_version,
        arch=agent.arch,
        agent_version=agent.agent_version,
        status=_stale_status(agent),
        registered_at=agent.registered_at,
        last_seen_at=agent.last_seen_at,
        tags=agent.tags,
        group_id=agent.group_id,
        stealth_mode=agent.stealth_mode,
        cpu_pct=agent.cpu_pct,
        memory_pct=agent.memory_pct,
        disk_free_bytes=agent.disk_free_bytes,
        update_status=agent.update_status,
    )


# ---------- Admin / investigator endpoints ----------

def _investigator_viewer(db, request, require_admin=False):
    user = current_user(request, db)
    if require_admin and user.role != "administrator":
        raise HTTPException(403, "Administrator access required")
    if user.role not in ("administrator", "investigator"):
        raise HTTPException(403, "Read-only for this role on agents module")
    return user


@router.get("", dependencies=[Depends(current_user)])
def list_agents(
    status: str = Query(default=""),
    os: str = Query(default=""),
    group_id: int | None = None,
    q: str = Query(default=""),
    limit: int = Query(default=200, ge=1, le=1000),
    db=Depends(get_db),
):
    query = db.query(EndpointAgent)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(EndpointAgent.hostname.like(like), EndpointAgent.machine_id.like(like)))
    if os:
        query = query.filter_by(os=os)
    if group_id is not None:
        query = query.filter_by(group_id=group_id)
    rows = query.order_by(desc(EndpointAgent.last_seen_at), desc(EndpointAgent.id)).limit(limit).all()
    return [
        AgentOut(
            id=r.id, machine_id=r.machine_id, hostname=r.hostname, os=r.os,
            os_version=r.os_version, arch=r.arch, agent_version=r.agent_version,
            status=_stale_status(r), registered_at=r.registered_at,
            last_seen_at=r.last_seen_at, tags=r.tags, group_id=r.group_id,
            stealth_mode=r.stealth_mode, cpu_pct=r.cpu_pct, memory_pct=r.memory_pct,
            disk_free_bytes=r.disk_free_bytes, update_status=r.update_status,
        )
        for r in rows
    ]


@router.get("/groups", dependencies=[Depends(current_user)])
def list_groups(db=Depends(get_db)):
    rows = db.query(EndpointAgentGroup).order_by(EndpointAgentGroup.name).all()
    return [GroupOut(id=r.id, name=r.name, description=r.description, created_at=r.created_at) for r in rows]


@router.post("/groups", status_code=201, dependencies=[Depends(administrator)])
def create_group(payload: GroupCreate, db=Depends(get_db)):
    row = EndpointAgentGroup(
        name=payload.name.strip(),
        description=payload.description,
        default_config=_json_dumps(payload.default_config),
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Group name already exists")
    db.refresh(row)
    return GroupOut(id=row.id, name=row.name, description=row.description, created_at=row.created_at)


@router.get("/{agent_id}", dependencies=[Depends(current_user)])
def get_agent(agent_id: int, db=Depends(get_db)):
    r = db.get(EndpointAgent, agent_id)
    if r is None:
        raise HTTPException(404, "Agent not found")
    return AgentOut(
        id=r.id, machine_id=r.machine_id, hostname=r.hostname, os=r.os,
        os_version=r.os_version, arch=r.arch, agent_version=r.agent_version,
        status=_stale_status(r), registered_at=r.registered_at,
        last_seen_at=r.last_seen_at, tags=r.tags, group_id=r.group_id,
        stealth_mode=r.stealth_mode, cpu_pct=r.cpu_pct, memory_pct=r.memory_pct,
        disk_free_bytes=r.disk_free_bytes, update_status=r.update_status,
    )


@router.patch("/{agent_id}", dependencies=[Depends(administrator)])
def update_agent(agent_id: int, payload: AgentUpdate, db=Depends(get_db)):
    r = db.get(EndpointAgent, agent_id)
    if r is None:
        raise HTTPException(404, "Agent not found")
    if payload.hostname is not None:
        r.hostname = payload.hostname
    if payload.status is not None:
        r.status = payload.status
    if payload.tags is not None:
        r.tags = _json_dumps(payload.tags)
    if payload.group_id is not None:
        r.group_id = payload.group_id
    if payload.stealth_mode is not None:
        r.stealth_mode = payload.stealth_mode
    if payload.config_json is not None:
        # merge shallow keys with defaults from AgentConfig
        merged = AgentConfig(**{**_json_loads(r.config_json, {}), **payload.config_json})
        r.config_json = _json_dumps(merged.model_dump())
    db.commit()
    db.refresh(r)
    return {"id": r.id, "status": "updated"}


@router.delete("/{agent_id}", status_code=204, dependencies=[Depends(administrator)])
def revoke_agent(agent_id: int, db=Depends(get_db)):
    r = db.get(EndpointAgent, agent_id)
    if r is None:
        raise HTTPException(404, "Agent not found")
    r.status = "suspended"
    r.token_hash = "revoked-" + secrets.token_hex(32)
    db.commit()
    return None


@router.post("/{agent_id}/command", status_code=202, dependencies=[Depends(writer)])
def send_agent_command(agent_id: int, payload: AgentCommand, db=Depends(get_db)):
    r = db.get(EndpointAgent, agent_id)
    if r is None:
        raise HTTPException(404, "Agent not found")
    if r.status == "suspended":
        raise HTTPException(400, "Agent suspended")
    r.pending_command = _json_dumps({"command": payload.command, "args": payload.args, "actor": payload.actor})
    db.commit()
    return {"queued": True, "command": payload.command, "agent_id": r.id}


@router.post("/{agent_id}/screenshot-command", status_code=202, dependencies=[Depends(writer)])
def request_screenshot(agent_id: int, db=Depends(get_db)):
    r = db.get(EndpointAgent, agent_id)
    if r is None:
        raise HTTPException(404, "Agent not found")
    from app.privacy import capture_allowed
    capture_allowed(db, agent_id)
    r.pending_command = _json_dumps({"command": "screenshot_now", "args": {}, "actor": "ui"})
    db.commit()
    return {"queued": True, "agent_id": r.id}


@router.get("/{agent_id}/events", dependencies=[Depends(current_user)])
def list_agent_events(
    agent_id: int,
    type: str = Query(default=""),
    severity: str = Query(default=""),
    before_id: int | None = None,
    since: str = Query(default=""),
    until: str = Query(default=""),
    limit: int = Query(default=200, ge=1, le=2000),
    db=Depends(get_db),
):
    r = db.get(EndpointAgent, agent_id)
    if r is None:
        raise HTTPException(404, "Agent not found")
    query = db.query(EndpointEvent).filter_by(agent_id=agent_id)
    if type:
        query = query.filter_by(type=type)
    if severity:
        query = query.filter_by(severity=severity)
    if before_id is not None:
        query = query.filter(EndpointEvent.id < before_id)
    rows = query.order_by(desc(EndpointEvent.id)).limit(limit).all()
    return [
        EndpointEventOut(
            id=e.id, agent_id=e.agent_id, type=e.type, severity=e.severity,
            occurred_at=e.occurred_at, received_at=e.received_at, payload=e.payload,
            alert_id=e.alert_id, case_id=e.case_id, linked_by=e.linked_by,
        )
        for e in rows
    ]


@router.get("/events/search", dependencies=[Depends(current_user)])
def search_events(
    q: str = Query(default=""),
    type: str = Query(default=""),
    severity: str = Query(default=""),
    agent_id: int | None = None,
    case_id: int | None = None,
    before_id: int | None = None,
    limit: int = Query(default=200, ge=1, le=2000),
    db=Depends(get_db),
):
    query = db.query(EndpointEvent)
    if agent_id is not None:
        query = query.filter_by(agent_id=agent_id)
    if case_id is not None:
        query = query.filter_by(case_id=case_id)
    if type:
        query = query.filter_by(type=type)
    if severity:
        query = query.filter_by(severity=severity)
    if q:
        like = f"%{q}%"
        query = query.filter(EndpointEvent.payload.like(like))
    if before_id is not None:
        query = query.filter(EndpointEvent.id < before_id)
    rows = query.order_by(desc(EndpointEvent.id)).limit(limit).all()
    return [
        EndpointEventOut(
            id=e.id, agent_id=e.agent_id, type=e.type, severity=e.severity,
            occurred_at=e.occurred_at, received_at=e.received_at, payload=e.payload,
            alert_id=e.alert_id, case_id=e.case_id, linked_by=e.linked_by,
        )
        for e in rows
    ]


@router.get("/{agent_id}/tamper-events", dependencies=[Depends(current_user)])
def list_tamper_events(agent_id: int, limit: int = Query(default=100, ge=1, le=500), db=Depends(get_db)):
    r = db.get(EndpointAgent, agent_id)
    if r is None:
        raise HTTPException(404, "Agent not found")
    rows = db.query(EndpointTamperEvent).filter_by(agent_id=agent_id).order_by(desc(EndpointTamperEvent.id)).limit(limit).all()
    return [
        TamperEventOut(id=t.id, agent_id=t.agent_id, type=t.type, detail=t.detail,
                       occurred_at=t.occurred_at, resolved=t.resolved)
        for t in rows
    ]


@router.post("/events/{event_id}/link", dependencies=[Depends(writer)])
def link_event_to_case(event_id: int, payload: EventLink, db=Depends(get_db)):
    evt = db.get(EndpointEvent, event_id)
    if evt is None:
        raise HTTPException(404, "Event not found")
    case = db.get(Case, payload.case_id)
    if case is None:
        raise HTTPException(404, "Case not found")
    alert_id = evt.alert_id
    if payload.create_alert and alert_id is None:
        title = payload.alert_title.strip() or f"Endpoint event: {evt.type}"
        alert = Alert(
            title=title[:200],
            description=f"Linked from endpoint event #{evt.id}.",
            score=payload.alert_score,
            entity_type="endpoint",
            entity_ref=f"agent:{evt.agent_id}",
            channel=evt.type,
            case_id=case.id,
            status="linked",
        )
        db.add(alert)
        db.flush()
        alert_id = alert.id
        evt.alert_id = alert_id
    evt.case_id = case.id
    evt.linked_by = payload.actor
    db.add(Activity(
        case_id=case.id,
        action="event_linked",
        detail=f"Endpoint event #{evt.id} ({evt.type}) linked by {payload.actor}",
        actor=payload.actor,
    ))
    if case.score < payload.alert_score:
        case.score = payload.alert_score
    case.updated_at = utcnow()
    db.commit()
    return {"linked": True, "event_id": evt.id, "case_id": case.id, "alert_id": alert_id}


@router.post("/events/bulk-link", dependencies=[Depends(writer)])
def bulk_link_events(payload: BulkEventLink, db=Depends(get_db)):
    case = db.get(Case, payload.case_id)
    if case is None:
        raise HTTPException(404, "Case not found")
    linked = 0
    alerts = 0
    for eid in payload.event_ids:
        evt = db.get(EndpointEvent, eid)
        if evt is None:
            continue
        if evt.case_id == case.id:
            continue
        if payload.create_alert and evt.alert_id is None:
            alert = Alert(
                title=f"Endpoint event: {evt.type}"[:200],
                description=f"Linked from endpoint event #{evt.id}.",
                score=payload.alert_score,
                entity_type="endpoint",
                entity_ref=f"agent:{evt.agent_id}",
                channel=evt.type,
                case_id=case.id,
                status="linked",
            )
            db.add(alert)
            db.flush()
            evt.alert_id = alert.id
            alerts += 1
        evt.case_id = case.id
        evt.linked_by = payload.actor
        linked += 1
    if linked:
        db.add(Activity(
            case_id=case.id,
            action="bulk_event_linked",
            detail=f"Bulk-linked {linked} endpoint events by {payload.actor}",
            actor=payload.actor,
        ))
        case.updated_at = utcnow()
        if case.score < payload.alert_score:
            case.score = payload.alert_score
    db.commit()
    return {"linked": linked, "alerts_created": alerts, "case_id": case.id}
