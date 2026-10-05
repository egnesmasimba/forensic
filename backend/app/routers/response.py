import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, update
from app.auth import administrator, current_user, get_db
from app.enforcement import CAPABILITIES, automatable_actions
from app.models import Alert, Case, EndpointAgent, utcnow
from app.response_models import ResponseCommand, ResponseAudit, ReplaySession
from app.routers.agents import _agent_from_token

router = APIRouter(prefix="/api/response", tags=["endpoint response"])
ACTIONS = ("process_list","process_terminate","isolate","release","snapshot","rollback","verify_rollback","live_start","live_stop","control_input","isolation_status")

class CommandInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["process_list","process_terminate","isolate","release","snapshot","rollback","verify_rollback","live_start","live_stop","control_input","isolation_status"]
    arguments: dict = Field(default_factory=dict)
    reason: str = Field(min_length=3, max_length=500)
    case_id: int | None = Field(default=None, ge=1)

class ProcessTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pid: int = Field(ge=5,le=2147483647)
    create_time: float = Field(gt=0,allow_inf_nan=False)

class SnapshotOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Literal["files","windows_system"] = "files"

class PointTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    point_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    scope: Literal["files","windows_system"] = "files"

class LiveOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["view","control"] = "view"
    duration: int = Field(default=300,ge=30,le=600)

class SessionTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: int = Field(ge=1)

class ControlInput(SessionTarget):
    event: Literal["click","key","text","scroll"]
    x: float | None = Field(default=None,ge=0,le=1,allow_inf_nan=False)
    y: float | None = Field(default=None,ge=0,le=1,allow_inf_nan=False)
    key: str = Field(default="",max_length=20)
    text: str = Field(default="",max_length=1000)
    amount: int = Field(default=0,ge=-10,le=10)

class ResultInput(BaseModel):
    state: Literal["succeeded","failed","indeterminate","pending_verification"]
    detail: dict


def audit(db, agent_id, action, actor, command_id=None, case_id=None, **detail):
    db.add(ResponseAudit(agent_id=agent_id,command_id=command_id,case_id=case_id,action=action,actor=actor,detail=json.dumps(detail,default=str)))

def command_payload(row, private=False):
    return {"id":row.id,"agent_id":row.agent_id,"case_id":row.case_id,"action":row.action,"arguments":{k: ("[redacted]" if k=="text" and not private else v) for k,v in json.loads(row.arguments).items()},
            "actor":row.actor,"reason":row.reason,"state":row.state,"result":json.loads(row.result),
            "expires_at":row.expires_at.replace(tzinfo=timezone.utc).isoformat()}

def valid_arguments(data):
    classes={"snapshot":SnapshotOptions,"process_terminate":ProcessTarget,"rollback":PointTarget,"verify_rollback":PointTarget,
             "live_start":LiveOptions,"live_stop":SessionTarget,"control_input":ControlInput}
    try:
        if data.action in classes: return classes[data.action](**data.arguments).model_dump()
        if data.arguments: raise ValueError("This command takes no arguments")
        return {}
    except ValueError as error: raise HTTPException(422,str(error))

@router.post("/agents/{agent_id}/commands",status_code=202)
def queue_command(agent_id:int,data:CommandInput,user=Depends(administrator),db=Depends(get_db)):
    agent=db.get(EndpointAgent,agent_id)
    if agent is None: raise HTTPException(404,"Agent not found")
    if agent.status == "suspended": raise HTTPException(409,"Agent is suspended")
    arguments=valid_arguments(data)
    if not data.reason.strip():raise HTTPException(422,"Enter a reason")
    case_id=None
    if data.case_id is not None:
        # An endpoint action may only be filed under a case that already holds an
        # alert from this same endpoint. Without this the timeline would carry
        # containment of host A as evidence in an unrelated investigation.
        if db.get(Case, data.case_id) is None: raise HTTPException(404,"Case not found")
        linked=db.query(Alert).filter(Alert.case_id==data.case_id,Alert.entity_ref==f"agent:{agent_id}").count()
        if not linked: raise HTTPException(409,"That case has no alert from this endpoint")
        case_id=data.case_id
    if db.query(ResponseCommand).filter(ResponseCommand.agent_id == agent_id, ResponseCommand.state.in_(["queued","dispatched"])).count() >= 100:
        raise HTTPException(409,"Agent command queue is full")
    session=None
    if data.action == "live_start":
        from app.privacy import capture_allowed
        capture_allowed(db, agent_id)
        active=db.query(ReplaySession).filter(ReplaySession.agent_id==agent_id,ReplaySession.status.in_(["requested","active"]),ReplaySession.expires_at>utcnow()).first()
        if active: raise HTTPException(409,"Stop the existing live session first")
        session=ReplaySession(title=f"{agent.hostname} live desktop",platform="desktop",agent_id=agent_id,case_id=case_id,
            mode=arguments["mode"],status="requested",created_by=user.username,expires_at=utcnow()+timedelta(seconds=arguments["duration"]))
        db.add(session);db.flush();arguments["session_id"]=session.id
    if data.action in ("live_stop","control_input"):
        session=db.get(ReplaySession,arguments["session_id"])
        if session is None or session.agent_id!=agent_id: raise HTTPException(404,"Session not found on this agent")
        if data.action=="control_input":
            if session.status!="active" or session.mode!="control" or session.expires_at.replace(tzinfo=timezone.utc)<utcnow(): raise HTTPException(409,"Control session is not active")
            if session.created_by!=user.username: raise HTTPException(403,"Only the session operator can control this desktop")
            if arguments["event"]=="click" and (arguments["x"] is None or arguments["y"] is None): raise HTTPException(422,"Click needs coordinates")
        else: session.status="stopping"
    lifetime=10 if data.action=="control_input" else 600
    row=ResponseCommand(agent_id=agent_id,case_id=case_id,action=data.action,arguments=json.dumps(arguments),actor=user.username,
                        reason=data.reason,state="queued",expires_at=utcnow()+timedelta(seconds=lifetime))
    db.add(row);db.flush();audit(db,agent_id,"command_queued",user.username,row.id,case_id=case_id,action_name=data.action,reason=data.reason,
        # Typed input may contain secrets: retain lengths, not keystroke text.
        arguments={k: (len(v) if k=="text" else v) for k,v in arguments.items()})
    db.commit();return command_payload(row)

def expire_commands(db,agent_id):
    now=utcnow()
    stale=db.query(ResponseCommand).filter(ResponseCommand.agent_id==agent_id,ResponseCommand.state.in_(["queued","dispatched"]),ResponseCommand.expires_at<now).all()
    for row in stale:
        row.state="expired" if row.state=="queued" else "indeterminate"
        if row.action=="control_input":
            arguments=json.loads(row.arguments);arguments["text"]="";row.arguments=json.dumps(arguments)
        audit(db,agent_id,"command_expired","server",row.id,case_id=row.case_id,state=row.state)
        if row.action=="live_start":
            session=db.get(ReplaySession,json.loads(row.arguments).get("session_id"))
            if session:session.status="expired"
    db.commit()

@router.get("/poll")
def poll(request:Request,db=Depends(get_db)):
    agent=_agent_from_token(request,db)
    now=utcnow()
    expire_commands(db,agent.id)
    # Input is never replayed after a lease timeout: a repeated click could act on a new window.
    rows=db.query(ResponseCommand).filter(ResponseCommand.agent_id==agent.id,ResponseCommand.expires_at>=now,
        or_(ResponseCommand.state=="queued",(ResponseCommand.state=="dispatched") & (ResponseCommand.lease_until<now))).order_by(ResponseCommand.id).limit(10).all()
    for row in rows:
        if row.action == "live_start":
            from app.privacy import capture_allowed
            try: capture_allowed(db, agent.id)
            except HTTPException:
                row.state = "failed"
                audit(db, agent.id, "privacy_blocked", "server", row.id, case_id=row.case_id)
                db.commit(); continue
        if row.state=="dispatched" and row.action=="control_input":
            row.state="indeterminate";audit(db,agent.id,"input_delivery_unknown","server",row.id,case_id=row.case_id);db.commit();continue
        old_state=row.state;old_lease=row.lease_until
        conditions=[ResponseCommand.id==row.id,ResponseCommand.state==old_state]
        if old_state=="dispatched":conditions.append(ResponseCommand.lease_until==old_lease)
        changed=db.execute(update(ResponseCommand).where(*conditions).values(state="dispatched",lease_until=now+timedelta(seconds=120)))
        if not changed.rowcount:db.rollback();continue
        audit(db,agent.id,"command_dispatched","agent",row.id,case_id=row.case_id);db.commit();db.refresh(row)
        return {"command":command_payload(row, private=True)}
    return {"command":None}

@router.post("/commands/{command_id}/result")
def result(command_id:int,data:ResultInput,request:Request,db=Depends(get_db)):
    agent=_agent_from_token(request,db)
    row=db.get(ResponseCommand,command_id)
    if row is None or row.agent_id!=agent.id:raise HTTPException(404,"Command not found")
    encoded=json.dumps(data.model_dump(),sort_keys=True,separators=(",",":"))
    if len(encoded.encode())>256*1024:raise HTTPException(413,"Result is too large")
    digest=hashlib.sha256(encoded.encode()).hexdigest()
    if row.result_digest:
        if row.result_digest!=digest:raise HTTPException(409,"A different result was already acknowledged")
        return {"acknowledged":True,"duplicate":True}
    if row.state not in ("dispatched","indeterminate"):raise HTTPException(409,"Command was not dispatched")
    if data.state=="pending_verification" and (row.action!="rollback" or json.loads(row.arguments).get("scope")!="windows_system"):
        raise HTTPException(422,"Only native Windows rollback can await reboot verification")
    arguments=json.loads(row.arguments)
    if data.state=="succeeded":
        required={"process_terminate":"terminated","isolate":"isolated","release":"released",
                  "live_start":"local_consent","live_stop":"stopped","control_input":"input_applied",
                  "snapshot":"verified","rollback":"verified","verify_rollback":"verified"}.get(row.action)
        if required and data.detail.get(required) is not True:
            raise HTTPException(422,"Successful result must include its action confirmation")
        if row.action in ("snapshot","rollback","verify_rollback"):
            identity=data.detail.get("point_id","")
            if len(identity)!=32 or any(c not in "0123456789abcdef" for c in identity):raise HTTPException(422,"Result needs a valid point identity")
            if row.action!="snapshot" and identity!=arguments["point_id"]:raise HTTPException(422,"Result refers to another rollback point")
        if row.action=="process_terminate" and (data.detail.get("pid")!=arguments["pid"] or data.detail.get("create_time")!=arguments["create_time"]):
            raise HTTPException(422,"Termination confirmation refers to another process")
    if data.state=="pending_verification" and (data.detail.get("restart_scheduled") is not True or data.detail.get("point_id")!=arguments["point_id"]):
        raise HTTPException(422,"Pending verification must confirm the scheduled restart and point")
    changed=db.execute(update(ResponseCommand).where(ResponseCommand.id==row.id,ResponseCommand.result_digest=="",
        ResponseCommand.state.in_(["dispatched","indeterminate"])).values(result=json.dumps(data.detail),result_digest=digest,state=data.state))
    if not changed.rowcount:
        db.rollback();raise HTTPException(409,"Concurrent result acknowledgement; retry")
    if row.action in ("live_start","live_stop"):
        session=db.get(ReplaySession,json.loads(row.arguments)["session_id"])
        if session:
            if row.action=="live_stop":session.status="stopped" if data.state=="succeeded" else "stop_failed"
            else:session.status="active" if data.state=="succeeded" and session.status=="requested" and session.expires_at.replace(tzinfo=timezone.utc)>utcnow() else "failed"
    audit(db,agent.id,"command_result","agent",row.id,case_id=row.case_id,state=data.state,detail=data.detail)
    if row.action=="verify_rollback" and data.state=="succeeded" and data.detail.get("verified"):
        arguments=json.loads(row.arguments)
        for pending in db.query(ResponseCommand).filter_by(agent_id=agent.id,action="rollback",state="pending_verification").all():
            if json.loads(pending.arguments)==arguments:
                pending.state="succeeded"
                old=json.loads(pending.result);old["verification_command_id"]=row.id;old["verification"]=data.detail;pending.result=json.dumps(old)
                audit(db,agent.id,"rollback_verified","agent",pending.id,case_id=pending.case_id,verification_command_id=row.id)
    # Avoid retaining remote typed text beyond the short dispatch window.
    if row.action=="control_input":
        arguments=json.loads(row.arguments);arguments["text"]="";row.arguments=json.dumps(arguments)
    db.commit();return {"acknowledged":True,"duplicate":False}

@router.get("/capabilities")
def capabilities(db=Depends(get_db)):
    # Deliberately readable by any signed-in user: an operator must be able to
    # see which controls are real before relying on one, not discover it after.
    return {"capabilities": [dict(entry) for entry in CAPABILITIES],
            "automatable": list(automatable_actions())}


@router.get("/agents/{agent_id}/commands",dependencies=[Depends(current_user)])
def commands(agent_id:int,limit:int=Query(50,ge=1,le=100),db=Depends(get_db)):
    expire_commands(db,agent_id)
    return [command_payload(row) for row in db.query(ResponseCommand).filter_by(agent_id=agent_id).order_by(ResponseCommand.id.desc()).limit(limit)]

@router.get("/agents/{agent_id}/audit",dependencies=[Depends(current_user)])
def history(agent_id:int,limit:int=Query(100,ge=1,le=500),db=Depends(get_db)):
    return [{"id":row.id,"actor":row.actor,"action":row.action,"command_id":row.command_id,"detail":json.loads(row.detail),
        "occurred_at":row.occurred_at.replace(tzinfo=timezone.utc).isoformat()} for row in db.query(ResponseAudit).filter_by(agent_id=agent_id).order_by(ResponseAudit.id.desc()).limit(limit)]


class SessionEnded(SessionTarget):
    reason: str = Field(default="local stop or expiry",max_length=100)

@router.post("/session-ended")
def session_ended(data:SessionEnded,request:Request,db=Depends(get_db)):
    agent=_agent_from_token(request,db)
    session=db.get(ReplaySession,data.session_id)
    if session is None or session.agent_id!=agent.id:raise HTTPException(404,"Session not found")
    if session.status!="stopped":
        session.status="stopped";audit(db,agent.id,"desktop_session_ended","local endpoint",case_id=session.case_id,session_id=session.id,reason=data.reason)
        db.commit()
    return {"acknowledged":True}
