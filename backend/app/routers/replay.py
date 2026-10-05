import base64
import io
import json
from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from app.auth import current_user, get_db, writer
from app.models import EndpointAgent
from app.response_models import ReplaySession, ReplayFrame
from app.search_models import SearchDocument
from app.search_index import assign
from app.content_parser import parse_content
from app.replay_display import display_html
from app.routers.agents import _agent_from_token

router = APIRouter(prefix="/api/replay", tags=["visual replay"])

def iso(value):
    return value.replace(tzinfo=timezone.utc).isoformat() if value.tzinfo is None else value.astimezone(timezone.utc).isoformat()

class SessionInput(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    platform: Literal["mainframe", "web", "client-server", "desktop"]

class FrameInput(BaseModel):
    sequence: int = Field(ge=0, le=100000)
    occurred_at: datetime
    text: str = Field(default="", max_length=262144)
    fields: dict[str, str] = Field(default_factory=dict, max_length=200)
    original_html: str = Field(default="", max_length=262144)
    image_base64: str = Field(default="", max_length=700000)

    @field_validator("occurred_at")
    @classmethod
    def timestamp(cls, value):
        if value.tzinfo is None:
            raise ValueError("Timestamp must include timezone")
        return value.astimezone(timezone.utc)

    @field_validator("fields")
    @classmethod
    def bounded_fields(cls, value):
        if any(len(k) > 120 or len(v) > 4096 for k, v in value.items()):
            raise ValueError("Field names/values exceed limits")
        return value

def session_payload(db, row):
    status=row.status
    if row.expires_at and row.status in ("requested","active") and datetime.now(timezone.utc)>=datetime.fromisoformat(iso(row.expires_at)):
        status="expired"
    return {"id":row.id, "title":row.title, "platform":row.platform, "agent_id":row.agent_id,
            "mode":row.mode, "status":status, "created_by":row.created_by,
            "expires_at":iso(row.expires_at) if row.expires_at else None,
            "frames":db.query(ReplayFrame).filter_by(session_id=row.id).count()}

def frame_payload(db, row):
    previous = db.query(ReplayFrame).filter(ReplayFrame.session_id == row.session_id,
                ReplayFrame.sequence < row.sequence).order_by(ReplayFrame.sequence.desc()).first()
    before = json.loads(previous.fields) if previous else {}
    fields = json.loads(row.fields)
    changes = [{"field":key, "before":before.get(key), "after":fields.get(key)}
               for key in sorted(before.keys() | fields.keys()) if previous and before.get(key) != fields.get(key)]
    return {"id":row.id, "session_id":row.session_id, "sequence":row.sequence, "occurred_at":iso(row.occurred_at),
            "text":row.text, "fields":fields, "changes":changes, "original_html":row.original_html, "display_html":display_html(row.original_html),
            "image_base64":base64.b64encode(row.image).decode() if row.image else "", "document_id":row.document_id}

def get_session(db, session_id):
    row = db.get(ReplaySession, session_id)
    if row is None: raise HTTPException(404, "Session not found")
    return row

def add_frame(db, session, data):
    if db.query(ReplayFrame).filter_by(session_id=session.id).count() >= 600:
        raise HTTPException(409, "Session reached the 600-frame recording limit")
    image = None
    if data.image_base64:
        try:
            from PIL import Image
            image = base64.b64decode(data.image_base64, validate=True)
            if len(image) > 512 * 1024: raise ValueError("Image exceeds 512 KB")
            with Image.open(io.BytesIO(image)) as parsed:
                if parsed.format != "JPEG" or parsed.width > 4096 or parsed.height > 2160:
                    raise ValueError("Use a bounded JPEG image")
                parsed.verify()
        except Exception as error:
            raise HTTPException(422, "Invalid or oversized JPEG frame") from error
    total_images=db.query(func.coalesce(func.sum(func.length(ReplayFrame.image)),0)).scalar()
    if image and total_images+len(image)>512*1024*1024:
        raise HTTPException(409,"Global replay image storage reached 512 MB; archive recordings before capturing more")
    if not (data.text or data.original_html or image or data.fields):
        raise HTTPException(422, "Provide screen content")
    row = ReplayFrame(session_id=session.id, sequence=data.sequence, occurred_at=data.occurred_at,
                      text=data.text, fields=json.dumps(data.fields), original_html=data.original_html, image=image)
    db.add(row)
    try: db.flush()
    except IntegrityError:
        db.rollback(); raise HTTPException(409, "Sequence already recorded")
    # Separate documents keep search results linked to their exact screen.
    if data.text or data.original_html or data.fields:
        try:
            parsed = parse_content(data.original_html or data.text or json.dumps(data.fields),
                                   "html" if data.original_html else "screen", session.title)
        except ValueError as error:
            db.rollback(); raise HTTPException(422, str(error))
        if not row.text: row.text=parsed["body"]
        supplied=[{"caption":key,"value":value} for key,value in data.fields.items()]
        parsed["fields"]=(supplied+parsed["fields"])[:200]
        doc = SearchDocument(source_key=f"replay:{row.id}", source_kind="replay", source_id=str(row.id), created_by=session.created_by)
        assign(doc, parsed, session.platform, data.occurred_at)
        db.add(doc); db.flush(); row.document_id = doc.id
    return row

@router.post("/sessions", status_code=201)
def create_session(data: SessionInput, user=Depends(writer), db=Depends(get_db)):
    row = ReplaySession(title=data.title, platform=data.platform, created_by=user.username)
    db.add(row); db.commit()
    return session_payload(db,row)

@router.get("/sessions", dependencies=[Depends(current_user)])
def sessions(platform: str = "", limit: int = Query(50, ge=1, le=100), db=Depends(get_db)):
    query = db.query(ReplaySession)
    if platform: query = query.filter_by(platform=platform)
    return [session_payload(db,row) for row in query.order_by(ReplaySession.id.desc()).limit(limit)]

@router.post("/sessions/{session_id}/frames", status_code=201)
def import_frame(session_id:int, data:FrameInput, user=Depends(writer), db=Depends(get_db)):
    session = get_session(db,session_id)
    if session.mode != "recorded": raise HTTPException(409,"Live frames must come from the assigned agent")
    row = add_frame(db,session,data); db.commit()
    return frame_payload(db,row)

@router.post("/agent/sessions/{session_id}/frames", status_code=201)
def agent_frame(session_id:int,data:FrameInput,request:Request,db=Depends(get_db)):
    agent = _agent_from_token(request,db)
    session = get_session(db,session_id)
    if session.agent_id != agent.id: raise HTTPException(403,"Session belongs to another agent")
    from app.iam_models import PrivilegedRecording, PrivilegedRequest, IdentitySession, IdentityPolicy
    from app.models import LoginSession, User
    link = db.get(PrivilegedRecording, session.id)
    if link:
        from app.iam import privileged_capture_allowed
        privileged_capture_allowed(db, agent.id)
        grant = db.get(PrivilegedRequest, link.request_id)
        login = db.get(LoginSession, grant.activated_session) if grant else None
        person = db.get(User, grant.user_id) if grant else None
        now = datetime.now(timezone.utc)
        if (not grant or grant.status != 'active' or not grant.expires_at or grant.expires_at.replace(tzinfo=timezone.utc) <= now
                or not login or login.expires_at.replace(tzinfo=timezone.utc) <= now or not person or person.disabled):
            raise HTTPException(403, 'Privileged recording approval or individual session expired')
        identity = db.get(IdentitySession, login.token_hash)
        if identity and identity.shared_user_id:
            shared = db.get(User, identity.shared_user_id)
            policy = db.get(IdentityPolicy, identity.shared_user_id)
            if not shared or shared.disabled or not policy or not policy.shared or person.id not in json.loads(policy.members):
                raise HTTPException(403, 'Shared-account membership was revoked')
    if session.status != "active" or datetime.now(timezone.utc) >= datetime.fromisoformat(iso(session.expires_at)):
        raise HTTPException(409,"Session is not active")
    from app.privacy import capture_allowed
    capture_allowed(db, agent.id)
    row = add_frame(db,session,data); db.commit()
    return {"recorded":True,"sequence":row.sequence}

@router.get("/sessions/{session_id}",dependencies=[Depends(current_user)])
def session(session_id:int,db=Depends(get_db)):
    return session_payload(db,get_session(db,session_id))

@router.get("/sessions/{session_id}/frames", dependencies=[Depends(current_user)])
def frames(session_id:int,after:int=Query(-1,ge=-1),before:int | None=Query(None,ge=0),limit:int=Query(30,ge=1,le=100),db=Depends(get_db)):
    get_session(db,session_id)
    query = db.query(ReplayFrame).filter(ReplayFrame.session_id == session_id)
    if before is not None:
        rows = list(reversed(query.filter(ReplayFrame.sequence < before).order_by(ReplayFrame.sequence.desc()).limit(limit).all()))
    else:
        rows = query.filter(ReplayFrame.sequence > after).order_by(ReplayFrame.sequence).limit(limit).all()
    return [frame_payload(db,row) for row in rows]

@router.get("/from-search/{document_id}", dependencies=[Depends(current_user)])
def from_search(document_id:int,db=Depends(get_db)):
    doc = db.get(SearchDocument,document_id)
    if doc is None: raise HTTPException(404,"Search document not found")
    row = db.query(ReplayFrame).filter_by(document_id=document_id).first()
    if row: return {"session":session_payload(db,get_session(db,row.session_id)),"frame":frame_payload(db,row)}
    # Network indexing keys identify the capture/session and decoded direction.
    # Decoders do not supply per-screen times; preserve decoded order and say so.
    records=[doc]
    notice="Parsed source display; no original screen recording is linked to this record."
    if doc.source_kind=="network" and len(doc.source_key.split(":"))>=6:
        prefix=":".join(doc.source_key.split(":")[:3])+":"
        records=db.query(SearchDocument).filter(SearchDocument.source_kind=="network",SearchDocument.source_id==doc.source_id,SearchDocument.source_key.like(prefix+"%")).limit(500).all()
        records.sort(key=lambda item:(int(item.source_key.split(":")[-3]),item.source_key.split(":")[-2],int(item.source_key.split(":")[-1])))
        notice="Decoded session order, grouped by direction. Per-screen timestamps and original pixels are unavailable; capture gaps remain in the source report."
    output=[]
    for sequence,item in enumerate(records):
        output.append({"document_id":item.id,"sequence":sequence,"text":item.body,
            "fields":{f["caption"]:f["value"] for f in json.loads(item.fields)},"changes":[],
            "original_html":"","image_base64":"","occurred_at":iso(item.occurred_at),"partial":item.partial})
    for index,item in enumerate(output):
        before=output[index-1]["fields"] if index else {}
        item["changes"]=[{"field":key,"before":before.get(key),"after":item["fields"].get(key)}
            for key in sorted(before.keys() | item["fields"].keys()) if before.get(key)!=item["fields"].get(key)]
    return {"session":None,"frame":next(item for item in output if item["document_id"]==doc.id),"frames":output,"notice":notice}
