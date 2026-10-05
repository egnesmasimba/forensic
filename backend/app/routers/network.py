import base64
import hashlib
import io
import json
from datetime import timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from typing import Literal
from sqlalchemy.exc import IntegrityError

from app.auth import current_user, get_db, writer
from app.models import NetworkCapture, NetworkMessageLayout
from network_sensor.config import SensorConfig
from network_sensor.layouts import decode_layout, import_layout
from network_sensor.layout_application import apply_layouts
from network_sensor.commands import collect
from network_sensor.files import collect as collect_files
from network_sensor.findings import TACTICS, matches as finding_matches
from network_sensor.packets import CaptureError
from network_sensor.pipeline import analyze_pcap
from network_sensor.protocols import CAPABILITIES, PROTOCOLS

router = APIRouter(prefix="/api/network", tags=["network sensor"], dependencies=[Depends(current_user)])
MAX_UPLOAD = 10 * 1024 * 1024


@router.get("/capabilities")
def capabilities():
    return {"capture_backend": "Npcap on Windows / libpcap on Unix", "offline_format": "PCAP and timestamped PCAPNG",
            "live_capture": "Run the separate network_sensor CLI; no capture is started by a web request",
            "protocols": [{"name": name, "coverage": CAPABILITIES.get(name, "Identification/opaque recording only")}
                          for name in PROTOCOLS], "max_upload_bytes": MAX_UPLOAD}


def summary(row):
    report = json.loads(row.report)
    return {"id": row.id, "name": row.name, "imported_by": row.imported_by,
            "created_at": row.created_at.replace(tzinfo=timezone.utc).isoformat(),
            "sha256": row.sha256, "format": "pcapng" if row.raw[:4] == b"\x0a\x0d\x0d\x0a" else "pcap",
            "size": len(row.raw), "metrics": report["metrics"], "sessions": len(report["sessions"]), "traffic_analysis": report.get("traffic_analysis")}


@router.post("/pcap", status_code=201)
async def upload_pcap(file: UploadFile, config: str = Form(default="{}", max_length=8192),
                      user=Depends(writer), db=Depends(get_db)):
    try:
        settings = SensorConfig.model_validate_json(config)
    except ValidationError:
        raise HTTPException(422, "Invalid protocol or sensor configuration")
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "Capture file must be at most 10 MB")
    try:
        report = await run_in_threadpool(analyze_pcap, io.BytesIO(data), settings.model_dump())
    except CaptureError as error:
        raise HTTPException(422, str(error))
    row = NetworkCapture(name=(file.filename or "capture.pcap").replace("\\", "/").split("/")[-1][:200],
                         imported_by=user.username, raw=data, report=json.dumps(report),
                         sha256=hashlib.sha256(data).hexdigest())
    db.add(row)
    db.commit()
    db.refresh(row)
    return summary(row)


@router.get("/captures")
def captures(limit: int = Query(default=30, ge=1, le=100), before_id: int | None = Query(default=None, ge=1), db=Depends(get_db)):
    query = db.query(NetworkCapture)
    if before_id:
        query = query.filter(NetworkCapture.id < before_id)
    return [summary(row) for row in query.order_by(NetworkCapture.id.desc()).limit(limit).all()]


def capture_or_404(db, capture_id):
    row = db.get(NetworkCapture, capture_id)
    if row is None:
        raise HTTPException(404, "Capture not found")
    return row


class IndicatorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    malware_ips: list[str] = Field(default_factory=list, max_length=100)
    c2_ips: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("malware_ips", "c2_ips")
    @classmethod
    def addresses(cls, values):
        from ipaddress import ip_address
        try:
            return sorted({str(ip_address(value)) for value in values})
        except ValueError:
            raise ValueError("Indicators must be IP addresses")


@router.post("/captures/{capture_id}/indicators")
async def reanalyze_indicators(capture_id: int, body: IndicatorInput, user=Depends(writer), db=Depends(get_db)):
    if not body.malware_ips and not body.c2_ips:
        raise HTTPException(422, "Name at least one address")
    row = capture_or_404(db, capture_id)
    if hashlib.sha256(row.raw).hexdigest() != row.sha256:
        raise HTTPException(409, "Stored capture no longer matches its hash")
    settings = SensorConfig(malware_ips=body.malware_ips, c2_ips=body.c2_ips)
    try:
        report = await run_in_threadpool(analyze_pcap, io.BytesIO(row.raw), settings.model_dump())
    except CaptureError as error:
        raise HTTPException(422, str(error))
    row.report = json.dumps(report)
    db.commit()
    return summary(row)


@router.post("/captures/{capture_id}/rules")
async def reapply_rules(capture_id: int, user=Depends(writer), db=Depends(get_db)):
    row = capture_or_404(db, capture_id)
    if hashlib.sha256(row.raw).hexdigest() != row.sha256:
        raise HTTPException(409, "Stored capture no longer matches its hash")
    try:
        report = await run_in_threadpool(analyze_pcap, io.BytesIO(row.raw), SensorConfig().model_dump())
    except CaptureError as error:
        raise HTTPException(422, str(error))
    digest = row.sha256
    row.report = json.dumps(report)
    db.commit()
    result = summary(row)
    if result["sha256"] != digest:
        raise HTTPException(409, "Stored capture no longer matches its hash")
    return result


@router.get("/findings/search")
def search_findings(tactic: str = Query(min_length=3, max_length=40), db=Depends(get_db)):
    if tactic not in TACTICS:
        raise HTTPException(422, "Unknown stored-finding search")
    hits = []
    for row in db.query(NetworkCapture).order_by(NetworkCapture.id.desc()).limit(20).all():
        report = json.loads(row.report)
        for finding in report.get("traffic_analysis", {}).get("findings", []):
            if not finding_matches(finding, tactic):
                continue
            hits.append({
                "capture_id": row.id, "capture_name": row.name, "tactic": tactic,
                "title": finding.get("title", ""), "category": finding.get("category", ""),
                "evidence": finding.get("evidence") or {},
            })
            if len(hits) >= 50:
                return hits
    return hits


@router.get("/files/search")
def search_files(q: str = Query(min_length=2, max_length=80), db=Depends(get_db)):
    term = q.strip().lower()
    if len(term) < 2:
        raise HTTPException(422, "Enter at least two characters")
    hits = []
    for row in db.query(NetworkCapture).order_by(NetworkCapture.id.desc()).limit(20).all():
        for session in json.loads(row.report)["sessions"]:
            for item in session.get("files") or collect_files(session):
                blob = " ".join(str(item.get(key) or "") for key in ("protocol", "sha256", "name", "sensitive")).lower()
                if term not in blob:
                    continue
                hits.append({
                    "capture_id": row.id, "capture_name": row.name, "protocol": item["protocol"],
                    "length": item["length"], "sha256": item["sha256"],
                    "name": item.get("name", ""), "sensitive": item.get("sensitive", ""),
                })
                if len(hits) >= 50:
                    return hits
    return hits


@router.get("/sessions/search")
def search_sessions(q: str = Query(min_length=2, max_length=80), db=Depends(get_db)):
    term = q.strip().lower()
    if len(term) < 2:
        raise HTTPException(422, "Enter at least two characters")
    hits = []
    for row in db.query(NetworkCapture).order_by(NetworkCapture.id.desc()).limit(20).all():
        for session in json.loads(row.report)["sessions"]:
            ends = " <-> ".join(":".join(map(str, endpoint)) for endpoint in session.get("endpoints", []))
            blob = " ".join([session.get("protocol", ""), session.get("transport", ""), ends]).lower()
            if term not in blob:
                continue
            hits.append({
                "capture_id": row.id, "capture_name": row.name, "protocol": session.get("protocol"),
                "transport": session.get("transport"), "session": ends, "packets": session.get("packets", 0),
            })
            if len(hits) >= 50:
                return hits
    return hits


@router.get("/commands/search")
def search_commands(q: str = Query(min_length=2, max_length=80), db=Depends(get_db)):
    term = q.strip().lower()
    if len(term) < 2:
        raise HTTPException(422, "Enter at least two characters")
    hits = []
    for row in db.query(NetworkCapture).order_by(NetworkCapture.id.desc()).limit(20).all():
        for session in json.loads(row.report)["sessions"]:
            ends = " <-> ".join(":".join(map(str, endpoint)) for endpoint in session.get("endpoints", []))
            for command in session.get("commands") or collect(session):
                if term not in command["text"].lower():
                    continue
                hits.append({
                    "capture_id": row.id, "capture_name": row.name, "session": ends,
                    "protocol": command["protocol"], "text": command["text"][:200],
                })
                if len(hits) >= 50:
                    return hits
    return hits


@router.get("/messages/search")
def search_messages(q: str = Query(min_length=2, max_length=80), db=Depends(get_db)):
    term = q.strip().lower()
    if len(term) < 2:
        raise HTTPException(422, "Enter at least two characters")
    layouts = db.query(NetworkMessageLayout).filter_by(enabled=True).order_by(NetworkMessageLayout.id).limit(100).all()
    captures = db.query(NetworkCapture).order_by(NetworkCapture.id.desc()).limit(20).all()
    hits = []
    for row in captures:
        sessions = json.loads(row.report)["sessions"]
        budget = {"records": 500, "bytes": 1024 * 1024}
        for session in sessions:
            apply_layouts(session, layouts, budget)
            ends = " <-> ".join(":".join(map(str, endpoint)) for endpoint in session.get("endpoints", []))
            for result in session["layout_results"]:
                for record in result["records"]:
                    fields = {key: str(value)[:80] for key, value in record["fields"].items()}
                    blob = " ".join([record.get("message_type", ""), *fields.values()]).lower()
                    if term not in blob:
                        continue
                    hits.append({
                        "capture_id": row.id,
                        "capture_name": row.name,
                        "session": ends,
                        "direction": result["direction"],
                        "layout": result["name"],
                        "record": record["index"] + 1,
                        "message_type": record.get("message_type", ""),
                        "fields": fields,
                    })
                    if len(hits) >= 50:
                        return hits
    return hits


@router.get("/captures/{capture_id}")
def capture_detail(capture_id: int, db=Depends(get_db)):
    row = capture_or_404(db, capture_id)
    sessions = json.loads(row.report)["sessions"]
    layouts = db.query(NetworkMessageLayout).filter_by(enabled=True).order_by(NetworkMessageLayout.id).limit(100).all()
    budget = {"records": 500, "bytes": 1024 * 1024}
    for session in sessions:
        apply_layouts(session, layouts, budget)
        for datagram in session["datagrams"]:
            raw = base64.b64decode(datagram.pop("payload_base64"))
            datagram["length"] = len(raw)
            datagram["hex_preview"] = raw[:256].hex()
        for direction in session["directions"]:
            direction.pop("payload_base64", None)
    return {**summary(row), "session_details": sessions}


@router.get("/captures/{capture_id}/download")
def capture_download(capture_id: int, db=Depends(get_db)):
    row = capture_or_404(db, capture_id)
    extension = "pcapng" if row.raw[:4] == b"\x0a\x0d\x0d\x0a" else "pcap"
    return Response(row.raw, media_type="application/octet-stream" if extension == "pcapng" else "application/vnd.tcpdump.pcap",
                    headers={"Content-Disposition": f"attachment; filename=capture-{row.id}.{extension}",
                             "X-Capture-SHA256": row.sha256, "Cache-Control": "no-store"})


class LayoutPreview(BaseModel):
    language: str = Field(max_length=12)
    declaration: str = Field(min_length=1, max_length=65536)
    message_base64: str = Field(default="", max_length=90000)
    encoding: str = "ascii"
    byteorder: str = "big"


@router.post("/layouts/preview")
def layout_preview(payload: LayoutPreview, user=Depends(writer)):
    try:
        layout = import_layout(payload.language, payload.declaration)
        decoded = None
        if payload.message_base64:
            data = base64.b64decode(payload.message_base64, validate=True)
            decoded = decode_layout(layout, data, payload.encoding, payload.byteorder)
        return {"layout": layout, "decoded": decoded}
    except (CaptureError, ValueError, UnicodeError) as error:
        raise HTTPException(422, str(error))


class LayoutCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80, pattern=r"\S")
    version: int = Field(ge=1, le=1000000)
    protocol: str
    direction: Literal["both", "0", "1"] = "both"
    offset: int = Field(default=0, ge=0, le=65535)
    language: Literal["cobol", "cobol-ibm", "c", "c-msvc", "vb"]
    declaration: str = Field(min_length=1, max_length=65536)
    encoding: Literal["ascii", "cp037", "latin-1"] = "ascii"
    byteorder: Literal["big", "little"] = "big"
    identify_field: str = Field(default="", max_length=80)
    framing: Literal["fixed", "length_prefix"] = "fixed"
    length_width: Literal[2, 4] = 2
    envelope: int = Field(default=0, ge=0, le=32)


def saved_layout(row):
    definition = json.loads(row.definition)
    return {"id": row.id, "name": row.name, "version": row.version, "protocol": row.protocol,
            "direction": row.direction, "offset": row.offset, "encoding": row.encoding,
            "byteorder": row.byteorder, "identify_field": row.identify_field, "declaration": row.declaration,
            "definition": definition, "framing": definition.get("framing", "fixed"),
            "length_width": definition.get("length_width", 2), "envelope": definition.get("envelope", 0),
            "enabled": row.enabled, "created_by": row.created_by,
            "created_at": row.created_at.replace(tzinfo=timezone.utc).isoformat()}


@router.get("/layouts")
def list_layouts(db=Depends(get_db)):
    return [saved_layout(row) for row in db.query(NetworkMessageLayout).order_by(NetworkMessageLayout.id.desc()).limit(100).all()]


@router.post("/layouts", status_code=201)
def save_layout(payload: LayoutCreate, user=Depends(writer), db=Depends(get_db)):
    if payload.protocol not in PROTOCOLS or payload.protocol in ("https", "ssh"):
        raise HTTPException(422, "Choose a supported plaintext or opaque application protocol; encrypted streams cannot use layouts")
    try:
        definition = import_layout(payload.language, payload.declaration)
        definition["framing"] = payload.framing
        definition["length_width"] = payload.length_width
        definition["envelope"] = payload.envelope
    except CaptureError as error:
        raise HTTPException(422, str(error))
    if len(definition["fields"]) > 100:
        raise HTTPException(422, "Saved layouts are limited to 100 fields")
    names = {field["name"] for field in definition["fields"]}
    if payload.identify_field and payload.identify_field not in names:
        raise HTTPException(422, "The identifying field must be one of the layout fields")
    if db.query(NetworkMessageLayout).count() >= 100:
        raise HTTPException(409, "Layout library is limited to 100 versions")
    row = NetworkMessageLayout(name=payload.name.strip(), version=payload.version, protocol=payload.protocol,
                               direction=payload.direction, offset=payload.offset, encoding=payload.encoding,
                               byteorder=payload.byteorder, declaration=payload.declaration,
                               definition=json.dumps(definition), identify_field=payload.identify_field,
                               created_by=user.username)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "That layout name and version already exists; use a new version")
    db.refresh(row)
    return saved_layout(row)


class LayoutToggle(BaseModel):
    enabled: bool


@router.patch("/layouts/{layout_id}")
def toggle_layout(layout_id: int, payload: LayoutToggle, user=Depends(writer), db=Depends(get_db)):
    row = db.get(NetworkMessageLayout, layout_id)
    if row is None:
        raise HTTPException(404, "Layout not found")
    row.enabled = payload.enabled
    db.commit()
    return saved_layout(row)
