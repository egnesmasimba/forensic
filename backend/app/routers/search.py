import json
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text

from app.auth import current_user, get_db, writer
from app.content_parser import MAX_CONTENT, parse_content
from app.search_elastic import SearchUnavailable, sync_pending
from app.search_index import SOURCE_MODELS, assign, payload, refresh_source
from app.search_models import SearchDocument, SearchOutbox
from app.search_query import fts_query, fuzzy_hit, parse_query, snippet


router = APIRouter(prefix="/api/search", tags=["free-text search"], dependencies=[Depends(current_user)])


def utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        raise HTTPException(422, "Timeframe values must include a timezone")
    return value.astimezone(timezone.utc)


class ContentInput(BaseModel):
    kind: Literal["html", "screen"]
    content: str = Field(min_length=1, max_length=MAX_CONTENT)
    title: str = Field(default="", max_length=200)
    platform: str = Field(default="web", min_length=1, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def timestamp(cls, value):
        if value.tzinfo is None:
            raise ValueError("Include a timezone in the timestamp")
        return value.astimezone(timezone.utc)


@router.post("/documents", status_code=201)
def ingest(data: ContentInput, user=Depends(writer), db=Depends(get_db)):
    try:
        parsed = parse_content(data.content, data.kind, data.title)
    except ValueError as error:
        raise HTTPException(422, str(error))
    key = str(uuid.uuid4())
    doc = SearchDocument(source_key="content:" + key, source_kind=data.kind, source_id=key, created_by=user.username)
    assign(doc, parsed, data.platform, data.occurred_at)
    db.add(doc)
    db.commit()
    return payload(doc)


@router.get("/documents/{document_id}")
def document(document_id: int, db=Depends(get_db)):
    doc = db.get(SearchDocument, document_id)
    if doc is None:
        raise HTTPException(404, "Search document not found")
    return payload(doc)


@router.delete("/documents/{document_id}", status_code=204)
def remove(document_id: int, user=Depends(writer), db=Depends(get_db)):
    doc = db.get(SearchDocument, document_id)
    if doc is None:
        raise HTTPException(404, "Search document not found")
    if doc.source_kind not in ("html", "screen"):
        raise HTTPException(409, "This document is managed by its source record")
    db.delete(doc)
    db.commit()


@router.get("/status")
def status(request: Request, db=Depends(get_db)):
    return {"backend": "elasticsearch" if request.app.state.search_index else "sqlite",
            "documents": db.query(SearchDocument).count(),
            "pending_external_updates": db.query(SearchOutbox).count() if request.app.state.search_index else 0,
            "partial_documents": db.query(SearchDocument).filter_by(partial=True).count(),
            "external_error": request.app.state.search_last_error,
            "platforms": [r[0] for r in db.query(SearchDocument.platform).distinct().order_by(SearchDocument.platform)],
            "source_kinds": [r[0] for r in db.query(SearchDocument.source_kind).distinct().order_by(SearchDocument.source_kind)]}


@router.post("/backfill")
def backfill(source_kind: Literal["case", "alert", "note", "artifact", "endpoint", "import", "network", "mail"],
             after: str = Query(default="", max_length=120), limit: int = Query(default=100, ge=1, le=100),
             user=Depends(writer), db=Depends(get_db)):
    model = SOURCE_MODELS[source_kind]
    column = model.key if source_kind == "import" else model.id
    cursor = after
    if source_kind != "import":
        try:
            cursor = int(after or "0")
            if cursor < 0:
                raise ValueError()
        except ValueError:
            raise HTTPException(422, "Invalid backfill cursor")
    rows = db.query(model).filter(column > cursor).order_by(column).limit(limit + 1).all()
    for row in rows[:limit]:
        refresh_source(db, row)
    db.commit()
    return {"processed": min(len(rows), limit), "has_more": len(rows) > limit,
            "next_after": str(getattr(rows[min(len(rows), limit) - 1], column.key)) if rows else after}


@router.post("/sync")
def sync(request: Request, limit: int = Query(default=100, ge=1, le=500), user=Depends(writer), db=Depends(get_db)):
    try:
        result = sync_pending(request.app.state.search_index, db, request.app.state.search_sync_lock, limit)
        request.app.state.search_last_error = None
        return result
    except SearchUnavailable as error:
        request.app.state.search_last_error = str(error)
        raise HTTPException(503, str(error))


@router.get("")
def search(request: Request, q: str = Query(min_length=1, max_length=500),
           platform: str | None = Query(default=None, max_length=40), source_kind: str | None = Query(default=None, max_length=40),
           start: datetime | None = None, end: datetime | None = None,
           language: str = Query(default="", max_length=8),
           limit: int = Query(default=20, ge=1, le=100), offset: int = Query(default=0, ge=0, le=9900), db=Depends(get_db)):
    start, end = utc(start), utc(end)
    if start and end and start > end:
        raise HTTPException(422, "Start must be before end")
    try:
        groups = parse_query(q, language or None)
    except ValueError as error:
        raise HTTPException(422, str(error))
    if platform:
        platform = platform.lower()
    index = request.app.state.search_index
    if index:
        try:
            result = index.search(groups, platform, source_kind, start, end, limit, offset)
        except SearchUnavailable as error:
            raise HTTPException(503, str(error))
        # Verify external results against current source records: deleted/stale index entries
        # never expose text that has already been removed or edited locally.
        verified = []
        for item in result["results"]:
            doc = db.query(SearchDocument).filter_by(source_key=item["source_key"]).first()
            if doc is not None and payload(doc) == {k: v for k, v in item.items() if k != "score"}:
                verified.append(item)
        result["results"] = verified
        result["total_is_external"] = True
    else:
        clauses = ["search_fts MATCH :query"]
        params = {"query": fts_query(groups), "limit": limit, "offset": offset}
        for name, value in (("platform", platform), ("source_kind", source_kind)):
            if value:
                clauses.append(f"d.{name} = :{name}")
                params[name] = value
        for operator, name, value in ((">=", "start", start), ("<=", "end", end)):
            if value:
                clauses.append(f"d.occurred_at {operator} :{name}")
                params[name] = value.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")
        where = " AND ".join(clauses)
        join = " FROM search_fts JOIN search_documents d ON d.id = search_fts.rowid WHERE " + where
        total = db.execute(text("SELECT COUNT(*)" + join), params).scalar_one()
        hits = db.execute(text("SELECT d.id, -bm25(search_fts, 8, 5, 4, 3, 1) AS score" + join +
                               " ORDER BY score DESC, d.occurred_at DESC, d.source_key ASC LIMIT :limit OFFSET :offset"), params).all()
        result = {"total": total, "results": [{**payload(db.get(SearchDocument, hit.id)), "score": hit.score} for hit in hits],
                  "total_is_external": False}
    if any(term[3] for group in groups for term in group):
        result["results"] = [item for item in result["results"] if fuzzy_hit(groups, item)]
        if offset == 0 and len(result["results"]) < limit:
            result["total"] = len(result["results"])
    for item in result["results"]:
        item["snippet"] = snippet(item, groups)
        # Full parsed content is available only through the dedicated document endpoint.
        for name in ("body", "headers_text", "captions_text", "values_text", "headers", "fields"):
            item.pop(name, None)
    return {**result, "backend": "elasticsearch" if index else "sqlite", "offset": offset, "limit": limit,
            "pending_external_updates": db.query(SearchOutbox).count() if index else 0}
