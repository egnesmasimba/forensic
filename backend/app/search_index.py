import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import event

from app.content_parser import MAX_CONTENT, parse_content
from app.models import Alert, Case, CollectedArtifact, EndpointAgent, EndpointEvent, ImportedEvent, NetworkCapture, Note, utcnow
from app.search_models import SearchDocument, SearchOutbox
from app.mail_models import MailEvidence


SOURCE_MODELS = {"case": Case, "alert": Alert, "note": Note, "artifact": CollectedArtifact,
                 "endpoint": EndpointEvent, "import": ImportedEvent, "network": NetworkCapture, "mail": MailEvidence}
MODEL_KINDS = {model: kind for kind, model in SOURCE_MODELS.items()}


def iso(value):
    return value.replace(tzinfo=timezone.utc).isoformat() if value.tzinfo is None else value.astimezone(timezone.utc).isoformat()


def payload(row):
    return {"id": row.id, "source_key": row.source_key, "source_kind": row.source_kind,
            "source_id": row.source_id, "platform": row.platform, "occurred_at": iso(row.occurred_at),
            "title": row.title, "headers": json.loads(row.headers), "fields": json.loads(row.fields),
            "headers_text": row.headers_text, "captions_text": row.captions_text,
            "values_text": row.values_text, "body": row.body, "partial": row.partial}


def assign(row, parsed, platform, occurred_at):
    row.title = parsed["title"]
    row.headers = json.dumps(parsed["headers"], ensure_ascii=False)
    row.fields = json.dumps(parsed["fields"], ensure_ascii=False)
    row.headers_text = "\n".join(parsed["headers"])
    row.captions_text = "\n".join(f["caption"] for f in parsed["fields"])
    row.values_text = "\n".join(f["value"] for f in parsed["fields"])
    row.body = parsed["body"]
    row.partial = parsed.get("partial", False)
    row.platform = platform[:40].lower()
    row.occurred_at = occurred_at.astimezone(timezone.utc) if occurred_at.tzinfo else occurred_at.replace(tzinfo=timezone.utc)
    row.updated_at = utcnow()


def plain(title, body):
    parsed = parse_content(body[:MAX_CONTENT], "screen", title)
    parsed["partial"] |= len(body) > MAX_CONTENT
    return parsed


def source_documents(db, row):
    """Never read raw packets, credentials, or screenshot bytes into the text index."""
    kind = MODEL_KINDS[type(row)]
    source_id = str(row.key if isinstance(row, ImportedEvent) else row.id)
    base = f"{kind}:{source_id}"
    when = getattr(row, "occurred_at", None) or getattr(row, "created_at", None) or getattr(row, "imported_at", None) or utcnow()
    platform = "application"
    if isinstance(row, MailEvidence):
        report = json.loads(row.report)
        content = "\n".join([report["body"], report["sender"], *report["recipient_domains"],
                             *(attachment["text"] for attachment in report["attachments"])])
        yield base, plain(row.subject or "Email message", content), row.client, when
    elif isinstance(row, Case):
        yield base, plain(row.title, "\n".join((row.case_type, row.assignee, row.summary, row.conclusion))), platform, when
    elif isinstance(row, Alert):
        yield base, plain(row.title, "\n".join((row.description, row.entity_ref, row.channel))), platform, when
    elif isinstance(row, Note):
        yield base, plain(f"Case {row.case_id} note", row.body), platform, when
    elif isinstance(row, CollectedArtifact):
        yield base, plain(row.filename, row.summary), "collector", when
    elif isinstance(row, (EndpointEvent, ImportedEvent)):
        data = json.loads(row.payload)
        if isinstance(row, EndpointEvent):
            agent = db.get(EndpointAgent, row.agent_id)
            platform = agent.os if agent else "endpoint"
            title = row.type
        else:
            platform = str(data.get("platform", "import"))
            title = row.source
            if data.get("occurred_at"):
                try:
                    observed = datetime.fromisoformat(str(data["occurred_at"]).replace("Z", "+00:00"))
                    if observed.tzinfo:
                        when = observed.astimezone(timezone.utc)
                except ValueError:
                    pass
        # Screenshot payloads contain metadata only; OCR is a separate pending feature.
        content = str(data.get("html") or data.get("screen_text") or json.dumps(data, ensure_ascii=False))
        try:
            parsed = parse_content(content[:MAX_CONTENT], "html" if data.get("html") else "screen", title)
        except ValueError:
            parsed = plain(title, "Source content exceeded the webpage parser structure limits. Original source is retained.")
            parsed["partial"] = True
        parsed["partial"] |= len(content) > MAX_CONTENT
        yield base, parsed, platform, when
    elif isinstance(row, NetworkCapture):
        report = json.loads(row.report)
        count = 0
        for session in report["sessions"]:
            when = datetime.fromtimestamp(session["first"], timezone.utc)
            protocol = session["protocol"]
            platform = "mainframe" if protocol == "tn3270" else "iseries" if protocol == "tn5250" else "network"
            for direction_index, direction in enumerate(session["directions"]):
                decoded = direction.get("decoded", {})
                for group in ("screens", "messages"):
                    for index, item in enumerate(decoded.get(group, [])):
                        if count >= 500:
                            # Explicit marker makes the extraction cap visible in search status/results.
                            parsed = plain(row.name, "Additional decoded records exceeded the 500-record indexing limit. Original capture is retained.")
                            parsed["partial"] = True
                            yield base + ":limit", parsed, platform, when
                            return
                        content = "\n".join(item["rows"]) if group == "screens" else json.dumps(item, ensure_ascii=False)
                        parsed = plain(f"{row.name} {protocol} {group[:-1]}", content)
                        if group == "messages" and isinstance(item.get("headers"), dict):
                            parsed["headers"] = list(item["headers"])[:200]
                            parsed["fields"] = [{"caption": str(caption)[:200], "value": str(value)[:4096]}
                                                for caption, value in list(item["headers"].items())[:200]]
                        elif group == "messages" and isinstance(item.get("fields"), list):
                            parsed["fields"] = [{"caption": value.split("=", 1)[0][:200], "value": value.split("=", 1)[1][:4096]}
                                                for value in item["fields"][:200] if isinstance(value, str) and "=" in value]
                        parsed["partial"] |= bool(item.get("partial") or direction.get("truncated") or direction.get("gaps") or not direction.get("syn_seen"))
                        key = f"{base}:{session['id']}:{direction_index}:{group}:{index}"
                        yield key, parsed, platform, when
                        count += 1


def refresh_source(db, source, deleted=False):
    kind = MODEL_KINDS[type(source)]
    source_id = str(source.key if isinstance(source, ImportedEvent) else source.id)
    existing = {doc.source_key: doc for doc in db.query(SearchDocument).filter_by(source_kind=kind, source_id=source_id)}
    if not deleted:
        for key, parsed, platform, when in source_documents(db, source):
            doc = existing.pop(key, None)
            if doc is None:
                doc = SearchDocument(source_key=key, source_kind=kind, source_id=source_id, created_by="source")
                db.add(doc)
            assign(doc, parsed, platform, when)
    for doc in existing.values():
        db.delete(doc)


def initialize_fts(engine):
    if engine.dialect.name != "sqlite":
        raise ValueError("The local full-text index currently requires SQLite")
    with engine.begin() as conn:
        found = conn.exec_driver_sql("SELECT name FROM sqlite_master WHERE name='search_fts'").first()
        conn.exec_driver_sql("""CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
            title, headers_text, captions_text, values_text, body,
            content='search_documents', content_rowid='id', tokenize='unicode61 remove_diacritics 2')""")
        columns = "title, headers_text, captions_text, values_text, body"
        new = ", ".join("new." + col.strip() for col in columns.split(","))
        old = ", ".join("old." + col.strip() for col in columns.split(","))
        conn.exec_driver_sql(f"""CREATE TRIGGER IF NOT EXISTS search_fts_insert AFTER INSERT ON search_documents BEGIN
            INSERT INTO search_fts(rowid, {columns}) VALUES (new.id, {new}); END""")
        conn.exec_driver_sql(f"""CREATE TRIGGER IF NOT EXISTS search_fts_delete AFTER DELETE ON search_documents BEGIN
            INSERT INTO search_fts(search_fts, rowid, {columns}) VALUES ('delete', old.id, {old}); END""")
        conn.exec_driver_sql(f"""CREATE TRIGGER IF NOT EXISTS search_fts_update AFTER UPDATE ON search_documents BEGIN
            INSERT INTO search_fts(search_fts, rowid, {columns}) VALUES ('delete', old.id, {old});
            INSERT INTO search_fts(rowid, {columns}) VALUES (new.id, {new}); END""")
        if not found:
            conn.exec_driver_sql("INSERT INTO search_fts(search_fts) VALUES ('rebuild')")


def install_index_hooks(factory):
    @event.listens_for(factory, "before_flush")
    def gather(db, context, instances):
        sources = [(row, row in db.deleted) for row in set(db.new) | set(db.dirty) | set(db.deleted)
                   if type(row) in MODEL_KINDS]
        db.info["search_sources"] = sources
        docs = [(row, row in db.deleted) for row in set(db.new) | set(db.dirty) | set(db.deleted)
                if isinstance(row, SearchDocument)]
        db.info["search_documents"] = docs

    @event.listens_for(factory, "after_flush_postexec")
    def persist(db, context):
        for source, deleted in db.info.pop("search_sources", []):
            refresh_source(db, source, deleted)
        for doc, deleted in db.info.pop("search_documents", []):
            serialized = None if deleted else json.dumps(payload(doc), ensure_ascii=False, sort_keys=True)
            revision = hashlib.sha256((serialized or "deleted").encode()).hexdigest()
            outbox = db.get(SearchOutbox, doc.source_key)
            if outbox is None:
                outbox = SearchOutbox(source_key=doc.source_key)
                db.add(outbox)
            outbox.revision, outbox.payload = revision, serialized
