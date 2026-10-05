"""Optional Elasticsearch REST adapter; credentials remain server-side."""
import hashlib
import json
import os
import re
from urllib.parse import urlsplit

import httpx
from sqlalchemy import delete

from app.search_models import SearchOutbox

from app.search_query import elastic_query


class SearchUnavailable(Exception):
    pass


class ElasticIndex:
    def __init__(self, url, index="zanaq-content-v1", api_key=None, transport=None):
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Invalid Elasticsearch URL")
        if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("Remote Elasticsearch connections require HTTPS")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", index):
            raise ValueError("Invalid Elasticsearch index name")
        self.index = index
        self.client = httpx.Client(base_url=url.rstrip("/") + "/", timeout=10,
                                   headers={"Authorization": "ApiKey " + api_key} if api_key else {},
                                   transport=transport)

    def request(self, method, path, **kwargs):
        try:
            response = self.client.request(method, path, **kwargs)
            if response.status_code >= 400:
                raise SearchUnavailable("Elasticsearch request failed; check the server connection and index permissions")
            return response.json() if response.content else {}
        except (httpx.HTTPError, ValueError) as error:
            raise SearchUnavailable("Elasticsearch is unavailable; local source documents are retained") from error

    def ensure_index(self):
        try:
            response = self.client.head(self.index)
        except httpx.HTTPError as error:
            raise SearchUnavailable("Elasticsearch is unavailable") from error
        if response.status_code == 200:
            return
        if response.status_code != 404:
            raise SearchUnavailable("Cannot access the configured Elasticsearch index")
        properties = {name: {"type": "text"} for name in ("title", "headers_text", "captions_text", "values_text", "body")}
        properties.update({name: {"type": "keyword"} for name in ("source_key", "source_kind", "source_id", "platform")})
        properties.update(id={"type": "long"}, occurred_at={"type": "date"}, partial={"type": "boolean"},
                          fields={"type": "object", "enabled": False}, headers={"type": "text", "index": False})
        self.request("PUT", self.index, json={"mappings": {"dynamic": "strict", "properties": properties}})

    def publish(self, key, document):
        doc_id = hashlib.sha256(key.encode()).hexdigest()
        path = f"{self.index}/_doc/{doc_id}"
        if document is None:
            try:
                response = self.client.delete(path)
            except httpx.HTTPError as error:
                raise SearchUnavailable("Elasticsearch deletion failed") from error
            if response.status_code not in (200, 404):
                raise SearchUnavailable("Elasticsearch deletion failed")
        else:
            self.request("PUT", path, json=document)

    def refresh(self):
        self.request("POST", self.index + "/_refresh")

    def publish_many(self, records):
        lines = []
        for key, document in records:
            action = "delete" if document is None else "index"
            lines.append(json.dumps({action: {"_id": hashlib.sha256(key.encode()).hexdigest()}}))
            if document is not None:
                lines.append(json.dumps(document, ensure_ascii=False))
        result = self.request("POST", self.index + "/_bulk", params={"refresh": "wait_for"},
                              content="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"})
        items = result.get("items", [])
        if len(items) != len(records):
            raise SearchUnavailable("Elasticsearch returned an incomplete indexing acknowledgement")
        succeeded = []
        for item, (_, document) in zip(items, records):
            action = "delete" if document is None else "index"
            status = item.get(action, {}).get("status", 0)
            succeeded.append(200 <= status < 300 or document is None and status == 404)
        return succeeded

    def search(self, groups, platform, source_kind, start, end, limit, offset):
        filters = []
        for name, value in (("platform", platform), ("source_kind", source_kind)):
            if value:
                filters.append({"term": {name: value}})
        bounds = {}
        if start:
            bounds["gte"] = start.isoformat()
        if end:
            bounds["lte"] = end.isoformat()
        if bounds:
            filters.append({"range": {"occurred_at": bounds}})
        result = self.request("POST", self.index + "/_search", json={"query": elastic_query(groups, filters),
                              "size": limit, "from": offset, "track_total_hits": True,
                              "sort": [{"_score": "desc"}, {"occurred_at": "desc"}, {"source_key": "asc"}]})
        return {"total": result["hits"]["total"]["value"],
                "results": [{**hit["_source"], "score": hit["_score"]} for hit in result["hits"]["hits"]]}

    def close(self):
        self.client.close()


def configured_index():
    backend = os.getenv("EFMTT_SEARCH_BACKEND", "sqlite")
    if backend == "sqlite":
        return None
    if backend != "elasticsearch":
        raise ValueError("EFMTT_SEARCH_BACKEND must be sqlite or elasticsearch")
    url = os.getenv("EFMTT_ELASTICSEARCH_URL")
    if not url:
        raise ValueError("Set EFMTT_ELASTICSEARCH_URL for Elasticsearch search")
    return ElasticIndex(url, os.getenv("EFMTT_ELASTICSEARCH_INDEX", "zanaq-content-v1"), os.getenv("EFMTT_ELASTICSEARCH_API_KEY"))


def sync_pending(index, db, lock, limit=100):
    if index is None:
        return {"published": 0, "pending": 0, "backend": "sqlite"}
    if not lock.acquire(blocking=False):
        return {"published": 0, "pending": db.query(SearchOutbox).count(), "backend": "elasticsearch", "busy": True}
    try:
        rows = db.query(SearchOutbox).order_by(SearchOutbox.source_key).limit(limit).all()
        snapshots = [(row.source_key, row.revision, json.loads(row.payload) if row.payload else None) for row in rows]
        # End the read transaction before the external request, allowing source updates.
        db.rollback()
        if not snapshots:
            return {"published": 0, "pending": 0, "backend": "elasticsearch"}
        index.ensure_index()
        delivered = index.publish_many([(key, document) for key, _, document in snapshots])
        for (key, revision, _), success in zip(snapshots, delivered):
            if success:
                db.execute(delete(SearchOutbox).where(SearchOutbox.source_key == key, SearchOutbox.revision == revision))
        db.commit()
        if not all(delivered):
            raise SearchUnavailable("Some Elasticsearch updates failed; failed documents remain queued for retry")
        return {"published": sum(delivered), "pending": db.query(SearchOutbox).count(), "backend": "elasticsearch"}
    finally:
        lock.release()
