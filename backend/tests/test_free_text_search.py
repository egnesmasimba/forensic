import json
from datetime import datetime, timezone

import httpx
import pytest

from app.content_parser import parse_content
from app.models import Case, EndpointAgent, EndpointEvent, ImportedEvent, NetworkCapture, User
from app.search_elastic import ElasticIndex
from app.search_models import SearchDocument, SearchOutbox
from app.search_query import elastic_query, fts_query, parse_query
from test_api import make_client
from test_network_sensor import sample_capture


def ingest(client, content, **kwargs):
    result = client.post("/api/search/documents", json={"content": content, "kind": "screen",
                         "occurred_at": "2026-10-03T10:00:00Z", "platform": "windows", **kwargs})
    assert result.status_code == 201, result.text
    return result.json()


def test_parsers_extract_captions_values_and_omit_hidden_content():
    html = '''<html><head><title>Account review</title><script>secret script</script></head>
        <h1>Transfers</h1><label for="account">Account number</label><input id="account" value="ABC42">
        <label>Memo<input value="Payment"></label><textarea aria-label="Comment">Quarter end</textarea>
        <select aria-label="Currency"><option>USD</option><option selected>EUR</option></select>
        <input type="password" value="password-secret"><input type="hidden" value="token-secret">
        <div hidden><h2>hidden-title</h2><input value="hidden-value"></div>
        <style>secret style</style><p>Visible &amp; searchable</p></html>'''
    parsed = parse_content(html, "html")
    assert parsed["title"] == "Account review"
    assert parsed["headers"] == ["Transfers"]
    assert {f["caption"]: f["value"] for f in parsed["fields"]} == {
        "Account number": "ABC42", "Memo": "Payment", "Comment": "Quarter end", "Currency": "EUR"}
    assert all(secret not in json.dumps(parsed) for secret in ("secret script", "password-secret", "token-secret", "hidden-title", "hidden-value", "secret style"))
    parsed = parse_content("PAYMENT REVIEW\nAccount: ABC42  Amount: 1500\nCurrency = EUR", "screen")
    assert parsed["fields"] == [{"caption": "Account", "value": "ABC42"}, {"caption": "Amount", "value": "1500"}, {"caption": "Currency", "value": "EUR"}]
    with pytest.raises(ValueError, match="structure"):
        parse_content("<div>" * 101, "html")


def test_ranked_query_filters_pagination_and_validation(tmp_path):
    with make_client(tmp_path) as client:
        first = ingest(client, "Account: ABC42\nlarge wire transfer", title="Wire transfer", platform="mainframe")
        second = ingest(client, "wire transfer denied", title="Review", platform="windows", occurred_at="2026-10-03T12:00:00+02:00")
        third = ingest(client, "wire transfer approved", title="Review", platform="linux", occurred_at="2026-10-04T10:00:00Z")
        hits = client.get("/api/search", params={"q": '"wire transfer"'}).json()
        assert hits["total"] == 3
        assert hits["results"][0]["id"] == first["id"]
        assert all(r["score"] > 0 and "body" not in r for r in hits["results"])
        assert client.get("/api/search", params={"q": "wire -denied"}).json()["total"] == 2
        assert client.get("/api/search", params={"q": "ABC42 OR denied"}).json()["total"] == 2
        assert client.get("/api/search", params={"q": "ABC42"}).json()["results"][0]["id"] == first["id"]
        filtered = client.get("/api/search", params={"q": "wire", "platform": "WINDOWS", "start": "2026-10-03T10:00:00Z", "end": "2026-10-03T10:00:00Z"}).json()
        assert [r["id"] for r in filtered["results"]] == [second["id"]]
        page = client.get("/api/search", params={"q": "wire", "limit": 1, "offset": 1}).json()
        assert page["total"] == 3 and len(page["results"]) == 1
        for query in ('"unclosed', "wire OR", "-wire", "OR wire", "*", "wire OR -denied"):
            assert client.get("/api/search", params={"q": query}).status_code == 422
        assert client.get("/api/search", params={"q": "wire", "start": "2026-10-03T10:00:00"}).status_code == 422
        assert client.get("/api/search", params={"q": "wire", "start": "2026-10-04T10:00:00Z", "end": "2026-10-03T10:00:00Z"}).status_code == 422
        assert client.get("/api/search", params={"q": 'wire" OR 1=1 --'}).status_code in (200, 422)
        assert client.get("/api/search/documents/" + str(third["id"])).json()["body"] == "wire transfer approved"


def test_source_updates_rollback_backfill_and_persistent_index(tmp_path):
    with make_client(tmp_path) as client:
        result = client.post("/api/cases", json={"title": "Original review", "case_type": "Other", "summary": "firstunique"})
        assert result.status_code == 201, result.text
        case_id = result.json()["id"]
        assert client.get("/api/search", params={"q": "firstunique"}).json()["total"] == 1
        with client.app.state.session_factory() as db:
            row = db.get(Case, case_id)
            row.summary = "secondunique"
            db.commit()
            row.summary = "rolledbackunique"
            db.flush()
            db.rollback()
        assert client.get("/api/search", params={"q": "firstunique"}).json()["total"] == 0
        assert client.get("/api/search", params={"q": "secondunique"}).json()["total"] == 1
        assert client.get("/api/search", params={"q": "rolledbackunique"}).json()["total"] == 0
        assert client.post("/api/search/backfill", params={"source_kind": "case", "limit": 1}).json()["processed"] == 1
        assert client.get("/api/search", params={"q": "secondunique"}).json()["total"] == 1
        capture = client.post("/api/network/pcap", files={"file": ("capture.pcap", sample_capture())})
        assert capture.status_code == 201
        assert client.get("/api/search", params={"q": "example.test", "source_kind": "network"}).json()["total"] == 1
        assert client.get("/api/search", params={"q": "secret", "source_kind": "network"}).json()["total"] == 0
        with client.app.state.session_factory() as db:
            db.delete(db.get(NetworkCapture, capture.json()["id"]))
            db.commit()
        assert client.get("/api/search", params={"q": "example.test"}).json()["total"] == 0
        client.app.state.engine.dispose()
        assert client.get("/api/search", params={"q": "secondunique"}).json()["total"] == 1


def test_search_permissions_delete_and_timezone_requirement(tmp_path):
    with make_client(tmp_path) as client:
        doc = ingest(client, "deletionunique")
        assert client.post("/api/search/documents", json={"content": "x", "kind": "screen", "occurred_at": "2026-10-03T10:00:00"}).status_code == 422
        with client.app.state.session_factory() as db:
            user = db.query(User).filter_by(username="investigator").one()
            user.role = "viewer"
            db.commit()
        assert client.get("/api/search", params={"q": "deletionunique"}).status_code == 200
        assert client.post("/api/search/backfill", params={"source_kind": "case"}).status_code == 403
        assert client.post("/api/search/sync").status_code == 403
        assert client.delete(f"/api/search/documents/{doc['id']}").status_code == 403
        with client.app.state.session_factory() as db:
            db.query(User).filter_by(username="investigator").one().role = "investigator"
            db.commit()
        assert client.delete(f"/api/search/documents/{doc['id']}").status_code == 204
        assert client.get("/api/search", params={"q": "deletionunique"}).json()["total"] == 0
        client.cookies.clear()
        assert client.get("/api/search", params={"q": "anything"}).status_code == 401
        assert client.get(f"/api/search/documents/{doc['id']}").status_code == 401


def test_elasticsearch_mapping_retry_search_and_delete_contract(tmp_path):
    requests, indexed, failure = [], {}, [True]
    def handler(request):
        requests.append(request)
        path = request.url.path
        if failure[0]:
            return httpx.Response(503, json={"error": "private server detail"})
        if request.method == "HEAD":
            return httpx.Response(404)
        if path.endswith("/_search"):
            docs = list(indexed.values())
            return httpx.Response(200, json={"hits": {"total": {"value": len(docs)}, "hits": [{"_source": d, "_score": 3.5} for d in docs]}})
        if path.endswith("/_bulk"):
            lines = request.content.decode().splitlines()
            items = []
            while lines:
                action = json.loads(lines.pop(0))
                name = next(iter(action))
                key = action[name]["_id"]
                if name == "delete":
                    indexed.pop(key, None)
                else:
                    indexed[key] = json.loads(lines.pop(0))
                items.append({name: {"status": 200}})
            return httpx.Response(200, json={"items": items, "errors": False})
        if "/_doc/" in path:
            if request.method == "DELETE":
                indexed.pop(path, None)
            else:
                indexed[path] = json.loads(request.content)
        return httpx.Response(200, json={})
    index = ElasticIndex("http://localhost:9200", api_key="server-only-key", transport=httpx.MockTransport(handler))
    with make_client(tmp_path) as client:
        client.app.state.search_index = index
        doc = ingest(client, "Account: ABC42", title="Transfer")
        assert client.get("/api/search/status").json()["pending_external_updates"] == 1
        failed = client.post("/api/search/sync")
        assert failed.status_code == 503 and "private server detail" not in failed.text
        assert client.get("/api/search/status").json()["pending_external_updates"] == 1
        failure[0] = False
        assert client.post("/api/search/sync").json()["published"] == 1
        result = client.get("/api/search", params={"q": '"Account" -denied', "platform": "windows", "start": "2026-10-03T00:00:00Z"}).json()
        assert result["results"][0]["id"] == doc["id"]
        body = json.loads(next(r.content for r in reversed(requests) if r.url.path.endswith("/_search")))
        assert body["query"]["bool"]["filter"][0] == {"term": {"platform": "windows"}}
        assert body["query"]["bool"]["should"][0]["bool"]["must_not"]
        mapping = json.loads(next(r.content for r in requests if r.method == "PUT" and "/_doc/" not in r.url.path))
        assert mapping["mappings"]["properties"]["occurred_at"]["type"] == "date"
        assert all(r.headers["Authorization"] == "ApiKey server-only-key" for r in requests)
        assert client.delete(f"/api/search/documents/{doc['id']}").status_code == 204
        # Stale external hits are suppressed immediately, before the delete is delivered.
        assert client.get("/api/search", params={"q": "ABC42"}).json()["results"] == []
        assert client.post("/api/search/sync").json()["published"] == 1
        assert not indexed


def test_external_configuration_and_literal_query_are_bounded():
    with pytest.raises(ValueError, match="HTTPS"):
        ElasticIndex("http://remote.example:9200")
    with pytest.raises(ValueError):
        ElasticIndex("https://example.test", index="*private")
    with pytest.raises(ValueError):
        parse_query(" ".join(["word"] * 21))
    groups = parse_query('"wire transfer" -denied OR ABC42')
    assert '"wire transfer"' in fts_query(groups)
    assert len(elastic_query(groups, [])["bool"]["should"]) == 2


def test_cross_platform_sources_use_observation_time_and_extract_screens(tmp_path):
    with make_client(tmp_path) as client:
        with client.app.state.session_factory() as db:
            agent = EndpointAgent(machine_id="linux-demo", hostname="test-host", os="linux", token_hash="test-token")
            db.add(agent)
            db.flush()
            db.add(EndpointEvent(agent_id=agent.id, type="window", occurred_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
                                 payload=json.dumps({"screen_text": "Account: sourceunique"})))
            db.add(ImportedEvent(key="test-import", source="history", event_id="1", imported_by="investigator",
                                 payload=json.dumps({"occurred_at": "2020-01-01T01:00:00+01:00", "platform": "macos", "detail": "sourceunique"})))
            db.add(NetworkCapture(name="screen.pcap", imported_by="investigator", sha256="0" * 64, raw=b"test",
                report=json.dumps({"sessions": [{"id": "demo", "first": 1577836800, "protocol": "tn3270",
                    "directions": [{"syn_seen": True, "decoded": {"screens": [{"rows": ["PAYMENT", "Account: sourceunique"]}], "messages": []}}]}]})))
            db.commit()
        hits = client.get("/api/search", params={"q": "sourceunique", "start": "2020-01-01T00:00:00Z", "end": "2020-01-01T00:00:00Z"}).json()
        assert hits["total"] == 3
        assert {item["platform"] for item in hits["results"]} == {"linux", "macos", "mainframe"}
        screen = next(item for item in hits["results"] if item["platform"] == "mainframe")
        assert client.get(f"/api/search/documents/{screen['id']}").json()["fields"] == [{"caption": "Account", "value": "sourceunique"}]


def test_bulk_partial_failure_and_newer_revision_remain_queued(tmp_path):
    calls = [0]
    with make_client(tmp_path) as client:
        def handler(request):
            if request.method == "HEAD":
                return httpx.Response(200)
            if request.url.path.endswith("/_bulk"):
                calls[0] += 1
                lines = request.content.decode().splitlines()
                count = len(lines) // 2
                if calls[0] == 1:
                    return httpx.Response(200, json={"items": [{"index": {"status": 201}}, {"index": {"status": 400}}]})
                if calls[0] == 2:
                    # The source changes while its previous revision is in flight.
                    with client.app.state.session_factory() as db:
                        remaining = db.query(SearchOutbox).one()
                        doc = db.query(SearchDocument).filter_by(source_key=remaining.source_key).one()
                        doc.body = "newerrevision"
                        db.commit()
                return httpx.Response(200, json={"items": [{"index": {"status": 201}} for _ in range(count)]})
            return httpx.Response(200, json={})
        client.app.state.search_index = ElasticIndex("http://localhost:9200", transport=httpx.MockTransport(handler))
        ingest(client, "first")
        ingest(client, "second")
        assert client.post("/api/search/sync").status_code == 503
        assert client.get("/api/search/status").json()["pending_external_updates"] == 1
        assert client.post("/api/search/sync").json()["pending"] == 1
        assert client.post("/api/search/sync").json()["pending"] == 0


def test_fuzzy_term_keeps_one_edit_and_drops_a_different_word(tmp_path):
    with make_client(tmp_path) as client:
        payment = ingest(client, "payment review", title="Payment")
        ingest(client, "payroll report", title="Payroll")
        hits = client.get("/api/search", params={"q": "paymant~"}).json()
        assert [item["id"] for item in hits["results"]] == [payment["id"]]
        assert hits["total"] == 1
        assert client.get("/api/search", params={"q": "ab~"}).status_code == 422
        groups = parse_query("paymant~")
        assert elastic_query(groups, [])["bool"]["should"][0]["bool"]["must"][0]["multi_match"]["fuzziness"] == 1


def test_language_drops_a_short_stopword_list(tmp_path):
    with make_client(tmp_path) as client:
        ingest(client, "wire transfer", title="Wire")
        hits = client.get("/api/search", params={"q": "the wire", "language": "en"}).json()
        assert hits["total"] == 1
        assert client.get("/api/search", params={"q": "the wire", "language": "fr"}).json()["total"] == 0
        assert client.get("/api/search", params={"q": "wire", "language": "it"}).status_code == 422
