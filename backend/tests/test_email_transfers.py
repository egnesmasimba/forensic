import base64
import gzip
import hashlib
import io
import json
import mailbox
import shutil
import sqlite3
import struct
from datetime import datetime, timezone
from email.message import EmailMessage

import httpx
import pytest

from app.models import Alert, DetectionSetting, EndpointEvent, User
from app.mail_models import MailEvidence
from endpoint_agent.content_scan import normalize_domain, parse_email, scan_bytes
from endpoint_agent.collectors.mail_capture import MailCollector
from endpoint_agent.collectors.transfers import TransferCollector
from endpoint_agent.collectors.browser_downloads import BrowserDownloadCollector
from endpoint_agent.native_capture import event_from_browser, read_message, write_message
from endpoint_agent.protocol import AgentClient
from test_api import make_client


def message(body="Confidential customer data", recipient="review@gmail.com", attachment=None):
    mail = EmailMessage()
    mail["From"], mail["To"] = "staff@company.test", recipient
    mail["Cc"], mail["Bcc"] = "manager@company.test", "audit@company.test"
    mail["Subject"], mail["Message-ID"] = "Review transfer", "<test-message@company.test>"
    mail["Date"] = "Sat, 03 Oct 2026 10:00:00 +0200"
    mail.set_content(body)
    mail.add_alternative("<html><style>hidden-secret</style><p>" + body + "</p></html>", subtype="html")
    if attachment:
        mail.add_attachment(attachment, maintype="application", subtype="octet-stream", filename="review.txt")
    return mail.as_bytes()


def register(client):
    response = client.post("/api/agents/register", json={"machine_id":"mail-transfer-fixture", "hostname":"test-host", "os":"windows"})
    assert response.status_code == 201, response.text
    return {"X-Agent-Token":response.json()["agent_token"]}


def test_mime_metadata_body_attachments_and_domain_normalization():
    report = parse_email(message(attachment=b"confidential bank account"), client="thunderbird", direction="outgoing")
    assert report["occurred_at"] == "2026-10-03T08:00:00+00:00"
    assert {r["kind"] for r in report["recipients"]} == {"to", "cc", "bcc"}
    assert "hidden-secret" not in report["body"]
    assert "confidential" in report["body_analysis"]["sensitive_terms"]
    assert report["attachments"][0]["analysis"]["sensitive_terms"] == ["confidential", "bank account"]
    assert report["attachments"][0]["sha256"] == hashlib.sha256(b"confidential bank account").hexdigest()
    assert normalize_domain("BÜCHER.example.") == "xn--bcher-kva.example"
    with pytest.raises(ValueError):
        normalize_domain("company.test/evil")


def test_archive_and_encryption_inspection_is_bounded_and_not_extension_based():
    import zipfile
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("../sensitive.txt", "confidential")
    scan = scan_bytes(raw.getvalue(), "renamed.bin")
    assert scan["archive"] and scan["format"] == "zip"
    assert scan["analysis"]["sensitive_terms"] == ["confidential"]
    encrypted = bytearray(raw.getvalue())
    struct.pack_into("<H", encrypted, 6, 1)
    central = encrypted.index(b"PK\x01\x02")
    struct.pack_into("<H", encrypted, central + 8, 1)
    protected = scan_bytes(bytes(encrypted), "attachment.zip")
    assert protected["encryption"] == "confirmed" and not protected["text"]
    assert scan_bytes(b"ordinary text", "pretend.enc")["encryption"] == "not_detected"
    assert scan_bytes(b"-----BEGIN PGP MESSAGE-----\nbody", "data.asc")["encryption"] == "confirmed"
    bomb = scan_bytes(gzip.compress(b"a" * (3 * 1024 * 1024)), "large.gz")
    assert bomb["partial"] and bomb["archive"] and not bomb["text"]
    malformed = scan_bytes(b"PK\x03\x04bad", "bad.zip")
    assert malformed["partial"]


def test_mail_capture_api_alerts_search_dedup_and_roles(tmp_path):
    with make_client(tmp_path) as client:
        response = client.post("/api/mail/eml", files={"file":("mail.eml",message(attachment=b"bank account"))}, data={"direction":"outgoing"})
        assert response.status_code == 201, response.text
        record = response.json()
        assert record["alert_id"] and len(record["findings"]) == 2
        duplicate = client.post("/api/mail/eml", files={"file":("mail.eml",message(attachment=b"bank account"))}, data={"direction":"outgoing"})
        # MIME boundaries vary when rebuilding a message, so retry identical bytes below.
        raw = message(body="uniquemailbody")
        first = client.post("/api/mail/eml", files={"file":("same.eml",raw)})
        again = client.post("/api/mail/eml", files={"file":("same.eml",raw)})
        assert again.json()["duplicate"] and first.json()["id"] == again.json()["id"]
        detail = client.get(f"/api/mail/messages/{record['id']}").json()
        assert detail["original_message_retained"]
        assert detail["report"]["attachments"][0]["text"] == "bank account"
        assert client.get("/api/search", params={"q":"uniquemailbody", "source_kind":"mail"}).json()["total"] == 1
        assert client.put("/api/mail/policy", json={"internal_domains":["company.test"], "sensitive_terms":["confidential"]}).status_code == 403
        with client.app.state.session_factory() as db:
            user=db.query(User).filter_by(username="investigator").one()
            user.role="administrator"
            db.commit()
        assert client.put("/api/mail/policy", json={"internal_domains":["company.test"], "sensitive_terms":["confidential"]}).status_code == 200
        internal = client.post("/api/mail/eml", files={"file":("internal.eml",message(recipient="person@sub.company.test"))}, data={"direction":"outgoing"}).json()
        assert not internal["findings"]
        spoof = client.post("/api/mail/eml", files={"file":("spoof.eml",message(recipient="person@company.test.evil.example"))}, data={"direction":"outgoing"}).json()
        assert spoof["findings"]
        with client.app.state.session_factory() as db:
            db.query(User).filter_by(username="investigator").one().role="viewer"
            db.commit()
        assert client.get("/api/mail/messages").status_code == 200
        assert client.post("/api/mail/eml", files={"file":("mail.eml",raw)}).status_code == 403
        assert client.post("/api/mail/scan", files={"file":("test.txt",b"text")}).status_code == 403
        client.cookies.clear()
        assert client.get("/api/mail/messages").status_code == 401


def test_agent_mail_delivery_receipts_and_atomic_invalid_batch(tmp_path):
    with make_client(tmp_path) as client:
        headers=register(client)
        report=parse_email(message(),client="outlook",direction="outgoing")
        event={"type":"email_capture", "event_key":"a"*64, "occurred_at":"2026-10-03T10:00:00+02:00", "payload":report}
        first=client.post("/api/agents/events",headers=headers,json={"events":[event]})
        assert first.status_code == 200, first.text
        assert first.json()["accepted"] == first.json()["alerts_created"] == 1
        retry=client.post("/api/agents/events",headers=headers,json={"events":[event]})
        assert retry.json()["duplicates"] == 1 and retry.json()["accepted"] == 0
        conflict={**event,"payload":{**report,"subject":"Different"}}
        assert client.post("/api/agents/events",headers=headers,json={"events":[conflict]}).status_code == 409
        invalid={"type":"transfer_observed","payload":{"channel":"usb","bytes":-1}}
        assert client.post("/api/agents/events",headers=headers,json={"events":[{**event,"event_key":"b"*64},invalid]}).status_code == 422
        with client.app.state.session_factory() as db:
            assert db.query(EndpointEvent).count() == 1 and db.query(MailEvidence).count() == 1
        stored=client.get("/api/agents/events/search").json()[0]
        assert stored["occurred_at"].startswith("2026-10-03T08:00:00")


def test_direct_transfer_tracking_and_configured_alert_thresholds(tmp_path):
    source=tmp_path/"source";target=tmp_path/"usb";cloud=tmp_path/"cloud";share=tmp_path/"share"
    for path in (source,target,cloud,share):path.mkdir()
    (source/"review.txt").write_text("confidential customer data")
    config={"enabled":True,"state_path":str(tmp_path/"state.sqlite"), "roots":[
        {"path":str(source),"channel":"local"},{"path":str(target),"channel":"usb"},
        {"path":str(cloud),"channel":"cloud","provider":"onedrive"},{"path":str(share),"channel":"network_share"}]}
    collector=TransferCollector(config)
    assert not collector.collect()
    for path in (target,cloud,share):shutil.copyfile(source/"review.txt",path/"review.txt")
    assert not collector.collect() # Debounce until stable on the next observation.
    events=collector.collect()
    assert {e["payload"]["channel"] for e in events} == {"usb","cloud","network_share"}
    assert all(e["payload"]["source_match"] == "content_hash" for e in events)
    assert not TransferCollector(config).collect() # Persistent checkpoints prevent restart replay.
    (tmp_path/"api").mkdir()
    with make_client(tmp_path/"api") as client:
        headers=register(client)
        wire=[AgentClient._wire_event(e) for e in events]
        response=client.post("/api/agents/events",headers=headers,json={"events":wire})
        assert response.status_code == 200, response.text
        assert response.json()["alerts_created"] == 3
        assert client.post("/api/agents/events",headers=headers,json={"events":wire}).json()["duplicates"] == 3


def test_thunderbird_mbox_maildir_and_outlook_provider(tmp_path):
    path=tmp_path/"Sent"
    box=mailbox.mbox(path);box.add(mailbox.mboxMessage(message(body="First")));box.flush();box.close()
    config={"enabled":True,"state_path":str(tmp_path/"mail.sqlite"),"sources":[{"path":str(path),"format":"mbox","direction":"outgoing"}]}
    collector=MailCollector(config)
    assert not collector.collect()
    box=mailbox.mbox(path);box.add(mailbox.mboxMessage(message(body="Second")));box.flush();box.close()
    captured=collector.collect()
    assert len(captured) == 1 and captured[0]["payload"]["client"] == "thunderbird"
    assert not MailCollector(config).collect()
    maildir=tmp_path/"Maildir";store=mailbox.Maildir(maildir);store.add(message());store.close()
    observed=MailCollector({"enabled":True,"capture_existing":True,"state_path":str(tmp_path/"maildir.sqlite"),"sources":[{"path":str(maildir),"format":"maildir"}]}).collect()
    assert len(observed) == 1
    outlook=MailCollector({"enabled":True,"capture_existing":True,"outlook":True,"state_path":str(tmp_path/"outlook.sqlite")},outlook_provider=lambda limit:[(message(),"outgoing")])
    assert outlook.collect()[0]["payload"]["client"] == "outlook"
    assert not outlook.collect()  # Fresh MIME boundaries do not create duplicate Outlook evidence.


def test_browser_completed_downloads_and_native_message_bridge(tmp_path):
    path=tmp_path/"History"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE downloads(id INTEGER,guid TEXT,target_path TEXT,total_bytes INTEGER,start_time INTEGER,end_time INTEGER,state INTEGER,tab_url TEXT)")
        db.execute("INSERT INTO downloads VALUES(1,'first','C:/Downloads/test',20,13400000000000000,13400000000000001,0,'https://example.test/file?token=secret')")
    config={"enabled":True,"state_path":str(tmp_path/"downloads.sqlite"),"databases":[{"path":str(path),"browser":"edge"}]}
    collector=BrowserDownloadCollector(config)
    assert not collector.collect()
    with sqlite3.connect(path) as db:db.execute("UPDATE downloads SET state=1")
    event=collector.collect()[0]
    assert event["type"] == "browser_download" and event["payload"]["source_url"] == "https://example.test/file"
    assert not BrowserDownloadCollector(config).collect()
    capture={"kind":"mail","event_key":"c"*64,"occurred_at":"2026-10-03T10:00:00Z","source_url":"https://mail.google.com/mail/u/0", "subject":"Native fixture","sender":"person@company.test",
             "recipients":[{"kind":"to","address":"other@gmail.com"}],"body":"confidential","send_intent":True,
             "attachments":[{"filename":"test.txt","size":3,"data_base64":base64.b64encode(b"abc").decode()}]}
    translated=event_from_browser(capture)
    assert translated["payload"]["direction"] == "send_intent" and translated["payload"]["attachments"][0]["text"] == "abc"
    framed=io.BytesIO();write_message(framed,capture);framed.seek(0)
    assert read_message(framed) == capture
    with pytest.raises(ValueError):read_message(io.BytesIO(struct.pack("<I",5*1024*1024)))
    with pytest.raises(ValueError):event_from_browser({**capture,"source_url":"https://untrusted.example/"})


def test_agent_transport_uses_real_routes_and_persists_before_retry(tmp_path):
    requests=[]
    def unavailable(request):
        requests.append(request)
        return httpx.Response(503,json={})
    client=AgentClient("https://server.example","test-token",queue_path=tmp_path/"queue.jsonl",retries=0)
    client._client=httpx.Client(base_url="https://server.example",transport=httpx.MockTransport(unavailable))
    event={"type":"browser_download","event_key":"d"*64,"ts":1700000000,"payload":{"channel":"downloads","bytes":20}}
    assert not client.post_event(event)
    client.close()
    restarted=AgentClient("https://server.example","test-token",queue_path=tmp_path/"queue.jsonl",retries=0)
    def available(request):
        requests.append(request)
        return httpx.Response(200,json={"accepted":1})
    restarted._client=httpx.Client(base_url="https://server.example",transport=httpx.MockTransport(available))
    assert restarted.flush_queue() == (1,1)
    assert requests[-1].url.path == "/api/agents/events"
    wire=json.loads(requests[-1].content)["events"][0]
    assert wire["event_key"] == "d"*64 and wire["occurred_at"].startswith("2023-")
    restarted.heartbeat({"collectors":{"collectors":{"email":{"coverage":"complete"}}}})
    assert requests[-1].url.path == "/api/agents/heartbeat"
    assert "collector_status" in json.loads(requests[-1].content)
    restarted.close()
