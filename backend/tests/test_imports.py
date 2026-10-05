import csv
import io

from app.models import ImportedEvent, User
from test_api import make_client


def activity_csv(*rows):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["event_id", "occurred_at", "user", "action", "destination", "bytes", "records"])
    writer.writerows(rows)
    return output.getvalue().encode()


def upload(client, content, source="audit log"):
    return client.post("/api/imports/csv", data={"source": source}, files={"file": ("activity.csv", content, "text/csv")})


def test_detection_deduplication_and_case_workflow(tmp_path):
    with make_client(tmp_path) as client:
        rows = [
            ["export", "2026-10-03T09:00:00+02:00", "alice", "data_export", "report.csv", 0, 1000],
            ["transfer", "2026-10-03T09:01:00+02:00", "bob", "file_transfer", "USB", 10485760, 0],
            ["small", "2026-10-03T09:02:00+02:00", "bob", "file_transfer", "cloud", 10485759, 0],
            ["local", "2026-10-03T09:03:00+02:00", "bob", "file_transfer", "local", 10485760, 0],
        ]
        result = upload(client, activity_csv(*rows, rows[0]))
        assert result.status_code == 201
        assert result.json()["accepted"] == 4
        assert result.json()["duplicates"] == 1
        assert result.json()["alerts_created"] == 2
        assert upload(client, activity_csv(*rows)).json()["alerts_created"] == 0
        alerts = client.get("/api/alerts?status=open").json()
        assert [row["score"] for row in alerts] == [80, 70]
        assert "2026-10-03T07:00:00+00:00" in alerts[1]["description"]
        events = client.get("/api/imports/events").json()
        assert len(events) == 4
        assert all(event["imported_by"] == "investigator" for event in events)
        case = client.post("/api/cases", json={"title": "Import investigation", "case_type": "Other"}).json()
        linked = client.patch(f"/api/alerts/{alerts[0]['id']}", json={"case_id": case["id"]})
        assert linked.status_code == 200
        detail = client.get(f"/api/cases/{case['id']}").json()
        assert detail["score"] == 80
        assert detail["activities"][-1]["actor"] == "investigator"


def test_imported_exfiltration_channels(tmp_path):
    with make_client(tmp_path) as client:
        rows = [
            ["browser", "2026-10-03T10:00:00Z", "nina", "browser_download", "report.pdf", 10485760, 0],
            ["sync", "2026-10-03T10:01:00Z", "nina", "cloud_sync", "Google Drive", 10485760, 0],
            ["named", "2026-10-03T10:02:00Z", "nina", "file_transfer", "Dropbox", 10485760, 0],
            ["share", "2026-10-03T10:03:00Z", "nina", "file_transfer", "share", 10485760, 0],
            ["zip", "2026-10-03T10:04:00Z", "nina", "archive", "files.zip", 10485760, 0],
            ["locked", "2026-10-03T10:05:00Z", "nina", "encrypt", "files.zip.enc", 10485760, 0],
            ["small-download", "2026-10-03T10:06:00Z", "nina", "browser_download", "note.txt", 10485759, 0],
            ["local-sync", "2026-10-03T10:07:00Z", "nina", "cloud_sync", "local", 10485760, 0],
        ]
        result = upload(client, activity_csv(*rows))
        assert result.status_code == 201
        assert result.json()["accepted"] == 8
        assert result.json()["alerts_created"] == 6
        alerts = client.get("/api/alerts?status=open").json()
        rules = [row["description"].split(".")[0] for row in alerts]
        assert "Rule: browser-download" in rules
        assert "Rule: cloud-sync" in rules
        assert "Rule: large-external-transfer" in rules
        assert "Rule: network-share" in rules
        assert "Rule: archive" in rules
        assert "Rule: encryption" in rules


def test_email_metadata_and_traffic_summaries(tmp_path):
    with make_client(tmp_path) as client:
        email = activity_csv(
            ["m1", "2026-10-03T10:00:00Z", "nina", "gmail.com", "report.pdf", 10485760, "yes"],
            ["m2", "2026-10-03T10:01:00Z", "nina", "company.example", "notes.txt", 100, "no"],
        ).replace(
            b"event_id,occurred_at,user,action,destination,bytes,records",
            b"message_id,occurred_at,sender,recipient_domain,attachment_name,attachment_bytes,encrypted",
        )
        imported = client.post("/api/imports/email", data={"source": "Mail export"}, files={"file": ("mail.csv", email, "text/csv")})
        assert imported.status_code == 201
        assert imported.json()["accepted"] == 2
        assert imported.json()["alerts_created"] == 1
        alert = client.get("/api/alerts?status=open").json()[0]
        assert alert["score"] == 75
        assert "external-recipient" in alert["description"]
        assert "large-attachment" in alert["description"]
        assert "encrypted-attachment" in alert["description"]
        assert "attachment-context" in alert["description"]
        shown = client.get("/api/imports/events").json()
        assert shown[0]["event"]["action"] == "email"
        assert shown[0]["event"]["user"] == "nina"

        traffic = (
            "flow_id,occurred_at,user,protocol,application,destination,bytes,connections\n"
            "f1,2026-10-03T11:00:00Z,omar,CUSTOM,sync,198.51.100.8,104857600,100\n"
            "f2,2026-10-03T11:01:00Z,omar,https,browser,203.0.113.9,100,1\n"
        ).encode()
        flows = client.post("/api/imports/traffic", data={"source": "Flow export"}, files={"file": ("flows.csv", traffic, "text/csv")})
        assert flows.status_code == 201
        assert flows.json()["alerts_created"] == 1
        descriptions = [row["description"] for row in client.get("/api/alerts?status=open").json()]
        assert any("unusual-protocol" in item and "bandwidth-heavy" in item and "repeated-connections" in item for item in descriptions)
        assert client.post(
            "/api/imports/email",
            data={"source": "Mail export"},
            files={"file": ("mail.csv", email.replace(b"yes", b"maybe"), "text/csv")},
        ).status_code == 422


def test_invalid_conflicting_and_unauthorized_imports_are_atomic(tmp_path):
    with make_client(tmp_path) as client:
        valid = ["one", "2026-10-03T09:00:00Z", "alice", "data_export", "report", 0, 1000]
        invalid = ["two", "2026-10-03T09:00:00", "alice", "data_export", "report", 0, 1000]
        assert upload(client, activity_csv(valid, invalid)).status_code == 422
        assert client.get("/api/imports/events").json() == []
        assert client.get("/api/alerts").json() == []
        assert upload(client, activity_csv(valid)).status_code == 201
        changed = valid.copy()
        changed[-1] = 2000
        fresh = valid.copy()
        fresh[0] = "fresh"
        assert upload(client, activity_csv(fresh, changed)).status_code == 409
        assert len(client.get("/api/imports/events").json()) == 1
        assert len(client.get("/api/alerts").json()) == 1
        assert upload(client, b"bad,columns\nvalue,value\n").status_code == 422
        assert upload(client, b"\xff").status_code == 422
        assert upload(client, b"x" * (2 * 1024 * 1024 + 1)).status_code == 413
        assert upload(client, activity_csv()).status_code == 422
        negative = valid.copy()
        negative[0], negative[-2] = "negative", -1
        assert upload(client, activity_csv(negative)).status_code == 422
        assert upload(client, activity_csv(valid), source=" ").status_code == 422
        assert upload(client, activity_csv(valid), source="different source").json()["accepted"] == 1
        csrf = client.headers.pop("X-CSRF-Token")
        assert upload(client, activity_csv(valid)).status_code == 403
        client.headers["X-CSRF-Token"] = csrf
        with client.app.state.session_factory() as db:
            db.query(User).filter_by(username="investigator").first().role = "viewer"
            db.commit()
        assert upload(client, activity_csv(valid)).status_code == 403
        assert client.get("/api/imports/events").status_code == 200
        client.cookies.clear()
        assert upload(client, activity_csv(valid)).status_code == 401
        assert client.get("/api/imports/events").status_code == 401
