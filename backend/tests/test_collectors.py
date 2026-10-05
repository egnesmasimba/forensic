import sqlite3

from test_api import make_client


def test_text_binary_log_xml_and_correlation(tmp_path):
    with make_client(tmp_path) as client:
        text = client.post(
            "/api/collectors/file",
            data={"source": "Notes"},
            files={"file": ("notes.txt", b"alpha\nbeta\n", "text/plain")},
        )
        assert text.status_code == 201
        assert text.json()["kind"] == "text"
        assert "2 lines" in text.json()["summary"]

        binary = client.post(
            "/api/collectors/file",
            data={"source": "Image"},
            files={"file": ("evidence.bin", b"HEAD\x00SECRET-TOKEN\x00TAIL", "application/octet-stream")},
        )
        assert binary.status_code == 201
        assert binary.json()["kind"] == "binary"
        assert "SECRET-TOKEN" in binary.json()["summary"]

        client.post(
            "/api/alerts",
            json={"title": "Known staff", "entity_type": "user", "entity_ref": "alice", "channel": "Core banking", "score": 10},
        )
        log = client.post(
            "/api/collectors/file",
            data={"source": "Branch log"},
            files={"file": ("branch.log", b"2026-10-03T09:00:00+00:00 alice data_export report.csv 0 1000\nnoise\n", "text/plain")},
        )
        assert log.status_code == 201
        assert log.json()["accepted"] == 1
        assert log.json()["alerts_created"] == 1
        assert any(item["entity_ref"] == "alice" and item["channel"] == "Core banking" for item in log.json()["correlations"])

        xml = """<events><event>
            <event_id>x1</event_id><occurred_at>2026-10-03T10:00:00+00:00</occurred_at>
            <user>erin</user><action>login_failure</action><destination>web</destination>
            <bytes>0</bytes><records>0</records></event></events>"""
        parsed = client.post("/api/collectors/file", data={"source": "XML feed"}, files={"file": ("feed.xml", xml.encode(), "application/xml")})
        assert parsed.status_code == 201
        assert parsed.json()["accepted"] == 1
        rejected = client.post(
            "/api/collectors/file",
            data={"source": "XML feed"},
            files={"file": ("bad.xml", b"<!DOCTYPE events [<!ENTITY a 'b'>]><events></events>", "application/xml")},
        )
        assert rejected.status_code == 422


def test_table_layout_queue_and_schedule(tmp_path):
    database = tmp_path / "activity.sqlite"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE activity (event_id TEXT, occurred_at TEXT, user TEXT, action TEXT, destination TEXT, bytes TEXT, records TEXT)"
    )
    connection.execute(
        "INSERT INTO activity VALUES ('t1', '2026-10-03T11:00:00+00:00', 'cara', 'login_success', 'branch', '0', '0')"
    )
    connection.commit()
    connection.close()

    with make_client(tmp_path) as client:
        table = client.post(
            "/api/collectors/table",
            data={"source": "Operations db", "table": "activity"},
            files={"file": ("activity.sqlite", database.read_bytes(), "application/octet-stream")},
        )
        assert table.status_code == 201
        assert table.json()["accepted"] == 1
        assert client.post(
            "/api/collectors/table",
            data={"source": "Operations db", "table": "activity;drop"},
            files={"file": ("activity.sqlite", database.read_bytes(), "application/octet-stream")},
        ).status_code == 422

        layout = client.post(
            "/api/collectors/layouts",
            json={
                "name": "Teller fixed",
                "mode": "fixed",
                "spec": {
                    "fields": [
                        {"name": "event_id", "start": 0, "length": 4},
                        {"name": "occurred_at", "start": 4, "length": 25},
                        {"name": "user", "start": 29, "length": 5},
                        {"name": "action", "start": 34, "length": 13},
                        {"name": "destination", "start": 47, "length": 6},
                        {"name": "bytes", "start": 53, "length": 1},
                        {"name": "records", "start": 54, "length": 1},
                    ]
                },
            },
        )
        assert layout.status_code == 201
        record = "e0012026-10-03T12:00:00+00:00dave login_successbranch01"
        applied = client.post(
            f"/api/collectors/layouts/{layout.json()['id']}/apply",
            data={"source": "Teller tape"},
            files={"file": ("tape.txt", record.encode(), "text/plain")},
        )
        assert applied.status_code == 201
        assert applied.json()["accepted"] == 1

        queued = client.post(
            "/api/collectors/queue",
            json={
                "message": {
                    "event_id": "q1",
                    "occurred_at": "2026-10-03T13:00:00+00:00",
                    "user": "frank",
                    "action": "login_failure",
                    "destination": "queue",
                    "bytes": 0,
                    "records": 0,
                }
            },
        )
        assert queued.status_code == 201
        assert queued.json()["kind"] == "queue"

        inbox = tmp_path / "inbox"
        inbox.mkdir(exist_ok=True)
        (inbox / "drop.log").write_text(
            "2026-10-03T14:00:00+00:00 gina login_success branch 0 0\n",
            encoding="utf-8",
        )
        ran = client.post("/api/collectors/run")
        assert ran.status_code == 200
        assert ran.json()["accepted"] == 1
        assert not (inbox / "drop.log").exists()
        assert (inbox / "done" / "drop.log").exists()
