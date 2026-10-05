from test_api import make_client

TRANSFER = "Transfer funds\nAccount 20418\n150.00"


def test_screen_navigation_builds_an_audit_trail(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.routers.ocr.recognize",
        lambda path, language: (TRANSFER, 90.0),
    )
    with make_client(tmp_path) as client:
        screen = client.post("/api/screens", json={"name": "Transfer"}).json()
        assert client.post(
            f"/api/screens/{screen['id']}/markers",
            json={"text": "Transfer funds", "line": 1},
        ).status_code == 201
        assert client.post(
            f"/api/screens/{screen['id']}/fields",
            json={"name": "account", "label": "Account", "line": 2, "start_column": 9, "length": 8, "action": "read"},
        ).status_code == 201
        assert client.post(
            f"/api/screens/{screen['id']}/fields",
            json={"name": "amount", "label": "Amount", "line": 3, "start_column": 1, "length": 6, "action": "update"},
        ).status_code == 201
        found = client.post("/api/screens/identify", json={"text": TRANSFER})
        assert found.status_code == 200
        values = {item["name"]: item["value"] for item in found.json()["fields"]}
        assert values == {"account": "20418", "amount": "150.00"}
        assert client.post("/api/screens/identify", json={"text": "Welcome"}).status_code == 409

        case_id = client.post("/api/cases", json={"title": "Image process", "case_type": "Other"}).json()["id"]
        image = client.post(
            f"/api/cases/{case_id}/attachments",
            files={"file": ("page.png", b"image-bytes", "image/png")},
        )
        assert client.post(f"/api/ocr/attachments/{image.json()['id']}").status_code == 201
        captured = client.get("/api/audit/fields").json()
        assert captured[0]["source"] == "image"
        assert captured[0]["value"] in {"20418", "150.00"}
        assert {row["value"] for row in captured[:2]} == {"20418", "150.00"}

        confirm = client.post("/api/screens", json={"name": "Confirm"}).json()
        client.post(f"/api/screens/{confirm['id']}/markers", json={"text": "Confirmed", "line": 1})
        process = client.post("/api/processes", json={"name": "Wire transfer", "description": "Branch wire"})
        assert process.status_code == 201
        process_id = process.json()["id"]
        assert client.post("/api/processes", json={"name": "Wire transfer"}).status_code == 409
        client.post(f"/api/processes/{process_id}/steps", json={"screen_id": screen["id"]})
        client.post(f"/api/processes/{process_id}/steps", json={"screen_id": confirm["id"]})
        wrong = client.post("/api/processes/" + str(process_id) + "/apply", json={"texts": ["Confirmed", TRANSFER]})
        assert wrong.status_code == 422
        assert client.get(f"/api/processes/{process_id}/audit").json()["rows"] == []
        applied = client.post(
            f"/api/processes/{process_id}/apply",
            json={"texts": [TRANSFER, "Confirmed"]},
        )
        assert applied.status_code == 201
        row = applied.json()["audit"]["rows"][0]
        assert row["Account"] == "20418"
        assert row["Amount"] == "150.00"
        assert row["Recorded by"] == "investigator"

        other = client.post("/api/screens", json={"name": "Also transfer"}).json()
        client.post(f"/api/screens/{other['id']}/markers", json={"text": "Transfer funds", "line": 1})
        assert client.post("/api/screens/identify", json={"text": TRANSFER}).status_code == 409
