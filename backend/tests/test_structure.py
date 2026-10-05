from fastapi.testclient import TestClient

from app.auth import hash_password
from app.main import create_app
from app.models import Base, User


def client_for(tmp_path):
    app = create_app(
        f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
        seed=False,
        attachment_dir=tmp_path / "files",
        collection_dir=tmp_path / "inbox",
    )
    Base.metadata.create_all(app.state.engine)
    with app.state.session_factory() as db:
        db.add(User(username="investigator", password_hash=hash_password("test-password-123"), role="investigator"))
        db.add(User(username="admin", password_hash=hash_password("admin-password-123"), role="administrator"))
        db.commit()
    client = TestClient(app)
    return client


def sign_in(client, username, password):
    login = client.post("/api/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200
    client.headers["X-CSRF-Token"] = login.json()["csrf"]


def test_custom_fields_and_routing(tmp_path):
    with client_for(tmp_path) as client:
        sign_in(client, "investigator", "test-password-123")
        denied = client.post(
            "/api/structure/fields",
            json={"case_type": "Phone Banking Fraud", "key": "callback_number", "label": "Callback number", "required": True},
        )
        assert denied.status_code == 403

        sign_in(client, "admin", "admin-password-123")
        created = client.post(
            "/api/structure/fields",
            json={"case_type": "Phone Banking Fraud", "key": "callback_number", "label": "Callback number", "required": True},
        )
        assert created.status_code == 201
        client.post(
            "/api/routes",
            json={"name": "Any new case", "case_type": "", "min_risk": "low", "assignee": "General desk"},
        )
        specific = client.post(
            "/api/routes",
            json={
                "name": "High phone fraud",
                "case_type": "Phone Banking Fraud",
                "min_risk": "high",
                "assignee": "Phone fraud desk",
            },
        )
        assert specific.status_code == 201

        missing = client.post(
            "/api/cases",
            json={"title": "Callback mismatch", "case_type": "Phone Banking Fraud", "risk": "high"},
        )
        assert missing.status_code == 422
        assert "Callback number" in missing.json()["detail"]

        routed = client.post(
            "/api/cases",
            json={
                "title": "Callback mismatch",
                "case_type": "Phone Banking Fraud",
                "risk": "high",
                "fields": {"callback_number": "555-0100"},
            },
        )
        assert routed.status_code == 201
        body = routed.json()
        assert body["assignee"] == "Phone fraud desk"
        assert body["fields"][0]["value"] == "555-0100"
        assert any(item["action"] == "routed" for item in body["activities"])

        general = client.post(
            "/api/cases",
            json={"title": "Medium phone review", "case_type": "Phone Banking Fraud", "risk": "medium", "fields": {"callback_number": "555-0199"}},
        )
        assert general.status_code == 201
        assert general.json()["assignee"] == "General desk"

        other = client.post(
            "/api/cases",
            json={"title": "Other high review", "case_type": "Other", "risk": "high", "assignee": "Named reviewer"},
        )
        assert other.json()["assignee"] == "Named reviewer"


def test_link_depth_dates_and_fraud_mark(tmp_path):
    with client_for(tmp_path) as client:
        sign_in(client, "investigator", "test-password-123")
        first = client.post("/api/cases", json={"title": "Shared staff review", "case_type": "Employee Fraud", "risk": "high"}).json()
        second = client.post("/api/cases", json={"title": "Customer overlap", "case_type": "Account Takeover", "risk": "medium"}).json()
        for payload in (
            {"title": "Staff profile", "entity_type": "user", "entity_ref": "EMP-1", "case_id": first["id"], "score": 10},
            {"title": "Dormant account", "entity_type": "account", "entity_ref": "ACC-1", "case_id": first["id"], "score": 20},
            {"title": "Same staff profile", "entity_type": "user", "entity_ref": "EMP-1", "case_id": second["id"], "score": 15},
            {"title": "Customer profile", "entity_type": "customer", "entity_ref": "CUS-9", "case_id": second["id"], "score": 12},
        ):
            assert client.post("/api/alerts", json=payload).status_code == 201

        near = client.get("/api/links", params={"anchor_ref": "EMP-1", "anchor_type": "user", "depth": 1})
        assert near.status_code == 200
        near_labels = {node["label"] for node in near.json()["nodes"]}
        assert "EMP-1" in near_labels
        assert "Shared staff review" in near_labels
        assert "ACC-1" not in near_labels

        wide = client.get("/api/links", params={"anchor_ref": "EMP-1", "anchor_type": "user", "depth": 2})
        wide_labels = {node["label"] for node in wide.json()["nodes"]}
        assert {"ACC-1", "CUS-9", "Shared staff review", "Customer overlap"} <= wide_labels
        assert any(edge["source"] == "entity:user:EMP-1" for edge in wide.json()["edges"])

        marked = client.put("/api/links/marks", json={"entity_type": "account", "entity_ref": "ACC-1", "fraudulent": True})
        assert marked.status_code == 200
        flagged = client.get("/api/links", params={"anchor_ref": "ACC-1", "depth": 1}).json()
        account = next(node for node in flagged["nodes"] if node.get("entity_ref") == "ACC-1")
        assert account["fraudulent"] is True
        assert account["investigating"] is True

        future = client.get("/api/links", params={"start": "2999-01-01"})
        assert future.json()["nodes"] == []
