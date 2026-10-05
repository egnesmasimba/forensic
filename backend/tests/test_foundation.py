import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.models import User
from test_api import make_client


def _pem(days: int) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "local")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_operations_report_disk_queue_and_notice_export(tmp_path):
    with make_client(tmp_path) as client:
        assert client.get("/api/foundation/operations").status_code == 403
        assert client.get("/api/foundation/notices.csv").status_code == 403
        with client.app.state.session_factory() as db:
            db.query(User).filter_by(username="investigator").one().role = "administrator"
            db.commit()
        report = client.get("/api/foundation/operations")
        assert report.status_code == 200, report.text
        body = report.json()
        assert body["database"] == "sqlite" and body["failover"] is False
        assert body["disk_free_bytes"] > 0 and body["status"] == "ok"
        assert body["response_backlog_limit"] == 100
        exported = client.get("/api/foundation/notices.csv")
        assert exported.status_code == 200
        assert exported.text.splitlines()[0].startswith("id,user,channel")


def test_local_foundation_access_and_certificate(tmp_path, monkeypatch):
    monkeypatch.setenv("ZANAQ_ENV", "production")
    monkeypatch.setenv("ZANAQ_SECRET_SAMPLE", "do-not-echo-this-secret")
    with make_client(tmp_path) as client:
        health = client.get("/api/health")
        assert health.json()["environment"]["name"] == "local"
        assert health.json()["environment"]["accepted"] is False
        record = client.get("/api/foundation")
        assert record.status_code == 200
        body = record.text
        assert "do-not-echo-this-secret" not in body
        assert any(item["id"] == "ADR-1" for item in record.json()["decisions"])
        assert "MD5 signatures are not created." in record.json()["standards"]
        assert client.get("/api/foundation/access").status_code == 403
        assert client.post("/api/foundation/certificate", json={"pem": _pem(10)}).status_code == 403
        with client.app.state.session_factory() as db:
            db.query(User).filter_by(username="investigator").one().role = "administrator"
            db.commit()
        checked = client.post("/api/foundation/certificate", json={"pem": _pem(10)})
        assert checked.status_code == 200
        assert checked.json()["alert"] is True and checked.json()["opened"] is True
        again = client.post("/api/foundation/certificate", json={"pem": _pem(10)})
        assert again.json()["opened"] is False
        later = client.post("/api/foundation/certificate", json={"pem": _pem(90)})
        assert later.json()["alert"] is False
        assert client.post("/api/foundation/certificate", json={"pem": "not-a-certificate-block"}).status_code == 422
        rows = client.get("/api/foundation/access").json()
        assert any(row["actor"] == "investigator" and row["path"] == "/api/foundation" and "secret" not in row["path"] for row in rows)
        assert os.environ["ZANAQ_SECRET_SAMPLE"] not in str(rows)
    rules = (tmp_path.parents[0] / "ruff.toml")
    del rules
    from pathlib import Path
    text = Path(__file__).resolve().parents[1].joinpath("ruff.toml").read_text(encoding="utf-8")
    assert 'select = ["E", "F"]' in text
    docker = Path(__file__).resolve().parents[1].joinpath("Dockerfile").read_text(encoding="utf-8")
    workflow = Path(__file__).resolve().parents[2].joinpath(".github", "workflows", "tests.yml").read_text(encoding="utf-8")
    assert "kubernetes" not in docker.lower() and "8000" in docker
    assert "pytest" in workflow and "deploy" not in workflow
