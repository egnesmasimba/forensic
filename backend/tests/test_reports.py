import zipfile
from io import BytesIO

from test_api import make_client


def test_saved_report_columns_and_case_package(tmp_path):
    with make_client(tmp_path) as client:
        created = client.post("/api/cases", json={"title": "Packaged review", "case_type": "Other", "score": 40, "summary": "Include me"})
        case_id = created.json()["id"]
        client.post("/api/cases", json={"title": "Other review", "case_type": "Other", "score": 10})
        uploaded = client.post(f"/api/cases/{case_id}/attachments", files={"file": ("roster.txt", b"Roster comparison", "text/plain")})
        assert uploaded.status_code == 201

        saved = client.post(
            "/api/reports/templates",
            json={"name": "Titles only", "columns": ["title", "score"], "min_score": 20, "sort": "score", "order": "desc"},
        )
        assert saved.status_code == 201
        assert client.post("/api/reports/templates", json={"name": "Titles only", "columns": ["title"]}).status_code == 409
        assert client.post("/api/reports/templates", json={"name": "Bad column", "columns": ["secret"]}).status_code == 422

        report = saved.json()
        exported = client.get("/api/reports/cases.csv", params={"min_score": report["min_score"], "columns": "title,score"})
        assert exported.status_code == 200
        header, row = exported.text.strip().splitlines()
        assert header == "Title,Score"
        assert "Packaged review,40" in row
        assert "Other review" not in exported.text

        package = client.get(f"/api/reports/cases/{case_id}/package.zip")
        assert package.status_code == 200
        with zipfile.ZipFile(BytesIO(package.content)) as archive:
            names = archive.namelist()
            assert f"case-{case_id}.pdf" in names
            assert any(name.endswith("roster.txt") for name in names)
            assert archive.read(f"case-{case_id}.pdf").startswith(b"%PDF")
            evidence = next(name for name in names if name.endswith("roster.txt"))
            assert archive.read(evidence) == b"Roster comparison"

        assert client.delete(f"/api/reports/templates/{report['id']}").status_code == 204
        assert client.get("/api/reports/templates").json() == []
