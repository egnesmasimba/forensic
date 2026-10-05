from app.models import Case
from test_api import make_client


def test_case_status_sql_counts_stored_cases(tmp_path):
    with make_client(tmp_path) as client:
        with client.app.state.session_factory() as db:
            db.add(Case(title="Stored matter", case_type="Other", status="new"))
            db.commit()
        page = client.get("/api/reports/sql/case-status")
        assert page.status_code == 200, page.text
        assert page.json()["source"] == "case_status.sql"
        assert {"status": "new", "case_count": 1} in page.json()["rows"]
