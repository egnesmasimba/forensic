"""The one checked-in SQL report. Callers cannot supply a statement."""
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session

STATEMENT_PATH = Path(__file__).with_name("sql") / "case_status.sql"
STATEMENT = STATEMENT_PATH.read_text(encoding="utf-8").strip()


def case_status(db: Session) -> dict:
    folded = STATEMENT.casefold()
    if ";" in STATEMENT or not folded.startswith("select") or "from cases" not in folded:
        raise RuntimeError("The status report must stay a single SELECT")
    rows = db.execute(text(STATEMENT)).mappings().all()
    return {"source": STATEMENT_PATH.name, "rows": [dict(row) for row in rows[:100]]}
