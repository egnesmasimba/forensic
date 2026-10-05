"""Stored CSV exports for a saved report template. Nothing is emailed."""
import json
from datetime import timedelta

from fastapi import HTTPException

from app.models import ReportSchedule, ReportTemplate, ScheduledExport, utcnow
from app.reports import build_cases_csv
from app.routers.cases import filtered_cases, summaries_for

EXPORT_LIMIT = 500


def run_due_exports(db, now=None):
    now = now or utcnow()
    written = 0
    due = db.query(ReportSchedule).filter(ReportSchedule.next_run <= now).order_by(ReportSchedule.id).all()
    for schedule in due:
        template = db.get(ReportTemplate, schedule.template_id)
        schedule.next_run = now + timedelta(seconds=schedule.interval_seconds)
        if template is None:
            continue
        cases = filtered_cases(
            db,
            status=template.status or None,
            min_score=template.min_score,
            q=template.query or None,
            sort=template.sort,
            order=template.order,
        )[:EXPORT_LIMIT]
        body = build_cases_csv(summaries_for(db, cases), json.loads(template.columns))
        row = db.query(ScheduledExport).filter_by(schedule_id=schedule.id).one_or_none()
        if row is None:
            row = ScheduledExport(schedule_id=schedule.id, body=body, row_count=len(cases))
            db.add(row)
        else:
            row.body, row.row_count, row.created_at = body, len(cases), now
        written += 1
    return written


def require_template(db, template_id: int) -> ReportTemplate:
    row = db.get(ReportTemplate, template_id)
    if row is None:
        raise HTTPException(404, "Report not found")
    return row
