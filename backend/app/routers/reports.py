import json
import zipfile
from io import BytesIO
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import current_user, writer
from app.models import Attachment, ReportSchedule, ReportTemplate, ScheduledExport, utcnow
from app.report_schedule import require_template, run_due_exports
from app.reports import COLUMN_KEYS, build_case_pdf, build_cases_csv, build_cases_xlsx
from app.routers.attachments import _stored_path
from app.routers.cases import _case_or_404, _detail, filtered_cases, get_db, summaries_for
from app.structure import field_values
from app.models import CaseFieldValue, ReportDefinition
from app.reporting_query import DefinitionInput, ReportInput, catalog, filtered_query, query_page
from app.sql_report import case_status

router = APIRouter(prefix="/api/reports", tags=["reports"], dependencies=[Depends(current_user)])


@router.get("/sql/case-status")
def sql_case_status(db=Depends(get_db)):
    return case_status(db)


@router.get("/input-fields")
def input_fields(db=Depends(get_db)):
    return list(catalog(db).values())


@router.post("/query")
def query_report(payload: ReportInput, after_id: int = Query(default=0, ge=0),
                 limit: int = Query(default=100, ge=1, le=500), db=Depends(get_db)):
    return query_page(db, payload, after_id, limit)


@router.get("/definitions")
def definitions(db=Depends(get_db)):
    return [{"id": row.id, "name": row.name, "created_by": row.created_by,
             "definition": json.loads(row.definition)} for row in db.query(ReportDefinition).order_by(ReportDefinition.name)]


@router.post("/definitions", status_code=201)
def save_definition(payload: DefinitionInput, user=Depends(writer), db=Depends(get_db)):
    definition = ReportInput.model_validate(payload.model_dump(exclude={"name"}))
    filtered_query(db, definition)
    row = ReportDefinition(name=payload.name, definition=definition.model_dump_json(), created_by=user.username)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A report definition with that name already exists")
    return {"id": row.id, "name": row.name, "definition": definition.model_dump()}


@router.delete("/definitions/{definition_id}", status_code=204)
def delete_definition(definition_id: int, user=Depends(writer), db=Depends(get_db)):
    row = db.get(ReportDefinition, definition_id)
    if row is None:
        raise HTTPException(404, "Report definition not found")
    db.delete(row)
    db.commit()


@router.get("/definitions/{definition_id}/data")
def external_report(definition_id: int, after_id: int = Query(default=0, ge=0),
                    limit: int = Query(default=100, ge=1, le=500),
                    format: str = Query(default="json", pattern="^(json|csv)$"), db=Depends(get_db)):
    row = db.get(ReportDefinition, definition_id)
    if row is None:
        raise HTTPException(404, "Report definition not found")
    page = query_page(db, ReportInput.model_validate_json(row.definition), after_id, limit)
    headers = {"Cache-Control": "no-store"}
    if page["next_after_id"] is not None:
        headers["X-Next-After-ID"] = str(page["next_after_id"])
    if format == "json":
        return Response(json.dumps(page), media_type="application/json", headers=headers)
    import csv
    from io import StringIO
    from app.reports import spreadsheet_safe
    output = StringIO()
    writer = csv.writer(output)
    keys = [column["key"] for column in page["columns"]]
    writer.writerow(["case_id", *keys])
    for item in page["rows"]:
        writer.writerow([item["case_id"], *[spreadsheet_safe(item["values"][key]) for key in keys]])
    headers["Content-Disposition"] = f"attachment; filename=report-{definition_id}-after-{after_id}.csv"
    return Response(output.getvalue(), media_type="text/csv", headers=headers)


@router.get("/cases/{case_id}/drilldown")
def drilldown(case_id: int, field: str = Query(max_length=80), db=Depends(get_db)):
    case = _case_or_404(db, case_id)
    definition = ReportInput(columns=[field])
    page = query_page(db, definition.model_copy(update={"filters": []}), case_id - 1, 1)
    value = page["rows"][0]["values"][field]
    source = {"table": "cases", "record_id": case.id, "column": field}
    if field.startswith("field:"):
        field_id = int(field.split(":")[1])
        stored = db.query(CaseFieldValue).filter_by(case_id=case.id, field_id=field_id).first()
        source = {"table": "case_field_values", "record_id": stored.id if stored and value is not None else None,
                  "field_definition_id": field_id, "column": "value"}
    return {"case_id": case.id, "field": page["columns"][0], "value": value, "source": source,
            "case_updated_at": case.updated_at, "case_url": f"/api/cases/{case.id}",
            "note": "Current stored value; this is not a historical field-change record."}


class TemplateCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    columns: list[str] = Field(min_length=1, max_length=len(COLUMN_KEYS))
    status: str = ""
    query: str = Field(default="", max_length=200)
    min_score: int | None = Field(default=None, ge=0, le=1000)
    sort: str = "score"
    order: str = "desc"

    @field_validator("columns")
    @classmethod
    def known_columns(cls, value: list[str]) -> list[str]:
        unknown = [item for item in value if item not in COLUMN_KEYS]
        if unknown:
            raise ValueError("Unknown column")
        return value

    @field_validator("sort")
    @classmethod
    def known_sort(cls, value: str) -> str:
        if value not in ("score", "updated", "created"):
            raise ValueError("Unknown sort")
        return value

    @field_validator("order")
    @classmethod
    def known_order(cls, value: str) -> str:
        if value not in ("asc", "desc"):
            raise ValueError("Unknown order")
        return value


def _columns(value: str | None) -> list[str] | None:
    if not value:
        return None
    keys = [item.strip() for item in value.split(",") if item.strip()]
    unknown = [item for item in keys if item not in COLUMN_KEYS]
    if unknown:
        raise HTTPException(422, "Unknown report column")
    return keys or None


def _listed(
    db: Session,
    status: str | None,
    risk: str | None,
    min_score: int | None,
    q: str | None,
    sort: str,
    order: str,
):
    cases = filtered_cases(
        db,
        status=status,
        risk=risk,
        min_score=min_score,
        q=q,
        sort=sort,
        order=order,
    )
    return summaries_for(db, cases)


@router.get("/cases.csv")
def export_csv(
    status: str | None = None,
    risk: str | None = None,
    min_score: int | None = Query(default=None, ge=0, le=1000),
    q: str | None = None,
    sort: str = Query(default="score", pattern="^(score|updated|created)$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    columns: str | None = None,
    db: Session = Depends(get_db),
):
    body = build_cases_csv(_listed(db, status, risk, min_score, q, sort, order), _columns(columns))
    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cases.csv"},
    )


@router.get("/cases.xlsx")
def export_xlsx(
    status: str | None = None,
    risk: str | None = None,
    min_score: int | None = Query(default=None, ge=0, le=1000),
    q: str | None = None,
    sort: str = Query(default="score", pattern="^(score|updated|created)$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    columns: str | None = None,
    db: Session = Depends(get_db),
):
    body = build_cases_xlsx(_listed(db, status, risk, min_score, q, sort, order), _columns(columns))
    return Response(
        content=body,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=cases.xlsx"},
    )


@router.get("/cases/{case_id}/fields")
def case_fields(case_id: int, db: Session = Depends(get_db)):
    return field_values(db, _case_or_404(db, case_id))


@router.get("/cases/{case_id}.pdf")
def export_pdf(case_id: int, db: Session = Depends(get_db)):
    detail = _detail(db, _case_or_404(db, case_id))
    return Response(
        content=build_case_pdf(detail),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=case-{case_id}.pdf"},
    )


def _template_out(row: ReportTemplate) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "columns": json.loads(row.columns),
        "status": row.status,
        "query": row.query,
        "min_score": row.min_score,
        "sort": row.sort,
        "order": row.order,
        "created_by": row.created_by,
    }


@router.get("/templates")
def list_templates(db: Session = Depends(get_db)):
    rows = db.query(ReportTemplate).order_by(ReportTemplate.name).all()
    return [_template_out(row) for row in rows]


@router.post("/templates", status_code=201)
def create_template(payload: TemplateCreate, user=Depends(writer), db: Session = Depends(get_db)):
    row = ReportTemplate(
        name=payload.name.strip(),
        columns=json.dumps(payload.columns),
        status=payload.status.strip(),
        query=payload.query.strip(),
        min_score=payload.min_score,
        sort=payload.sort,
        order=payload.order,
        created_by=user.username,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A report with that name already exists")
    db.refresh(row)
    return _template_out(row)


class ScheduleCreate(BaseModel):
    template_id: int = Field(ge=1)
    interval_seconds: int = Field(ge=60, le=86400)


@router.get("/schedules")
def list_schedules(db: Session = Depends(get_db)):
    rows = db.query(ReportSchedule).order_by(ReportSchedule.id).all()
    return [{"id": row.id, "template_id": row.template_id, "interval_seconds": row.interval_seconds,
             "next_run": row.next_run, "created_by": row.created_by} for row in rows]


@router.post("/schedules", status_code=201)
def create_schedule(payload: ScheduleCreate, user=Depends(writer), db: Session = Depends(get_db)):
    require_template(db, payload.template_id)
    if db.query(ReportSchedule).count() >= 20:
        raise HTTPException(409, "Twenty report schedules is the maximum")
    row = ReportSchedule(template_id=payload.template_id, interval_seconds=payload.interval_seconds,
                         next_run=utcnow(), created_by=user.username)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "template_id": row.template_id, "next_run": row.next_run}


@router.get("/schedules/{schedule_id}/export")
def download_scheduled_export(schedule_id: int, db: Session = Depends(get_db)):
    row = db.query(ScheduledExport).filter_by(schedule_id=schedule_id).one_or_none()
    if row is None:
        raise HTTPException(404, "No stored export for that schedule")
    return Response(content=row.body, media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=scheduled-report-{schedule_id}.csv"})


@router.delete("/templates/{template_id}", status_code=204)
def delete_template(template_id: int, user=Depends(writer), db: Session = Depends(get_db)):
    del user
    row = db.get(ReportTemplate, template_id)
    if row is None:
        raise HTTPException(404, "Report not found")
    db.delete(row)
    db.commit()


@router.get("/cases/{case_id}/package.zip")
def export_package(case_id: int, request: Request, db: Session = Depends(get_db)):
    case = _case_or_404(db, case_id)
    detail = _detail(db, case)
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"case-{case_id}.pdf", build_case_pdf(detail))
        lines = []
        for item in detail.activities:
            stamp = item.created_at.isoformat() if hasattr(item.created_at, "isoformat") else item.created_at
            lines.append(f"{stamp} {item.detail}")
        archive.writestr("timeline.txt", "\n".join(lines) + ("\n" if lines else ""))
        root = Path(request.app.state.attachment_dir)
        for row in db.query(Attachment).filter_by(case_id=case_id).all():
            path = _stored_path(root, row.stored_name)
            if path.is_file():
                archive.write(path, f"files/{row.id}-{Path(row.original_name).name}")
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=case-{case_id}-package.zip"},
    )
