"""Allowlisted report filters shared by interactive and external consumers."""
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, or_

from app.models import Case, CaseField, CaseFieldValue

FIELDS = {
    "id": ("Case ID", "number"), "title": ("Title", "text"),
    "case_type": ("Case type", "text"), "status": ("Status", "text"),
    "risk": ("Risk", "text"), "score": ("Score", "number"),
    "assignee": ("Assignee", "text"), "summary": ("Summary", "text"),
    "conclusion": ("Conclusion", "text"), "created_at": ("Created", "date"),
    "updated_at": ("Updated", "date"),
}
OPERATORS = {"text": ["eq", "contains"], "number": ["eq", "gte", "lte"], "date": ["gte", "lte"]}


class InputFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str = Field(max_length=80)
    operator: Literal["eq", "contains", "gte", "lte"] = "eq"
    value: str = Field(max_length=500)


class ReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    columns: list[str] = Field(default_factory=lambda: ["id", "title", "status", "score"], min_length=1, max_length=30)
    filters: list[InputFilter] = Field(default_factory=list, max_length=20)
    match: Literal["all", "any"] = "all"

    @field_validator("columns")
    @classmethod
    def unique_columns(cls, values):
        if len(set(values)) != len(values):
            raise ValueError("Report columns must be unique")
        return values


class DefinitionInput(ReportInput):
    name: str = Field(min_length=2, max_length=80)

    @field_validator("name")
    @classmethod
    def name_valid(cls, value):
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Enter a report name")
        return value


def catalog(db):
    result = {key: {"key": key, "label": label, "type": kind, "operators": OPERATORS[kind]}
              for key, (label, kind) in FIELDS.items()}
    for field in db.query(CaseField).order_by(CaseField.id):
        key = f"field:{field.id}"
        result[key] = {"key": key, "label": f"{field.case_type}: {field.label}",
                       "type": "text", "operators": OPERATORS["text"], "case_type": field.case_type}
    return result


def filtered_query(db, definition):
    fields = catalog(db)
    if any(key not in fields for key in definition.columns):
        raise HTTPException(422, "Unknown report column")
    conditions = []
    for item in definition.filters:
        meta = fields.get(item.field)
        if not meta or item.operator not in meta["operators"]:
            raise HTTPException(422, "Unknown field or unsupported filter operator")
        value = item.value
        try:
            if meta["type"] == "number":
                value = int(value)
                if not -(2**63) <= value < 2**63:
                    raise ValueError()
            elif meta["type"] == "date":
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if value.tzinfo is None:
                    raise ValueError()
                value = value.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            raise HTTPException(422, "Use an integer or a date with a timezone for this filter")
        custom = item.field.startswith("field:")
        column = CaseFieldValue.value if custom else getattr(Case, item.field)
        if item.operator == "eq": predicate = column == value
        elif item.operator == "contains": predicate = column.contains(value, autoescape=True)
        elif item.operator == "gte": predicate = column >= value
        else: predicate = column <= value
        if custom:
            predicate = and_(Case.case_type == meta["case_type"], db.query(CaseFieldValue.id).filter(
                CaseFieldValue.case_id == Case.id,
                CaseFieldValue.field_id == int(item.field.split(":")[1]), predicate).exists())
        conditions.append(predicate)
    query = db.query(Case)
    if conditions:
        query = query.filter((and_ if definition.match == "all" else or_)(*conditions))
    return query, fields


def query_page(db, definition, after_id=0, limit=100):
    query, fields = filtered_query(db, definition)
    cases = query.filter(Case.id > after_id).order_by(Case.id).limit(limit + 1).all()
    more = len(cases) > limit
    cases = cases[:limit]
    values = {(row.case_id, row.field_id): row.value for row in db.query(CaseFieldValue).filter(
        CaseFieldValue.case_id.in_([case.id for case in cases])).all()} if cases else {}
    rows = []
    for case in cases:
        cells = {}
        for key in definition.columns:
            if key.startswith("field:"):
                value = values.get((case.id, int(key.split(":")[1]))) if case.case_type == fields[key]["case_type"] else None
            else:
                value = getattr(case, key)
                if isinstance(value, datetime):
                    value = value.replace(tzinfo=timezone.utc).isoformat() if value.tzinfo is None else value.isoformat()
            cells[key] = value
        rows.append({"case_id": case.id, "values": cells})
    return {"schema_version": 1, "columns": [fields[key] for key in definition.columns],
            "rows": rows, "next_after_id": cases[-1].id if more else None,
            "filters": definition.model_dump(), "ordering": "case_id ascending"}
