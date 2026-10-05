from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import administrator, current_user
from app.constants import CASE_TYPES, RISK_LEVELS
from app.models import CaseField, CaseFieldValue, RouteRule, User
from app.structure import check_field_key, choose_route

router = APIRouter(dependencies=[Depends(current_user)])


def get_db(request: Request):
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


class FieldCreate(BaseModel):
    case_type: str
    key: str
    label: str = Field(min_length=2, max_length=80)
    required: bool = False

    @field_validator("case_type")
    @classmethod
    def known_type(cls, value: str) -> str:
        if value not in CASE_TYPES:
            raise ValueError("Unknown case type")
        return value


class FieldOut(BaseModel):
    id: int
    case_type: str
    key: str
    label: str
    required: bool
    position: int


class RouteCreate(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    case_type: str = ""
    min_risk: str = "low"
    assignee: str = Field(min_length=1, max_length=120)

    @field_validator("case_type")
    @classmethod
    def known_type(cls, value: str) -> str:
        if value and value not in CASE_TYPES:
            raise ValueError("Unknown case type")
        return value

    @field_validator("min_risk")
    @classmethod
    def known_risk(cls, value: str) -> str:
        if value not in RISK_LEVELS:
            raise ValueError("Unknown risk level")
        return value

    @field_validator("assignee")
    @classmethod
    def assignee_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("Assignee is required")
        return text


class RouteOut(BaseModel):
    id: int
    name: str
    case_type: str
    min_risk: str
    assignee: str
    position: int
    enabled: bool


def _field_out(row: CaseField) -> FieldOut:
    return FieldOut(
        id=row.id,
        case_type=row.case_type,
        key=row.key,
        label=row.label,
        required=row.required,
        position=row.position,
    )


def _route_out(row: RouteRule) -> RouteOut:
    return RouteOut(
        id=row.id,
        name=row.name,
        case_type=row.case_type,
        min_risk=row.min_risk,
        assignee=row.assignee,
        position=row.position,
        enabled=row.enabled,
    )


@router.get("/api/structure/fields", response_model=list[FieldOut])
def list_fields(case_type: str | None = None, db: Session = Depends(get_db)):
    query = db.query(CaseField)
    if case_type:
        query = query.filter(CaseField.case_type == case_type)
    rows = query.order_by(CaseField.case_type.asc(), CaseField.position.asc(), CaseField.id.asc()).all()
    return [_field_out(row) for row in rows]


@router.post("/api/structure/fields", response_model=FieldOut, status_code=201)
def create_field(payload: FieldCreate, db: Session = Depends(get_db), user: User = Depends(administrator)):
    del user
    key = check_field_key(payload.key.strip())
    position = db.query(CaseField).filter(CaseField.case_type == payload.case_type).count()
    row = CaseField(
        case_type=payload.case_type,
        key=key,
        label=payload.label.strip(),
        required=payload.required,
        position=position,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="That field key already exists for this case type")
    db.refresh(row)
    return _field_out(row)


@router.delete("/api/structure/fields/{field_id}", status_code=204)
def delete_field(field_id: int, db: Session = Depends(get_db), user: User = Depends(administrator)):
    del user
    row = db.get(CaseField, field_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Field not found")
    db.query(CaseFieldValue).filter(CaseFieldValue.field_id == row.id).delete()
    db.delete(row)
    db.commit()


@router.get("/api/routes", response_model=list[RouteOut])
def list_routes(db: Session = Depends(get_db)):
    rows = db.query(RouteRule).order_by(RouteRule.position.asc(), RouteRule.id.asc()).all()
    return [_route_out(row) for row in rows]


@router.post("/api/routes", response_model=RouteOut, status_code=201)
def create_route(payload: RouteCreate, db: Session = Depends(get_db), user: User = Depends(administrator)):
    del user
    position = db.query(RouteRule).count()
    row = RouteRule(
        name=payload.name.strip(),
        case_type=payload.case_type,
        min_risk=payload.min_risk,
        assignee=payload.assignee,
        position=position,
        enabled=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _route_out(row)


@router.delete("/api/routes/{rule_id}", status_code=204)
def delete_route(rule_id: int, db: Session = Depends(get_db), user: User = Depends(administrator)):
    del user
    row = db.get(RouteRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Routing rule not found")
    db.delete(row)
    db.commit()


@router.get("/api/routes/match")
def match_route(case_type: str, risk: str, db: Session = Depends(get_db)):
    if case_type not in CASE_TYPES or risk not in RISK_LEVELS:
        raise HTTPException(status_code=422, detail="Unknown case type or risk")
    rule = choose_route(db, case_type, risk)
    if rule is None:
        return {"rule": None}
    return {"rule": _route_out(rule).model_dump()}
