from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError

from app.auth import administrator, current_user, get_db, writer
from app.ingest import MAX_BYTES, events_from_rows, read_csv_dicts
from app.models import SiteRule
from app.websites import CATEGORIES, VisitRecord, access_patterns, category_report, hostname_of, seed_site_policy, store_visits

router = APIRouter(prefix="/api/websites", tags=["websites"], dependencies=[Depends(current_user)])
VISIT_FIELDS = ["visit_id", "occurred_at", "user", "url", "seconds"]


@router.get("/categories")
def categories():
    return list(CATEGORIES)


@router.get("/rules")
def list_rules(db=Depends(get_db)):
    rows = db.query(SiteRule).order_by(SiteRule.host).all()
    return [{"id": row.id, "host": row.host, "category": row.category} for row in rows]


class RuleCreate(BaseModel):
    host: str = Field(min_length=1, max_length=300)
    category: str


@router.post("/rules", status_code=201)
def create_rule(body: RuleCreate, user=Depends(administrator), db=Depends(get_db)):
    if body.category not in CATEGORIES or body.category == "Uncategorized":
        raise HTTPException(422, "Choose one of the built-in categories")
    try:
        host = hostname_of(body.host)
    except ValueError as error:
        raise HTTPException(422, str(error))
    row = SiteRule(host=host, category=body.category, created_by=user.username)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "That hostname is already mapped")
    db.refresh(row)
    return {"id": row.id, "host": row.host, "category": row.category}


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, user=Depends(administrator), db=Depends(get_db)):
    row = db.get(SiteRule, rule_id)
    if row is None:
        raise HTTPException(404, "Host mapping not found")
    db.delete(row)
    db.commit()


@router.get("/policy")
def policy(db=Depends(get_db)):
    seed_site_policy(db)
    from app.models import SitePolicy
    rows = db.query(SitePolicy).order_by(SitePolicy.category).all()
    return [{"category": row.category, "denied": row.denied} for row in rows]


class PolicyUpdate(BaseModel):
    denied: bool


@router.put("/policy/{category}")
def update_policy(category: str, body: PolicyUpdate, user=Depends(administrator), db=Depends(get_db)):
    from app.models import SitePolicy
    if category not in CATEGORIES:
        raise HTTPException(422, "Unknown category")
    seed_site_policy(db)
    row = db.get(SitePolicy, category)
    row.denied = body.denied
    db.commit()
    return {"category": row.category, "denied": row.denied}


@router.post("/visits", status_code=201)
async def import_visits(file: UploadFile, source: str = Form(min_length=1, max_length=80),
                        user=Depends(writer), db=Depends(get_db)):
    source = source.strip()
    if not source:
        raise HTTPException(422, "Source is required")
    seed_site_policy(db)
    rows = read_csv_dicts(await file.read(MAX_BYTES + 1), VISIT_FIELDS)
    return store_visits(db, events_from_rows(rows, model=VisitRecord), source, user.username)


@router.get("/report")
def report(db=Depends(get_db)):
    return category_report(db)


@router.get("/patterns")
def patterns(db=Depends(get_db)):
    return access_patterns(db)
