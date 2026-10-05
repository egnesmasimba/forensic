from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import administrator, current_user, get_db
from app.foundation import DECISIONS, STANDARDS, certificate_status, environment, notice_csv, open_certificate_alert, operations
from app.models import AccessLog, User

router = APIRouter(prefix="/api/foundation", tags=["foundation"], dependencies=[Depends(current_user)])


class CertificateIn(BaseModel):
    pem: str = Field(min_length=20, max_length=20000)


@router.get("")
def foundation_record():
    return {"environment": environment(), "decisions": list(DECISIONS), "standards": list(STANDARDS)}


@router.get("/operations")
def operations_view(request: Request, db: Session = Depends(get_db), user: User = Depends(administrator)):
    del user
    return operations(db, request.app.state.collection_dir)


@router.get("/notices.csv")
def export_notices(db: Session = Depends(get_db), user: User = Depends(administrator)):
    del user
    return Response(content=notice_csv(db), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=notices.csv"})


@router.get("/access")
def access_log(db: Session = Depends(get_db), user: User = Depends(administrator)):
    del user
    rows = db.query(AccessLog).order_by(AccessLog.id.desc()).limit(50).all()
    return [{"actor": row.actor, "method": row.method, "path": row.path, "status": row.status} for row in rows]


@router.post("/certificate")
def check_certificate(payload: CertificateIn, db: Session = Depends(get_db), user: User = Depends(administrator)):
    del user
    try:
        status = certificate_status(payload.pem.encode())
    except ValueError as error:
        raise HTTPException(422, "The certificate could not be read") from error
    opened = open_certificate_alert(db, status["days_remaining"]) if status["alert"] else False
    db.commit()
    return {**status, "opened": opened}
