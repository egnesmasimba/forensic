from datetime import timedelta

from sqlalchemy.orm import Session

from app.models import Activity, Alert, Case, Note, utcnow


def seed_if_empty(db: Session) -> None:
    if db.query(Case).first() is not None:
        return

    now = utcnow()

    dormant = Case(
        title="Repeated access to dormant accounts",
        case_type="Employee Fraud",
        status="investigating",
        risk="high",
        score=86,
        assignee="Fraud investigator",
        summary="Several dormant accounts were opened by the same staff profile over two days.",
        created_at=now - timedelta(days=2),
        updated_at=now - timedelta(hours=3),
    )
    export = Case(
        title="Bulk customer export from a shared login",
        case_type="Information Leakage",
        status="in_review",
        risk="high",
        score=74,
        assignee="Duty supervisor",
        summary="A shared operations login exported a large customer list outside the usual weekly window.",
        created_at=now - timedelta(days=1),
        updated_at=now - timedelta(hours=8),
    )
    takeover = Case(
        title="Simultaneous sessions on one customer profile",
        case_type="Account Takeover",
        status="new",
        risk="medium",
        score=41,
        assignee="",
        summary="The same customer profile was active from two terminals in the same hour.",
        created_at=now - timedelta(hours=6),
        updated_at=now - timedelta(hours=6),
    )
    cleared = Case(
        title="Production query reviewed and cleared",
        case_type="Privileged IT User",
        status="closed",
        risk="low",
        score=22,
        assignee="Duty supervisor",
        summary="A privileged query against production was flagged for review.",
        conclusion="Change matched an approved maintenance window. No further action.",
        created_at=now - timedelta(days=9),
        updated_at=now - timedelta(days=8),
    )
    db.add_all([dormant, export, takeover, cleared])
    db.flush()

    db.add_all(
        [
            Alert(
                title="Dormant account access above peer baseline",
                description="Account access volume on dormant accounts exceeded the peer group for this role.",
                score=86,
                status="linked",
                entity_type="account",
                entity_ref="ACC-20418",
                channel="Core banking",
                case_id=dormant.id,
                created_at=now - timedelta(days=2),
            ),
            Alert(
                title="After-hours inquiry on the same accounts",
                description="The same staff profile looked up those accounts after the branch closed.",
                score=64,
                status="linked",
                entity_type="user",
                entity_ref="EMP-1044",
                channel="Branch teller",
                case_id=dormant.id,
                created_at=now - timedelta(days=1, hours=4),
            ),
            Alert(
                title="Large customer-list export",
                description="Export size was well above the usual weekly operations report.",
                score=74,
                status="linked",
                entity_type="user",
                entity_ref="OPS-SHARED-2",
                channel="Back office",
                case_id=export.id,
                created_at=now - timedelta(days=1),
            ),
            Alert(
                title="Second active terminal for one profile",
                description="Two terminals held an active session for the same customer profile.",
                score=41,
                status="open",
                entity_type="customer",
                entity_ref="CUS-88310",
                channel="eBanking",
                created_at=now - timedelta(hours=6),
            ),
            Alert(
                title="Privileged production query",
                description="A privileged user ran a query in production during a published window.",
                score=22,
                status="linked",
                entity_type="user",
                entity_ref="DBA-17",
                channel="Database",
                case_id=cleared.id,
                created_at=now - timedelta(days=9),
            ),
        ]
    )
    db.add(
        Note(
            case_id=dormant.id,
            author="Fraud investigator",
            body="Pulled the account list and compared it with the last quarter's dormant-access pattern.",
            created_at=now - timedelta(hours=5),
        )
    )
    db.add_all(
        [
            Activity(
                case_id=dormant.id,
                action="opened",
                detail="Case opened",
                actor="Intake desk",
                created_at=dormant.created_at,
            ),
            Activity(
                case_id=dormant.id,
                action="status_changed",
                detail="Status changed from In review to Investigating",
                actor="Fraud investigator",
                created_at=now - timedelta(hours=4),
            ),
            Activity(
                case_id=export.id,
                action="opened",
                detail="Case opened",
                actor="Intake desk",
                created_at=export.created_at,
            ),
            Activity(
                case_id=takeover.id,
                action="opened",
                detail="Case opened",
                actor="Intake desk",
                created_at=takeover.created_at,
            ),
            Activity(
                case_id=cleared.id,
                action="opened",
                detail="Case opened",
                actor="Intake desk",
                created_at=cleared.created_at,
            ),
            Activity(
                case_id=cleared.id,
                action="status_changed",
                detail="Status changed from Investigating to Closed",
                actor="Duty supervisor",
                created_at=cleared.updated_at,
            ),
        ]
    )
    db.commit()
