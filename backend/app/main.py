import asyncio
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.constants import (
    ACTION_LABELS,
    CASE_TYPES,
    ENTITY_TYPES,
    RISK_LEVELS,
    STATUS_LABELS,
    STATUSES,
    TRANSITIONS,
)
from app.auth import client_address, current_user, reserve_api_attempt
from app.auth import router as auth_router
from app.models import Base
from app import privacy_models, analytic_models, iam_models
from app.routers import privacy, education, live_analytics, biometrics, applications
from app.collect import scan_inbox
from app.foundation import environment, record_access
from app.routers import alerts, analytics, attachments, automation, cases, collectors, compliance, detection, dlp, foundation, imports, links, ocr, processes, profiles, reports, structure, websites
from app.routers import agents, network
from app.routers import search
from app.routers import mail, replay, response
from app.search_elastic import SearchUnavailable, configured_index, sync_pending
from app.search_index import initialize_fts, install_index_hooks
from app.routers.detection import seed_detection
from app.behavior import seed_indicators
from app.automation import seed_automation
from app.dlp import seed_dlp
from app.profiles import seed_library
from app.websites import seed_site_policy
from app.seed import seed_if_empty
from app.schema import ensure_schema
from app.transport_security import (TransportSettings, apply_security_headers,
                                    install_transport_security)


def _backfill_after_migration(engine):
    """Copy existing values into columns that were added without one.

    ``biometric_samples.received_at`` was introduced alongside ``occurred_at``,
    and older rows have a real acquisition time already recorded. Leaving
    received_at NULL would make historical samples look never-received, so the
    value is carried over rather than left for an operator to notice.
    """
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE biometric_samples SET received_at = occurred_at WHERE received_at IS NULL"
        )


def ensure_database_schema(engine):
    """Create missing tables and add missing columns, indexes, and constraints.

    Replaces the previous hand-maintained column list, which only ever contained
    the columns someone remembered to add and never ran on any dialect but
    SQLite. The expected shape is now read from the models, so a new column
    cannot be forgotten here.
    """
    report = ensure_schema(engine)
    _backfill_after_migration(engine)
    app.state_schema_report = report
    return report

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DEFAULT_DB = DATA_DIR / "zanaq.db"
STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(
    database_url: str | None = None,
    *,
    seed: bool = True,
    attachment_dir: Path | str | None = None,
    collection_dir: Path | str | None = None,
    collect_interval: int = 60,
) -> FastAPI:
    if database_url is None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        database_url = "sqlite:///" + DEFAULT_DB.resolve().as_posix()

    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    install_index_hooks(session_factory)

    async def _collect_loop(app: FastAPI):
        try:
            while True:
                await asyncio.sleep(app.state.collect_interval)
                db = app.state.session_factory()
                try:
                    scan_inbox(db, app.state.collection_dir, "collector")
                    from app.privacy import setting, retention
                    if setting(db).automatic_retention:
                        retention(db, dry_run=False)
                        from app.compliance import age_facts
                        age_facts(db, "retention", dry_run=False)
                    from app.report_schedule import run_due_exports
                    run_due_exports(db)
                    from app.audit_export import run_due_exports as run_audit_exports
                    run_audit_exports(db)
                    db.commit()
                except Exception:
                    db.rollback()
                finally:
                    db.close()
        except asyncio.CancelledError:
            return

    def publish_search(app):
        with app.state.session_factory() as db:
            try:
                sync_pending(app.state.search_index, db, app.state.search_sync_lock, 100)
                app.state.search_last_error = None
            except SearchUnavailable as error:
                app.state.search_last_error = str(error)

    async def _search_loop(app):
        while True:
            await asyncio.sleep(5)
            if app.state.search_index:
                delivery = asyncio.create_task(asyncio.to_thread(publish_search, app))
                try:
                    await asyncio.shield(delivery)
                except asyncio.CancelledError:
                    await delivery  # Finish the bounded request before closing its connection.
                    raise

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ensure_database_schema(app.state.engine)
        initialize_fts(app.state.engine)
        app.state.collection_dir.mkdir(parents=True, exist_ok=True)
        db = app.state.session_factory()
        try:
            seed_detection(db)
            seed_site_policy(db)
            seed_indicators(db)
            seed_library(db)
            seed_dlp(db)
            seed_automation(db)
            if app.state.seed:
                seed_if_empty(db)
        finally:
            db.close()
        task = asyncio.create_task(_collect_loop(app))
        search_task = asyncio.create_task(_search_loop(app))
        yield
        task.cancel()
        search_task.cancel()
        await asyncio.gather(task, search_task, return_exceptions=True)
        app.state.engine.dispose()
        if app.state.search_index:
            app.state.search_index.close()

    app = FastAPI(title="ZANAQ Forensic smart Investigation Center", lifespan=lifespan)
    app.state.engine = engine
    app.state.transport = TransportSettings.from_env()
    install_transport_security(app, app.state.transport)
    app.state.session_factory = session_factory
    app.state.search_index = configured_index()
    app.state.search_sync_lock = threading.Lock()
    app.state.search_last_error = None
    app.state.seed = seed
    app.state.attachment_dir = Path(attachment_dir) if attachment_dir else DATA_DIR / "attachments"
    app.state.collection_dir = Path(collection_dir) if collection_dir else DATA_DIR / "inbox"
    app.state.collect_interval = collect_interval
    app.state.max_attachment_bytes = 10 * 1024 * 1024
    app.include_router(auth_router)
    from app.routers.iam import router as iam_router
    app.include_router(iam_router)
    app.include_router(cases.router)
    app.include_router(alerts.router)
    app.include_router(attachments.router)
    app.include_router(ocr.router)
    app.include_router(processes.router)
    app.include_router(reports.router)
    app.include_router(imports.router)
    app.include_router(collectors.router)
    app.include_router(structure.router)
    app.include_router(detection.router)
    app.include_router(links.router)
    app.include_router(network.router)
    app.include_router(agents.router)
    app.include_router(search.router)
    app.include_router(mail.router)
    app.include_router(replay.router)
    app.include_router(response.router)
    app.include_router(websites.router)
    app.include_router(analytics.router)
    app.include_router(profiles.router)
    app.include_router(dlp.router)
    app.include_router(automation.router)
    app.include_router(compliance.router)
    app.include_router(foundation.router)
    app.include_router(privacy.router)
    app.include_router(education.router)
    app.include_router(applications.router)
    app.include_router(live_analytics.router)
    app.include_router(biometrics.router)
    privacy.install_privacy(app)

    @app.middleware("http")
    async def api_throttle(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and not path.startswith("/api/auth/") and path != "/api/health":
            material = request.cookies.get("zanaq_session") or client_address(request)
            db = app.state.session_factory()
            try:
                reserve_api_attempt(db, material)
            except HTTPException as exc:
                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=dict(exc.headers or {}))
            finally:
                db.close()
        return await call_next(request)

    @app.middleware("http")
    async def access_audit(request: Request, call_next):
        response = await call_next(request)
        db = app.state.session_factory()
        try:
            record_access(db, request, response.status_code)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
        return response

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "zanaq-forensic-smart", "environment": environment()}

    @app.get("/api/meta", dependencies=[Depends(current_user)])
    def meta():
        return {
            "case_types": CASE_TYPES,
            "statuses": STATUSES,
            "status_labels": STATUS_LABELS,
            "action_labels": ACTION_LABELS,
            "transitions": TRANSITIONS,
            "risk_levels": RISK_LEVELS,
            "entity_types": ENTITY_TYPES,
        }

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def home():
        return FileResponse(STATIC_DIR / "index.html")

    return app


app = create_app()
