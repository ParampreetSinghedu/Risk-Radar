import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from risk_radar.api.v1.brands import router as brands_router
from risk_radar.api.v1.cases import router as cases_router
from risk_radar.api.v1.collect import router as collect_router
from risk_radar.api.v1.correlate import router as correlate_router
from risk_radar.api.v1.demo import router as demo_router
from risk_radar.api.v1.discover import router as discover_router
from risk_radar.api.v1.evaluation import router as evaluation_router
from risk_radar.api.v1.evidence import router as evidence_router
from risk_radar.api.v1.gate import router as gate_router
from risk_radar.api.v1.health import router as health_router
from risk_radar.api.v1.investigate import router as investigate_router
from risk_radar.api.v1.ml import router as ml_router
from risk_radar.api.v1.monitoring import router as monitoring_router
from risk_radar.api.v1.rag import router as rag_router
from risk_radar.api.v1.review import router as review_router
from risk_radar.api.v1.risk import router as risk_router
from risk_radar.api.v1.rules import router as rules_router
from risk_radar.api.v1.submissions import router as submissions_router
from risk_radar.core.config import get_settings
from risk_radar.db.session import init_db
from risk_radar.monitoring.service import (
    release_scheduler_batch_claim,
    run_claimed_scheduler_batch,
    try_claim_scheduler_batch,
)

settings = get_settings()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ensure database schema is created when running on SQLite in local dev mode."""
    if settings.database_url.drivername.startswith("sqlite"):
        init_db()
    scheduler_task = None
    scheduler_registered = False
    if settings.monitoring_scheduler_enabled:
        scheduler_task = getattr(app.state, "monitoring_scheduler_task", None)
        if scheduler_task is None or scheduler_task.done():
            scheduler_task = asyncio.create_task(_monitoring_scheduler())
            app.state.monitoring_scheduler_task = scheduler_task
            app.state.monitoring_scheduler_users = 0
        app.state.monitoring_scheduler_users += 1
        scheduler_registered = True
    try:
        yield
    finally:
        if scheduler_registered:
            app.state.monitoring_scheduler_users -= 1
        if scheduler_registered and app.state.monitoring_scheduler_users == 0:
            scheduler_task.cancel()
            try:
                await scheduler_task
            except asyncio.CancelledError:
                pass
            del app.state.monitoring_scheduler_task
            del app.state.monitoring_scheduler_users


async def _monitoring_scheduler() -> None:
    """One bounded scheduler task; checks targets sequentially in capped batches."""
    interval = min(max(settings.monitoring_scheduler_poll_seconds, 1.0), 300.0)
    batch_size = min(max(settings.monitoring_scheduler_batch_size, 1), 50)
    while True:
        try:
            # Claim before executor submission. If lifespan cancellation happens
            # while the thread is still running, that thread releases the claim
            # when it exits; a restarted scheduler cannot queue another batch.
            if try_claim_scheduler_batch():
                loop = asyncio.get_running_loop()
                try:
                    future = loop.run_in_executor(
                        None, run_claimed_scheduler_batch, batch_size
                    )
                except BaseException:
                    release_scheduler_batch_claim()
                    raise
                await asyncio.shield(future)
        except Exception as exc:  # noqa: BLE001 - preserve future ticks without leaking values
            logger.warning("monitoring scheduler tick failed (%s)", exc.__class__.__name__)
        await asyncio.sleep(interval)


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(health_router, prefix="/api/v1")
app.include_router(brands_router, prefix="/api/v1")
app.include_router(cases_router, prefix="/api/v1")
app.include_router(review_router, prefix="/api/v1")
app.include_router(demo_router, prefix="/api/v1")
app.include_router(evaluation_router, prefix="/api/v1")
app.include_router(submissions_router, prefix="/api/v1")
app.include_router(discover_router, prefix="/api/v1")
app.include_router(evidence_router, prefix="/api/v1")
app.include_router(collect_router, prefix="/api/v1")
app.include_router(gate_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(risk_router, prefix="/api/v1")
app.include_router(rag_router, prefix="/api/v1")
app.include_router(ml_router, prefix="/api/v1")
app.include_router(investigate_router, prefix="/api/v1")
app.include_router(correlate_router, prefix="/api/v1")
app.include_router(monitoring_router, prefix="/api/v1")

# Serve the single-page dashboard (static, no build step).
_STATIC_DIR = Path(__file__).resolve().parent / "static"
if _STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")
