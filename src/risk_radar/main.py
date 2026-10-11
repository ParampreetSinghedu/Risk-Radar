"""FastAPI application entry point."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from risk_radar.api.v1.brands import router as brands_router
from risk_radar.api.v1.cases import router as cases_router
from risk_radar.api.v1.collect import router as collect_router
from risk_radar.api.v1.correlate import router as correlate_router
from risk_radar.api.v1.discover import router as discover_router
from risk_radar.api.v1.evidence import router as evidence_router
from risk_radar.api.v1.gate import router as gate_router
from risk_radar.api.v1.health import router as health_router
from risk_radar.api.v1.investigate import router as investigate_router
from risk_radar.api.v1.ml import router as ml_router
from risk_radar.api.v1.rag import router as rag_router
from risk_radar.api.v1.risk import router as risk_router
from risk_radar.api.v1.rules import router as rules_router
from risk_radar.api.v1.submissions import router as submissions_router
from risk_radar.core.config import get_settings

settings = get_settings()
app = FastAPI(title=settings.app_name)
app.include_router(health_router, prefix="/api/v1")
app.include_router(brands_router, prefix="/api/v1")
app.include_router(cases_router, prefix="/api/v1")
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

# Serve the Stage 13 single-page dashboard (static, no build step).
_STATIC_DIR = Path(__file__).resolve().parent / "static"
if _STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")
