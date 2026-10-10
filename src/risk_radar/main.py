"""FastAPI application entry point."""

from fastapi import FastAPI

from risk_radar.api.v1.health import router as health_router
from risk_radar.core.config import get_settings

settings = get_settings()
app = FastAPI(title=settings.app_name)
app.include_router(health_router, prefix="/api/v1")
