"""Minimal liveness endpoint."""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Response returned when the API process is ready to serve requests."""

    status: Literal["ok"]


@router.get("/health", response_model=HealthResponse, summary="Liveness check")
def read_health() -> HealthResponse:
    """Return the API's liveness status without contacting dependencies."""
    return HealthResponse(status="ok")
