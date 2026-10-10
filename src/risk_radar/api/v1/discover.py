"""Discovery endpoint (Stage 3)."""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator

from risk_radar.discovery.service import (
    DiscoveryResult,
    DiscoveryService,
    default_connectors,
)

router = APIRouter(tags=["discovery"])


def get_discovery_service() -> DiscoveryService:
    """Build the discovery service with the default connector registry."""
    return DiscoveryService(default_connectors())


class DiscoverRequest(BaseModel):
    """Query used to run discovery across the registered connectors."""

    query: str = Field(min_length=1, max_length=255)

    @field_validator("query")
    @classmethod
    def query_must_not_be_blank(cls, value: str) -> str:
        """Reject blank queries before any connector runs."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("query must not be blank")
        return stripped


@router.post(
    "/discover",
    response_model=DiscoveryResult,
    summary="Run discovery for a query",
)
def discover(
    payload: DiscoverRequest,
    service: Annotated[DiscoveryService, Depends(get_discovery_service)],
) -> DiscoveryResult:
    """Return deduplicated candidates with per-connector failure details."""
    return service.discover(payload.query)
