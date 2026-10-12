"""Discovery endpoint (Stage 3)."""

import re
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from risk_radar.db.session import get_db
from risk_radar.discovery.base import CandidateType
from risk_radar.discovery.service import (
    DiscoveryResult,
    DiscoveryService,
    default_connectors,
)
from risk_radar.evidence.brand_profile import BrandProfileAnalyzer

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
    db: Annotated[Session, Depends(get_db)],
) -> DiscoveryResult:
    """Return deduplicated candidates with source data and registry comparisons."""
    result = service.discover(payload.query)
    for candidate in result.candidates:
        if candidate.candidate_type != CandidateType.SOCIAL_PROFILE:
            continue
        if re.fullmatch(r"@[A-Za-z0-9_.]{1,50}", candidate.target):
            analysis = BrandProfileAnalyzer().analyze(
                db,
                candidate.target,
                kind="handle",
                input_id=f"discovery:{candidate.candidate_id}",
                input_type="social_profile",
            )
            candidate.metadata["brand_profile_analysis"] = analysis.model_dump(mode="json")
        else:
            candidate.metadata["brand_profile_analysis"] = {
                "status": "unavailable",
                "limitations": [
                    "provider result is not a plain @handle; no platform-specific "
                    "profile URL parser is configured"
                ],
            }
    return result
