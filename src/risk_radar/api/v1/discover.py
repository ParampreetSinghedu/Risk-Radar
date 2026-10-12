"""Discovery endpoint (Stage 3)."""

import re
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from risk_radar.db.session import get_db
from risk_radar.discovery.base import Candidate, CandidateType
from risk_radar.discovery.service import (
    DiscoveryFailure,
    DiscoveryResult,
    DiscoveryService,
    default_connectors,
)
from risk_radar.evidence.brand_profile import BrandProfileAnalyzer

router = APIRouter(tags=["discovery"])
_HANDLE_FORMAT = re.compile(r"^@?[A-Za-z0-9_.]{1,50}$")


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


class SocialProfileRequest(BaseModel):
    """A syntactically valid social handle to look up through an authorized provider."""

    handle: str = Field(min_length=1, max_length=51)

    @field_validator("handle")
    @classmethod
    def validate_handle(cls, value: str) -> str:
        stripped = value.strip()
        normalized = stripped[1:] if stripped.startswith("@") else stripped
        if not normalized or not re.fullmatch(r"[A-Za-z0-9_.]{1,50}", normalized):
            raise ValueError("handle must be 1-50 letters, digits, underscores or dots")
        return f"@{normalized}"


class SocialProfileDiscovery(BaseModel):
    """Provider status and only genuinely returned profile candidates."""

    query: str
    status: str
    candidates: list[Candidate] = Field(default_factory=list)
    failures: list[DiscoveryFailure] = Field(default_factory=list)
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


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


@router.post(
    "/discover/social-profile",
    response_model=SocialProfileDiscovery,
    summary="Discover a social profile using configured authorized providers",
)
def discover_social_profile(
    payload: SocialProfileRequest,
    service: Annotated[DiscoveryService, Depends(get_discovery_service)],
    db: Annotated[Session, Depends(get_db)],
) -> SocialProfileDiscovery:
    """Run only configured social providers; never scrape platform pages implicitly."""
    social_connectors = [
        connector for connector in service.connectors if connector.name == "social"
    ]
    result = DiscoveryService(social_connectors).discover(payload.handle)
    for candidate in result.candidates:
        if candidate.candidate_type != CandidateType.SOCIAL_PROFILE:
            continue
        if re.fullmatch(r"@?[A-Za-z0-9_.]{1,50}", candidate.target):
            candidate.metadata["brand_profile_analysis"] = BrandProfileAnalyzer().analyze(
                db,
                candidate.target,
                kind="handle",
                input_id=f"discovery:{candidate.candidate_id}",
                input_type="social_profile",
            ).model_dump(mode="json")

    failures = result.failures
    if result.candidates and failures:
        status = "partial"
    elif result.candidates:
        status = "completed"
    elif failures and any(
        "no authorized platform API provider" in item.reason for item in failures
    ):
        status = "provider_unavailable"
    elif failures:
        status = "provider_error"
    else:
        status = "inconclusive"
    return SocialProfileDiscovery(
        query=payload.handle,
        status=status,
        candidates=result.candidates,
        failures=failures,
    )
