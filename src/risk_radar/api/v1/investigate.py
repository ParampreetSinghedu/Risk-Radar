"""AI investigator endpoint (Stage 9)."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from risk_radar.core.config import get_settings
from risk_radar.db.session import get_db
from risk_radar.investigator.contracts import InvestigationResult
from risk_radar.investigator.llm import get_provider
from risk_radar.investigator.service import InvestigationRequest, InvestigatorService

router = APIRouter(tags=["investigator"])


def get_investigator_service() -> InvestigatorService:
    """Build the investigator with the configured provider (None when unset)."""
    return InvestigatorService(provider=get_provider(get_settings()))


@router.post("/investigate", response_model=InvestigationResult, summary="Investigate a candidate")
def investigate(
    payload: InvestigationRequest,
    db: Annotated[Session, Depends(get_db)],
    service: Annotated[InvestigatorService, Depends(get_investigator_service)],
) -> InvestigationResult:
    """Run a read-only investigation; findings require source citations."""
    return service.investigate(db=db, request=payload)
