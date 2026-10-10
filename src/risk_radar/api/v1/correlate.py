"""Evidence correlation endpoint (Stage 10)."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from risk_radar.correlation.service import CorrelationResult, CorrelationService
from risk_radar.db.session import get_db

router = APIRouter(tags=["correlation"])


class CorrelateCandidateRequest(BaseModel):
    """Minimal correlation input for one candidate."""

    candidate_ref: str = Field(min_length=1, max_length=255)
    target: str = Field(min_length=1, max_length=2048)
    observed_at: datetime | None = None


class CorrelateRequest(BaseModel):
    """Two or more candidates to correlate."""

    candidates: list[CorrelateCandidateRequest] = Field(min_length=2, max_length=100)


@router.post("/correlate", response_model=CorrelationResult, summary="Correlate candidates")
def correlate(
    payload: CorrelateRequest,
    db: Annotated[Session, Depends(get_db)],
) -> CorrelationResult:
    """Group gate-eligible candidates into campaign views with a timeline."""
    return CorrelationService().correlate(db=db, candidates=payload.candidates)
