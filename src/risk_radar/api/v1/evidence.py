"""Multimodal evidence-analysis endpoint (Stage 5).

Runs the analyzers and returns the teammate's ``AnalyzerResult`` v1.0 outputs.
The endpoint is read-only and makes no safety determination: Stage 6 remains
authoritative and consumes these results through the shared contract.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from risk_radar.db.session import get_db
from risk_radar.evidence.service import (
    EvidenceAnalysisResult,
    EvidenceEngine,
    EvidenceRequest,
)

router = APIRouter(tags=["evidence"])


@router.post(
    "/evidence/analyze",
    response_model=EvidenceAnalysisResult,
    summary="Analyze a candidate's multimodal evidence",
)
def analyze_evidence(
    payload: EvidenceRequest,
    db: Annotated[Session, Depends(get_db)],
) -> EvidenceAnalysisResult:
    """Run configured analyzers over one candidate; failures are isolated."""
    return EvidenceEngine().analyze(db, payload)
