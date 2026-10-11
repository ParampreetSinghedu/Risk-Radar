"""Multimodal evidence-analysis endpoint (Stage 5).

Runs the analyzers and returns the teammate's ``AnalyzerResult`` v1.0 outputs.
The endpoint is read-only and makes no safety determination: Stage 6 remains
authoritative and consumes these results through the shared contract.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from risk_radar.core.config import get_settings
from risk_radar.db.models import Brand
from risk_radar.db.session import get_db
from risk_radar.evidence.resolvers import get_resolvers
from risk_radar.evidence.service import (
    EvidenceAnalysisResult,
    EvidenceEngine,
    EvidenceRequest,
)
from risk_radar.evidence.url_domain import UrlDomainAnalyzer
from risk_radar.evidence.vision import get_vision_provider

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
    if payload.brand_id is not None and db.get(Brand, payload.brand_id) is None:
        raise HTTPException(status_code=404, detail="Brand not found")
    settings = get_settings()
    vision = get_vision_provider(settings)
    dns, rdap, redirects = get_resolvers(settings)
    url_analyzer = UrlDomainAnalyzer(dns=dns, rdap=rdap, redirects=redirects)
    return EvidenceEngine(url=url_analyzer, vision=vision).analyze(db, payload)
