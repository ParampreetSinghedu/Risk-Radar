"""Grounded RAG + LLM analysis endpoint (Stage 12).

Runs the exclusion gate server-side, retrieves stored evidence, and (only when
a provider is configured) produces citation-validated claims. Stage 6 remains
authoritative; the LLM can never trigger an automatic block or alert.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from risk_radar.core.config import get_settings
from risk_radar.db.session import get_db
from risk_radar.investigator.llm import get_provider
from risk_radar.rag.service import RAGAnalysis, RAGAnalysisEngine, RAGRequest

router = APIRouter(tags=["rag"])


@router.post(
    "/rag/analyze",
    response_model=RAGAnalysis,
    summary="Produce evidence-grounded analysis for a candidate",
)
def analyze_rag(
    payload: RAGRequest,
    db: Annotated[Session, Depends(get_db)],
) -> RAGAnalysis:
    """Retrieve stored evidence and generate citation-validated claims."""
    provider = get_provider(get_settings())
    return RAGAnalysisEngine(provider=provider).analyze(db, payload)
