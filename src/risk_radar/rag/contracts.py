"""Structured contracts for retrieval and grounded analysis (Stage 12).

Claims are explicitly typed so observed facts, model inferences and
recommendations are never conflated. Every factual claim must cite at least one
retrieved source; citations that do not resolve to a real retrieved document are
rejected rather than trusted.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from risk_radar.gate.service import GateDecision

ClaimKind = Literal["observed_fact", "model_inference", "recommendation"]


class RetrievedDocument(BaseModel):
    """One retrievable stored document with provenance and relevance."""

    doc_id: str
    source_type: Literal["submission", "brand_asset", "audit_log", "analyzer", "target"]
    locator: str | None = None
    content: str
    relevance: float = Field(ge=0, le=1, default=0.0)
    retrieved_at: datetime
    provenance: dict[str, Any] = Field(default_factory=dict)


class SourceCitation(BaseModel):
    """A traceable citation pointing at one retrieved document."""

    doc_id: str
    source_type: str
    locator: str | None = None
    retrieved_at: datetime | None = None


class AnalysisClaim(BaseModel):
    """One claim, typed as fact / inference / recommendation, with citations.

    ``observed_fact`` and ``model_inference`` claims require at least one
    citation. ``recommendation`` claims may stand alone but must state a basis.
    """

    kind: ClaimKind
    text: str = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0, le=1)
    citations: list[SourceCitation] = Field(default_factory=list)
    basis: str | None = None


class RAGAnalysis(BaseModel):
    """Full grounded-analysis output for one candidate."""

    schema_version: str = "1.0"
    status: Literal[
        "completed",
        "partial",
        "provider_unavailable",
        "no_evidence",
        "excluded_verified_official",
        "routed_to_verification",
        "failed_closed",
    ]
    candidate_ref: str
    provider: str
    gate_decision: GateDecision | None = None
    retrieved_documents: list[RetrievedDocument] = Field(default_factory=list)
    claims: list[AnalysisClaim] = Field(default_factory=list)
    risk_factors: list[AnalysisClaim] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    recommended_next_actions: list[AnalysisClaim] = Field(default_factory=list)
    rejected_claims: list[dict[str, Any]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)
    analyzed_at: datetime
