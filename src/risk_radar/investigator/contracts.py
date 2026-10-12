"""Structured contracts for investigations, findings and citations (Stage 9)."""

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from risk_radar.gate.service import GateDecision


class EvidenceHit(BaseModel):
    """One stored-evidence match produced by the evidence-search tool."""

    reference: str
    kind: Literal["submission", "brand", "brand_asset", "audit_log"]
    summary: str
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ResearchHit(BaseModel):
    """One validated external research result."""

    reference: str
    source: str
    url: str
    summary: str
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    title: str | None = None
    snippet: str | None = None
    content_kind: str = "provider_record"
    page_content_retrieved: bool = False
    search_query: str | None = None


class SourceCitation(BaseModel):
    """A traceable source behind one factual finding."""

    source_type: Literal["target", "evidence", "web"]
    reference: str
    locator: str | None = None
    retrieved_at: datetime | None = None


class InvestigativeFinding(BaseModel):
    """One factual finding that must cite at least one known source."""

    finding: str = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0, le=1)
    citations: list[SourceCitation] = Field(min_length=1)


class InvestigationResult(BaseModel):
    """Outcome of one read-only investigation."""

    schema_version: str = "1.0"
    status: Literal[
        "completed",
        "partial",
        "provider_unavailable",
        "excluded_verified_official",
        "routed_to_verification",
        "failed_closed",
    ]
    candidate_ref: str
    provider: str
    gate_decision: GateDecision | None = None
    findings: list[InvestigativeFinding] = Field(default_factory=list)
    evidence_hits: list[EvidenceHit] = Field(default_factory=list)
    research_hits: list[ResearchHit] = Field(default_factory=list)
    investigated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    limitations: list[str] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)
