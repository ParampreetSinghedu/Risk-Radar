from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


SchemaStatus = Literal["completed", "partial", "unavailable", "failed"]
AnalyzerType = Literal["url", "brand_profile", "image", "text"]


class SourceReference(BaseModel):
    input_id: str
    kind: str
    locator: str | None = None


class EvidenceRecord(BaseModel):
    evidence_id: str
    evidence_type: str
    description: str

    source_reference: SourceReference
    provenance: dict[str, Any] = Field(default_factory=dict)

    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    confidence: float | None = Field(default=None, ge=0, le=1)
    severity: Literal[
        "informational", "low", "medium", "high", "critical", "unknown"
    ] = "unknown"

    limitations: list[str] = Field(default_factory=list)


class AnalyzerAssessment(BaseModel):
    level: Literal["informational", "low", "medium", "high", "critical", "unknown"] = "unknown"
    confidence: float | None = Field(default=None, ge=0, le=1)
    reason_codes: list[str] = Field(default_factory=list)


class AnalyzerResult(BaseModel):
    schema_version: str = "1.0"
    investigation_id: str
    analysis_id: str

    analyzer_type: AnalyzerType
    input_type: str
    status: SchemaStatus

    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    source_reference: SourceReference

    observations: list[dict[str, Any]] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    entities: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)

    analyzer_assessment: AnalyzerAssessment = Field(
        default_factory=AnalyzerAssessment
    )
    limitations: list[str] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)