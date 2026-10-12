"""Shared analyzer scaffolding for the Multimodal Evidence Engine (Stage 5).

Every analyzer returns the teammate-owned ``AnalyzerResult`` v1.0 contract
(``app.schemas.evidence``), which is the single source of truth. This module
provides deterministic helpers so analyzers report status, provenance,
confidence and limitations uniformly.

Safety invariants (Stage 6 stays authoritative):
- No analyzer ever declares a target safe or malicious; assessments describe
  observations only.
- Missing or unavailable data yields an explicit status plus a limitation,
  never a verdict and never a silent "clean" result.
- Every observation carries provenance so later stages can trace its source.
"""

from datetime import UTC, datetime
from typing import Any, Literal

from app.schemas.evidence import (
    AnalyzerAssessment,
    AnalyzerResult,
    EvidenceRecord,
    SchemaStatus,
    SourceReference,
)

AnalyzerKind = Literal["url", "brand_profile", "image", "text", "application"]

# Severity levels shared with the teammate schema (kept explicit for callers).
Severity = Literal["informational", "low", "medium", "high", "critical", "unknown"]


def utcnow() -> datetime:
    """Return an aware UTC timestamp (deterministic tz, wall-clock value)."""
    return datetime.now(UTC)


def clamp_confidence(value: Any) -> float | None:
    """Coerce a value to a 0..1 confidence, or None when genuinely unknown.

    Booleans, non-numeric values and NaN map to None rather than being
    fabricated into a confidence figure.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number:  # NaN
        return None
    return max(0.0, min(1.0, number))


def claimed_identity_observation(
    kind: Literal["domain", "handle", "name", "application"], value: str, confidence: float | None
) -> dict[str, Any]:
    """Build a claimed-identity observation in the Stage 6 gate convention.

    The exclusion gate consumes observations shaped like
    ``{"kind": ..., "value": ..., "confidence": ...}`` to extract identities.
    Analyzers reuse this exact shape so their output plugs into the gate.
    """
    return {"kind": kind, "value": value, "confidence": clamp_confidence(confidence)}


def signal_observation(kind: str, value: Any, method: str, **extra: Any) -> dict[str, Any]:
    """Build a generic structured observation with explicit provenance."""
    observation: dict[str, Any] = {"kind": kind, "value": value, "method": method}
    observation.update(extra)
    return observation


def evidence_record(
    input_id: str,
    evidence_type: str,
    description: str,
    locator: str | None = None,
    confidence: float | None = None,
    severity: Severity = "unknown",
    **provenance: Any,
) -> EvidenceRecord:
    """Build one source-referenced evidence record with provenance."""
    return EvidenceRecord(
        evidence_id=f"{input_id}:{evidence_type}",
        evidence_type=evidence_type,
        description=description,
        source_reference=SourceReference(input_id=input_id, kind=evidence_type, locator=locator),
        provenance=provenance,
        observed_at=utcnow(),
        confidence=clamp_confidence(confidence),
        severity=severity,
    )


def assessment_from_reasons(
    reason_codes: list[str], confidence: float | None = None
) -> AnalyzerAssessment:
    """Summarize an assessment without ever asserting a safety verdict.

    The level is informational when there are reason codes and unknown when
    there are none: an analyzer describes what it observed, not whether the
    target is malicious.
    """
    level: Severity = "informational" if reason_codes else "unknown"
    return AnalyzerAssessment(
        level=level,  # type: ignore[arg-type]
        confidence=clamp_confidence(confidence),
        reason_codes=reason_codes,
    )


def build_result(
    *,
    analyzer_type: AnalyzerKind,
    input_type: str,
    status: SchemaStatus,
    input_id: str,
    locator: str | None = None,
    investigation_id: str = "unspecified",
    observations: list[dict[str, Any]] | None = None,
    indicators: list[dict[str, Any]] | None = None,
    entities: list[dict[str, Any]] | None = None,
    evidence: list[EvidenceRecord] | None = None,
    assessment: AnalyzerAssessment | None = None,
    limitations: list[str] | None = None,
    errors: list[dict[str, str]] | None = None,
) -> AnalyzerResult:
    """Assemble a contract-valid ``AnalyzerResult`` with deterministic ids."""
    return AnalyzerResult(
        investigation_id=investigation_id,
        analysis_id=f"{analyzer_type}:{input_id}",
        analyzer_type=analyzer_type,  # type: ignore[arg-type]
        input_type=input_type,
        status=status,
        observed_at=utcnow(),
        source_reference=SourceReference(input_id=input_id, kind=analyzer_type, locator=locator),
        observations=observations or [],
        indicators=indicators or [],
        entities=entities or [],
        evidence=evidence or [],
        analyzer_assessment=assessment or assessment_from_reasons([]),
        limitations=limitations or [],
        errors=errors or [],
    )
