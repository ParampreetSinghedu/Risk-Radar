"""Adapter for the Stage 5 evidence contract (Stage 6 boundary).

Mirrors the teammate's ``AnalyzerResult`` v1.0 schema (branch
``teammate/evidence-engine``, ``app/schemas/evidence.py``) as the subset the
gate consumes. Her full payloads deserialize into these models unchanged:
identical field names and value shapes; fields the gate does not need
(``investigation_id``, ``analysis_id``, ``input_type``, ``indicators``,
``entities``, ``evidence``) are accepted and ignored.

Claimed-identity observation convention consumed by the gate::

    {"kind": "domain" | "handle" | "name", "value": "...", "confidence": 0.0-1.0}

Observations in other shapes are skipped and reported in ``limitations``.
Analyzer ``status`` of ``unavailable`` or ``failed`` yields no identities:
missing evidence is never treated as proof of anything.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field

AnalyzerStatus = Literal["completed", "partial", "unavailable", "failed"]
IdentityKind = Literal["domain", "handle", "name"]
_USABLE_STATUSES = {"completed", "partial"}


class SourceReference(BaseModel):
    """Evidence input reference (same shape as the teammate's schema)."""

    input_id: str
    kind: str
    locator: str | None = None


class AnalyzerAssessment(BaseModel):
    """Analyzer-level assessment subset used by the gate."""

    level: Literal["informational", "low", "medium", "high", "critical", "unknown"] = "unknown"
    confidence: float | None = Field(default=None, ge=0, le=1)
    reason_codes: list[str] = Field(default_factory=list)


class AnalyzerEvidence(BaseModel):
    """Stage 5 analyzer output accepted by the Stage 6 gate."""

    schema_version: str = "1.0"
    analyzer_type: Literal["url", "brand_profile", "image", "text"]
    status: AnalyzerStatus
    source_reference: SourceReference
    observations: list[dict[str, Any]] = Field(default_factory=list)
    analyzer_assessment: AnalyzerAssessment = Field(default_factory=AnalyzerAssessment)
    limitations: list[str] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)


class ClaimedIdentity(BaseModel):
    """A claimed brand/username/domain extracted from analyzer observations."""

    kind: IdentityKind
    value: str
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence_input_id: str


def usable_observations(
    evidence: AnalyzerEvidence,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Return analyzer observations only when the analyzer status is usable.

    A ``failed`` or ``unavailable`` analyzer contributes nothing: missing
    evidence is never interpreted as a safe or clean result.
    """
    if evidence.status not in _USABLE_STATUSES:
        return [], [f"analyzer status '{evidence.status}': no usable observations extracted"]
    return list(evidence.observations), list(evidence.limitations)


def claimed_identities(evidence: AnalyzerEvidence) -> tuple[list[ClaimedIdentity], list[str]]:
    """Extract claimed identities and limitations from analyzer output."""
    limitations: list[str] = list(evidence.limitations)
    if evidence.status not in _USABLE_STATUSES:
        limitations.append(f"analyzer status '{evidence.status}': no usable observations extracted")
        return [], limitations

    identities: list[ClaimedIdentity] = []
    skipped = 0
    for observation in evidence.observations:
        kind = observation.get("kind")
        value = observation.get("value")
        valid_kind = kind in {"domain", "handle", "name"}
        if not valid_kind or not isinstance(value, str) or not value.strip():
            skipped += 1
            continue
        confidence = observation.get("confidence")
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
            confidence = min(1.0, max(0.0, float(confidence)))
        else:
            confidence = None
        identities.append(
            ClaimedIdentity(
                kind=kind,
                value=value.strip(),
                confidence=float(confidence) if confidence is not None else None,
                evidence_input_id=evidence.source_reference.input_id,
            )
        )
    if skipped:
        limitations.append(f"{skipped} observation(s) skipped: unrecognized shape")
    return identities, limitations
