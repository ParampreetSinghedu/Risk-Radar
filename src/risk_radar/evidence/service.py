"""Evidence Engine orchestration (Stage 5).

Runs the analyzers against one candidate and returns their contract-valid
``AnalyzerResult`` outputs (teammate's schema) together with a provenance-rich
summary. The engine is read-only and never declares a target safe: every
signal is traceable to its source, and Stage 6 remains authoritative.

Downstream stages (6/7/8/9) consume these results directly via the shared
``AnalyzerResult`` contract; no duplicate schema is introduced here.
"""

from __future__ import annotations

import base64
import binascii
from typing import Literal

from app.schemas.evidence import AnalyzerResult
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from risk_radar.evidence.base import utcnow
from risk_radar.evidence.brand_profile import BrandProfileAnalyzer
from risk_radar.evidence.image_text import ImageAnalyzer, TextAnalyzer
from risk_radar.evidence.url_domain import UrlDomainAnalyzer
from risk_radar.evidence.vision import VisionProvider

AnalyzerName = Literal["url", "brand_profile", "text", "image"]


class EvidenceRequest(BaseModel):
    """One candidate to analyze across the configured analyzers."""

    target: str = Field(min_length=1, max_length=2048)
    kind: Literal["auto", "domain", "handle", "name"] = "auto"
    text: str | None = Field(default=None, max_length=20000)
    image_b64: str | None = None
    input_type: str = "url"
    investigation_id: str = Field(default="unspecified", max_length=128)
    analyzers: list[AnalyzerName] | None = None


class AnalyzerSummary(BaseModel):
    """Per-analyzer outcome header (full result carries the evidence)."""

    analyzer: AnalyzerName
    status: str
    observation_count: int
    indicator_count: int
    evidence_count: int
    limitation_count: int
    error_count: int


class EvidenceAnalysisResult(BaseModel):
    """Aggregate output of one evidence-analysis run."""

    schema_version: str = "1.0"
    investigation_id: str
    candidate_ref: str
    analyzed_at: str
    results: list[AnalyzerResult] = Field(default_factory=list)
    summaries: list[AnalyzerSummary] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)


class EvidenceEngine:
    """Run selected analyzers over one candidate, isolating failures."""

    def __init__(
        self,
        url: UrlDomainAnalyzer | None = None,
        brand: BrandProfileAnalyzer | None = None,
        text: TextAnalyzer | None = None,
        image: ImageAnalyzer | None = None,
        vision: VisionProvider | None = None,
    ) -> None:
        self._url = url or UrlDomainAnalyzer()
        self._brand = brand or BrandProfileAnalyzer()
        self._text = text or TextAnalyzer()
        # Image analysis is optional: a vision provider is used when configured,
        # otherwise the analyzer reports an explicit unavailable status.
        self._image = image or ImageAnalyzer(vision=vision)

    def analyze(self, db: Session, request: EvidenceRequest) -> EvidenceAnalysisResult:
        """Analyze one candidate; analyzer errors never abort the run."""

        selected = request.analyzers or ["url", "brand_profile"]
        results: list[AnalyzerResult] = []
        limitations: list[str] = []
        errors: list[dict[str, str]] = []
        iid = request.investigation_id

        for name in selected:
            try:
                if name == "url":
                    results.append(
                        self._url.analyze(
                            request.target,
                            input_type=request.input_type,
                            investigation_id=iid,
                        )
                    )
                elif name == "brand_profile":
                    results.append(
                        self._brand.analyze(
                            db,
                            request.target,
                            kind=request.kind,
                            input_type=request.input_type,
                            investigation_id=iid,
                        )
                    )
                elif name == "text":
                    results.append(
                        self._text.analyze(
                            request.text or request.target,
                            input_type=request.input_type,
                            investigation_id=iid,
                        )
                    )
                elif name == "image":
                    image_bytes = self._decode_image(request.image_b64, errors)
                    results.append(
                        self._image.analyze(
                            image_bytes,
                            input_type=request.input_type,
                            investigation_id=iid,
                        )
                    )
            except Exception as exc:  # noqa: BLE001 - isolate analyzer failures
                errors.append({"stage": name, "message": exc.__class__.__name__})
                limitations.append(f"analyzer '{name}' failed ({exc.__class__.__name__})")

        summaries = [
            AnalyzerSummary(
                analyzer=name,
                status=next((r.status for r in results if r.analyzer_type == name), "missing"),
                observation_count=len(r.observations),
                indicator_count=len(r.indicators),
                evidence_count=len(r.evidence),
                limitation_count=len(r.limitations),
                error_count=len(r.errors),
            )
            for name, r in ((r.analyzer_type, r) for r in results)
        ]

        return EvidenceAnalysisResult(
            investigation_id=iid,
            candidate_ref=request.target[:255],
            analyzed_at=utcnow().isoformat(),
            results=results,
            summaries=summaries,
            limitations=limitations,
            errors=errors,
        )

    @staticmethod
    def _decode_image(image_b64: str | None, errors: list[dict[str, str]]) -> bytes | None:
        if not image_b64:
            return None
        try:
            return base64.b64decode(image_b64, validate=True)
        except (binascii.Error, ValueError):
            errors.append({"stage": "image", "message": "invalid base64 image data"})
            return None
