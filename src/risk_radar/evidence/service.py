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
import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit

from app.schemas.evidence import AnalyzerResult
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from risk_radar.evidence.application import ApplicationListingAnalyzer
from risk_radar.evidence.base import utcnow
from risk_radar.evidence.brand_profile import BrandProfileAnalyzer
from risk_radar.evidence.image_text import ImageAnalyzer, TextAnalyzer
from risk_radar.evidence.url_domain import UrlDomainAnalyzer
from risk_radar.evidence.vision import VisionProvider

AnalyzerName = Literal["url", "brand_profile", "text", "image", "application"]
_HANDLE_FORMAT = re.compile(r"^@?[A-Za-z0-9_.]{1,50}$")
_MAX_IMAGE_BASE64_LENGTH = 4 * ((10 * 1024 * 1024 + 2) // 3)


class EvidenceRequest(BaseModel):
    """One candidate to analyze across the configured analyzers."""

    target: str = Field(min_length=1, max_length=2048)
    brand_id: int | None = Field(default=None, gt=0)
    kind: Literal["auto", "domain", "handle", "name", "application"] = "auto"
    text: str | None = Field(default=None, max_length=20000)
    image_b64: str | None = Field(default=None, max_length=_MAX_IMAGE_BASE64_LENGTH)
    input_type: str = "url"
    investigation_id: str = Field(default="unspecified", max_length=128)
    analyzers: list[AnalyzerName] | None = None

    @model_validator(mode="after")
    def validate_social_handle(self) -> EvidenceRequest:
        if self.kind == "handle" or self.input_type in {"handle", "social_profile"}:
            if not _HANDLE_FORMAT.fullmatch(self.target.strip()):
                raise ValueError("handle must be 1-50 letters, digits, underscores or dots")
        return self


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
        application: ApplicationListingAnalyzer | None = None,
    ) -> None:
        self._url = url or UrlDomainAnalyzer()
        self._brand = brand or BrandProfileAnalyzer()
        self._text = text or TextAnalyzer()
        # Image analysis is optional: a vision provider is used when configured,
        # otherwise the analyzer reports an explicit unavailable status.
        self._image = image or ImageAnalyzer(vision=vision)
        self._application = application or ApplicationListingAnalyzer()

    def analyze(self, db: Session, request: EvidenceRequest) -> EvidenceAnalysisResult:
        """Analyze one candidate; analyzer errors never abort the run."""
        candidate_kind, input_type = classify_candidate(
            request.target, kind=request.kind, input_type=request.input_type
        )
        default_selection = {
            "domain": ["url", "brand_profile"],
            "handle": ["brand_profile"],
            "name": ["brand_profile"],
            "application": ["application"],
        }
        requested = (
            list(request.analyzers)
            if request.analyzers is not None
            else default_selection[candidate_kind] + (["image"] if request.image_b64 else [])
        )
        selected = [
            name
            for name in requested
            if not (
                name == "url" and candidate_kind not in {"domain"}
                or name == "application" and candidate_kind != "application"
            )
        ]
        results: list[AnalyzerResult] = []
        limitations: list[str] = []
        errors: list[dict[str, str]] = []
        iid = request.investigation_id
        if len(selected) < len(requested):
            skipped = sorted(set(requested) - set(selected))
            limitations.append(
                f"analyzers {', '.join(skipped)} skipped: input classified as {candidate_kind}"
            )

        for name in selected:
            try:
                if name == "url":
                    results.append(
                        self._url.analyze(
                            request.target,
                            input_type=input_type,
                            investigation_id=iid,
                        )
                    )
                elif name == "brand_profile":
                    results.append(
                        self._brand.analyze(
                            db,
                            request.target,
                            kind=candidate_kind,
                            input_type=input_type,
                            investigation_id=iid,
                            brand_id=request.brand_id,
                        )
                    )
                elif name == "text":
                    results.append(
                        self._text.analyze(
                            request.text or request.target,
                            input_type=input_type,
                            investigation_id=iid,
                        )
                    )
                elif name == "image":
                    image_bytes = self._decode_image(request.image_b64, errors)
                    results.append(
                        self._image.analyze(
                            image_bytes,
                            input_type=input_type,
                            investigation_id=iid,
                        )
                    )
                elif name == "application":
                    results.append(
                        self._application.analyze(
                            db,
                            request.target,
                            input_type=input_type,
                            investigation_id=iid,
                            brand_id=request.brand_id,
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


_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_DOMAIN_TLD = re.compile(r"^[A-Za-z]{2,63}$")


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    return (
        len(labels) >= 2
        and _DOMAIN_TLD.fullmatch(labels[-1]) is not None
        and all(_DOMAIN_LABEL.fullmatch(label) is not None for label in labels[:-1])
    )


def classify_candidate(
    target: str, *, kind: str = "auto", input_type: str = "url"
) -> tuple[str, str]:
    """Resolve explicit types first, then validate formats before dispatch."""
    value = target.strip()
    if kind != "auto":
        resolved = kind
    elif input_type in {"social_profile", "handle"}:
        resolved = "handle"
    elif input_type in {"application", "app_listing"}:
        resolved = "application"
    elif input_type in {"name", "text"}:
        resolved = "name"
    elif value.startswith("@"):
        resolved = "handle"
    elif value.isdecimal():
        resolved = "application"
    elif value.startswith(("http://", "https://")):
        parts = None
        try:
            parts = urlsplit(value)
            host = parts.hostname or ""
        except ValueError:
            host = ""
        if parts is not None and parts.scheme in {"http", "https"} and _valid_host(host):
            if ApplicationListingAnalyzer._parse(value) is not None:
                resolved = "application"
            else:
                resolved = "domain"
        else:
            resolved = "name"
    elif value.lower().startswith("com.") and ApplicationListingAnalyzer._parse(value):
        resolved = "application"
    elif _valid_host(value):
        resolved = "domain"
    else:
        resolved = "name"

    resolved_input = {
        "domain": "url",
        "handle": "social_profile",
        "name": "text",
        "application": "app_listing",
    }[resolved]
    return resolved, resolved_input
