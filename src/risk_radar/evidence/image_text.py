"""Analyzer C: image and text analysis (Stage 5).

Text analysis is fully supported with the standard library (read-only): it
extracts observable signals (embedded URLs, handles, urgency phrases) and
reports them with provenance. Nothing is classified as malicious here.

Image analysis depends on an OCR/image backend. None is installed in this
project by default, so the analyzer reports an explicit ``unavailable`` status
and a limitation unless a backend is injected. It never fabricates OCR text,
logo matches or image contents.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

from app.schemas.evidence import AnalyzerResult

from risk_radar.evidence.base import (
    assessment_from_reasons,
    build_result,
    evidence_record,
    signal_observation,
)

_URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
_HANDLE_RE = re.compile(r"@[A-Za-z0-9_.]{1,50}\b")
_PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
# Documented urgency phrases (lower-case match); purely descriptive.
_URGENCY_PHRASES = (
    "verify your account",
    "suspended",
    "urgent",
    "act now",
    "confirm your password",
    "unusual activity",
)


class OcrBackend(Protocol):
    """Extract text from image bytes; None when OCR is unavailable."""

    def extract_text(self, image: bytes) -> str | None: ...


class UnavailableOcr:
    """Default OCR backend: none installed, so always unavailable."""

    def extract_text(self, image: bytes) -> str | None:
        return None


class TextAnalyzer:
    """Read-only textual signal extraction from a message or page."""

    analyzer_type = "text"

    def analyze(
        self,
        text: str,
        input_id: str = "target",
        input_type: str = "message",
        investigation_id: str = "unspecified",
    ) -> AnalyzerResult:
        """Extract observable text signals; never judges maliciousness."""
        raw = text or ""
        if not raw.strip():
            return build_result(
                analyzer_type="text",
                input_type=input_type,
                status="failed",
                input_id=input_id,
                investigation_id=investigation_id,
                errors=[{"stage": "normalize", "message": "empty text"}],
                limitations=["empty text: no content to analyze"],
            )

        observations: list[dict[str, Any]] = []
        indicators: list[dict[str, Any]] = []
        evidence = [
            evidence_record(
                input_id,
                "text",
                f"analyzed {len(raw)} characters of text",
                method="text_length",
                length=len(raw),
            )
        ]
        reason_codes: list[str] = []
        limitations: list[str] = []

        lowered = raw.lower()
        urls = _URL_RE.findall(raw)
        if urls:
            observations.append(
                signal_observation("embedded_urls", urls[:20], "regex_url_extraction")
            )
            indicators.append(
                {
                    "kind": "embedded_url",
                    "value": urls[0],
                    "count": len(urls),
                    "severity": "informational",
                    "confidence": 1.0,
                }
            )
            reason_codes.append("embedded_url")

        handles = _HANDLE_RE.findall(raw)
        if handles:
            observations.append(
                signal_observation("embedded_handles", handles[:20], "regex_handle_extraction")
            )

        phones = _PHONE_RE.findall(raw)
        if phones:
            observations.append(
                signal_observation("phone_like_strings", phones[:20], "regex_phone_extraction")
            )

        urgency = [phrase for phrase in _URGENCY_PHRASES if phrase in lowered]
        if urgency:
            indicators.append(
                {
                    "kind": "urgency_language",
                    "value": urgency,
                    "severity": "informational",
                    "confidence": 1.0,
                }
            )
            evidence.append(
                evidence_record(
                    input_id,
                    "language",
                    f"urgency phrases present: {', '.join(urgency)}",
                    method="documented_phrase_list",
                )
            )
            reason_codes.append("urgency_language")

        if not reason_codes:
            limitations.append(
                "no configured textual indicators were observed; this is not a statement of safety"
            )

        return build_result(
            analyzer_type="text",
            input_type=input_type,
            status="completed",
            input_id=input_id,
            investigation_id=investigation_id,
            observations=observations,
            indicators=indicators,
            evidence=evidence,
            assessment=assessment_from_reasons(reason_codes, confidence=1.0),
            limitations=limitations,
        )


class ImageAnalyzer:
    """Image inspection through an optional OCR backend.

    Without a backend the result is explicitly ``unavailable``; image contents
    are never guessed.
    """

    analyzer_type = "image"

    def __init__(self, ocr: OcrBackend | None = None) -> None:
        self._ocr = ocr or UnavailableOcr()

    def analyze(
        self,
        image: bytes | None = None,
        input_id: str = "target",
        input_type: str = "screenshot",
        investigation_id: str = "unspecified",
    ) -> AnalyzerResult:
        """Inspect image bytes; report unavailable rather than inventing text."""
        if image is None:
            return build_result(
                analyzer_type="image",
                input_type=input_type,
                status="failed",
                input_id=input_id,
                investigation_id=investigation_id,
                errors=[{"stage": "input", "message": "no image bytes supplied"}],
                limitations=["no image bytes supplied: nothing to analyze"],
            )

        evidence = [
            evidence_record(
                input_id,
                "image",
                f"received image of {len(image)} bytes",
                method="image_input",
                size=len(image),
            )
        ]
        extracted = self._ocr.extract_text(image)
        if extracted is None:
            return build_result(
                analyzer_type="image",
                input_type=input_type,
                status="unavailable",
                input_id=input_id,
                investigation_id=investigation_id,
                evidence=evidence,
                assessment=assessment_from_reasons([]),
                limitations=[
                    "OCR/image backend unavailable: no text or logo could be extracted "
                    "and none was fabricated"
                ],
            )

        observations = [signal_observation("ocr_text", extracted, "ocr_backend")]
        return build_result(
            analyzer_type="image",
            input_type=input_type,
            status="completed",
            input_id=input_id,
            investigation_id=investigation_id,
            observations=observations,
            evidence=evidence,
            assessment=assessment_from_reasons(["ocr_text"], confidence=1.0),
        )
