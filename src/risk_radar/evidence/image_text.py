"""Analyzer C: image and text analysis (Stage 5).

Text analysis is fully supported with the standard library (read-only): it
extracts observable signals (embedded URLs, handles, urgency phrases) and
reports them with provenance. Nothing is classified as malicious here.

Image analysis depends on an OCR/image backend. None is installed by default,
so the analyzer reports an explicit ``unavailable`` status and a limitation
unless a backend is injected. An optional Claude vision provider
(``risk_radar.evidence.vision``) can be injected to extract visible text from
screenshots; without credentials the analyzer stays ``unavailable`` and never
fabricates OCR text, logo matches or image contents.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Protocol

from app.schemas.evidence import AnalyzerResult

from risk_radar.evidence.base import (
    assessment_from_reasons,
    build_result,
    evidence_record,
    signal_observation,
)
from risk_radar.evidence.vision import VisionError, VisionProvider, validate_image

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
    """Image inspection through an optional OCR or vision backend.

    Without a backend the result is explicitly ``unavailable``; image contents
    are never guessed. A ``VisionProvider`` (for example the Claude adapter) may
    be injected to extract visible text. Image bytes are validated (format and
    size) before any provider call and treated as untrusted input.
    """

    analyzer_type = "image"

    def __init__(
        self,
        ocr: OcrBackend | None = None,
        vision: VisionProvider | None = None,
    ) -> None:
        self._ocr = ocr
        self._vision = vision

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
                observations=[
                    signal_observation(
                        "provider_status",
                        {"provider": "local_ocr", "status": "not_run_no_input"},
                        "provider_execution",
                    ),
                    signal_observation(
                        "provider_status",
                        {"provider": "vision", "status": "not_run_no_input"},
                        "provider_execution",
                    ),
                ],
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

        limitations: list[str] = []

        media_type, problems = validate_image(image)
        if problems:
            unavailable = any("decoder unavailable" in problem for problem in problems)
            return build_result(
                analyzer_type="image",
                input_type=input_type,
                status="unavailable" if unavailable else "failed",
                input_id=input_id,
                investigation_id=investigation_id,
                observations=[
                    signal_observation(
                        "provider_status",
                        {
                            "provider": "local_ocr",
                            "status": "not_run_image_validation_failed",
                        },
                        "provider_execution",
                    ),
                    signal_observation(
                        "provider_status",
                        {"provider": "vision", "status": "not_run_image_validation_failed"},
                        "provider_execution",
                    ),
                ],
                evidence=evidence,
                errors=[{"stage": "validate", "message": problem} for problem in problems],
                limitations=problems,
            )

        evidence.append(
            evidence_record(
                input_id,
                "validated_image",
                "image content decoded successfully",
                method="pillow_image_decode",
                media_type=media_type,
                sha256=hashlib.sha256(image).hexdigest(),
            )
        )

        result = None
        ocr_status = "unavailable"
        ocr_error = None
        if self._ocr is not None:
            try:
                extracted = self._ocr.extract_text(image)
            except Exception as exc:  # noqa: BLE001 - OCR is optional and failure is explicit
                ocr_status = "error"
                limitations.append("configured OCR backend failed; no text was fabricated")
                ocr_error = {"stage": "ocr", "message": exc.__class__.__name__}
            else:
                if extracted is not None:
                    ocr_status = "completed" if extracted.strip() else "empty"
                    backend_name = getattr(self._ocr, "name", "local_ocr")
                    result = self._completed(
                        extracted,
                        f"ocr:{backend_name}",
                        input_id,
                        input_type,
                        investigation_id,
                        evidence,
                        limitations,
                        media_type=media_type,
                    )
                else:
                    ocr_status = "empty"
                    limitations.append("OCR backend returned no text; no text was fabricated")
        else:
            limitations.append("local OCR provider unavailable or not configured")

        # Vision is a second, separately attributed observation source. It runs
        # alongside local OCR when both are configured; neither authenticates
        # identities observed in pixels.
        vision_status = "unavailable"
        vision_error = None
        if self._vision is not None and media_type is not None:
            try:
                extracted = self._vision.extract_text(image, media_type)
            except VisionError as exc:
                vision_error = {"stage": "vision", "message": str(exc)}
                limitations.append("vision provider failed; no model observation was fabricated")
            except Exception as exc:  # noqa: BLE001 - timeouts or unexpected failures
                vision_error = {"stage": "vision", "message": exc.__class__.__name__}
                limitations.append(
                    f"vision provider error ({exc.__class__.__name__}); "
                    "no model observation was fabricated"
                )
            else:
                if isinstance(extracted, str) and extracted.strip():
                    vision_status = "completed"
                    provider_name = getattr(self._vision, "name", "vision_provider")
                    if result is None:
                        result = self._unavailable(
                            input_id, input_type, investigation_id, evidence, limitations
                        )
                        result.observations.append(
                            signal_observation("media_type", media_type, "image_validation")
                        )
                    result.observations.append(
                        signal_observation(
                            "vision_model_observation",
                            extracted.strip()[:20_000],
                            f"vision:{provider_name}",
                            unverified=True,
                        )
                    )
                    model_text = TextAnalyzer().analyze(
                        extracted,
                        input_id=input_id,
                        input_type="vision_model_observation",
                        investigation_id=investigation_id,
                    )
                    for observation in model_text.observations:
                        normalized = dict(observation)
                        normalized["method"] = f"vision_text_parse:{provider_name}"
                        normalized["unverified"] = True
                        result.observations.append(normalized)
                    for indicator in model_text.indicators:
                        normalized_indicator = dict(indicator)
                        normalized_indicator["source_provider"] = provider_name
                        normalized_indicator["unverified"] = True
                        result.indicators.append(normalized_indicator)
                    result.evidence.append(
                        evidence_record(
                            input_id,
                            "vision_model_observation",
                            "Vision model returned an unverified visual description",
                            method=f"vision:{provider_name}",
                            provider=provider_name,
                            media_type=media_type,
                        )
                    )
                else:
                    vision_status = "empty"
                    limitations.append("vision provider returned no usable observations")
        else:
            limitations.append("vision AI provider unavailable or not configured")

        if result is None:
            result = self._unavailable(
                input_id, input_type, investigation_id, evidence, limitations
            )
        result.observations.extend(
            [
                signal_observation(
                    "provider_status",
                    {"provider": "local_ocr", "status": ocr_status},
                    "provider_execution",
                ),
                signal_observation(
                    "provider_status",
                    {"provider": "vision", "status": vision_status},
                    "provider_execution",
                ),
            ]
        )
        successful_providers = sum(
            provider_status == "completed" for provider_status in (ocr_status, vision_status)
        )
        if successful_providers:
            result.status = "completed" if successful_providers == 2 else "partial"
        result.limitations = list(dict.fromkeys(result.limitations + limitations))
        if ocr_error:
            result.errors.append(ocr_error)
        if vision_error:
            result.errors.append(vision_error)
        return result

    @staticmethod
    def _unavailable(input_id, input_type, investigation_id, evidence, limitations):
        return build_result(
            analyzer_type="image",
            input_type=input_type,
            status="unavailable",
            input_id=input_id,
            investigation_id=investigation_id,
            evidence=evidence,
            assessment=assessment_from_reasons([]),
            limitations=limitations
            + [
                "OCR/image backend unavailable: no text or logo could be extracted "
                "and none was fabricated"
            ],
        )

    @staticmethod
    def _completed(
        extracted,
        method,
        input_id,
        input_type,
        investigation_id,
        evidence,
        limitations,
        media_type=None,
    ):
        raw_text = extracted.strip()
        clean_text = raw_text[:20_000]
        observations = (
            [signal_observation("ocr_text", clean_text, method)] if clean_text else []
        )
        if media_type:
            observations.append(signal_observation("media_type", media_type, "image_validation"))
        # Provenance: record which observation came from the image itself.
        evidence.append(
            evidence_record(
                input_id,
                "ocr",
                f"extracted {len(clean_text)} characters from image via {method}",
                method=method,
                chars=len(clean_text),
                **({"media_type": media_type} if media_type else {}),
            )
        )
        limitations = list(limitations)
        if len(raw_text) > len(clean_text):
            limitations.append(
                "OCR transcript was truncated to the 20,000-character analysis limit"
            )
        indicators: list[dict[str, Any]] = []
        if clean_text:
            text_result = TextAnalyzer().analyze(
                clean_text,
                input_id=input_id,
                input_type="ocr_text",
                investigation_id=investigation_id,
            )
            observations.extend(text_result.observations)
            indicators.extend(text_result.indicators)
            evidence.extend(text_result.evidence)
        else:
            limitations.append("OCR completed but no text was extracted; this is inconclusive")
        return build_result(
            analyzer_type="image",
            input_type=input_type,
            status="completed",
            input_id=input_id,
            investigation_id=investigation_id,
            observations=observations,
            indicators=indicators,
            evidence=evidence,
            assessment=assessment_from_reasons(
                ["ocr_text"] if clean_text else [], confidence=1.0 if clean_text else None
            ),
            limitations=limitations,
        )
