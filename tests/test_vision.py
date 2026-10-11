"""Stage 5 vision-adapter tests (optional image analysis).

All vision responses are mocked; no network, credentials or external services
are required. Covers missing credentials, malformed/oversized images, valid
extraction, provider failures, source provenance and Stage 6 gate enforcement.
"""

from __future__ import annotations

from app.schemas.evidence import AnalyzerResult

from risk_radar.evidence.image_text import ImageAnalyzer
from risk_radar.evidence.vision import (
    MAX_IMAGE_BYTES,
    ClaudeVisionProvider,
    VisionError,
    detect_media_type,
    get_vision_provider,
    validate_image,
)
from risk_radar.gate.contracts import AnalyzerEvidence
from risk_radar.gate.service import ExclusionGate

PNG = b"\x89PNG\r\n\x1a\n" + b"fake-png-body"
JPEG = b"\xff\xd8\xff\xe0" + b"fake-jpeg-body"
WEBP = b"RIFF\x00\x00\x00\x00WEBP" + b"fake"


class FakeVision:
    """Deterministic mock vision backend."""

    name = "fake_vision"

    def __init__(self, text: str = "PayPal - verify your account http://evil.com"):
        self._text = text

    def extract_text(self, image: bytes, media_type: str) -> str:
        return self._text


class ErrorVision:
    name = "error_vision"

    def extract_text(self, image: bytes, media_type: str) -> str:
        raise VisionError("vision request failed (Timeout)")


class CrashVision:
    name = "crash_vision"

    def extract_text(self, image: bytes, media_type: str) -> str:
        raise TimeoutError("boom")


# --- detection / validation ------------------------------------------------


def test_detect_media_types():
    assert detect_media_type(PNG) == "image/png"
    assert detect_media_type(JPEG) == "image/jpeg"
    assert detect_media_type(WEBP) == "image/webp"
    assert detect_media_type(b"junk") is None


def test_validate_image_rejects_empty_and_unknown():
    _, problems = validate_image(b"")
    assert problems
    _, problems = validate_image(b"junk")
    assert any("unsupported" in p for p in problems)


def test_validate_image_rejects_oversized():
    big = PNG + b"x" * (MAX_IMAGE_BYTES + 10)
    _, problems = validate_image(big)
    assert any("exceeding" in p for p in problems)


def test_validate_image_accepts_valid_png():
    media_type, problems = validate_image(PNG)
    assert media_type == "image/png" and problems == []


# --- analyzer behaviour ----------------------------------------------------


def test_valid_extraction_returns_completed_with_ocr_text():
    result = ImageAnalyzer(vision=FakeVision()).analyze(PNG)
    assert isinstance(result, AnalyzerResult)
    assert result.status == "completed"
    ocr = [o for o in result.observations if o["kind"] == "ocr_text"]
    assert ocr and "verify your account" in ocr[0]["value"]


def test_missing_provider_reports_unavailable_not_safe():
    result = ImageAnalyzer().analyze(PNG)
    assert result.status == "unavailable"
    assert result.observations == []
    assert any("fabricated" in limitation for limitation in result.limitations)


def test_provider_error_is_unavailable_and_never_fabricates():
    result = ImageAnalyzer(vision=ErrorVision()).analyze(PNG)
    assert result.status == "unavailable"
    assert result.errors and result.errors[0]["stage"] == "vision"
    assert any("fabricated" in limitation for limitation in result.limitations)


def test_provider_crash_is_isolated():
    result = ImageAnalyzer(vision=CrashVision()).analyze(PNG)
    assert result.status == "unavailable"
    assert result.errors and result.errors[0]["message"] == "TimeoutError"


def test_malformed_image_fails_before_provider_call():
    class Boom:
        name = "boom"

        def extract_text(self, image, media_type):
            raise AssertionError("provider must not be called for invalid image")

    result = ImageAnalyzer(vision=Boom()).analyze(b"junk")
    assert result.status == "failed"
    assert any(e["stage"] == "validate" for e in result.errors)


def test_oversized_image_fails_before_provider_call():
    class Boom:
        name = "boom"

        def extract_text(self, image, media_type):
            raise AssertionError("provider must not be called for oversized image")

    big = PNG + b"x" * (MAX_IMAGE_BYTES + 10)
    result = ImageAnalyzer(vision=Boom()).analyze(big)
    assert result.status == "failed"


def test_no_image_bytes_fails():
    result = ImageAnalyzer(vision=FakeVision()).analyze(None)
    assert result.status == "failed"


# --- provenance ------------------------------------------------------------


def test_ocr_evidence_carries_source_reference_and_provenance():
    result = ImageAnalyzer(vision=FakeVision()).analyze(PNG)
    ocr_evidence = [e for e in result.evidence if e.evidence_type == "ocr"]
    assert ocr_evidence
    record = ocr_evidence[0]
    assert record.source_reference.input_id == "target"
    assert record.provenance["method"] == "vision:fake_vision"
    assert record.provenance["media_type"] == "image/png"
    assert record.provenance["chars"] > 0


def test_media_type_observation_present():
    result = ImageAnalyzer(vision=FakeVision()).analyze(PNG)
    media = [o for o in result.observations if o["kind"] == "media_type"]
    assert media and media[0]["value"] == "image/png"


# --- credentials / provider construction -----------------------------------


def test_get_vision_provider_none_without_key():
    class Settings:
        anthropic_api_key = None
        llm_model = "claude-x"

    assert get_vision_provider(Settings()) is None


def test_get_vision_provider_builds_with_key():
    from pydantic import SecretStr

    class Settings:
        anthropic_api_key = SecretStr("sk-test")
        llm_model = "claude-3-5-haiku-latest"

    provider = get_vision_provider(Settings())
    assert isinstance(provider, ClaudeVisionProvider)
    assert provider.name == "claude_vision"


def test_claude_vision_uses_injected_http_client():
    """ClaudeVisionProvider posts a valid image block; response is parsed."""

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"content": [{"type": "text", "text": "visible text here"}]}

    class FakeHttp:
        def __init__(self):
            self.last = None

        def post(self, url, json=None, headers=None):
            self.last = {"url": url, "json": json, "headers": headers}
            return FakeResponse()

    http = FakeHttp()
    provider = ClaudeVisionProvider(api_key="sk-test", model="claude-x", client=http)
    text = provider.extract_text(PNG, "image/png")
    assert text == "visible text here"
    sent = http.last["json"]["messages"][0]["content"][0]
    assert sent["type"] == "image"
    assert sent["source"]["type"] == "base64"
    assert sent["source"]["media_type"] == "image/png"
    assert http.last["headers"]["x-api-key"] == "sk-test"


# --- Stage 6 gate enforcement ----------------------------------------------


def test_vision_signals_feed_gate_and_verified_official_is_excluded(client):
    """An image whose OCR claims a verified official domain is excluded."""
    session = _session_from_client(client)
    _register_brand(session, "PayPal", [("domain", "paypal.com")], verify_first=True)

    vision = FakeVision(text="Go to https://paypal.com/login now")
    result = ImageAnalyzer(vision=vision).analyze(PNG)
    subset = AnalyzerEvidence.model_validate(result.model_dump())
    decision = ExclusionGate().evaluate(
        session, "https://paypal.com/login", kind="auto", analysis=subset
    )
    assert decision.outcome == "verified_official"
    assert decision.alert_eligible is False


def test_image_analysis_never_overrides_gate(client):
    session = _session_from_client(client)
    result = ImageAnalyzer(vision=FakeVision()).analyze(PNG)
    subset = AnalyzerEvidence.model_validate(result.model_dump())
    # analyzer status is 'completed' but the gate still decides independently
    assert result.status == "completed"
    decision = ExclusionGate().evaluate(
        session, "http://192.0.2.9/img", kind="auto", analysis=subset
    )
    assert decision.outcome in {"not_matched", "unverified", "verified_official"}


# --- helpers ---------------------------------------------------------------


def _session_from_client(client):
    from risk_radar.db.session import get_db

    return next(client.app.dependency_overrides[get_db]())


def _register_brand(session, name, assets, verify_first=False):
    from risk_radar.db.models import Brand, BrandAsset

    brand = Brand(name=name)
    session.add(brand)
    session.flush()
    for asset_type, value in assets:
        session.add(
            BrandAsset(brand_id=brand.id, asset_type=asset_type, value=value, verified=verify_first)
        )
    session.commit()
