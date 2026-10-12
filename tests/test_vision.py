"""Stage 5 vision-adapter tests (optional image analysis).

All vision responses are mocked; no network, credentials or external services
are required. Covers missing credentials, malformed/oversized images, valid
extraction, provider failures, source provenance and Stage 6 gate enforcement.
"""

from __future__ import annotations

import shutil
import struct
import zlib
from io import BytesIO

import pytest
from app.schemas.evidence import AnalyzerResult

from risk_radar.evidence import image_text
from risk_radar.evidence.image_text import ImageAnalyzer
from risk_radar.evidence.vision import (
    MAX_IMAGE_BYTES,
    ClaudeVisionProvider,
    VisionError,
    detect_media_type,
    get_tesseract_ocr,
    get_vision_provider,
    validate_image,
)
from risk_radar.gate.contracts import AnalyzerEvidence
from risk_radar.gate.service import ExclusionGate


def _chunk(kind: bytes, data: bytes) -> bytes:
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


PNG = (
    b"\x89PNG\r\n\x1a\n"
    + _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    + _chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
    + _chunk(b"IEND", b"")
)
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


def test_local_ocr_and_vision_outputs_are_both_provenanced(monkeypatch):
    monkeypatch.setattr(image_text, "validate_image", lambda _image: ("image/png", []))

    class Ocr:
        name = "test_tesseract"

        def extract_text(self, image: bytes) -> str:
            return "Contact @acme_support"

    result = ImageAnalyzer(ocr=Ocr(), vision=FakeVision("Logo resembles Acme")) .analyze(PNG)
    by_kind = {item["kind"]: item for item in result.observations}
    assert result.status == "completed"
    assert "@acme_support" in by_kind["ocr_text"]["value"]
    assert by_kind["ocr_text"]["method"] == "ocr:test_tesseract"
    assert by_kind["vision_model_observation"]["value"] == "Logo resembles Acme"
    assert by_kind["vision_model_observation"]["unverified"] is True
    assert any(
        item.evidence_type == "vision_model_observation"
        and item.provenance["provider"] == "fake_vision"
        for item in result.evidence
    )


def test_vision_empty_response_fails_without_erasing_ocr(monkeypatch):
    monkeypatch.setattr(image_text, "validate_image", lambda _image: ("image/png", []))

    class Ocr:
        name = "test_tesseract"

        def extract_text(self, image: bytes) -> str:
            return "real extracted text"

    class EmptyVision:
        name = "empty_vision"

        def extract_text(self, image: bytes, media_type: str) -> str:
            return " "

    result = ImageAnalyzer(ocr=Ocr(), vision=EmptyVision()).analyze(PNG)
    assert result.status == "partial"
    assert any(item["kind"] == "ocr_text" for item in result.observations)
    assert not any(item["kind"] == "vision_model_observation" for item in result.observations)
    assert any("no usable observations" in item for item in result.limitations)


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
    assert media_type == "image/png"
    if "PIL" not in __import__("sys").modules:
        try:
            import PIL  # noqa: F401
        except ImportError:
            assert any("decoder unavailable" in problem for problem in problems)
            return
    assert problems == []


# --- analyzer behaviour ----------------------------------------------------


def test_vision_output_is_distinct_and_unverified_not_mislabeled_as_ocr():
    pytest.importorskip("PIL.Image")
    result = ImageAnalyzer(vision=FakeVision()).analyze(PNG)
    assert isinstance(result, AnalyzerResult)
    assert result.status == "partial"  # local OCR is not configured in this test
    vision = [o for o in result.observations if o["kind"] == "vision_model_observation"]
    assert vision and "verify your account" in vision[0]["value"]
    assert vision[0]["unverified"] is True
    assert not any(o["kind"] == "ocr_text" for o in result.observations)


def test_ocr_text_is_normalized_into_url_and_handle_observations():
    pytest.importorskip("PIL.Image")

    class Ocr:
        def extract_text(self, image: bytes) -> str:
            return "Contact @acme_support at https://acme-login.example/verify urgently"

    result = ImageAnalyzer(ocr=Ocr()).analyze(PNG)
    observations = {item["kind"]: item["value"] for item in result.observations}
    assert observations["embedded_urls"] == ["https://acme-login.example/verify"]
    assert observations["embedded_handles"] == ["@acme_support"]
    assert any(item["kind"] == "urgency_language" for item in result.indicators)


def test_empty_ocr_is_explicitly_inconclusive():
    pytest.importorskip("PIL.Image")

    class EmptyOcr:
        def extract_text(self, image: bytes) -> str:
            return "  "

    result = ImageAnalyzer(ocr=EmptyOcr()).analyze(PNG)
    assert result.status == "completed"  # OCR ran; its empty transcript is inconclusive.
    assert not any(item["kind"] == "ocr_text" for item in result.observations)
    assert any("no text was extracted" in limitation for limitation in result.limitations)


def test_real_tesseract_ocr_on_generated_image_when_installed():
    pytest.importorskip("PIL.Image")
    if get_tesseract_ocr() is None or shutil.which("tesseract") is None:
        pytest.skip("Pillow, pytesseract and the Tesseract executable are not all installed")
    from PIL import Image, ImageDraw, ImageFont

    image = Image.new("RGB", (900, 240), "white")
    draw = ImageDraw.Draw(image)
    draw.text((30, 60), "VERIFY ACCOUNT", fill="black", font=ImageFont.load_default(size=64))
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    result = ImageAnalyzer(ocr=get_tesseract_ocr()).analyze(buffer.getvalue())
    extracted = next(item["value"] for item in result.observations if item["kind"] == "ocr_text")
    assert "VERIFY" in extracted.upper()


def test_missing_provider_reports_unavailable_not_safe():
    result = ImageAnalyzer().analyze(PNG)
    assert result.status == "unavailable"
    assert all(item["kind"] == "provider_status" for item in result.observations)
    assert result.limitations


def test_provider_error_is_unavailable_and_never_fabricates():
    pytest.importorskip("PIL.Image")
    result = ImageAnalyzer(vision=ErrorVision()).analyze(PNG)
    assert result.status == "unavailable"
    assert result.errors and result.errors[0]["stage"] == "vision"
    assert any("fabricated" in limitation for limitation in result.limitations)


def test_provider_crash_is_isolated():
    pytest.importorskip("PIL.Image")
    result = ImageAnalyzer(vision=CrashVision()).analyze(PNG)
    assert result.status == "unavailable"
    assert result.errors and result.errors[0]["message"] == "TimeoutError"


def test_ocr_evidence_survives_vision_provider_failure():
    pytest.importorskip("PIL.Image")

    class Ocr:
        name = "fixture_ocr"

        def extract_text(self, image: bytes) -> str:
            return "contact @acme_support"

    result = ImageAnalyzer(ocr=Ocr(), vision=ErrorVision()).analyze(PNG)
    assert result.status == "partial"
    assert any(item["kind"] == "ocr_text" for item in result.observations)
    assert any(item["kind"] == "embedded_handles" for item in result.observations)
    assert not any(item["kind"] == "vision_model_observation" for item in result.observations)
    assert any(error["stage"] == "vision" for error in result.errors)


def test_malformed_image_fails_before_provider_call():
    class Boom:
        name = "boom"

        def extract_text(self, image, media_type):
            raise AssertionError("provider must not be called for invalid image")

    result = ImageAnalyzer(vision=Boom()).analyze(b"junk")
    assert result.status == "failed"
    assert any(e["stage"] == "validate" for e in result.errors)


def test_corrupt_image_with_valid_signature_fails_content_decode():
    pytest.importorskip("PIL.Image")
    result = ImageAnalyzer(vision=FakeVision()).analyze(b"\x89PNG\r\n\x1a\ntruncated")
    assert result.status == "failed"
    assert any("corrupt" in item.lower() for item in result.limitations)


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
    pytest.importorskip("PIL.Image")
    result = ImageAnalyzer(vision=FakeVision()).analyze(PNG)
    vision_evidence = [
        e for e in result.evidence if e.evidence_type == "vision_model_observation"
    ]
    assert vision_evidence
    record = vision_evidence[0]
    assert record.source_reference.input_id == "target"
    assert record.provenance["method"] == "vision:fake_vision"
    assert record.provenance["media_type"] == "image/png"
    assert result.status == "partial"


def test_media_type_observation_present():
    pytest.importorskip("PIL.Image")
    result = ImageAnalyzer(vision=FakeVision()).analyze(PNG)
    media = [o for o in result.observations if o["kind"] == "media_type"]
    assert media and media[0]["value"] == "image/png"


# --- credentials / provider construction -----------------------------------


def test_get_vision_provider_none_without_key():
    class Settings:
        anthropic_api_key = None
        llm_model = "claude-x"
        vision_model = "claude-haiku-4-5-20251001"

    assert get_vision_provider(Settings()) is None


def test_get_vision_provider_builds_with_key():
    from pydantic import SecretStr

    class Settings:
        anthropic_api_key = SecretStr("sk-test")
        llm_model = "claude-3-5-haiku-latest"
        vision_model = "claude-haiku-4-5-20251001"

    provider = get_vision_provider(Settings())
    assert isinstance(provider, ClaudeVisionProvider)
    assert provider.name == "claude_vision"
    assert provider._model == "claude-haiku-4-5-20251001"


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
    prompt = http.last["json"]["messages"][0]["content"][1]["text"]
    assert "Do not claim" in prompt and "not OCR" in prompt
    assert http.last["headers"]["x-api-key"] == "sk-test"


# --- Stage 6 gate enforcement ----------------------------------------------


def test_vision_signals_feed_gate_and_verified_official_is_excluded(client):
    pytest.importorskip("PIL.Image")
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
    pytest.importorskip("PIL.Image")
    session = _session_from_client(client)
    result = ImageAnalyzer(vision=FakeVision()).analyze(PNG)
    subset = AnalyzerEvidence.model_validate(result.model_dump())
    # model observations are useful but remain partial and never authenticate identity.
    assert result.status == "partial"
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
