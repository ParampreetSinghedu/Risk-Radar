"""Stage 5 — Multimodal Evidence Engine tests.

Covers each analyzer, the teammate's shared contract, missing dependencies,
partial results, malformed input, source references, confidence bounds and
Stage 6 integration. No network, OCR or external services are required.
"""

from __future__ import annotations

import base64
import struct
import zlib

import pytest
from app.schemas.evidence import AnalyzerResult

from risk_radar.evidence.brand_profile import BrandProfileAnalyzer
from risk_radar.evidence.image_text import ImageAnalyzer, TextAnalyzer
from risk_radar.evidence.resolvers import (
    DnsResolver,
    RdapClient,
    RedirectChecker,
)
from risk_radar.evidence.service import EvidenceEngine, EvidenceRequest
from risk_radar.evidence.url_domain import UrlDomainAnalyzer, registrable_domain
from risk_radar.gate.contracts import AnalyzerEvidence
from risk_radar.gate.service import ExclusionGate

# --- shared contract -------------------------------------------------------


def test_results_are_teammate_contract_type():
    """Every analyzer returns the teammate's AnalyzerResult v1.0 model."""
    result = UrlDomainAnalyzer().analyze("https://example.com")
    assert isinstance(result, AnalyzerResult)
    assert result.schema_version == "1.0"


def test_result_deserializes_into_stage6_gate_subset():
    """Stage 6 consumes her full payload unchanged via the shared contract."""
    result = UrlDomainAnalyzer().analyze("https://login.example.com")
    subset = AnalyzerEvidence.model_validate(result.model_dump())
    assert subset.analyzer_type == "url"
    assert subset.status in {"completed", "partial", "unavailable", "failed"}


# --- A: URL/domain analyzer ------------------------------------------------


def test_url_analyzer_reports_partial_with_explicit_limitations():
    """Default (unavailable) resolvers yield partial status + limitations."""
    result = UrlDomainAnalyzer().analyze("https://sub.example.com/a")
    assert result.status == "partial"
    assert any("DNS" in limitation for limitation in result.limitations)
    assert any(
        "RDAP" in limitation or "registration" in limitation for limitation in result.limitations
    )


def test_url_analyzer_structural_indicators():
    result = UrlDomainAnalyzer().analyze("http://xn--pypal-4ve.com:8080/x")
    kinds = {i["kind"] for i in result.indicators}
    assert "punycode_host" in kinds
    assert "plaintext_http" in kinds


def test_url_analyzer_emits_claimed_identity_for_gate():
    result = UrlDomainAnalyzer().analyze("https://a.example.com")
    observed = [o for o in result.observations if o.get("kind") == "domain"]
    assert observed and observed[0]["value"] == "a.example.com"
    assert observed[0]["confidence"] == 1.0


def test_url_analyzer_malformed_input_fails_without_inventing_data():
    result = UrlDomainAnalyzer().analyze("   ")
    assert result.status == "failed"
    assert result.errors and result.observations == []


def test_url_analyzer_confidence_bounds():
    result = UrlDomainAnalyzer().analyze("https://example.com")
    for indicator in result.indicators:
        conf = indicator.get("confidence")
        assert conf is None or 0.0 <= conf <= 1.0


def test_url_analyzer_uses_injected_resolvers_when_available():
    class FakeDns(DnsResolver):
        def resolve(self, host):
            return ["203.0.113.7"]

    class FakeRdap(RdapClient):
        def registration(self, domain):
            return {"created": "2024-01-01", "registrar": "ExampleReg"}

    class FakeRedirect(RedirectChecker):
        def final_url(self, url):
            return "https://final.example.com/landing"

    analyzer = UrlDomainAnalyzer(dns=FakeDns(), rdap=FakeRdap(), redirects=FakeRedirect())
    result = analyzer.analyze("https://example.com/start")
    assert result.status == "completed"
    kinds = {o["kind"] for o in result.observations}
    assert {"dns_addresses", "registration", "final_url"} <= kinds
    # registration evidence preserves a source reference
    reg_evidence = [e for e in result.evidence if e.evidence_type == "registration"]
    assert reg_evidence and reg_evidence[0].source_reference.input_id == "target"


def test_registrable_domain_heuristic():
    assert registrable_domain("a.b.example.com") == "example.com"
    assert registrable_domain("localhost") is None


# --- B: brand/profile analyzer --------------------------------------------


def test_brand_analyzer_unavailable_without_assets(client):
    """No registered brands => unavailable, never a statement of safety."""
    result = BrandProfileAnalyzer().analyze(_session_from_client(client), "@somehandle")
    assert result.status == "unavailable"
    assert any("NOT evidence of safety" in limitation for limitation in result.limitations)


def test_brand_analyzer_exact_and_heuristic_signals(client):
    session = _session_from_client(client)
    _register_brand(session, "PayPal", [("account", "@paypal"), ("domain", "paypal.com")])
    analyzer = BrandProfileAnalyzer()

    exact = analyzer.analyze(session, "@paypal", kind="handle")
    assert exact.status == "completed"
    assert any(i["kind"] == "exact_match" for i in exact.indicators)
    assert exact.analyzer_assessment.level == "informational"

    # heuristic: close-but-not-equal handle
    heur = analyzer.analyze(session, "@paypa1", kind="handle")
    hits = [i for i in heur.indicators if i["kind"] == "heuristic_similarity"]
    assert hits and hits[0]["confidence"] < 1.0  # capped below exact


def test_brand_analyzer_distinguishes_exact_from_heuristic(client):
    session = _session_from_client(client)
    _register_brand(session, "Acme", [("name", "Acme")])
    analyzer = BrandProfileAnalyzer()
    result = analyzer.analyze(session, "acme", kind="name")
    exact = [i for i in result.indicators if i["kind"] == "exact_match"]
    assert exact and exact[0]["confidence"] == 1.0


# --- C: image/text analyzer -----------------------------------------------


def test_text_analyzer_extracts_signals():
    result = TextAnalyzer().analyze(
        "Urgent! Verify your account at http://phish.example.com, contact @support"
    )
    kinds = {i["kind"] for i in result.indicators}
    assert "embedded_url" in kinds
    assert "urgency_language" in kinds
    assert result.status == "completed"


def test_text_analyzer_empty_fails():
    assert TextAnalyzer().analyze("").status == "failed"


def test_text_analyzer_benign_text_has_no_indicators_but_is_not_safe():
    result = TextAnalyzer().analyze("hello there")
    assert result.analyzer_assessment.level == "unknown"
    assert any("not a statement of safety" in lim for lim in result.limitations)


def test_image_analyzer_unavailable_without_backend():
    """Absent providers are explicit; no image content is fabricated."""
    result = ImageAnalyzer().analyze(_valid_png())
    assert result.status == "unavailable"
    statuses = [item for item in result.observations if item["kind"] == "provider_status"]
    assert {item["value"]["provider"] for item in statuses} == {"local_ocr", "vision"}
    assert any("fabricated" in lim for lim in result.limitations)


def test_image_analyzer_rejects_invalid_image_signature():
    result = ImageAnalyzer().analyze(b"not-an-image")
    assert result.status == "failed"
    assert any("unsupported" in limitation for limitation in result.limitations)


def test_image_analyzer_uses_injected_ocr():
    pytest.importorskip("PIL.Image")

    class FakeOcr:
        def extract_text(self, image):
            return "PAYPAL LOGIN"

    result = ImageAnalyzer(ocr=FakeOcr()).analyze(_valid_png())
    assert result.status == "partial"  # OCR succeeded; optional vision is not configured.
    assert any(o.get("kind") == "ocr_text" for o in result.observations)


def test_image_analyzer_missing_bytes_fails():
    assert ImageAnalyzer().analyze(None).status == "failed"


# --- engine / service ------------------------------------------------------


def test_engine_runs_selected_analyzers(client):
    session = _session_from_client(client)
    request = EvidenceRequest(target="https://x.example.com", analyzers=["url", "text"])
    result = EvidenceEngine().analyze(session, request)
    assert {r.analyzer_type for r in result.results} == {"url", "text"}
    assert len(result.summaries) == 2
    # every result still validates as her contract
    for r in result.results:
        assert isinstance(r, AnalyzerResult)


def test_engine_auto_classifies_plain_name_without_url_analysis(client):
    session = _session_from_client(client)
    result = EvidenceEngine().analyze(session, EvidenceRequest(target="iron man"))
    assert [item.analyzer_type for item in result.results] == ["brand_profile"]
    assert all(item.analyzer_type != "url" for item in result.results)


def test_engine_classifies_domains_urls_handles_and_application_ids(client):
    session = _session_from_client(client)
    engine = EvidenceEngine()
    cases = [
        ("https://example.com/path", "auto", {"url", "brand_profile"}),
        ("example.com", "auto", {"url", "brand_profile"}),
        ("@example", "auto", {"brand_profile"}),
        ("com.example.app", "auto", {"application"}),
    ]
    for target, kind, expected in cases:
        result = engine.analyze(session, EvidenceRequest(target=target, kind=kind))
        assert {item.analyzer_type for item in result.results} == expected


def test_engine_preserves_explicit_name_type_and_image_decoder(client):
    session = _session_from_client(client)
    result = EvidenceEngine().analyze(
        session,
        EvidenceRequest(target="iron man", kind="name", analyzers=["brand_profile"]),
    )
    assert [item.analyzer_type for item in result.results] == ["brand_profile"]
    good = base64.b64encode(b"png").decode()
    image = EvidenceEngine().analyze(
        session, EvidenceRequest(target="unused", analyzers=["image"], image_b64=good)
    )
    assert image.results[0].analyzer_type == "image"


def test_engine_malformed_url_like_name_does_not_crash_or_reach_url_analyzer(client):
    session = _session_from_client(client)
    result = EvidenceEngine().analyze(session, EvidenceRequest(target="http://[broken"))
    assert [item.analyzer_type for item in result.results] == ["brand_profile"]


def test_engine_isolates_analyzer_failure(client):
    session = _session_from_client(client)

    class Boom:
        analyzer_type = "url"

        def analyze(self, *a, **k):
            raise RuntimeError("boom")

    engine = EvidenceEngine(url=Boom())
    result = engine.analyze(
        session, EvidenceRequest(target="https://a.example.com", analyzers=["url"])
    )
    assert any(e["stage"] == "url" for e in result.errors)
    assert result.results == []  # failed analyzer yields nothing, not a crash


def test_engine_image_b64_decoding_and_bad_input(client):
    session = _session_from_client(client)
    good = base64.b64encode(b"png").decode()
    result = EvidenceEngine().analyze(
        session,
        EvidenceRequest(target="irrelevant", analyzers=["image"], image_b64=good),
    )
    assert result.results[0].analyzer_type == "image"

    bad = EvidenceEngine().analyze(
        session,
        EvidenceRequest(target="irrelevant", analyzers=["image"], image_b64="!!!notb64!!!"),
    )
    assert any(e["stage"] == "image" for e in bad.errors)


# --- Stage 6 integration ---------------------------------------------------


def test_stage6_gate_consumes_brand_analyzer_and_excludes_verified_official(client):
    """A verified official asset must be excluded when the analyzer feeds it."""
    session = _session_from_client(client)
    _register_brand(session, "PayPal", [("account", "@paypal")], verify_first=True)
    result = BrandProfileAnalyzer().analyze(session, "@paypal", kind="handle")
    subset = AnalyzerEvidence.model_validate(result.model_dump())
    decision = ExclusionGate().evaluate(session, "@paypal", kind="handle", analysis=subset)
    assert decision.outcome == "verified_official"
    assert decision.alert_eligible is False


def test_stage6_gate_routes_unverified_for_review(client):
    session = _session_from_client(client)
    _register_brand(session, "PayPal", [("account", "@paypal")], verify_first=False)
    result = BrandProfileAnalyzer().analyze(session, "@paypal", kind="handle")
    subset = AnalyzerEvidence.model_validate(result.model_dump())
    decision = ExclusionGate().evaluate(session, "@paypal", kind="handle", analysis=subset)
    assert decision.outcome == "unverified"
    assert decision.alert_eligible is False


# --- helpers ---------------------------------------------------------------


def _session_from_client(client):
    """Pull a DB session from the app's overridden dependency."""
    dependency = client.app.dependency_overrides
    from risk_radar.db.session import get_db

    gen = dependency[get_db]()
    return next(gen)


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


def _valid_png():
    def chunk(kind, payload):
        body = kind + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
        + chunk(b"IEND", b"")
    )
