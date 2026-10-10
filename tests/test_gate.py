"""Tests for Stage 6 official-asset exclusion gate."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from risk_radar.gate.contracts import (
    AnalyzerEvidence,
    SourceReference,
    claimed_identities,
)
from risk_radar.gate.service import extract_identity


def _seed(client: TestClient) -> dict:
    """Create a brand with one verified domain and one unverified account."""
    brand = client.post("/api/v1/brands", json={"name": "Acme"}).json()
    client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "domain", "value": "acme.example", "verified": True},
    )
    client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "account", "value": "@acme", "verified": False},
    )
    return brand


def _evaluate(client: TestClient, **payload) -> dict:
    response = client.post("/api/v1/gate/evaluate", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_verified_official_is_excluded_and_audited(client: TestClient) -> None:
    """Outcome 1: verified official assets are excluded and never alert-eligible."""
    brand = _seed(client)

    decision = _evaluate(client, target="http://ACME.example/login")

    assert decision["outcome"] == "verified_official"
    assert decision["next_stage"] is None
    assert decision["alert_eligible"] is False
    assert decision["matched_brand_id"] == brand["id"]
    assert decision["matched_asset_id"] is not None
    assert decision["audit_id"] is not None

    audit = client.get("/api/v1/gate/audit").json()
    entry = audit[0]
    assert entry["id"] == decision["audit_id"]
    assert entry["decision"] == "verified_official"
    assert entry["alert_eligible"] is False
    assert entry["brand_id"] == brand["id"]
    assert entry["input_reference"].startswith("http://ACME.example")


def test_unverified_identity_is_sent_for_review(client: TestClient) -> None:
    """Outcome 2: unverified matches are routed to verification, not detection."""
    _seed(client)

    decision = _evaluate(client, target="@acme")

    assert decision["outcome"] == "unverified"
    assert decision["next_stage"] == "verification"
    assert decision["alert_eligible"] is False
    assert decision["audit_id"] is not None


def test_not_matched_continues_to_detection(client: TestClient) -> None:
    """Outcome 3: no official match continues to detection and is audited."""
    _seed(client)

    decision = _evaluate(client, target="http://unknown.example/lure")

    assert decision["outcome"] == "not_matched"
    assert decision["next_stage"] == "detection"
    assert decision["alert_eligible"] is True
    assert decision["matched_brand_id"] is None
    assert decision["audit_id"] is not None


def test_every_decision_is_recorded_in_audit_log(client: TestClient) -> None:
    """All three outcomes append to the audit log."""
    _seed(client)
    _evaluate(client, target="http://acme.example/")
    _evaluate(client, target="@acme")
    _evaluate(client, target="http://other.example/")

    audit = client.get("/api/v1/gate/audit").json()

    assert len(audit) == 3
    assert {entry["decision"] for entry in audit} == {
        "verified_official",
        "unverified",
        "not_matched",
    }


def test_handle_variant_and_case_insensitive_matching(client: TestClient) -> None:
    """Handles match with or without the @ prefix; domains ignore case."""
    brand = client.post("/api/v1/brands", json={"name": "Globex"}).json()
    client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "account", "value": "globex_official", "verified": True},
    )

    decision = _evaluate(client, target="@GLOBEX_official")

    assert decision["outcome"] == "verified_official"
    assert decision["alert_eligible"] is False


def test_teammate_analyzer_contract_supplies_claimed_identity(client: TestClient) -> None:
    """Stage 5 evidence shaped like her AnalyzerResult v1.0 drives the gate."""
    brand = _seed(client)
    analysis = {
        "schema_version": "1.0",
        "investigation_id": "inv-1",  # her extra fields are accepted
        "analysis_id": "ana-1",
        "analyzer_type": "brand_profile",
        "input_type": "social_profile",
        "status": "completed",
        "source_reference": {"input_id": "sub-42", "kind": "submission"},
        "observations": [
            {"kind": "handle", "value": "@acme", "confidence": 0.92},
        ],
        "indicators": [],
        "entities": [],
        "evidence": [],
        "analyzer_assessment": {"level": "medium", "confidence": 0.8, "reason_codes": []},
        "limitations": [],
        "errors": [],
    }

    decision = _evaluate(client, target="http://neutral.example/", analysis=analysis)

    assert decision["outcome"] == "unverified"
    assert decision["next_stage"] == "verification"
    assert decision["alert_eligible"] is False

    audit = client.get("/api/v1/gate/audit").json()
    assert audit[0]["analyzer_input_id"] == "sub-42"
    assert audit[0]["brand_id"] == brand["id"]


def test_failed_analyzer_never_infers_safe(client: TestClient) -> None:
    """A failed analyzer yields a limitation, never a false verified outcome."""
    _seed(client)
    analysis = {
        "analyzer_type": "url",
        "status": "failed",
        "source_reference": {"input_id": "sub-9", "kind": "submission"},
        "observations": [{"kind": "domain", "value": "acme.example"}],
        "errors": [{"code": "timeout", "message": "lookup timed out"}],
    }

    decision = _evaluate(client, target="http://neutral.example/", analysis=analysis)

    assert decision["outcome"] == "not_matched"  # observations unusable
    assert any("failed" in limitation for limitation in decision["limitations"])
    assert decision["alert_eligible"] is True  # unknown ≠ safe, ≠ official


def test_unusable_observation_shapes_are_skipped_with_limitation() -> None:
    """Malformed observations become limitations, not crashes."""
    evidence = AnalyzerEvidence(
        analyzer_type="brand_profile",
        status="completed",
        source_reference=SourceReference(input_id="s1", kind="submission"),
        observations=[
            {"kind": "handle", "value": "@ok", "confidence": 1.7},
            {"kind": "emoji", "value": "?"},
        ],
    )

    identities, limitations = claimed_identities(evidence)

    assert [identity.value for identity in identities] == ["@ok"]
    assert identities[0].confidence == 1.0  # clamped into 0..1
    assert any("skipped" in limitation for limitation in limitations)

    # Observations violating the Stage 5 contract are rejected at the boundary.
    with pytest.raises(ValidationError):
        AnalyzerEvidence(
            analyzer_type="brand_profile",
            status="completed",
            source_reference=SourceReference(input_id="s2", kind="submission"),
            observations=["not-a-dict"],
        )


def test_invalid_gate_requests_are_rejected(client: TestClient) -> None:
    """Blank targets and malformed analysis payloads return 422."""
    assert client.post("/api/v1/gate/evaluate", json={"target": ""}).status_code == 422
    bad_analysis = client.post(
        "/api/v1/gate/evaluate",
        json={"target": "http://x.example/", "analysis": {"analyzer_type": "url"}},
    )
    assert bad_analysis.status_code == 422


def test_identity_extraction_heuristics() -> None:
    """Auto-detection classifies URLs, handles, bare domains and names."""
    assert extract_identity("http://Sub.Example.com/x") == ("domain", "sub.example.com")
    assert extract_identity("@SomeUser") == ("handle", "@someuser")
    assert extract_identity("example.com") == ("domain", "example.com")
    assert extract_identity("Acme Corp") == ("name", "acme corp")
    assert extract_identity("anything", "handle") == ("handle", "@anything")


def test_no_brands_configured_never_blocks_the_gate(client: TestClient) -> None:
    """With an empty brand registry the gate still decides and audits."""
    decision = _evaluate(client, target="http://any.example/")

    assert decision["outcome"] == "not_matched"
    assert decision["audit_id"] is not None
