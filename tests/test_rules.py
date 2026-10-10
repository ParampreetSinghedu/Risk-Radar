"""Tests for Stage 7 rule engine: exclusion safety and deterministic rules."""

from fastapi.testclient import TestClient

from risk_radar.gate.service import ExclusionGate


def _seed(client: TestClient) -> dict:
    """Create a brand with a verified domain and an unverified account."""
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


def _official_asset_id(client: TestClient, brand: dict, value: str) -> int:
    assets = client.get(f"/api/v1/brands/{brand['id']}/assets").json()
    return next(asset["id"] for asset in assets if asset["value"] == value)


def _evaluate(client: TestClient, **payload) -> dict:
    response = client.post("/api/v1/rules/evaluate", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_verified_official_never_reaches_rule_evaluation(client: TestClient) -> None:
    """Outcome 1 is blocked before any rule runs and stays audited."""
    _seed(client)

    result = _evaluate(client, target="http://acme.example/login")

    assert result["status"] == "excluded_verified_official"
    assert result["findings"] == []
    assert result["not_matched"] == [] and result["skipped"] == []
    assert result["gate_decision"]["outcome"] == "verified_official"
    assert result["gate_decision"]["alert_eligible"] is False
    assert client.get("/api/v1/gate/audit").json()[0]["decision"] == "verified_official"


def test_client_cannot_bypass_gate_with_alert_eligible_flag(client: TestClient) -> None:
    """Extra client-supplied gate fields are ignored; the server decides."""
    _seed(client)

    result = _evaluate(
        client,
        target="http://acme.example/",
        alert_eligible=True,
        outcome="not_matched",
    )

    assert result["status"] == "excluded_verified_official"
    assert result["findings"] == []


def test_unverified_identity_routed_away_from_detection(client: TestClient) -> None:
    """Outcome 2 stays in verification: no rule evaluation happens."""
    _seed(client)

    result = _evaluate(client, target="@acme")

    assert result["status"] == "routed_to_verification"
    assert result["findings"] == []
    assert result["gate_decision"]["next_stage"] == "verification"


def test_not_matched_candidate_is_evaluated_with_no_benign_hits(client: TestClient) -> None:
    """Outcome 3 is eligible; a benign target produces no findings."""
    _seed(client)

    result = _evaluate(client, target="http://example.org/path")

    assert result["status"] == "evaluated"
    assert result["findings"] == []
    assert result["gate_decision"]["next_stage"] == "detection"
    skipped_ids = {note["rule_id"] for note in result["skipped"]}
    assert "newly_registered_domain" in skipped_ids  # missing data, not a match
    assert "logo_publisher_mismatch" in skipped_ids


def test_lookalike_subdomain_finding_has_reason_and_evidence_refs(client: TestClient) -> None:
    """A subdomain of an official domain matches with traceable evidence."""
    brand = _seed(client)
    asset_id = _official_asset_id(client, brand, "acme.example")

    result = _evaluate(client, target="http://login.acme.example/")

    finding = next(f for f in result["findings"] if f["rule_id"] == "lookalike_domain")
    assert finding["matched"] is True
    assert finding["severity"] == "medium"
    assert "acme.example" in finding["reason"]
    assert finding["observed_value"] == "login.acme.example"
    assert "target" in finding["evidence_refs"]
    assert f"brand_asset:{asset_id}" in finding["evidence_refs"]


def test_lookalike_brand_token_finding(client: TestClient) -> None:
    """Official brand token embedded in another domain matches with a reason."""
    _seed(client)

    result = _evaluate(client, target="http://acme-login.evil.com/")

    finding = next(f for f in result["findings"] if f["rule_id"] == "lookalike_domain")
    assert finding["severity"] == "high"
    assert "acme" in finding["reason"]
    assert finding["expected_value"] is not None or finding["observed_value"]


def test_lookalike_similarity_threshold_finding(client: TestClient) -> None:
    """Near-identical official domains match with computed confidence."""
    _seed(client)

    result = _evaluate(client, target="http://acme.exampl/")

    finding = next(f for f in result["findings"] if f["rule_id"] == "lookalike_domain")
    assert finding["confidence"] is not None and finding["confidence"] >= 0.90
    assert finding["observed_value"] == "acme.exampl"
    assert finding["expected_value"] == "acme.example"
    assert "similarity" in finding["reason"]


def test_username_similarity_finding_with_stated_reason(client: TestClient) -> None:
    """Handle similarity matches only against registered official identities."""
    brand = _seed(client)
    client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "account", "value": "@acme_support", "verified": True},
    )

    result = _evaluate(client, target="@acme_support2")

    finding = next(f for f in result["findings"] if f["rule_id"] == "username_similarity")
    assert finding["confidence"] is not None and finding["confidence"] >= 0.85
    assert finding["expected_value"] == "@acme_support"
    assert "similarity" in finding["reason"]


def test_ip_host_and_structure_rules_match_with_reasons(client: TestClient) -> None:
    """Multiple simultaneous matches, each with its own stated reason."""
    _seed(client)

    result = _evaluate(client, target="http://user:pass@203.0.113.9:8081/")

    rule_ids = {finding["rule_id"] for finding in result["findings"]}
    assert {"ip_host", "suspicious_url_structure"} <= rule_ids
    for finding in result["findings"]:
        assert finding["reason"]
        assert finding["provenance"].get("method")
    structure = next(f for f in result["findings"] if f["rule_id"] == "suspicious_url_structure")
    assert "userinfo" in structure["reason"]
    assert "8081" in structure["reason"]


def test_newly_registered_rule_skipped_without_registration_data(client: TestClient) -> None:
    """Without WHOIS/RDAP data the rule skips; missing data never matches."""
    _seed(client)

    result = _evaluate(client, target="http://fresh.example/")

    note = next(n for n in result["skipped"] if n["rule_id"] == "newly_registered_domain")
    assert note["status"] == "skipped"
    assert "WHOIS/RDAP" in note["reason"]


def test_newly_registered_rule_uses_explicit_age_observation(client: TestClient) -> None:
    """Explicit registration data enables the threshold check."""
    _seed(client)
    analysis = {
        "analyzer_type": "url",
        "status": "completed",
        "source_reference": {"input_id": "s1", "kind": "submission"},
        "observations": [{"kind": "domain_age_days", "value": 30}],
    }

    result = _evaluate(client, target="http://fresh.example/", analysis=analysis)

    finding = next(f for f in result["findings"] if f["rule_id"] == "newly_registered_domain")
    assert "30" in finding["reason"]
    assert finding["expected_value"] == "<= 90 days"

    older = dict(analysis)
    older["observations"] = [{"kind": "domain_age_days", "value": 400}]
    result = _evaluate(client, target="http://fresh.example/", analysis=older)
    note = next(n for n in result["not_matched"] if n["rule_id"] == "newly_registered_domain")
    assert "exceeds" in note["reason"]


def test_logo_mismatch_needs_explicit_evidence(client: TestClient) -> None:
    """The logo rule skips without evidence and matches only when explicit."""
    _seed(client)

    result = _evaluate(client, target="http://fresh.example/")
    note = next(n for n in result["skipped"] if n["rule_id"] == "logo_publisher_mismatch")
    assert "logo" in note["reason"].lower()

    analysis = {
        "analyzer_type": "image",
        "status": "completed",
        "source_reference": {"input_id": "s2", "kind": "submission"},
        "observations": [
            {
                "kind": "logo_mismatch",
                "observed_publisher": "evil-corp.example",
                "expected_publisher": "Acme",
            }
        ],
    }
    result = _evaluate(client, target="http://fresh.example/", analysis=analysis)
    finding = next(f for f in result["findings"] if f["rule_id"] == "logo_publisher_mismatch")
    assert "evil-corp.example" in finding["reason"]
    assert finding["expected_value"] == "Acme"


def test_failed_analysis_never_treated_as_safe(client: TestClient) -> None:
    """A failed analyzer adds limitations but no safe verdict."""
    _seed(client)
    analysis = {
        "analyzer_type": "url",
        "status": "failed",
        "source_reference": {"input_id": "s3", "kind": "submission"},
        "observations": [{"kind": "domain_age_days", "value": 1}],
        "errors": [{"code": "timeout", "message": "rdap timed out"}],
    }

    result = _evaluate(client, target="http://fresh.example/", analysis=analysis)

    assert result["status"] == "evaluated"  # not excluded, not declared safe
    assert any("failed" in limitation for limitation in result["limitations"])
    note = next(n for n in result["skipped"] if n["rule_id"] == "newly_registered_domain")
    assert note["status"] == "skipped"  # unusable observations never match


def test_fails_closed_when_gate_decision_unavailable(client: TestClient, monkeypatch) -> None:
    """No gate decision means no rule evaluation, ever."""
    _seed(client)

    def _boom(self, *args, **kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(ExclusionGate, "evaluate", _boom)

    result = _evaluate(client, target="http://anything.example/")

    assert result["status"] == "failed_closed"
    assert result["findings"] == []
    assert result["gate_decision"] is None
    assert result["errors"]
    assert any("failed closed" in limitation for limitation in result["limitations"])


def test_invalid_requests_rejected(client: TestClient) -> None:
    """Blank targets and malformed analysis payloads return 422."""
    assert client.post("/api/v1/rules/evaluate", json={"target": ""}).status_code == 422
    bad = client.post(
        "/api/v1/rules/evaluate",
        json={"target": "http://x.example/", "analysis": {"analyzer_type": "url"}},
    )
    assert bad.status_code == 422


def test_results_are_deterministic(client: TestClient) -> None:
    """Identical inputs produce identical findings and rule notes."""
    _seed(client)

    first = _evaluate(client, target="http://login.acme.example/")
    second = _evaluate(client, target="http://login.acme.example/")

    assert first["status"] == second["status"]
    assert first["findings"] == second["findings"]
    assert first["not_matched"] == second["not_matched"]
    assert first["skipped"] == second["skipped"]


def test_every_finding_states_its_reason_and_provenance(client: TestClient) -> None:
    """Acceptance: every rule hit has a stated reason."""
    _seed(client)

    result = _evaluate(client, target="http://user@203.0.113.9:8081/x")

    assert result["findings"], "expected at least one matched rule"
    for finding in result["findings"]:
        assert finding["rule_id"]
        assert finding["title"]
        assert finding["reason"].strip()
        assert finding["matched"] is True
        assert finding["provenance"]
        if finding["confidence"] is not None:
            assert 0.0 <= finding["confidence"] <= 1.0
