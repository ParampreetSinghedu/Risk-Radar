"""Stage 11 — Risk × Impact engine tests.

Covers formula correctness, determinism, missing business-impact data, gate
enforcement (verified-official exclusion, unverified routing, fail-closed) and
regression into Stages 5-10. No network or external services are required.
"""

from __future__ import annotations

from risk_radar.gate.service import ExclusionGate
from risk_radar.risk.service import RiskImpactEngine, RiskImpactRequest
from risk_radar.rules.engine import RuleEvaluation


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


def _session_from_client(client):
    from risk_radar.db.session import get_db

    return next(client.app.dependency_overrides[get_db]())


# --- formula correctness ---------------------------------------------------


def test_score_is_deterministic(client):
    session = _session_from_client(client)
    engine = RiskImpactEngine()
    request = RiskImpactRequest(target="https://riskylane-bank.com/login")
    first = engine.score(session, request)
    second = engine.score(session, request)
    assert first.overall_score == second.overall_score
    assert first.detection_risk.score == second.detection_risk.score


def test_detection_risk_uses_rules_and_reports_formula(client):
    session = _session_from_client(client)
    result = RiskImpactEngine().score(session, RiskImpactRequest(target="http://192.0.2.10/phish"))
    assert result.status == "scored"
    detection = result.detection_risk
    # IP host + plaintext HTTP rules should have matched.
    assert detection.rule_risk and detection.rule_risk > 0
    assert "0.60" in detection.formula and "0.40" in detection.formula
    # contributing signals carry evidence references
    assert detection.signals
    assert all(signal.evidence_refs for signal in detection.signals)


def test_overall_score_is_bounded(client):
    session = _session_from_client(client)
    result = RiskImpactEngine().score(session, RiskImpactRequest(target="http://192.0.2.10/phish"))
    assert 0.0 <= result.overall_score <= 1.0
    assert 0.0 <= result.detection_risk.score <= 1.0


def test_ml_risk_omitted_when_no_model(client):
    session = _session_from_client(client)
    result = RiskImpactEngine().score(
        session, RiskImpactRequest(target="http://192.0.2.10/phish"), ml_service=None
    )
    detection = result.detection_risk
    assert detection.ml_risk is None
    assert detection.weights == {"rule": 1.0}
    assert detection.score == detection.rule_risk


# --- missing business-impact data -----------------------------------------


def test_business_impact_unavailable_is_explicit_and_neutral(client):
    """No brand assets, no reports, no campaign => impact None, neutral 1.0."""
    session = _session_from_client(client)
    result = RiskImpactEngine().score(
        session, RiskImpactRequest(target="https://no-signal-here.example.net")
    )
    impact = result.business_impact
    assert impact.status == "unavailable"
    assert impact.score is None
    # genuinely missing impact data is named, not invented
    assert any("reach" in item for item in impact.missing_data)
    # neutral multiplier: overall == detection risk
    assert result.overall_score == result.detection_risk.score


def test_business_impact_available_from_verified_assets_and_reports(client):
    session = _session_from_client(client)
    _register_brand(session, "Acme", [("domain", "acme.com")], verify_first=True)
    from risk_radar.db.models import Submission

    session.add(
        Submission(
            submission_type="url",
            source="test",
            content="https://acme-secure.example.com",
            content_hash="h1",
        )
    )
    session.commit()
    result = RiskImpactEngine().score(
        session, RiskImpactRequest(target="https://acme-secure.example.com")
    )
    impact = result.business_impact
    assert impact.status == "available"
    assert impact.score is not None and 0.0 < impact.score <= 1.0
    names = {signal.name for signal in impact.signals}
    assert {"verified_brand_assets", "stored_reports"} <= names
    # overall = detection * impact multiplier, so it must differ from raw detection
    assert result.overall_score != result.detection_risk.score


def test_campaign_context_adjusts_impact_only_not_detection(client):
    session = _session_from_client(client)
    base = RiskImpactEngine().score(session, RiskImpactRequest(target="http://192.0.2.10/phish"))
    boosted = RiskImpactEngine().score(
        session,
        RiskImpactRequest(
            target="http://192.0.2.10/phish",
            campaign_context_size=3,
            campaign_evidence_refs=["campaign:abc123"],
        ),
    )
    # detection unchanged (correlation never sets maliciousness)
    assert base.detection_risk.score == boosted.detection_risk.score
    # impact present and overall differs via multiplier
    assert boosted.business_impact.status == "available"
    assert any(s.name == "campaign_context" for s in boosted.business_impact.signals)
    assert any("maliciousness" in lim for lim in boosted.limitations)


# --- gate enforcement ------------------------------------------------------


def test_verified_official_never_gets_alert_eligible_score(client):
    session = _session_from_client(client)
    _register_brand(session, "PayPal", [("domain", "paypal.com")], verify_first=True)
    result = RiskImpactEngine().score(
        session, RiskImpactRequest(target="https://paypal.com/login", kind="auto")
    )
    assert result.status == "excluded_verified_official"
    assert result.overall_score is None
    assert result.alert_eligible is False
    assert result.detection_risk is None


def test_unverified_routed_to_verification(client):
    session = _session_from_client(client)
    _register_brand(session, "PayPal", [("domain", "paypal.com")], verify_first=False)
    result = RiskImpactEngine().score(
        session, RiskImpactRequest(target="https://paypal.com/login", kind="auto")
    )
    assert result.status == "routed_to_verification"
    assert result.overall_score is None
    assert result.alert_eligible is False


def test_gate_failure_fails_closed(client, monkeypatch):
    session = _session_from_client(client)

    def boom(*a, **k):
        raise RuntimeError("gate down")

    monkeypatch.setattr(ExclusionGate, "evaluate", boom)
    result = RiskImpactEngine().score(
        session, RiskImpactRequest(target="https://anything.example.com")
    )
    assert result.status == "failed_closed"
    assert result.overall_score is None
    assert result.alert_eligible is False
    assert result.errors


def test_scored_candidate_is_alert_eligible(client):
    session = _session_from_client(client)
    result = RiskImpactEngine().score(session, RiskImpactRequest(target="http://192.0.2.10/phish"))
    assert result.status == "scored"
    assert result.alert_eligible is True


# --- score semantics and provenance ---------------------------------------


def test_score_is_labelled_as_ranking_not_probability(client):
    session = _session_from_client(client)
    result = RiskImpactEngine().score(session, RiskImpactRequest(target="http://192.0.2.10/phish"))
    assert "NOT a calibrated probability" in result.score_semantics


def test_no_rule_match_yields_zero_rule_risk_not_safe(client):
    session = _session_from_client(client)
    result = RiskImpactEngine().score(
        session, RiskImpactRequest(target="https://totally-benign.example.org")
    )
    assert result.status == "scored"
    assert result.detection_risk.rule_risk == 0.0
    assert any("not 'safe'" in lim for lim in result.detection_risk.limitations)


# --- API surface -----------------------------------------------------------


def test_api_endpoint_returns_score(client):
    response = client.post("/api/v1/risk/score", json={"target": "http://192.0.2.10/phish"})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "scored"
    assert body["overall_score"] is not None
    assert body["schema_version"] == "1.0"


def test_api_rejects_missing_target(client):
    response = client.post("/api/v1/risk/score", json={})
    assert response.status_code == 422


def test_api_verified_official_excluded(client):
    session = _session_from_client(client)
    _register_brand(session, "BigBank", [("domain", "bigbank.com")], verify_first=True)
    response = client.post(
        "/api/v1/risk/score",
        json={"target": "https://bigbank.com", "kind": "auto"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "excluded_verified_official"
    assert body["alert_eligible"] is False
    assert body["overall_score"] is None


# --- regression into earlier stages ---------------------------------------


def test_engine_reuses_rule_evaluation_shape(client):
    """Stage 11 consumes Stage 7's RuleEvaluation contract unchanged."""
    session = _session_from_client(client)
    from risk_radar.rules.engine import RuleEngine

    evaluation = RuleEngine().evaluate(db=session, target="http://192.0.2.10/phish")
    assert isinstance(evaluation, RuleEvaluation)
    assert evaluation.status == "evaluated"


# --- Phase 4: Missing data, confidence handling, partial analyzer failures ---


def test_risk_scoring_with_no_analyzers_reports_evidence_limitations(client):
    """When no analyzers are supplied, risk score is computed but limitations reflect it."""
    session = _session_from_client(client)
    engine = RiskImpactEngine()
    request = RiskImpactRequest(target="https://unknown-example.org/portal")
    score = engine.score(session, request)

    assert score.status == "scored"
    assert "analyzers_run=0" in score.input_quality
    assert any("no analyzer evidence supplied" in lim for lim in score.limitations)
    # Target has no matched rules and no impact data -> detection risk 0.0, multiplier 1.0
    assert score.detection_risk.score == 0.0
    assert score.overall_score == 0.0


def test_risk_scoring_with_partial_analyzer_failures(client):
    """When an analyzer reports partial failure/limitations, they propagate to score limitations."""
    from risk_radar.gate.contracts import AnalyzerEvidence, SourceReference

    session = _session_from_client(client)
    engine = RiskImpactEngine()
    evidence = AnalyzerEvidence(
        analyzer_type="url",
        status="partial",
        source_reference=SourceReference(
            input_id="sub:1", kind="url", locator="https://partial-example.org"
        ),
        limitations=["RDAP lookup timed out: domain age unknown"],
        errors=[{"stage": "rdap", "message": "timeout"}],
    )
    request = RiskImpactRequest(target="https://partial-example.org", analysis=evidence)
    score = engine.score(session, request)

    assert score.status == "scored"
    assert "analyzer=url" in score.input_quality
    assert "analyzer_status=partial" in score.input_quality
    assert any("RDAP" in lim for lim in score.limitations)


def test_missing_ml_service_does_not_invent_model_confidence(client):
    """When ML service is omitted, weight is transferred to rules; no score is fabricated."""
    session = _session_from_client(client)
    engine = RiskImpactEngine(ml_service=None)
    score = engine.score(session, RiskImpactRequest(target="http://192.0.2.10/test"))

    assert score.detection_risk.ml_risk is None
    assert score.detection_risk.weights == {"rule": 1.0}
    assert any("no ML service supplied" in lim for lim in score.detection_risk.limitations)
