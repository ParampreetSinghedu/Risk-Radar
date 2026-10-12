"""Offline end-to-end checks across the investigation API stages."""

from __future__ import annotations

from risk_radar.api.v1 import evidence as evidence_api
from risk_radar.api.v1 import investigate as investigator_api
from risk_radar.api.v1 import monitoring as monitoring_api
from risk_radar.api.v1 import rag as rag_api
from risk_radar.evidence.resolvers import UnavailableDns, UnavailableRdap, UnavailableRedirect
from risk_radar.investigator.service import InvestigatorService
from risk_radar.monitoring.service import MonitorCheckResult, MonitoringService, MonitorSignal


def test_investigation_results_flow_into_analysis_and_persist_as_case_snapshot(client, monkeypatch):
    """Stage 5 evidence reaches downstream APIs and the submitted snapshot persists."""
    monkeypatch.setattr(
        evidence_api,
        "get_resolvers",
        lambda _settings: (UnavailableDns(), UnavailableRdap(), UnavailableRedirect()),
    )
    monkeypatch.setattr(rag_api, "get_provider", lambda _settings: None)
    client.app.dependency_overrides[investigator_api.get_investigator_service] = lambda: (
        InvestigatorService(provider=None, connectors=[])
    )

    target = "http://192.0.2.10/login"
    gate = client.post("/api/v1/gate/evaluate", json={"target": target})
    evidence = client.post("/api/v1/evidence/analyze", json={"target": target})
    assert gate.status_code == evidence.status_code == 200
    url_analysis = next(r for r in evidence.json()["results"] if r["analyzer_type"] == "url")
    assert url_analysis["status"] in {"partial", "completed"}

    downstream = {"target": target, "analysis": url_analysis}
    rules = client.post("/api/v1/rules/evaluate", json=downstream)
    risk = client.post("/api/v1/risk/score", json=downstream)
    assert rules.status_code == risk.status_code == 200
    assert any(f["rule_id"] == "ip_host" for f in rules.json()["findings"])
    assert risk.json()["detection_risk"]["rule_risk"] > 0

    submission = client.post(
        "/api/v1/submissions",
        json={"submission_type": "url", "content": target, "source": "integration-test"},
    )
    assert submission.status_code == 201
    rag = client.post("/api/v1/rag/analyze", json=downstream)
    investigation = client.post("/api/v1/investigate", json=downstream)
    assert rag.status_code == investigation.status_code == 200
    assert rag.json()["status"] == "provider_unavailable"
    assert rag.json()["retrieved_documents"]
    assert investigation.json()["status"] == "provider_unavailable"
    assert investigation.json()["evidence_hits"]

    snapshot = {
        "gate": {"status": "completed", "data": gate.json()},
        "evidence": {"status": "partial", "data": evidence.json()},
        "rules": {"status": "completed", "data": rules.json()},
        "risk": {"status": "completed", "data": risk.json()},
        "rag": {"status": "partial", "data": rag.json()},
        "investigate": {"status": "partial", "data": investigation.json()},
    }
    created = client.post(
        "/api/v1/cases",
        json={"title": "Pipeline integration", "target": target, "snapshot": snapshot},
    )
    assert created.status_code == 201
    report = client.get(f"/api/v1/cases/{created.json()['id']}/report")
    assert report.status_code == 200
    assert report.json()["snapshot"] == snapshot


def test_social_handle_evidence_uses_profile_analyzer_and_reaches_rules(client):
    """A submitted social handle avoids URL parsing and reaches identity rules."""
    brand = client.post("/api/v1/brands", json={"name": "Acme"}).json()
    asset = client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "account", "value": "@acme", "verified": True},
    )
    assert asset.status_code == 201

    target = "@acmee"
    evidence = client.post(
        "/api/v1/evidence/analyze",
        json={
            "target": target,
            "kind": "handle",
            "input_type": "social_profile",
            "analyzers": ["brand_profile"],
        },
    )
    assert evidence.status_code == 200
    analysis = evidence.json()["results"][0]
    assert analysis["analyzer_type"] == "brand_profile"
    assert any(i["kind"] == "heuristic_similarity" for i in analysis["indicators"])

    rules = client.post(
        "/api/v1/rules/evaluate",
        json={"target": target, "kind": "handle", "analysis": analysis},
    )
    assert rules.status_code == 200
    assert any(f["rule_id"] == "username_similarity" for f in rules.json()["findings"])


def test_app_listing_metadata_and_identity_findings_flow_to_case_snapshot(client):
    """Android metadata stays unavailable while app identity signals persist end to end."""
    brand = client.post("/api/v1/brands", json={"name": "PayPal"}).json()
    asset = client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "application", "value": "com.paypal.mobile", "verified": True},
    )
    assert asset.status_code == 201

    target = "https://play.google.com/store/apps/details?id=com.paypa1.mobile"
    evidence_response = client.post(
        "/api/v1/evidence/analyze",
        json={
            "target": target,
            "kind": "application",
            "input_type": "app_listing",
            "analyzers": ["application"],
        },
    )
    assert evidence_response.status_code == 200
    analysis = evidence_response.json()["results"][0]
    assert analysis["status"] == "partial"
    assert analysis["observations"][0]["source"] == "user_submission"
    assert any(
        "Google Play metadata retrieval is not configured" in item
        for item in analysis["limitations"]
    )

    gate = client.post(
        "/api/v1/gate/evaluate",
        json={"target": target, "kind": "application", "analysis": analysis},
    )
    rules = client.post(
        "/api/v1/rules/evaluate",
        json={"target": target, "kind": "application", "analysis": analysis},
    )
    risk = client.post(
        "/api/v1/risk/score",
        json={"target": target, "kind": "application", "analysis": analysis},
    )
    assert gate.status_code == rules.status_code == risk.status_code == 200
    assert gate.json()["outcome"] == "not_matched"
    finding = next(
        item for item in rules.json()["findings"] if item["rule_id"] == "application_similarity"
    )
    assert finding["confidence"] < 1
    assert risk.json()["status"] == "scored"

    snapshot = {
        "evidence": evidence_response.json(),
        "gate": gate.json(),
        "rules": rules.json(),
        "risk": risk.json(),
    }
    case = client.post(
        "/api/v1/cases",
        json={
            "title": "App identifier review",
            "target": target,
            "kind": "application",
            "snapshot": snapshot,
        },
    )
    assert case.status_code == 201
    report = client.get(f"/api/v1/cases/{case.json()['id']}/report")
    assert report.status_code == 200
    assert report.json()["snapshot"] == snapshot


def test_monitoring_alert_can_be_reviewed_and_retained_in_case_snapshot(client, monkeypatch):
    """A persisted monitoring change is reviewable and can be captured in a case."""

    class AuthorizedFixtureChecker:
        def check(self, target, db):
            return MonitorCheckResult(
                status="completed",
                providers={"authorized_fixture": {"status": "completed"}},
                complete_sources=["authorized_fixture"],
                observations=[
                    MonitorSignal(
                        source="authorized_fixture",
                        kind="discovered_profile",
                        key="fixture-profile-1",
                        payload={
                            "profile": "@acme_support",
                            "source_reference": "fixture://authorized-profile/1",
                        },
                    )
                ],
            )

    monkeypatch.setattr(
        monitoring_api,
        "MonitoringService",
        lambda: MonitoringService(checker=AuthorizedFixtureChecker()),
    )
    dashboard = client.get("/").text
    frontend_script = client.get("/app.js").text
    assert "Monitoring" in dashboard and "data-alert-case" in frontend_script
    target_response = client.post(
        "/api/v1/monitoring/targets",
        json={"target_type": "domain", "target": "acme.example"},
    )
    assert target_response.status_code == 201
    target = target_response.json()

    check_response = client.post(f"/api/v1/monitoring/targets/{target['id']}/check", json={})
    assert check_response.status_code == 200
    check = check_response.json()
    assert check["status"] == "completed"
    stored_check = client.get(
        f"/api/v1/monitoring/targets/{target['id']}/checks/{check['id']}"
    )
    assert stored_check.status_code == 200 and stored_check.json() == check
    assert client.get(
        f"/api/v1/monitoring/targets/{target['id'] + 1}/checks/{check['id']}"
    ).status_code == 404
    alerts_response = client.get("/api/v1/monitoring/alerts?acknowledged=false")
    assert alerts_response.status_code == 200
    alerts = alerts_response.json()
    assert len(alerts) == 1 and alerts[0]["change_type"] == "new"

    acknowledged = client.post(
        f"/api/v1/monitoring/alerts/{alerts[0]['id']}/acknowledge",
        json={"acknowledged_by": "integration analyst"},
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["acknowledged_at"]

    snapshot = {"monitoring_check": check, "monitoring_alerts": [acknowledged.json()]}
    case = client.post(
        "/api/v1/cases",
        json={"title": "Monitoring finding", "target": "acme.example", "snapshot": snapshot},
    )
    assert case.status_code == 201
    report = client.get(f"/api/v1/cases/{case.json()['id']}/report")
    assert report.status_code == 200
    assert report.json()["snapshot"] == snapshot
