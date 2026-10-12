"""Offline tests for application listing evidence and provider outcomes."""

from __future__ import annotations

import httpx

from risk_radar.evidence.application import AppleStoreLookup, ApplicationListingAnalyzer
from risk_radar.gate.contracts import AnalyzerEvidence
from risk_radar.rules.engine import RuleEngine


def _session(client):
    from risk_radar.db.session import get_db

    return next(client.app.dependency_overrides[get_db]())


def test_verified_apple_metadata_is_provenanced_and_benign(client):
    payload = {
        "resultCount": 1,
        "results": [
            {
                "trackId": 12345,
                "trackName": "Weather Notes",
                "sellerName": "Northwind Labs",
                "bundleId": "com.northwind.weather",
                "trackViewUrl": "https://apps.apple.com/app/id12345",
                "version": "1.2",
                "primaryGenreName": "Utilities",
            }
        ],
    }
    http = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    )
    result = ApplicationListingAnalyzer(AppleStoreLookup(http)).analyze(
        _session(client), "https://apps.apple.com/us/app/weather-notes/id12345"
    )
    assert result.status == "completed"
    metadata = next(
        item for item in result.observations if item["kind"] == "store_listing_metadata"
    )
    assert metadata["verified"] is True
    assert metadata["source"] == "apple_itunes_lookup_api"
    assert metadata["value"]["developer_name"] == "Northwind Labs"
    assert metadata["retrieved_at"]
    assert not result.indicators
    assert AnalyzerEvidence.model_validate(result.model_dump()).analyzer_type == "application"
    http.close()


def test_lookalike_package_is_only_a_heuristic_and_reaches_rules(client):
    from risk_radar.db.models import Brand, BrandAsset

    db = _session(client)
    brand = Brand(name="PayPal")
    db.add(brand)
    db.flush()
    db.add(
        BrandAsset(
            brand_id=brand.id, asset_type="application", value="com.paypal.mobile", verified=True
        )
    )
    db.commit()
    result = ApplicationListingAnalyzer().analyze(db, "com.paypa1.mobile")
    assert result.status == "partial"  # valid candidate, no Android listing provider
    assert any(item["kind"] == "heuristic_application_similarity" for item in result.indicators)
    assert all(item["confidence"] < 1 for item in result.indicators)
    evaluation = RuleEngine().evaluate(
        db,
        "com.paypa1.mobile",
        kind="application",
        analysis=AnalyzerEvidence.model_validate(result.model_dump()),
    )
    finding = next(item for item in evaluation.findings if item.rule_id == "application_similarity")
    assert finding.provenance["method"] == "difflib.SequenceMatcher.ratio"
    assert "review is required" in finding.reason


def test_incomplete_listing_does_not_invent_identity(client):
    result = ApplicationListingAnalyzer().analyze(_session(client), "not a store URL")
    assert result.status == "partial"
    assert result.observations == []
    assert result.evidence == []
    assert "identifier could not be extracted" in result.limitations[0]


def test_unavailable_google_play_metadata_is_explicit(client):
    result = ApplicationListingAnalyzer().analyze(
        _session(client), "https://play.google.com/store/apps/details?id=com.example.product"
    )
    assert result.status == "partial"
    assert any(
        item["source"] == "user_submission" and item["verified"] is False
        for item in result.observations
    )
    assert any(
        "Google Play metadata retrieval is not configured" in limitation
        for limitation in result.limitations
    )


def test_apple_provider_error_is_reported_without_negative_finding(client):
    def unavailable(request):
        raise httpx.ConnectError("offline", request=request)

    http = httpx.Client(transport=httpx.MockTransport(unavailable))
    result = ApplicationListingAnalyzer(AppleStoreLookup(http)).analyze(_session(client), "12345")
    assert result.status == "partial"
    assert not result.indicators
    assert any("source was unavailable" in limitation for limitation in result.limitations)
    http.close()


def test_apple_lookup_empty_and_malformed_results_are_unavailable():
    for payload in ({"resultCount": 0, "results": []}, {"results": "bad"}, []):
        http = httpx.Client(
            transport=httpx.MockTransport(
                lambda request, body=payload: httpx.Response(200, json=body)
            )
        )
        metadata, limitation = AppleStoreLookup(http).lookup("apple_app_store", "12345")
        assert metadata is None
        assert limitation
        http.close()


def test_malformed_apple_id_does_not_call_lookup(client):
    class Lookup:
        called = False

        def lookup(self, store, identifier):
            self.called = True
            return None, "unexpected lookup"

    lookup = Lookup()
    result = ApplicationListingAnalyzer(lookup).analyze(
        _session(client), "https://apps.apple.com/app/idnot-a-number"
    )
    assert result.status == "partial"
    assert not lookup.called
    assert not result.observations


def test_app_listing_endpoint_returns_application_analysis(client):
    response = client.post(
        "/api/v1/evidence/analyze",
        json={
            "target": "com.example.product",
            "kind": "application",
            "input_type": "app_listing",
            "analyzers": ["application"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["results"][0]["analyzer_type"] == "application"
    assert body["results"][0]["status"] == "partial"
    scoped = client.post(
        "/api/v1/evidence/analyze",
        json={
            "target": "com.example.product",
            "brand_id": 999,
            "analyzers": ["application"],
        },
    )
    assert scoped.status_code == 404
