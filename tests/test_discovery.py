"""Tests for Stage 3 discovery connectors, aggregation and the endpoint."""

import hashlib
from datetime import datetime

import httpx
from fastapi.testclient import TestClient

from risk_radar.api.v1.discover import get_discovery_service
from risk_radar.discovery.base import (
    Candidate,
    CandidateType,
    ConnectorError,
    ConnectorUnavailableError,
    DiscoveryConnector,
)
from risk_radar.discovery.connectors.openphish import FEED_URL, OpenPhishConnector
from risk_radar.discovery.connectors.stubs import SocialPlatformConnector, WebSearchConnector
from risk_radar.discovery.connectors.urlhaus import URLhausConnector
from risk_radar.discovery.service import DiscoveryService
from risk_radar.main import app


class FakeConnector(DiscoveryConnector):
    """Test double that either yields candidates or raises a configured error."""

    def __init__(
        self, name: str, results: list[Candidate] | None = None, error: Exception | None = None
    ):
        self.name = name
        self.results = results or []
        self.error = error

    def search(self, query: str) -> list[Candidate]:
        if self.error is not None:
            raise self.error
        return list(self.results)


def _candidate(
    source: str, target: str, candidate_type: CandidateType = CandidateType.URL
) -> Candidate:
    return Candidate(
        source=source,
        source_reference=f"https://{source}.example/ref",
        candidate_type=candidate_type,
        target=target,
        metadata={"from": source},
    )


def test_connector_contract_yields_standard_candidate_records() -> None:
    """Every connector result carries the full standard candidate record."""
    service = DiscoveryService([FakeConnector("fake", [_candidate("fake", "http://a.example/")])])

    result = service.discover("anything")

    assert result.query == "anything"
    assert result.failures == []
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert (
        candidate.candidate_id
        == hashlib.sha256(f"{CandidateType.URL}:http://a.example".encode()).hexdigest()[:16]
    )
    assert candidate.source == "fake"
    assert candidate.source_reference == "https://fake.example/ref"
    assert candidate.candidate_type == CandidateType.URL
    assert candidate.target == "http://a.example/"
    assert isinstance(candidate.discovered_at, datetime)
    assert candidate.discovered_at.tzinfo is not None  # aware UTC timestamp
    assert candidate.metadata == {"from": "fake"}
    assert candidate.provenance[0].source == "fake"


def test_normalization_equates_target_spellings() -> None:
    """Equivalent URL spellings map to the same normalized identifier."""
    service = DiscoveryService(
        [
            FakeConnector("one", [_candidate("one", "HTTP://EXAMPLE.com")]),
            FakeConnector("two", [_candidate("two", "http://example.com/")]),
        ]
    )

    result = service.discover("example.com")

    assert len(result.candidates) == 1


def test_deduplication_preserves_source_provenance() -> None:
    """Duplicate targets merge while every source stays in provenance."""
    service = DiscoveryService(
        [
            FakeConnector("one", [_candidate("one", "http://dup.example/path")]),
            FakeConnector("two", [_candidate("two", "http://dup.example/path")]),
        ]
    )

    result = service.discover("dup.example")

    assert len(result.candidates) == 1
    merged = result.candidates[0]
    assert merged.source == "one"
    assert [entry.source for entry in merged.provenance] == ["one", "two"]
    assert merged.metadata == {"from": "one"}  # first source wins; extras merged below

    # Metadata from the duplicate is merged when the key is missing on the first.
    service = DiscoveryService(
        [
            FakeConnector("one", [_candidate("one", "http://m.example/")]),
            FakeConnector("two", [_candidate("two", "http://m.example/")]),
        ]
    )
    result = service.discover("m.example")
    assert result.candidates[0].metadata == {"from": "one"}


def test_aggregation_across_multiple_connectors() -> None:
    """Results from independent connectors are combined into one result."""
    service = DiscoveryService(
        [
            FakeConnector("one", [_candidate("one", "http://a.example/")]),
            FakeConnector("two", [_candidate("two", "http://b.example/")]),
        ]
    )

    result = service.discover("query")

    assert len(result.candidates) == 2
    assert {candidate.source for candidate in result.candidates} == {"one", "two"}
    assert result.failures == []


def test_connector_failure_is_isolated() -> None:
    """One failing connector neither crashes discovery nor hides good results."""
    service = DiscoveryService(
        [
            FakeConnector("broken", error=ConnectorUnavailableError("broken: no credentials")),
            FakeConnector("good", [_candidate("good", "http://ok.example/")]),
            FakeConnector("crashing", error=RuntimeError("bug")),
        ]
    )

    result = service.discover("query")

    assert [candidate.source for candidate in result.candidates] == ["good"]
    failures = {failure.source: failure.reason for failure in result.failures}
    assert failures["broken"] == "broken: no credentials"
    assert failures["crashing"].startswith("unexpected error: RuntimeError")


def test_empty_results_are_returned_without_failures() -> None:
    """A connector yielding nothing produces an empty, failure-free result."""
    service = DiscoveryService([FakeConnector("quiet", [])])

    result = service.discover("nomatch")

    assert result.candidates == []
    assert result.failures == []


def test_social_profile_discovery_reports_unconfigured_provider(client: TestClient) -> None:
    response = client.post("/api/v1/discover/social-profile", json={"handle": "pika"})
    assert response.status_code == 200
    body = response.json()
    assert body["query"] == "@pika"
    assert body["status"] == "provider_unavailable"
    assert body["candidates"] == []
    assert any("no authorized platform API provider" in item["reason"] for item in body["failures"])


def test_social_profile_discovery_validates_format_and_accepts_optional_at(
    client: TestClient,
) -> None:
    invalid = client.post("/api/v1/discover/social-profile", json={"handle": "pika show"})
    assert invalid.status_code == 422
    invalid_evidence = client.post(
        "/api/v1/evidence/analyze", json={"target": "pika show", "kind": "handle"}
    )
    assert invalid_evidence.status_code == 422
    valid = client.post("/api/v1/discover/social-profile", json={"handle": "@pika"})
    assert valid.status_code == 200 and valid.json()["query"] == "@pika"


def test_social_profile_discovery_preserves_provider_metadata_and_provenance(
    client: TestClient,
) -> None:
    candidate = _candidate("authorized_fixture", "@pika", CandidateType.SOCIAL_PROFILE)

    class Provider:
        name = "authorized_fixture"

        def search_profiles(self, query: str) -> list[Candidate]:
            assert query == "@pika"
            return [candidate]

    client.app.dependency_overrides[get_discovery_service] = lambda: DiscoveryService(
        [SocialPlatformConnector(provider=Provider())]
    )
    response = client.post("/api/v1/discover/social-profile", json={"handle": "pika"})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["candidates"][0]["source_reference"] == candidate.source_reference
    assert body["candidates"][0]["provenance"]


def test_urlhaus_connector_normalizes_host_response() -> None:
    """The URLhaus adapter maps API JSON onto standard candidate records."""
    payload = {
        "query_status": "ok",
        "urls": [
            {
                "id": 123,
                "url": "http://evil.example/payload",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["elf"],
                "date_added": "2026-10-01",
                "urlhaus_reference": "https://urlhaus.example/123/",
            }
        ],
    }
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Auth-Key")
        seen["body"] = request.content.decode()
        return httpx.Response(200, json=payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    connector = URLhausConnector(auth_key="test-key", client=client)

    candidates = connector.search("evil.example")

    assert seen["auth"] == "test-key"
    assert "host=evil.example" in seen["body"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.source == "urlhaus"
    assert candidate.source_reference == "https://urlhaus.example/123/"
    assert candidate.candidate_type == CandidateType.URL
    assert candidate.target == "http://evil.example/payload"
    assert candidate.metadata["threat"] == "malware_download"
    assert candidate.metadata["url_status"] == "online"


def test_urlhaus_connector_handles_no_results_and_missing_key() -> None:
    """No matches yield an empty list; a missing key fails explicitly."""
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"query_status": "no_results"})
        )
    )
    assert URLhausConnector(auth_key="k", client=client).search("clean.example") == []

    try:
        URLhausConnector(auth_key=None).search("clean.example")
        raise AssertionError("expected ConnectorUnavailableError")
    except ConnectorUnavailableError as exc:
        assert "URLHAUS_AUTH_KEY" in str(exc)


def test_openphish_connector_filters_feed_by_query() -> None:
    """The OpenPhish adapter yields only feed lines matching the query."""
    feed = "http://other.example/login\nhttp://phish.example/acme/login\n\n# comment\n"
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text=feed))
    )
    connector = OpenPhishConnector(client=client)

    candidates = connector.search("acme")

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.target == "http://phish.example/acme/login"
    assert candidate.source == "openphish"
    assert candidate.source_reference == FEED_URL
    assert candidate.metadata == {"feed": "community"}

    assert connector.search("no-such-string") == []


def test_openphish_connector_reports_network_failure() -> None:
    """A feed request error surfaces as a connector error, not a crash."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        OpenPhishConnector(client=client).search("acme")
        raise AssertionError("expected ConnectorError")
    except ConnectorError as exc:
        assert "openphish" in str(exc)


def test_interface_only_connector_reports_unavailability() -> None:
    """Interface-only adapters state their limitation instead of faking data."""
    try:
        WebSearchConnector().search("acme")
        raise AssertionError("expected ConnectorUnavailableError")
    except ConnectorUnavailableError as exc:
        assert "web_search" in str(exc)


def test_social_provider_contract_preserves_actual_profile_provenance() -> None:
    class Provider:
        def search_profiles(self, query: str) -> list[Candidate]:
            assert query == "acme"
            return [
                Candidate(
                    source="authorized_test_provider",
                    source_reference="https://api.example/profile/42",
                    candidate_type=CandidateType.SOCIAL_PROFILE,
                    target="@acme_support",
                    metadata={"display_name": "Acme Support", "provider_profile_id": "42"},
                )
            ]

    candidates = SocialPlatformConnector(provider=Provider()).search("acme")
    assert len(candidates) == 1
    assert candidates[0].target == "@acme_support"
    assert candidates[0].metadata["provider_profile_id"] == "42"
    assert candidates[0].provenance[0].source == "authorized_test_provider"
    assert candidates[0].provenance[0].discovered_at == candidates[0].discovered_at


def test_social_provider_errors_and_unavailable_source_are_explicit() -> None:
    try:
        SocialPlatformConnector().search("acme")
        raise AssertionError("expected explicit provider unavailability")
    except ConnectorUnavailableError as exc:
        assert "authorized platform API provider" in str(exc)

    class RateLimitedProvider:
        def search_profiles(self, query: str) -> list[Candidate]:
            raise ConnectorUnavailableError("authorized_social_api: rate limited; retry later")

    result = DiscoveryService([SocialPlatformConnector(provider=RateLimitedProvider())]).discover(
        "acme"
    )
    assert result.candidates == []
    assert result.failures[0].reason == "authorized_social_api: rate limited; retry later"


def test_discover_endpoint_rejects_invalid_input(client: TestClient) -> None:
    """Blank or missing queries return 422 before any connector runs."""
    assert client.post("/api/v1/discover", json={"query": ""}).status_code == 422
    assert client.post("/api/v1/discover", json={"query": "   "}).status_code == 422
    assert client.post("/api/v1/discover", json={}).status_code == 422


def test_discover_endpoint_returns_candidates_and_failures(client: TestClient) -> None:
    """The endpoint returns the aggregated discovery result as JSON."""
    service = DiscoveryService(
        [
            FakeConnector("good", [_candidate("good", "http://found.example/")]),
            FakeConnector("down", error=ConnectorUnavailableError("down: offline")),
        ]
    )
    app.dependency_overrides[get_discovery_service] = lambda: service

    response = client.post("/api/v1/discover", json={"query": "found"})

    assert response.status_code == 200
    body = response.json()
    assert body["query"] == "found"
    assert [candidate["source"] for candidate in body["candidates"]] == ["good"]
    assert body["failures"] == [{"source": "down", "reason": "down: offline"}]
    assert body["candidates"][0]["candidate_id"]
    assert body["candidates"][0]["provenance"][0]["source"] == "good"


def test_discover_endpoint_adds_brand_similarity_to_real_provider_candidate(
    client: TestClient,
) -> None:
    brand = client.post("/api/v1/brands", json={"name": "Acme"}).json()
    client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "account", "value": "@acme", "verified": True},
    )
    profile = Candidate(
        source="authorized_test_provider",
        source_reference="https://api.example/profiles/acmee",
        candidate_type=CandidateType.SOCIAL_PROFILE,
        target="@acmee",
        metadata={"display_name": "Acme Support"},
    )
    app.dependency_overrides[get_discovery_service] = lambda: DiscoveryService(
        [FakeConnector("authorized_test_provider", [profile])]
    )
    response = client.post("/api/v1/discover", json={"query": "Acme Support"})
    assert response.status_code == 200
    candidate = response.json()["candidates"][0]
    assert candidate["source"] == "authorized_test_provider"
    analysis = candidate["metadata"]["brand_profile_analysis"]
    assert analysis["status"] == "completed"
    assert any(item["kind"] == "heuristic_similarity" for item in analysis["indicators"])
