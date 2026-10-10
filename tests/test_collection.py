"""Tests for Stage 4 collection layer: normalization, validation, dedup."""

import httpx
from fastapi.testclient import TestClient

from risk_radar.collection.service import (
    CollectionService,
    clean_url,
    normalize_target,
    validate_target,
)
from risk_radar.discovery.base import Candidate, CandidateType
from risk_radar.discovery.connectors.openphish import OpenPhishConnector
from risk_radar.discovery.service import DiscoveryFailure, DiscoveryResult

SERVICE = CollectionService()


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


def test_url_normalization_preserves_meaningful_information() -> None:
    """Host/scheme case, default ports and fragments normalize; the rest survives."""
    assert (
        clean_url("HTTP://Example.COM:80/path/Thing?x=1#frag")
        == "http://example.com/path/Thing?x=1"
    )
    assert clean_url("https://example.com:443/") == "https://example.com"
    assert clean_url("http://example.com:8080/a?b=c&d=e") == "http://example.com:8080/a?b=c&d=e"
    assert clean_url("https://user:Pass@example.com/Keep") == "https://user:Pass@example.com/Keep"
    assert clean_url("https://EXAMPLE.com/CaseSensitive") == "https://example.com/CaseSensitive"
    assert clean_url("not a url") == "not a url"


def test_target_validation_by_candidate_type() -> None:
    """Each candidate type enforces its own format rules."""
    assert validate_target(CandidateType.URL, "http://ok.example/") == []
    assert validate_target(CandidateType.URL, "nonsense") != []
    assert validate_target(CandidateType.URL, "ftp://example.com/") != []
    assert validate_target(CandidateType.SOCIAL_PROFILE, "@acme") == []
    assert validate_target(CandidateType.SOCIAL_PROFILE, "acme") != []
    assert validate_target(CandidateType.SOCIAL_PROFILE, "https://social.example/acme") == []
    assert validate_target(CandidateType.APP_LISTING, "Free Firewall - fake listing") == []
    assert validate_target(CandidateType.URL, "   ") != []


def test_normalize_target_equates_spellings() -> None:
    """Equivalent spellings map to one identifier while originals stay intact."""
    left = normalize_target(CandidateType.URL, "HTTP://Example.com/")
    right = normalize_target(CandidateType.URL, "http://example.com#section")
    assert left == right == "http://example.com"
    assert normalize_target(CandidateType.SOCIAL_PROFILE, "Acme") == "@acme"
    assert normalize_target(CandidateType.SOCIAL_PROFILE, "@acme") == "@acme"


def test_duplicate_candidates_from_different_sources_merge() -> None:
    """The same target from different sources becomes one consistent record."""
    result = SERVICE.collect(
        [
            _candidate("urlhaus", "http://Evil.example/path#top"),
            _candidate("openphish", "http://evil.example/path"),
        ]
    )

    assert len(result.records) == 1
    record = result.records[0]
    assert record.sources == ["urlhaus", "openphish"]
    assert record.source_references == [
        "https://urlhaus.example/ref",
        "https://openphish.example/ref",
    ]
    assert [entry.source for entry in record.provenance] == ["urlhaus", "openphish"]
    assert record.metadata == {"from": "urlhaus"}  # first source wins on conflicts
    assert record.validation_status == "valid"
    assert result.errors == []


def test_records_share_one_consistent_format() -> None:
    """Every record carries the identical field set regardless of source or type."""
    result = SERVICE.collect(
        [
            _candidate("urlhaus", "http://a.example/"),
            _candidate("social", "@acme", CandidateType.SOCIAL_PROFILE),
            _candidate("store", "com.fake.app", CandidateType.APP_LISTING),
        ]
    )

    keys = [set(record.model_dump()) for record in result.records]
    assert len(keys) == 3
    assert all(key_set == keys[0] for key_set in keys)
    # record ids are deterministic for identical input
    again = SERVICE.collect([_candidate("urlhaus", "http://a.example/")])
    assert again.records[0].record_id == result.records[0].record_id


def test_invalid_targets_are_marked_with_structured_validation_errors() -> None:
    """Format-invalid targets keep their evidence but are flagged, not dropped."""
    result = SERVICE.collect([_candidate("web", "definitely-not-a-url")])

    assert len(result.records) == 1
    record = result.records[0]
    assert record.validation_status == "invalid"
    assert record.validation_errors
    assert record.original_target == "definitely-not-a-url"


def test_malformed_candidates_become_structured_errors_without_crashing() -> None:
    """Invalid shapes are reported per index; valid input still collects."""
    result = SERVICE.collect(
        [
            42,
            {"target": "http://missing-fields.example/"},
            "not even a mapping",
            _candidate("good", "http://good.example/"),
        ]
    )

    assert len(result.records) == 1
    assert result.records[0].sources == ["good"]
    assert len(result.errors) == 3
    assert [error.index for error in result.errors] == [0, 1, 2]
    assert all(error.error_type == "malformed" for error in result.errors)
    assert all(error.reason for error in result.errors)


def test_empty_input_returns_empty_result() -> None:
    """An empty collection run succeeds with no records and no errors."""
    result = SERVICE.collect([])

    assert result.records == []
    assert result.errors == []


def test_collect_discovery_carries_connector_failures() -> None:
    """Discovery connector failures surface as structured collection errors."""
    discovery = DiscoveryResult(
        query="acme",
        candidates=[_candidate("openphish", "http://phish.example/acme")],
        failures=[DiscoveryFailure(source="urlhaus", reason="urlhaus: key missing")],
    )

    result = SERVICE.collect_discovery(discovery)

    assert len(result.records) == 1
    connector_errors = [error for error in result.errors if error.error_type == "connector_error"]
    assert len(connector_errors) == 1
    assert connector_errors[0].source == "urlhaus"
    assert connector_errors[0].reason == "urlhaus: key missing"


def test_connector_output_collects_end_to_end() -> None:
    """Real connector output flows through collection into one valid record."""
    feed = "http://phish.example/acme/login\nhttp://other.example/x\n"
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text=feed))
    )
    candidates = OpenPhishConnector(client=client).search("acme")

    result = SERVICE.collect(candidates)

    assert len(result.records) == 1
    assert result.records[0].sources == ["openphish"]
    assert result.records[0].validation_status == "valid"
    assert result.errors == []


def test_collect_endpoint_returns_records_and_errors(client: TestClient) -> None:
    """The endpoint exposes the collection result without external calls."""
    response = client.post(
        "/api/v1/collect",
        json={
            "candidates": [
                {
                    "source": "urlhaus",
                    "source_reference": "https://x.example/1",
                    "candidate_type": "url",
                    "target": "http://Evil.example/a#f",
                },
                {
                    "source": "web",
                    "source_reference": "https://x.example/2",
                    "candidate_type": "url",
                    "target": "http://evil.example/a",
                },
                {"source": "broken", "candidate_type": "url"},
            ]
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["records"]) == 1  # the two spellings deduplicated
    assert body["records"][0]["sources"] == ["urlhaus", "web"]
    assert len(body["errors"]) == 1
    assert body["errors"][0]["error_type"] == "malformed"
    assert body["errors"][0]["index"] == 2


def test_collect_endpoint_rejects_missing_or_empty_payload(client: TestClient) -> None:
    """Invalid requests are rejected before collection runs."""
    assert client.post("/api/v1/collect", json={}).status_code == 422
    assert client.post("/api/v1/collect", json={"candidates": []}).status_code == 422
