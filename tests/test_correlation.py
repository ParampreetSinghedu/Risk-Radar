"""Tests for Stage 10 evidence correlation: signals, campaigns, timeline, gate."""

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from risk_radar.gate.service import ExclusionGate

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _correlate(client: TestClient, candidates: list[dict]) -> dict:
    response = client.post("/api/v1/correlate", json={"candidates": candidates})
    assert response.status_code == 200, response.text
    return response.json()


def test_shared_domain_correlation(client: TestClient) -> None:
    """Same host yields an explained, strength-scored link and one campaign."""
    body = _correlate(
        client,
        [
            {
                "candidate_ref": "a",
                "target": "http://evil.example/path1",
                "observed_at": NOW.isoformat(),
            },
            {
                "candidate_ref": "b",
                "target": "http://evil.example/path2",
                "observed_at": NOW.isoformat(),
            },
        ],
    )

    assert body["status"] == "completed"
    link = body["links"][0]
    assert link["signal"] == "shared_domain"
    assert link["strength"] == 0.9
    assert "evil.example" in link["reason"]
    assert "candidate:a" in link["evidence_refs"]
    assert len(body["campaigns"]) == 1
    assert body["campaigns"][0]["candidate_refs"] == ["a", "b"]
    assert body["campaigns"][0]["direct_links"][0]["signal"] == "shared_domain"
    assert all(view["alert_eligible"] for view in body["candidates"])


def test_registrable_domain_variant_correlates_with_lower_strength(client: TestClient) -> None:
    """Subdomains of one registrable domain link at the documented 0.7."""
    body = _correlate(
        client,
        [
            {"candidate_ref": "a", "target": "http://login.evil.example/x"},
            {"candidate_ref": "b", "target": "http://evil.example/"},
        ],
    )

    link = body["links"][0]
    assert link["signal"] == "shared_domain"
    assert link["strength"] == 0.7
    assert "registrable domain" in link["reason"]


def test_no_shared_evidence_produces_no_links(client: TestClient) -> None:
    """Unrelated candidates never form relationships or campaigns."""
    body = _correlate(
        client,
        [
            {"candidate_ref": "a", "target": "http://one.example/"},
            {"candidate_ref": "b", "target": "http://two-other.example/"},
        ],
    )

    assert body["links"] == []
    assert body["campaigns"] == []
    assert {view["candidate_ref"] for view in body["candidates"]} == {"a", "b"}


def test_duplicate_evidence_and_deterministic_campaign_id(client: TestClient) -> None:
    """Identical targets link at strength 1.0; campaign ids are deterministic."""
    payload = [
        {"candidate_ref": "a", "target": "http://dup.example/", "observed_at": NOW.isoformat()},
        {"candidate_ref": "b", "target": "http://dup.example/", "observed_at": NOW.isoformat()},
    ]
    first = _correlate(client, payload)
    second = _correlate(client, payload)

    link = first["links"][0]
    assert link["signal"] == "duplicate_content"
    assert link["strength"] == 1.0
    assert first["campaigns"][0]["campaign_id"] == second["campaigns"][0]["campaign_id"]
    assert first["links"] == second["links"]


def test_shared_brand_via_stored_submissions(client: TestClient) -> None:
    """Submissions for the same Stage 1 brand correlate with evidence refs."""
    brand = client.post("/api/v1/brands", json={"name": "Acme"}).json()
    client.post(
        "/api/v1/submissions",
        json={"submission_type": "url", "content": "http://a.example/x", "brand_id": brand["id"]},
    )
    client.post(
        "/api/v1/submissions",
        json={"submission_type": "url", "content": "http://b.example/y", "brand_id": brand["id"]},
    )

    body = _correlate(
        client,
        [
            {"candidate_ref": "a", "target": "http://a.example/x"},
            {"candidate_ref": "b", "target": "http://b.example/y"},
        ],
    )

    link = next(link for link in body["links"] if link["signal"] == "shared_brand")
    assert link["strength"] == 0.8
    assert f"brand:{brand['id']}" in link["evidence_refs"]
    assert any(ref.startswith("submission:") for ref in link["evidence_refs"])


def test_shared_brand_token_correlation(client: TestClient) -> None:
    """A registered brand name in both targets links as a shared theme."""
    client.post("/api/v1/brands", json={"name": "Acme"})

    body = _correlate(
        client,
        [
            {"candidate_ref": "a", "target": "http://acme-rebates.example/"},
            {"candidate_ref": "b", "target": "http://acme-prizes.example/"},
        ],
    )

    link = next(link for link in body["links"] if link["signal"] == "shared_brand_token")
    assert link["strength"] == 0.6
    assert "acme" in link["reason"]
    assert any(ref.startswith("brand:") for ref in link["evidence_refs"])


def test_direct_versus_indirect_connections(client: TestClient) -> None:
    """A-B and B-C link directly; A-C is marked indirect, not evidence."""
    client.post("/api/v1/brands", json={"name": "Acme"})
    body = _correlate(
        client,
        [
            {"candidate_ref": "a", "target": "http://evil.example/1"},
            {"candidate_ref": "b", "target": "http://acme.evil.example/2"},
            {"candidate_ref": "c", "target": "http://acme-themes.example/"},
        ],
    )

    # b and c share the acme token; a and b share the host
    campaign = body["campaigns"][0]
    assert campaign["candidate_refs"] == ["a", "b", "c"]
    assert len(campaign["direct_links"]) == 2
    assert ["a", "c"] in campaign["indirect_pairs"] or ["c", "a"] in campaign["indirect_pairs"]


def test_timeline_is_chronological_and_reports_missing_timestamps(client: TestClient) -> None:
    """Events sort by real timestamps; missing ones are counted, never faked."""
    later = (NOW + timedelta(hours=2)).isoformat()
    body = _correlate(
        client,
        [
            {"candidate_ref": "a", "target": "http://x.example/", "observed_at": later},
            {"candidate_ref": "b", "target": "http://x.example/o", "observed_at": NOW.isoformat()},
            {"candidate_ref": "c", "target": "http://y.example/"},
        ],
    )

    times = [event["occurred_at"] for event in body["timeline"]]
    assert times == sorted(times)
    assert any("omitted" in limitation for limitation in body["limitations"])


def test_verified_official_excluded_from_correlation(client: TestClient) -> None:
    """Stage 6 verified official assets never join campaigns or alert."""
    brand = client.post("/api/v1/brands", json={"name": "Acme"}).json()
    client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "domain", "value": "acme.example", "verified": True},
    )

    body = _correlate(
        client,
        [
            {"candidate_ref": "official", "target": "http://acme.example/"},
            {"candidate_ref": "other", "target": "http://acme.example/mirror"},
        ],
    )

    views = {view["candidate_ref"]: view for view in body["candidates"]}
    assert views["official"]["gate_outcome"] == "verified_official"
    assert views["official"]["alert_eligible"] is False
    assert views["official"]["campaign_id"] is None
    for campaign in body["campaigns"]:
        assert "official" not in campaign["candidate_refs"]


def test_unverified_candidate_stays_in_verification(client: TestClient) -> None:
    """Unverified identities are routed out of correlation campaigns."""
    brand = client.post("/api/v1/brands", json={"name": "Acme"}).json()
    client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "account", "value": "@acme", "verified": False},
    )

    body = _correlate(
        client,
        [
            {"candidate_ref": "unv", "target": "@acme"},
            {"candidate_ref": "other", "target": "http://else.example/"},
        ],
    )

    views = {view["candidate_ref"]: view for view in body["candidates"]}
    assert views["unv"]["gate_outcome"] == "unverified"
    assert views["unv"]["alert_eligible"] is False


def test_gate_failure_fails_closed(client: TestClient, monkeypatch) -> None:
    """Correlation produces nothing when the gate cannot be evaluated."""

    def _boom(self, *args, **kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr(ExclusionGate, "evaluate", _boom)

    body = _correlate(
        client,
        [
            {"candidate_ref": "a", "target": "http://x.example/"},
            {"candidate_ref": "b", "target": "http://x.example/2"},
        ],
    )

    assert body["status"] == "failed_closed"
    assert body["links"] == [] and body["campaigns"] == []
    assert any("failed closed" in limitation for limitation in body["limitations"])


def test_unsupported_signals_reported_honestly(client: TestClient) -> None:
    """Registrant and logo correlation are stated as unsupported, not faked."""
    body = _correlate(
        client,
        [
            {"candidate_ref": "a", "target": "http://x.example/"},
            {"candidate_ref": "b", "target": "http://x.example/2"},
        ],
    )

    assert any("registrant" in entry for entry in body["unsupported_signals"])
    assert any("logo" in entry for entry in body["unsupported_signals"])


def test_api_validation(client: TestClient) -> None:
    """Fewer than two candidates or blank fields are rejected."""
    assert client.post("/api/v1/correlate", json={"candidates": []}).status_code == 422
    assert (
        client.post(
            "/api/v1/correlate",
            json={"candidates": [{"candidate_ref": "a", "target": "http://x.example/"}]},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/correlate",
            json={
                "candidates": [
                    {"candidate_ref": "a", "target": ""},
                    {"candidate_ref": "b", "target": "http://y.example/"},
                ]
            },
        ).status_code
        == 422
    )
