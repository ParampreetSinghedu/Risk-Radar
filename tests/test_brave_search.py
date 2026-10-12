"""Deterministic coverage for the Brave Search provider adapter."""

from __future__ import annotations

import httpx
import pytest

from risk_radar.discovery.base import ConnectorError, ConnectorUnavailableError
from risk_radar.discovery.connectors.brave_search import (
    BRAVE_WEB_SEARCH_URL,
    BraveSearchConnector,
    build_search_query,
)
from risk_radar.investigator.tools import web_research


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_brave_search_maps_snippets_with_source_and_retrieval_metadata():
    def handler(request):
        assert request.url.host == httpx.URL(BRAVE_WEB_SEARCH_URL).host
        assert request.url.params["q"] == build_search_query("acme")
        assert request.headers["x-subscription-token"] == "test-key"
        assert request.extensions["timeout"]["read"] <= 8.0
        return httpx.Response(
            200,
            json={
                "web": {
                    "results": [
                        {
                            "url": "https://news.example/acme",
                            "title": "Acme report",
                            "description": "A search snippet, not page content.",
                            "page_age": "2026-10-10",
                        },
                        {
                            "url": "https://news.example/acme",
                            "title": "Duplicate",
                            "description": "duplicate result",
                        },
                    ]
                }
            },
        )

    with _client(handler) as client:
        results = BraveSearchConnector("test-key", client=client).search("acme")
    assert len(results) == 1
    candidate = results[0]
    assert candidate.source == "brave_search"
    assert candidate.target == candidate.source_reference == "https://news.example/acme"
    assert candidate.metadata["title"] == "Acme report"
    assert candidate.metadata["snippet"] == "A search snippet, not page content."
    assert candidate.metadata["content_kind"] == "search_snippet"
    assert candidate.metadata["page_content_retrieved"] is False
    assert candidate.provenance[0].discovered_at == candidate.discovered_at


def test_brave_search_requires_credentials_and_rejects_bad_response():
    with pytest.raises(ConnectorUnavailableError, match="BRAVE_SEARCH_API_KEY"):
        BraveSearchConnector().search("acme")

    with _client(lambda request: httpx.Response(200, json={"web": {}})) as client:
        with pytest.raises(ConnectorError, match="malformed"):
            BraveSearchConnector("key", client=client).search("acme")


@pytest.mark.parametrize(
    ("status_code", "message"),
    [(401, "authentication failed"), (429, "rate limited"), (503, "HTTP 503")],
)
def test_brave_search_provider_statuses_are_explicit(status_code, message):
    with _client(lambda request: httpx.Response(status_code)) as client:
        with pytest.raises(ConnectorError, match=message):
            BraveSearchConnector("key", client=client).search("acme")


def test_brave_search_timeout_is_explicit():
    def timeout(request):
        raise httpx.ReadTimeout("timed out", request=request)

    with _client(timeout) as client:
        with pytest.raises(ConnectorError, match="timed out"):
            BraveSearchConnector("key", client=client).search("acme")


def test_result_urls_are_metadata_only_and_never_fetched():
    requests = []

    def handler(request):
        requests.append(request.url)
        return httpx.Response(
            200,
            json={
                "web": {
                    "results": [
                        {
                            "url": "http://127.0.0.1/private",
                            "title": "Untrusted result URL",
                            "description": "This value must not trigger a fetch.",
                        }
                    ]
                }
            },
        )

    with _client(handler) as client:
        results = BraveSearchConnector("key", client=client).search("acme")
    assert len(requests) == 1
    assert requests[0].host == httpx.URL(BRAVE_WEB_SEARCH_URL).host
    assert len(results) == 1
    assert results[0].target == "http://127.0.0.1/private"


@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///etc/passwd", "https://user:pass@host/secret"])
def test_brave_search_discards_non_http_or_credentialed_result_locators(url):
    with _client(
        lambda request: httpx.Response(
            200,
            json={"web": {"results": [{"url": url, "title": "bad", "description": "bad"}]}},
        )
    ) as client:
        assert BraveSearchConnector("key", client=client).search("query") == []


def test_search_query_construction_and_research_contract_keep_snippets_distinct():
    query = build_search_query("https://Acme.example/login?token=not-searched")
    assert query == '"acme.example" brand impersonation scam fake profile'

    candidate = BraveSearchConnector(
        "test-key",
        client=_client(
            lambda request: httpx.Response(
                200,
                json={
                    "web": {
                        "results": [
                            {
                                "url": "https://public.example/report",
                                "title": "Report title",
                                "description": "Provider excerpt",
                            }
                        ]
                    }
                },
            )
        ),
    ).search("acme")
    hits, limitations = web_research("acme", connectors=[_OneCandidate(candidate[0])])
    assert not limitations
    assert hits[0].title == "Report title"
    assert hits[0].snippet == "Provider excerpt"
    assert hits[0].content_kind == "search_snippet"
    assert hits[0].page_content_retrieved is False


class _OneCandidate:
    name = "brave_search"

    def __init__(self, candidate):
        self.candidate = candidate

    def search(self, query):
        return [self.candidate]
