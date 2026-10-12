"""Mocked, offline-only tests for optional hosted search adapters and config."""

import httpx
import pytest

from risk_radar.api.v1 import providers as providers_api
from risk_radar.core.config import Settings
from risk_radar.discovery.base import ConnectorError, ConnectorUnavailableError
from risk_radar.discovery.connectors.brave_search import BraveSearchConnector
from risk_radar.discovery.connectors.exa import EXA_SEARCH_URL, ExaSearchConnector
from risk_radar.discovery.connectors.search_api import MAX_SEARCH_RESULTS
from risk_radar.discovery.connectors.tavily import TAVILY_SEARCH_URL, TavilySearchConnector
from risk_radar.discovery.service import configured_search_connector, default_connectors


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(
    ("connector_type", "key_name"),
    [
        (TavilySearchConnector, "TAVILY_API_KEY"),
        (ExaSearchConnector, "EXA_API_KEY"),
        (BraveSearchConnector, "BRAVE_SEARCH_API_KEY"),
    ],
)
def test_search_connectors_fail_closed_without_key(connector_type, key_name):
    with pytest.raises(ConnectorUnavailableError, match=key_name):
        connector_type().search("acme")


@pytest.mark.parametrize(
    ("provider", "endpoint", "connector_type", "response_body", "expected_snippet"),
    [
        (
            "tavily_search",
            TAVILY_SEARCH_URL,
            TavilySearchConnector,
            {
                "results": [
                    {
                        "title": "Acme",
                        "url": "https://news.example/a",
                        "content": "Tavily excerpt",
                    }
                ]
            },
            "Tavily excerpt",
        ),
        (
            "exa_search",
            EXA_SEARCH_URL,
            ExaSearchConnector,
            {
                "results": [
                    {
                        "title": "Acme",
                        "url": "https://news.example/a",
                        "highlights": ["Exa excerpt"],
                    }
                ]
            },
            "Exa excerpt",
        ),
    ],
)
def test_search_adapters_map_mock_responses_and_provenance(
    provider, endpoint, connector_type, response_body, expected_snippet
):
    requests = []

    def handler(request):
        requests.append(request)
        assert str(request.url) == endpoint
        assert request.headers["content-type"] == "application/json"
        assert request.extensions["timeout"]["read"] <= 8.0
        if provider == "tavily_search":
            assert request.headers["authorization"] == "Bearer test-key"
        else:
            assert request.headers["x-api-key"] == "test-key"
        import json

        payload = json.loads(request.content)
        assert payload["query"]
        result_limit = (
            payload["max_results"]
            if provider == "tavily_search"
            else payload["numResults"]
        )
        assert result_limit == MAX_SEARCH_RESULTS
        return httpx.Response(200, json=response_body)

    with _client(handler) as client:
        results = connector_type("test-key", client=client).search("acme")

    assert len(requests) == 1
    assert len(results) == 1
    result = results[0]
    assert result.source == provider
    assert result.target == result.source_reference == "https://news.example/a"
    assert result.metadata["snippet"] == expected_snippet
    assert result.metadata["content_kind"] == "search_snippet"
    assert result.metadata["page_content_retrieved"] is False
    assert result.metadata["retrieved_at"]
    assert result.provenance[0].source == provider
    assert result.provenance[0].discovered_at == result.discovered_at


@pytest.mark.parametrize("connector_type", [TavilySearchConnector, ExaSearchConnector])
@pytest.mark.parametrize(
    ("status", "message"),
    [(401, "authentication failed"), (429, "rate limited"), (503, "HTTP 503")],
)
def test_search_adapter_provider_errors_are_explicit(connector_type, status, message):
    with _client(lambda _request: httpx.Response(status)) as client:
        with pytest.raises(ConnectorError, match=message) as error:
            connector_type("test-key", client=client).search("acme")
    assert "test-key" not in str(error.value)


@pytest.mark.parametrize("connector_type", [TavilySearchConnector, ExaSearchConnector])
def test_search_adapter_rejects_malformed_json_contract(connector_type):
    with _client(lambda _request: httpx.Response(200, json={"unexpected": []})) as client:
        with pytest.raises(ConnectorError, match="results are malformed"):
            connector_type("test-key", client=client).search("acme")


def test_only_selected_search_provider_is_registered(monkeypatch):
    settings = Settings(
        _env_file=None,
        search_provider="tavily",
        tavily_api_key="test-tavily-key",
        exa_api_key="test-exa-key",
        brave_search_api_key="test-brave-key",
    )
    monkeypatch.setattr("risk_radar.discovery.service.get_settings", lambda: settings)
    connectors = default_connectors()
    search_connectors = [item for item in connectors if item.name.endswith("_search")]
    assert len(search_connectors) == 1
    assert isinstance(search_connectors[0], TavilySearchConnector)
    assert isinstance(configured_search_connector(settings), TavilySearchConnector)


def test_provider_configuration_reports_boolean_presence_without_secret_values(
    client, monkeypatch
):
    key_value = "unit-test-secret-that-must-never-be-returned"
    settings = Settings(
        _env_file=None,
        search_provider="exa",
        brave_search_api_key=" ",
        tavily_api_key="",
        exa_api_key=key_value,
        anthropic_api_key=key_value,
    )
    monkeypatch.setattr(providers_api, "get_settings", lambda: settings)
    response = client.get("/api/v1/providers/configuration")
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "selected_search_provider": "exa",
        "key_configured": {
            "BRAVE_SEARCH_API_KEY": False,
            "TAVILY_API_KEY": False,
            "EXA_API_KEY": True,
            "ANTHROPIC_API_KEY": True,
        },
    }
    assert key_value not in response.text


def test_provider_configuration_defaults_to_no_configured_keys():
    settings = Settings(_env_file=None)
    assert settings.search_provider == "brave"
    assert all(value is False for value in settings.provider_key_status.values())


def test_documented_environment_names_configure_presence_flags(monkeypatch):
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "test-brave")
    monkeypatch.setenv("TAVILY_API_KEY", "test-tavily")
    monkeypatch.setenv("EXA_API_KEY", "test-exa")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic")
    monkeypatch.setenv("SEARCH_PROVIDER", "tavily")
    settings = Settings(_env_file=None)
    assert settings.search_provider == "tavily"
    assert all(settings.provider_key_status.values())
    assert "test-tavily" not in str(settings.provider_key_status)


def test_unknown_search_provider_is_rejected_without_echoing_credentials():
    with pytest.raises(ValueError):
        Settings(_env_file=None, search_provider="unknown", tavily_api_key="test-key")

