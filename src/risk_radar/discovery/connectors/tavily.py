"""Optional Tavily web-search adapter using the shared discovery contract."""

from typing import Any

import httpx

from risk_radar.discovery.base import (
    Candidate,
    ConnectorError,
    ConnectorUnavailableError,
    DiscoveryConnector,
)
from risk_radar.discovery.connectors.brave_search import build_search_query
from risk_radar.discovery.connectors.search_api import (
    MAX_SEARCH_RESULTS,
    post_json,
    result_candidates,
)

TAVILY_SEARCH_URL = "https://api.tavily.com/search"


class TavilySearchConnector(DiscoveryConnector):
    """Search through Tavily when selected and configured by the operator."""

    name = "tavily_search"

    def __init__(
        self,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        timeout: float = 8.0,
    ) -> None:
        self._api_key = api_key
        self._client = client
        self._timeout = timeout

    def search(self, query: str) -> list[Candidate]:
        if not self._api_key or not self._api_key.strip():
            raise ConnectorUnavailableError("tavily_search: TAVILY_API_KEY is not configured")
        normalized_query = build_search_query(query)
        if not normalized_query:
            raise ConnectorError("tavily_search: query is empty")
        payload: dict[str, Any] = {
            "query": normalized_query,
            "search_depth": "basic",
            "max_results": MAX_SEARCH_RESULTS,
            "include_answer": False,
            "include_raw_content": False,
            "include_images": False,
            "include_image_descriptions": False,
        }
        response = post_json(
            provider=self.name,
            endpoint=TAVILY_SEARCH_URL,
            api_key=self._api_key,
            payload=payload,
            client=self._client,
            timeout=self._timeout,
        )
        rows = response.get("results")
        if not isinstance(rows, list):
            raise ConnectorError("tavily_search: response results are malformed")
        return result_candidates(
            provider=self.name,
            query=normalized_query,
            rows=rows,
            snippet_for=lambda row: row.get("content", ""),
        )
