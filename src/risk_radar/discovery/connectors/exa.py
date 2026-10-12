"""Optional Exa web-search adapter using the shared discovery contract."""

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

EXA_SEARCH_URL = "https://api.exa.ai/search"


class ExaSearchConnector(DiscoveryConnector):
    """Search through Exa when selected and configured by the operator."""

    name = "exa_search"

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
            raise ConnectorUnavailableError("exa_search: EXA_API_KEY is not configured")
        normalized_query = build_search_query(query)
        if not normalized_query:
            raise ConnectorError("exa_search: query is empty")
        response = post_json(
            provider=self.name,
            endpoint=EXA_SEARCH_URL,
            api_key=self._api_key,
            payload={
                "query": normalized_query,
                "type": "fast",
                "numResults": MAX_SEARCH_RESULTS,
                "contents": {"highlights": True},
            },
            client=self._client,
            timeout=self._timeout,
            auth_header="x-api-key",
            auth_value=self._api_key,
        )
        rows = response.get("results")
        if not isinstance(rows, list):
            raise ConnectorError("exa_search: response results are malformed")
        return result_candidates(
            provider=self.name,
            query=normalized_query,
            rows=rows,
            snippet_for=_exa_snippet,
        )


def _exa_snippet(row: dict) -> str:
    """Use Exa highlights only; do not request or label full page text as a snippet."""
    highlights = row.get("highlights")
    if isinstance(highlights, list):
        return "\n".join(item for item in highlights if isinstance(item, str))[:3000]
    summary = row.get("summary")
    return summary if isinstance(summary, str) else ""
