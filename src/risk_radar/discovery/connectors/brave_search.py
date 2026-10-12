"""Brave Search API connector; records result metadata without fetching result pages."""

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from risk_radar.discovery.base import (
    Candidate,
    CandidateType,
    ConnectorError,
    ConnectorUnavailableError,
    DiscoveryConnector,
)

BRAVE_WEB_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"
_MAX_RESULTS = 10
_MAX_QUERY_LENGTH = 600


def build_search_query(target: str) -> str:
    """Build bounded public-evidence query text from a target identifier."""
    search_term = target.strip()
    if search_term.startswith(("http://", "https://")):
        try:
            search_term = urlsplit(search_term).hostname or search_term
        except ValueError:
            pass
    search_term = search_term.replace('"', " ").strip()
    if not search_term:
        return ""
    return f'"{search_term[:250]}" brand impersonation scam fake profile'[:_MAX_QUERY_LENGTH]


class BraveSearchConnector(DiscoveryConnector):
    """Search Brave's public web index using the operator's configured API key."""

    name = "brave_search"

    def __init__(
        self,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        timeout: float = 8.0,
    ) -> None:
        self._api_key = api_key
        self._client = client
        self._timeout = min(max(float(timeout), 0.5), 15.0)

    def search(self, query: str) -> list[Candidate]:
        """Return sourced URL/title/snippet candidates, never retrieved page content."""
        if not self._api_key:
            raise ConnectorUnavailableError(
                "brave_search: BRAVE_SEARCH_API_KEY is not configured"
            )
        normalized_query = build_search_query(query)[:_MAX_QUERY_LENGTH]
        if not normalized_query:
            raise ConnectorError("brave_search: query is empty")

        try:
            if self._client is not None:
                response = self._client.get(
                    BRAVE_WEB_SEARCH_URL,
                    params={"q": normalized_query, "count": _MAX_RESULTS},
                    headers={
                        "Accept": "application/json",
                        "X-Subscription-Token": self._api_key,
                    },
                    timeout=self._timeout,
                )
            else:
                with httpx.Client(timeout=self._timeout) as client:
                    response = client.get(
                        BRAVE_WEB_SEARCH_URL,
                        params={"q": normalized_query, "count": _MAX_RESULTS},
                        headers={
                            "Accept": "application/json",
                            "X-Subscription-Token": self._api_key,
                        },
                    )
            response.raise_for_status()
            payload = response.json()
        except httpx.TimeoutException as exc:
            raise ConnectorError("brave_search: request timed out") from exc
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            reason = (
                "authentication failed"
                if code in {401, 403}
                else "rate limited or quota exhausted"
                if code == 429
                else f"provider returned HTTP {code}"
            )
            raise ConnectorError(f"brave_search: {reason}") from exc
        except httpx.HTTPError as exc:
            raise ConnectorError(
                f"brave_search: request failed ({exc.__class__.__name__})"
            ) from exc
        except ValueError as exc:
            raise ConnectorError("brave_search: response was not valid JSON") from exc

        if not isinstance(payload, dict) or not isinstance(payload.get("web"), dict):
            raise ConnectorError("brave_search: response has no web results object")
        results = payload["web"].get("results")
        if not isinstance(results, list):
            raise ConnectorError("brave_search: response web results are malformed")

        retrieved_at = datetime.now(UTC)
        candidates: list[Candidate] = []
        seen: set[str] = set()
        for result in results:
            if not isinstance(result, dict):
                continue
            url = result.get("url")
            title = result.get("title")
            snippet = result.get("description")
            if not isinstance(url, str) or not isinstance(title, str) or not isinstance(
                snippet, str
            ):
                continue
            if not _valid_result_url(url) or url in seen:
                continue
            seen.add(url)
            metadata: dict[str, Any] = {
                "provider": self.name,
                "query": normalized_query,
                "title": title[:500],
                "snippet": snippet[:3000],
                "content_kind": "search_snippet",
                "page_content_retrieved": False,
                "retrieved_at": retrieved_at.isoformat(),
            }
            for key in ("page_age", "profile", "language"):
                value = result.get(key)
                if isinstance(value, str):
                    metadata[key] = value[:500]
            candidates.append(
                Candidate(
                    source=self.name,
                    source_reference=url,
                    candidate_type=CandidateType.URL,
                    target=url,
                    discovered_at=retrieved_at,
                    metadata=metadata,
                )
            )
            if len(candidates) >= _MAX_RESULTS:
                break
        return candidates


def _valid_result_url(value: str) -> bool:
    """Accept only absolute HTTP(S) result locators; none are fetched here."""
    try:
        parts = httpx.URL(value)
    except (TypeError, ValueError):
        return False
    return parts.scheme in {"http", "https"} and bool(parts.host) and not (
        parts.username or parts.password
    )
