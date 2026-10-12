"""Shared bounded HTTP and provenance helpers for hosted search adapters."""

from datetime import UTC, datetime
from typing import Any

import httpx

from risk_radar.discovery.base import Candidate, CandidateType, ConnectorError

MAX_SEARCH_RESULTS = 10
MAX_SEARCH_TIMEOUT_SECONDS = 15.0


def post_json(
    *,
    provider: str,
    endpoint: str,
    api_key: str,
    payload: dict[str, Any],
    client: httpx.Client | None,
    timeout: float,
    auth_header: str = "Authorization",
    auth_value: str | None = None,
) -> dict[str, Any]:
    """Make one bounded provider request and return a validated JSON object.

    Error messages deliberately exclude request headers, response bodies and key
    values. These adapters never request candidate result URLs.
    """
    bounded_timeout = min(max(float(timeout), 0.5), MAX_SEARCH_TIMEOUT_SECONDS)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        auth_header: auth_value or f"Bearer {api_key}",
    }
    try:
        if client is not None:
            response = client.post(
                endpoint, json=payload, headers=headers, timeout=bounded_timeout
            )
        else:
            with httpx.Client(timeout=bounded_timeout) as owned_client:
                response = owned_client.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()
    except httpx.TimeoutException as exc:
        raise ConnectorError(f"{provider}: request timed out") from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        reason = (
            "authentication failed"
            if status in {401, 403}
            else "rate limited or quota exhausted"
            if status == 429
            else f"provider returned HTTP {status}"
        )
        raise ConnectorError(f"{provider}: {reason}") from exc
    except httpx.HTTPError as exc:
        raise ConnectorError(
            f"{provider}: request failed ({exc.__class__.__name__})"
        ) from exc
    except ValueError as exc:
        raise ConnectorError(f"{provider}: response was not valid JSON") from exc
    if not isinstance(body, dict):
        raise ConnectorError(f"{provider}: response was not a JSON object")
    return body


def result_candidates(
    *,
    provider: str,
    query: str,
    rows: list[Any],
    snippet_for,
) -> list[Candidate]:
    """Normalize hosted search results into the shared discovery contract."""
    retrieved_at = datetime.now(UTC)
    candidates: list[Candidate] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = row.get("url")
        title = row.get("title")
        snippet = snippet_for(row)
        if not isinstance(url, str) or not isinstance(title, str):
            continue
        if not isinstance(snippet, str):
            snippet = ""
        if not _valid_result_url(url) or url in seen:
            continue
        seen.add(url)
        metadata: dict[str, Any] = {
            "provider": provider,
            "query": query,
            "title": title[:500],
            "snippet": snippet[:3000],
            "content_kind": "search_snippet",
            "page_content_retrieved": False,
            "retrieved_at": retrieved_at.isoformat(),
        }
        published = row.get("published_date") or row.get("publishedDate")
        if isinstance(published, str):
            metadata["published_date"] = published[:100]
        candidates.append(
            Candidate(
                source=provider,
                source_reference=url,
                candidate_type=CandidateType.URL,
                target=url,
                discovered_at=retrieved_at,
                metadata=metadata,
            )
        )
        if len(candidates) >= MAX_SEARCH_RESULTS:
            break
    return candidates


def _valid_result_url(value: str) -> bool:
    """Allow HTTP(S) source references only; these locators are never fetched."""
    try:
        parts = httpx.URL(value)
    except (TypeError, ValueError):
        return False
    return parts.scheme in {"http", "https"} and bool(parts.host) and not (
        parts.username or parts.password
    )
