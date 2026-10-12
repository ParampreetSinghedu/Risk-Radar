"""OpenPhish public community feed connector (functional, no credentials)."""

from urllib.parse import urljoin

import httpx

from risk_radar.discovery.base import (
    Candidate,
    CandidateType,
    ConnectorError,
    DiscoveryConnector,
)

FEED_URL = "https://openphish.com/feed.txt"


class OpenPhishConnector(DiscoveryConnector):
    """Filter the OpenPhish plain-text feed down to URLs matching the query."""

    name = "openphish"

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client

    def search(self, query: str) -> list[Candidate]:
        """Fetch the community feed and yield URLs containing the query."""
        needle = query.strip().lower()
        if not needle:
            raise ConnectorError("openphish: query is empty")
        try:
            if self._client is not None:
                response = self._client.get(FEED_URL, timeout=10.0)
            else:
                with httpx.Client(timeout=10.0) as client:
                    response = client.get(FEED_URL)
                    response = self._follow_public_feed_redirect(client, response)
            if self._client is not None:
                response = self._follow_public_feed_redirect(self._client, response)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            if isinstance(exc, httpx.TimeoutException):
                reason = "feed request timed out"
            elif isinstance(exc, httpx.HTTPStatusError):
                reason = f"feed returned HTTP {exc.response.status_code}"
            else:
                reason = f"feed request failed ({exc.__class__.__name__})"
            raise ConnectorError(f"openphish: {reason}") from exc

        candidates = []
        for line in response.text.splitlines():
            url = line.strip()
            if url and not url.startswith("#") and needle in url.lower():
                candidates.append(
                    Candidate(
                        source=self.name,
                        source_reference=FEED_URL,
                        candidate_type=CandidateType.URL,
                        target=url,
                        metadata={"feed": "community"},
                    )
                )
        return candidates

    @staticmethod
    def _follow_public_feed_redirect(client: httpx.Client, response: httpx.Response):
        """Follow only OpenPhish's observed redirect to its own public-feed file."""
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("location")
        if not location:
            return response
        try:
            destination = httpx.URL(urljoin(str(response.url), location))
        except (TypeError, ValueError):
            return response
        if (
            destination.scheme != "https"
            or destination.host != "raw.githubusercontent.com"
            or not destination.path.startswith("/openphish/public_feed/")
        ):
            return response
        return client.get(str(destination), timeout=10.0)
