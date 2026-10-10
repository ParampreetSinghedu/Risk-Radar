"""OpenPhish public community feed connector (functional, no credentials)."""

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
        try:
            if self._client is not None:
                response = self._client.get(FEED_URL)
            else:
                with httpx.Client(timeout=10.0) as client:
                    response = client.get(FEED_URL)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ConnectorError(
                f"openphish: feed request failed ({exc.__class__.__name__})"
            ) from exc

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
