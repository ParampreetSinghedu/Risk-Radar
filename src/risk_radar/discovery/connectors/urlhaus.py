"""URLhaus host-lookup connector (functional; requires ``URLHAUS_AUTH_KEY``)."""

from urllib.parse import urlsplit

import httpx

from risk_radar.discovery.base import (
    Candidate,
    CandidateType,
    ConnectorError,
    ConnectorQueryError,
    ConnectorUnavailableError,
    DiscoveryConnector,
)

API_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"


class URLhausConnector(DiscoveryConnector):
    """Look up a hostname in URLhaus and yield its listed URLs as candidates."""

    name = "urlhaus"

    def __init__(self, auth_key: str | None = None, client: httpx.Client | None = None) -> None:
        self._auth_key = auth_key
        self._client = client

    @staticmethod
    def _extract_host(query: str) -> str:
        """Return the hostname implied by the query or raise a query error."""
        value = query.strip()
        if not value or any(character.isspace() for character in value):
            raise ConnectorQueryError("urlhaus: query must be a hostname or URL")
        candidate = value if "://" in value else f"http://{value}"
        try:
            host = urlsplit(candidate).hostname
        except ValueError as exc:
            raise ConnectorQueryError("urlhaus: query is not a valid hostname") from exc
        if not host:
            raise ConnectorQueryError("urlhaus: query is not a valid hostname")
        return host

    def search(self, query: str) -> list[Candidate]:
        """Query the URLhaus host endpoint and normalize the listed URLs."""
        if not self._auth_key or not self._auth_key.strip():
            raise ConnectorUnavailableError("urlhaus: URLHAUS_AUTH_KEY is not configured")
        host = self._extract_host(query)
        try:
            if self._client is not None:
                response = self._client.post(
                    API_HOST_URL,
                    data={"host": host},
                    headers={"Auth-Key": self._auth_key},
                )
            else:
                with httpx.Client(timeout=10.0) as client:
                    response = client.post(
                        API_HOST_URL,
                        data={"host": host},
                        headers={"Auth-Key": self._auth_key},
                    )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError as exc:
            if isinstance(exc, httpx.HTTPStatusError):
                status_code = exc.response.status_code
                reason = (
                    "authentication failed"
                    if status_code in {401, 403}
                    else "rate limited"
                    if status_code == 429
                    else f"provider returned HTTP {status_code}"
                )
                raise ConnectorError(f"urlhaus: {reason}") from exc
            raise ConnectorError(f"urlhaus: request failed ({exc.__class__.__name__})") from exc
        except ValueError as exc:
            raise ConnectorError("urlhaus: response was not valid JSON") from exc

        if not isinstance(payload, dict):
            raise ConnectorError("urlhaus: response was not a JSON object")

        status = payload.get("query_status")
        if status == "no_results":
            return []
        if status == "invalid_host":
            raise ConnectorQueryError(f"urlhaus: {host!r} is not a valid host")
        if status == "unknown_auth_key":
            raise ConnectorUnavailableError("urlhaus: URLhaus API rejected the Auth-Key")
        if status != "ok":
            raise ConnectorError(f"urlhaus: unexpected query_status {status!r}")

        entries = payload.get("urls")
        if not isinstance(entries, list):
            raise ConnectorError("urlhaus: response urls are malformed")

        candidates = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ConnectorError("urlhaus: response urls are malformed")
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                raise ConnectorError("urlhaus: response urls are malformed")
            metadata = {
                key: entry[key]
                for key in ("threat", "url_status", "tags", "date_added", "id")
                if entry.get(key) is not None
            }
            candidates.append(
                Candidate(
                    source=self.name,
                    source_reference=entry.get("urlhaus_reference") or API_HOST_URL,
                    candidate_type=CandidateType.URL,
                    target=url,
                    metadata=metadata,
                )
            )
        return candidates
