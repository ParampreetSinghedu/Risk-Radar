"""Discovery aggregation: run connectors, isolate failures, deduplicate (Stage 3)."""

from pydantic import BaseModel, Field

from risk_radar.core.config import Settings, get_settings
from risk_radar.discovery.base import Candidate, ConnectorError, DiscoveryConnector
from risk_radar.discovery.connectors.brave_search import BraveSearchConnector
from risk_radar.discovery.connectors.exa import ExaSearchConnector
from risk_radar.discovery.connectors.openphish import OpenPhishConnector
from risk_radar.discovery.connectors.stubs import (
    AppStoreConnector,
    SocialPlatformConnector,
)
from risk_radar.discovery.connectors.tavily import TavilySearchConnector
from risk_radar.discovery.connectors.urlhaus import URLhausConnector


class DiscoveryFailure(BaseModel):
    """Record of one connector that could not produce results."""

    source: str
    reason: str


class DiscoveryResult(BaseModel):
    """Aggregated, deduplicated discovery output for one query."""

    query: str
    candidates: list[Candidate] = Field(default_factory=list)
    failures: list[DiscoveryFailure] = Field(default_factory=list)


def deduplicate(candidates: list[Candidate]) -> list[Candidate]:
    """Merge candidates sharing a normalized target, preserving provenance."""
    by_id: dict[str, Candidate] = {}
    for candidate in candidates:
        existing = by_id.get(candidate.candidate_id)
        if existing is None:
            by_id[candidate.candidate_id] = candidate
            continue
        for entry in candidate.provenance:
            if entry not in existing.provenance:
                existing.provenance.append(entry)
        for key, value in candidate.metadata.items():
            existing.metadata.setdefault(key, value)
    return list(by_id.values())


class DiscoveryService:
    """Invoke every registered connector and combine their results safely."""

    def __init__(self, connectors: list[DiscoveryConnector]) -> None:
        self.connectors = connectors

    def discover(self, query: str) -> DiscoveryResult:
        """Return deduplicated candidates plus one failure entry per failing source."""
        collected: list[Candidate] = []
        failures: list[DiscoveryFailure] = []
        for connector in self.connectors:
            try:
                collected.extend(connector.search(query))
            except ConnectorError as exc:
                failures.append(DiscoveryFailure(source=connector.name, reason=str(exc)))
            except Exception as exc:  # noqa: BLE001 - isolate unexpected connector bugs
                failures.append(
                    DiscoveryFailure(
                        source=connector.name,
                        reason=f"unexpected error: {exc.__class__.__name__}",
                    )
                )
        return DiscoveryResult(query=query, candidates=deduplicate(collected), failures=failures)


def configured_search_connector(settings: Settings | None = None) -> DiscoveryConnector:
    """Build the single selected search adapter; no key means no outbound call."""
    settings = settings or get_settings()
    provider = settings.search_provider
    if provider == "tavily":
        key = settings.tavily_api_key.get_secret_value() if settings.tavily_api_key else None
        return TavilySearchConnector(key, timeout=settings.search_provider_timeout_seconds)
    if provider == "exa":
        key = settings.exa_api_key.get_secret_value() if settings.exa_api_key else None
        return ExaSearchConnector(key, timeout=settings.search_provider_timeout_seconds)
    key = (
        settings.brave_search_api_key.get_secret_value()
        if settings.brave_search_api_key
        else None
    )
    return BraveSearchConnector(key, timeout=settings.brave_search_timeout_seconds)


def default_connectors() -> list[DiscoveryConnector]:
    """Build the default connector registry from current configuration."""
    settings = get_settings()
    auth_key = settings.urlhaus_auth_key.get_secret_value() if settings.urlhaus_auth_key else None
    return [
        URLhausConnector(auth_key=auth_key),
        OpenPhishConnector(),
        configured_search_connector(settings),
        SocialPlatformConnector(),
        AppStoreConnector(),
    ]
