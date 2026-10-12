"""Connector adapters awaiting a supported provider or its configuration."""

from typing import Protocol

from risk_radar.discovery.base import (
    Candidate,
    ConnectorUnavailableError,
    DiscoveryConnector,
)


class WebSearchConnector(DiscoveryConnector):
    """Unavailable legacy adapter; configured deployments use BraveSearchConnector."""

    name = "web_search"

    def search(self, query: str) -> list[Candidate]:
        """Keep the old seam explicit for callers that have no provider config."""
        raise ConnectorUnavailableError("web_search: no search provider or API key is configured")


class SocialPlatformConnector(DiscoveryConnector):
    """Provider-backed social search; never scrapes a platform implicitly."""

    name = "social"

    def __init__(self, provider: "SocialProfileProvider | None" = None) -> None:
        self.provider = provider

    def search(self, query: str) -> list[Candidate]:
        """Return sourced profiles or an explicit unavailable/provider error."""
        if self.provider is None:
            raise ConnectorUnavailableError(
                "social: no authorized platform API provider is configured"
            )
        candidates = self.provider.search_profiles(query)
        invalid = [item for item in candidates if item.candidate_type.value != "social_profile"]
        if invalid:
            raise ConnectorUnavailableError(
                "social: provider returned records that are not social profiles"
            )
        return candidates


class SocialProfileProvider(Protocol):
    """Contract for a platform API the operator is authorized to use.

    Implementations must return genuine provider records with source references,
    timestamps, and profile metadata. They must handle authentication and rate
    limits without scraping or bypassing platform controls.
    """

    name: str

    def search_profiles(self, query: str) -> list[Candidate]:
        """Discover profiles for a query using the provider's authorized API."""


class AppStoreConnector(DiscoveryConnector):
    """App store adapter; no public listing source is configured yet."""

    name = "app_store"

    def search(self, query: str) -> list[Candidate]:
        """Raise an explicit availability error until a listing source is configured."""
        raise ConnectorUnavailableError("app_store: no app store listing source is configured")
