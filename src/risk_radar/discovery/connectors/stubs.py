"""Interface-only connector adapters awaiting credentials or provider configuration."""

from risk_radar.discovery.base import (
    Candidate,
    ConnectorUnavailableError,
    DiscoveryConnector,
)


class WebSearchConnector(DiscoveryConnector):
    """Web search adapter; no search provider is configured in this project yet."""

    name = "web_search"

    def search(self, query: str) -> list[Candidate]:
        """Raise an explicit availability error until a provider is configured."""
        raise ConnectorUnavailableError("web_search: no search provider or API key is configured")


class SocialPlatformConnector(DiscoveryConnector):
    """Social platform adapter; no platform API credentials are configured yet."""

    name = "social"

    def search(self, query: str) -> list[Candidate]:
        """Raise an explicit availability error until credentials are configured."""
        raise ConnectorUnavailableError("social: no platform API credentials are configured")


class AppStoreConnector(DiscoveryConnector):
    """App store adapter; no public listing source is configured yet."""

    name = "app_store"

    def search(self, query: str) -> list[Candidate]:
        """Raise an explicit availability error until a listing source is configured."""
        raise ConnectorUnavailableError("app_store: no app store listing source is configured")
