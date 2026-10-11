"""Pluggable network resolvers for the URL/domain analyzer (Stage 5A).

Network access (DNS/RDAP/WHOIS/redirects) is often unavailable in tests and
restricted environments. Analyzers depend only on these narrow protocols; the
default resolvers return ``None`` so the analyzer reports an explicit
"unavailable/partial" status instead of inventing data or blocking.

Real resolvers can be injected at construction time without touching analyzers.
"""

from __future__ import annotations

from typing import Protocol


class DnsResolver(Protocol):
    """Resolve a hostname to addresses; None when data is unavailable."""

    def resolve(self, host: str) -> list[str] | None: ...


class RdapClient(Protocol):
    """Return RDAP/WHOIS registration facts for a domain, or None."""

    def registration(self, domain: str) -> dict[str, object] | None: ...


class RedirectChecker(Protocol):
    """Return the final URL after redirects, or None when unknown."""

    def final_url(self, url: str) -> str | None: ...


class UnavailableDns:
    """Default DNS resolver: always unavailable (no network in tests)."""

    def resolve(self, host: str) -> list[str] | None:
        return None


class UnavailableRdap:
    """Default RDAP client: always unavailable (no network in tests)."""

    def registration(self, domain: str) -> dict[str, object] | None:
        return None


class UnavailableRedirect:
    """Default redirect checker: always unavailable (no network in tests)."""

    def final_url(self, url: str) -> str | None:
        return None
