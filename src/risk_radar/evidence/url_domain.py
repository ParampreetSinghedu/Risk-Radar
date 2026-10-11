"""Analyzer A: URL and domain analysis (Stage 5).

Normalizes a URL, extracts the host and registrable domain, and records
deterministic structural signals. Network-backed enrichment (DNS records,
RDAP/WHOIS registration age, redirect chains) is gathered only through the
injected resolvers; when they return nothing the analyzer reports an explicit
``partial`` status and a limitation.

A missing registration record is NEVER treated as "domain is new" or "domain is
safe"; it is simply unknown.
"""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from app.schemas.evidence import AnalyzerResult

from risk_radar.collection.service import clean_url
from risk_radar.evidence.base import (
    assessment_from_reasons,
    build_result,
    claimed_identity_observation,
    evidence_record,
    signal_observation,
)
from risk_radar.evidence.resolvers import (
    DnsResolver,
    RdapClient,
    RedirectChecker,
    UnavailableDns,
    UnavailableRdap,
    UnavailableRedirect,
)

_TLD_ALPHA = 2  # minimum labels for a plausible registrable domain


def registrable_domain(host: str) -> str | None:
    """Approximate the registrable domain as the last two labels.

    Documented limitation: this is a heuristic (no public-suffix list is
    bundled), matching the Rule Engine's documented behaviour.
    """
    labels = [label for label in host.lower().strip(".").split(".") if label]
    if len(labels) < _TLD_ALPHA:
        return None
    return ".".join(labels[-2:])


def _host_of(target: str) -> str | None:
    try:
        parts = urlsplit(target) if "://" in target else urlsplit("//" + target)
        return parts.hostname.lower() if parts.hostname else None
    except ValueError:
        return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


class UrlDomainAnalyzer:
    """Deterministic URL/domain inspection; network data is optional."""

    analyzer_type = "url"

    def __init__(
        self,
        dns: DnsResolver | None = None,
        rdap: RdapClient | None = None,
        redirects: RedirectChecker | None = None,
    ) -> None:
        self._dns = dns or UnavailableDns()
        self._rdap = rdap or UnavailableRdap()
        self._redirects = redirects or UnavailableRedirect()

    def analyze(
        self,
        target: str,
        input_id: str = "target",
        input_type: str = "url",
        investigation_id: str = "unspecified",
    ) -> AnalyzerResult:
        """Inspect a URL/domain and return a contract-valid result."""
        raw = target.strip()
        if not raw:
            return build_result(
                analyzer_type="url",
                input_type=input_type,
                status="failed",
                input_id=input_id,
                locator=None,
                investigation_id=investigation_id,
                errors=[{"stage": "normalize", "message": "empty target"}],
                limitations=["empty target: no URL to analyze"],
            )

        host = _host_of(raw)
        if host is None:
            return build_result(
                analyzer_type="url",
                input_type=input_type,
                status="failed",
                input_id=input_id,
                locator=raw[:2048],
                investigation_id=investigation_id,
                errors=[{"stage": "normalize", "message": "no hostname could be parsed"}],
                limitations=["target is not a URL or domain: host could not be derived"],
            )

        normalized = clean_url(raw) if "://" in raw else raw
        observations: list[dict[str, Any]] = []
        indicators: list[dict[str, Any]] = []
        evidence = [
            evidence_record(
                input_id,
                "url",
                f"normalized URL '{normalized}' with host '{host}'",
                locator=normalized,
                method="url_normalization",
            )
        ]
        limitations: list[str] = []
        reason_codes: list[str] = []

        reg = registrable_domain(host)
        observations.append(signal_observation("host", host, "urlparse.hostname"))
        if reg:
            observations.append(
                signal_observation("registrable_domain", reg, "two_label_heuristic")
            )
        # Claimed-identity observation lets Stage 6/7 consume this output.
        observations.append(claimed_identity_observation("domain", host, 1.0))

        if _is_ip(host):
            indicators.append(
                {"kind": "ip_host", "value": host, "severity": "medium", "confidence": 1.0}
            )
            reason_codes.append("ip_host")
        if any(label.startswith("xn--") for label in host.split(".")):
            indicators.append(
                {"kind": "punycode_host", "value": host, "severity": "low", "confidence": 1.0}
            )
            reason_codes.append("punycode_host")
        if raw.startswith("http://"):
            indicators.append(
                {"kind": "plaintext_http", "value": "http", "severity": "low", "confidence": 1.0}
            )
            reason_codes.append("plaintext_http")

        status = self._enrich(
            host=host,
            reg=reg,
            observations=observations,
            indicators=indicators,
            evidence=evidence,
            limitations=limitations,
            reason_codes=reason_codes,
            input_id=input_id,
            url=normalized,
        )

        return build_result(
            analyzer_type="url",
            input_type=input_type,
            status=status,
            input_id=input_id,
            locator=normalized[:2048],
            investigation_id=investigation_id,
            observations=observations,
            indicators=indicators,
            evidence=evidence,
            assessment=assessment_from_reasons(reason_codes, confidence=1.0),
            limitations=limitations,
        )

    def _enrich(
        self,
        *,
        host: str,
        reg: str | None,
        observations: list[dict[str, Any]],
        indicators: list[dict[str, Any]],
        evidence: list[Any],
        limitations: list[str],
        reason_codes: list[str],
        input_id: str,
        url: str,
    ) -> str:
        """Attach DNS/RDAP/redirect data when available; degrade honestly."""
        partial = False

        addresses = self._dns.resolve(host)
        if addresses:
            observations.append(signal_observation("dns_addresses", addresses, "dns_resolver"))
        else:
            partial = True
            limitations.append("DNS resolution unavailable: no address records obtained")

        if reg and not _is_ip(host):
            registration = self._rdap.registration(reg)
            if registration:
                observations.append(signal_observation("registration", registration, "rdap_client"))
                age_days = registration.get("domain_age_days")
                if isinstance(age_days, int) and not isinstance(age_days, bool) and age_days >= 0:
                    observations.append(
                        signal_observation("domain_age_days", age_days, "rdap_client")
                    )
                created = registration.get("created")
                if created is not None:
                    evidence.append(
                        evidence_record(
                            input_id,
                            "registration",
                            f"RDAP registration for '{reg}'",
                            locator=str(reg),
                            method="rdap_client",
                            created=created,
                        )
                    )
            else:
                partial = True
                limitations.append(
                    "RDAP/WHOIS registration data unavailable: registration age unknown "
                    "and NOT inferred"
                )

        final = self._redirects.final_url(url)
        if final:
            observations.append(
                signal_observation("final_url", final, "redirect_checker", differs=final != url)
            )
        else:
            partial = True
            limitations.append("redirect chain not followed: final destination unknown")

        return "partial" if partial else "completed"
