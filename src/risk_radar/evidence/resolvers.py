"""Pluggable network resolvers for the URL/domain analyzer (Stage 5A).

Network access (DNS/RDAP/WHOIS/redirects) is often unavailable in tests and
restricted environments. Analyzers depend only on these narrow protocols; the
default resolvers return ``None`` so the analyzer reports an explicit
"unavailable/partial" status instead of inventing data or blocking.

Real resolvers can be injected at construction time or configured via application
settings without breaking offline test execution.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import threading
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

import httpx


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


_DEFAULT_DNS_MAX_WORKERS = 4
_dns_executor_lock = threading.Lock()
_shared_dns_executor: concurrent.futures.ThreadPoolExecutor | None = None


def get_shared_dns_executor(
    max_workers: int = _DEFAULT_DNS_MAX_WORKERS,
) -> concurrent.futures.ThreadPoolExecutor:
    """Return a shared bounded thread pool for DNS resolution.

    Using a shared bounded pool ensures thread count is strictly bounded across
    requests and prevents repeated timeouts from accumulating unbounded workers.
    """
    global _shared_dns_executor
    if _shared_dns_executor is None:
        with _dns_executor_lock:
            if _shared_dns_executor is None:
                _shared_dns_executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=max_workers,
                    thread_name_prefix="dns-resolver",
                )
    return _shared_dns_executor


def reset_shared_dns_executor(wait: bool = False) -> None:
    """Shut down and reset the shared DNS executor (used in tests and teardown)."""
    global _shared_dns_executor
    with _dns_executor_lock:
        if _shared_dns_executor is not None:
            _shared_dns_executor.shutdown(wait=wait, cancel_futures=True)
            _shared_dns_executor = None


class SystemDnsResolver:
    """Standard-library socket-based DNS resolver with strict timeouts.

    Treats lookup failures, timeouts, and missing records as unavailable evidence,
    never as evidence of maliciousness.

    Uses a bounded worker pool so that lookups timing out in the background
    do not block the caller during cleanup, nor cause unbounded thread growth.
    """

    def __init__(
        self,
        timeout: float = 2.0,
        max_workers: int = _DEFAULT_DNS_MAX_WORKERS,
        executor: concurrent.futures.ThreadPoolExecutor | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_workers = max_workers
        self._executor = executor

    def _get_executor(self) -> concurrent.futures.ThreadPoolExecutor:
        if self._executor is not None:
            return self._executor
        return get_shared_dns_executor(self.max_workers)

    def resolve(self, host: str) -> list[str] | None:
        clean_host = host.strip().rstrip(".")
        if not clean_host:
            return None

        # If already an IP address, return it directly.
        try:
            ipaddress.ip_address(clean_host.strip("[]"))
            return [clean_host]
        except ValueError:
            pass

        def _lookup() -> list[str]:
            results = socket.getaddrinfo(
                clean_host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
            addresses: list[str] = []
            for item in results:
                sockaddr = item[4]
                ip = sockaddr[0]
                if ip not in addresses:
                    addresses.append(ip)
            return addresses

        executor = self._get_executor()
        future: concurrent.futures.Future[list[str]] | None = None
        try:
            future = executor.submit(_lookup)
            addresses = future.result(timeout=self.timeout)
            return addresses or None
        except (
            socket.gaierror,
            TimeoutError,
            concurrent.futures.TimeoutError,
            OSError,
            Exception,
        ):
            if future is not None:
                # Cancel queued lookup if it has not yet started.
                future.cancel()
            return None



class HttpRdapClient:
    """HTTP-based RDAP client using standard bootstrap routing.

    Fetches domain registration records via RDAP bootstrap servers (e.g., rdap.org
    or official IANA redirectors). Defensively parses dates without inferring registration
    age when data is missing or invalid.
    """

    def __init__(
        self,
        base_url: str = "https://rdap.org/domain/",
        timeout: float = 3.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = client

    def registration(self, domain: str) -> dict[str, object] | None:
        clean_domain = domain.strip().lower().rstrip(".")
        if not clean_domain:
            return None

        # Do not query RDAP for IP literals.
        try:
            ipaddress.ip_address(clean_domain.strip("[]"))
            return None
        except ValueError:
            pass

        url = f"{self.base_url}/{clean_domain}"
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "RiskRadar/1.0",
        }

        try:
            if self._client is not None:
                resp = self._client.get(url, headers=headers)
            else:
                with httpx.Client(
                    timeout=httpx.Timeout(self.timeout),
                    follow_redirects=True,
                ) as http:
                    resp = http.get(url, headers=headers)

            if resp.status_code != 200:
                return None

            body = resp.json()
            if not isinstance(body, dict):
                return None

            return self._parse_rdap_response(clean_domain, body)
        except (httpx.HTTPError, httpx.TimeoutException, ValueError, Exception):
            return None

    @staticmethod
    def _parse_rdap_response(domain: str, body: dict[str, Any]) -> dict[str, object] | None:
        events = body.get("events")
        created_str: str | None = None
        expiration_str: str | None = None

        if isinstance(events, list):
            for event in events:
                if isinstance(event, dict):
                    action = str(event.get("eventAction", "")).lower()
                    date = event.get("eventDate")
                    if isinstance(date, str) and date.strip():
                        if action in ("registration", "creation") and not created_str:
                            created_str = date.strip()
                        elif (
                            action in ("expiration", "registration expiration")
                            and not expiration_str
                        ):
                            expiration_str = date.strip()

        registrar: str | None = None
        entities = body.get("entities")
        if isinstance(entities, list):
            for entity in entities:
                if isinstance(entity, dict):
                    roles = entity.get("roles") or []
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray")
                        if (
                            isinstance(vcard, list)
                            and len(vcard) > 1
                            and isinstance(vcard[1], list)
                        ):
                            for prop in vcard[1]:
                                if (
                                    isinstance(prop, list)
                                    and len(prop) > 3
                                    and prop[0] == "fn"
                                    and isinstance(prop[3], str)
                                ):
                                    registrar = prop[3].strip()
                                    break
                        if not registrar and isinstance(entity.get("handle"), str):
                            registrar = entity["handle"].strip()
                        if not registrar and isinstance(entity.get("legalName"), str):
                            registrar = entity["legalName"].strip()
                        if registrar:
                            break

        domain_age_days: int | None = None
        if created_str:
            try:
                # ISO 8601 parsing with UTC normalization
                cleaned_date = created_str.replace("Z", "+00:00")
                created_dt = datetime.fromisoformat(cleaned_date)
                now = datetime.now(UTC)
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=UTC)
                if created_dt <= now:
                    domain_age_days = (now - created_dt).days
            except (ValueError, TypeError):
                domain_age_days = None

        result: dict[str, object] = {"domain": domain}
        if created_str:
            result["created"] = created_str
        if domain_age_days is not None:
            result["domain_age_days"] = domain_age_days
        if expiration_str:
            result["expiration"] = expiration_str
        if registrar:
            result["registrar"] = registrar

        # If no registration events or registrar was extracted, check for handle/ldhName
        has_identity = bool(body.get("handle") or body.get("ldhName"))
        if not created_str and not registrar and not has_identity:
            return None

        return result


def is_safe_network_ip(ip_str: str) -> bool:
    """Validate that an IP is not loopback, private, link-local, reserved, or metadata."""
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
    except ValueError:
        return False

    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return False

    # Block well-known cloud metadata endpoints
    if str(ip) in {"169.254.169.254", "169.254.170.2", "fd00:ec2::254"}:
        return False

    return True


class SafeRedirectChecker:
    """SSRF-protected redirect follower.

    Enforces strict destination checks before every request and hop:
    - Rejects non-HTTP(S) schemes.
    - Resolves hostnames and verifies all resolved IP addresses are public.
    - Blocks loopback, private, link-local, reserved, and cloud metadata addresses.
    - Limits total hops and applies request timeouts.
    """

    def __init__(
        self,
        max_hops: int = 5,
        timeout: float = 3.0,
        dns_resolver: DnsResolver | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.max_hops = max_hops
        self.timeout = timeout
        self._dns = dns_resolver or SystemDnsResolver(timeout=timeout)
        self._client = client

    def _is_safe_host(self, host: str) -> bool:
        clean = host.strip("[]")
        try:
            ip = ipaddress.ip_address(clean)
            return is_safe_network_ip(str(ip))
        except ValueError:
            pass

        addresses = self._dns.resolve(clean)
        if not addresses:
            return False
        return all(is_safe_network_ip(addr) for addr in addresses)

    def final_url(self, url: str) -> str | None:
        current_url = url.strip()
        hops = 0

        while hops < self.max_hops:
            parts = urlsplit(current_url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                return None

            if not self._is_safe_host(parts.hostname):
                return None

            try:
                headers = {"User-Agent": "RiskRadar/1.0"}
                if self._client is not None:
                    resp = self._client.head(
                        current_url, headers=headers, follow_redirects=False
                    )
                    if resp.status_code == 405:
                        resp = self._client.get(
                            current_url, headers=headers, follow_redirects=False
                        )
                else:
                    with httpx.Client(
                        timeout=httpx.Timeout(self.timeout),
                        follow_redirects=False,
                    ) as http:
                        resp = http.head(current_url, headers=headers)
                        if resp.status_code == 405:
                            resp = http.get(current_url, headers=headers)

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location")
                    if not location:
                        return current_url
                    next_url = urljoin(current_url, location)
                    current_url = next_url
                    hops += 1
                else:
                    return current_url
            except (httpx.HTTPError, httpx.TimeoutException, Exception):
                return None

        # Exceeded max hops
        return None


def get_resolvers(
    settings: Any = None,
) -> tuple[DnsResolver, RdapClient, RedirectChecker]:
    """Factory to build resolvers based on application settings.

    Defaults to deterministic unavailable resolvers when settings is None
    or when live resolvers are disabled (preserves offline tests).
    """
    if settings is None or not getattr(settings, "evidence_enable_live_resolvers", False):
        return UnavailableDns(), UnavailableRdap(), UnavailableRedirect()

    dns_timeout = getattr(settings, "evidence_dns_timeout_seconds", 2.0)
    dns = SystemDnsResolver(timeout=dns_timeout)

    rdap_timeout = getattr(settings, "evidence_rdap_timeout_seconds", 3.0)
    rdap_bootstrap = getattr(settings, "evidence_rdap_bootstrap_url", "https://rdap.org/domain/")
    rdap = HttpRdapClient(base_url=rdap_bootstrap, timeout=rdap_timeout)

    if getattr(settings, "evidence_enable_redirects", False):
        max_hops = getattr(settings, "evidence_redirect_max_hops", 5)
        redir_timeout = getattr(settings, "evidence_redirect_timeout_seconds", 3.0)
        redirects: RedirectChecker = SafeRedirectChecker(
            max_hops=max_hops,
            timeout=redir_timeout,
            dns_resolver=dns,
        )
    else:
        redirects = UnavailableRedirect()

    return dns, rdap, redirects
