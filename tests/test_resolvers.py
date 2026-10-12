"""Tests for Stage 5 optional network resolvers (DNS, RDAP, and SafeRedirectChecker).

Covers DNS resolution, timeouts, RDAP bootstrap and date parsing, SSRF-safe redirect
checks, private IP blocking, configuration factory, and integration with UrlDomainAnalyzer.
All tests use mocked network primitives and do not connect to live external services.
"""

from __future__ import annotations

import concurrent.futures
import socket
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from risk_radar.core.config import Settings
from risk_radar.evidence.resolvers import (
    HttpRdapClient,
    SafeRedirectChecker,
    SystemDnsResolver,
    UnavailableDns,
    UnavailableRdap,
    UnavailableRedirect,
    get_resolvers,
    is_safe_network_ip,
)
from risk_radar.evidence.url_domain import UrlDomainAnalyzer

# --- DNS Resolver Tests -----------------------------------------------------


def test_dns_resolver_success():
    resolver = SystemDnsResolver(timeout=2.0)
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),  # Duplicate
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0)),
    ]

    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        results = resolver.resolve("example.com")
        assert results == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]


def test_dns_resolver_handles_ip_literal_without_lookup():
    resolver = SystemDnsResolver(timeout=2.0)
    with patch("socket.getaddrinfo") as mock_lookup:
        assert resolver.resolve("198.51.100.1") == ["198.51.100.1"]
        mock_lookup.assert_not_called()


def test_dns_resolver_empty_or_whitespace_returns_none():
    resolver = SystemDnsResolver(timeout=2.0)
    assert resolver.resolve("") is None
    assert resolver.resolve("   ") is None


def test_dns_resolver_missing_records_returns_none():
    resolver = SystemDnsResolver(timeout=2.0)
    with patch("socket.getaddrinfo", side_effect=socket.gaierror(8, "nodename not found")):
        assert resolver.resolve("nonexistent.example") is None


def test_dns_resolver_timeout_returns_none():
    resolver = SystemDnsResolver(timeout=0.01)

    def slow_lookup(*args, **kwargs):
        raise concurrent.futures.TimeoutError()

    with patch.object(concurrent.futures.Future, "result", side_effect=slow_lookup):
        assert resolver.resolve("slow.example.com") is None


def test_dns_resolver_timeout_does_not_block_on_shutdown():
    release_event = threading.Event()

    def hanging_getaddrinfo(*args, **kwargs):
        release_event.wait(timeout=2.0)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    resolver = SystemDnsResolver(timeout=0.05, max_workers=2)
    with patch("socket.getaddrinfo", side_effect=hanging_getaddrinfo):
        start = time.perf_counter()
        result = resolver.resolve("hanging.example.com")
        elapsed = time.perf_counter() - start

        # Must return None within bounded time (< 0.4s), not waiting 2.0s for the worker.
        assert result is None
        assert elapsed < 0.4

    release_event.set()


def test_dns_resolver_repeated_timeouts_bounded_worker_growth():
    release_event = threading.Event()

    def hanging_getaddrinfo(*args, **kwargs):
        release_event.wait(timeout=1.0)
        return []

    custom_pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=2, thread_name_prefix="test-dns-bounded"
    )
    resolver = SystemDnsResolver(timeout=0.02, executor=custom_pool)

    with patch("socket.getaddrinfo", side_effect=hanging_getaddrinfo):
        for _ in range(8):
            res = resolver.resolve("slow.example.com")
            assert res is None

        # Verify threads in the pool are bounded by max_workers (<= 2)
        assert len(custom_pool._threads) <= 2

    release_event.set()
    custom_pool.shutdown(wait=False, cancel_futures=True)


def test_dns_resolver_concurrency():
    def fake_getaddrinfo(host, *args, **kwargs):
        ip = "192.0.2.1" if host == "alpha.example" else "192.0.2.2"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    resolver = SystemDnsResolver(timeout=2.0, max_workers=4)
    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(resolver.resolve, "alpha.example"),
                pool.submit(resolver.resolve, "beta.example"),
                pool.submit(resolver.resolve, "alpha.example"),
                pool.submit(resolver.resolve, "beta.example"),
            ]
            results = [f.result() for f in futures]
            assert results[0] == ["192.0.2.1"]
            assert results[1] == ["192.0.2.2"]
            assert results[2] == ["192.0.2.1"]
            assert results[3] == ["192.0.2.2"]



# --- RDAP Client Tests ------------------------------------------------------


def test_rdap_client_success_and_date_parsing():
    now = datetime.now(UTC)
    created_dt = now - timedelta(days=45)
    created_iso = created_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    sample_rdap_payload = {
        "handle": "example.com",
        "ldhName": "EXAMPLE.COM",
        "events": [
            {"eventAction": "registration", "eventDate": created_iso},
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Safe Registrar LLC"],
                    ],
                ],
            }
        ],
    }

    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = sample_rdap_payload
    mock_client.get.return_value = mock_resp

    client = HttpRdapClient(base_url="https://rdap.org/domain/", client=mock_client)
    result = client.registration("example.com")

    assert result is not None
    assert result["domain"] == "example.com"
    assert result["created"] == created_iso
    assert result["domain_age_days"] == 45
    assert result["registrar"] == "Safe Registrar LLC"
    assert result["expiration"] == "2030-01-01T00:00:00Z"


def test_rdap_client_missing_registration_never_infers_age():
    sample_payload = {
        "handle": "example.com",
        "events": [
            {"eventAction": "last changed", "eventDate": "2024-06-01T00:00:00Z"}
        ],
    }

    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = sample_payload
    mock_client.get.return_value = mock_resp

    client = HttpRdapClient(client=mock_client)
    result = client.registration("example.com")

    assert result is not None
    assert "created" not in result
    assert "domain_age_days" not in result


def test_rdap_client_future_date_not_inferred_as_age():
    future_date = (datetime.now(UTC) + timedelta(days=10)).isoformat()
    sample_payload = {
        "handle": "future.example",
        "events": [{"eventAction": "registration", "eventDate": future_date}],
    }

    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = sample_payload
    mock_client.get.return_value = mock_resp

    client = HttpRdapClient(client=mock_client)
    result = client.registration("future.example")
    assert result is not None
    assert "domain_age_days" not in result


def test_rdap_client_404_or_rate_limit_returns_none():
    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_client.get.return_value = mock_resp

    client = HttpRdapClient(client=mock_client)
    assert client.registration("unknown.example") is None

    mock_resp.status_code = 429
    assert client.registration("limited.example") is None


def test_rdap_client_timeout_or_http_error_returns_none():
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.side_effect = httpx.ConnectTimeout("connection timed out")

    client = HttpRdapClient(client=mock_client)
    assert client.registration("timeout.example") is None


def test_rdap_client_malformed_json_returns_none():
    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Invalid JSON")
    mock_client.get.return_value = mock_resp

    client = HttpRdapClient(client=mock_client)
    assert client.registration("corrupt.example") is None


# --- SSRF and Redirect Checker Tests ----------------------------------------


@pytest.mark.parametrize(
    ("ip_str", "is_safe"),
    [
        ("93.184.216.34", True),
        ("8.8.8.8", True),
        ("2606:2800:220:1:248:1893:25c8:1946", True),
        ("127.0.0.1", False),
        ("127.0.0.2", False),
        ("::1", False),
        ("10.0.0.1", False),
        ("192.168.1.1", False),
        ("172.16.0.1", False),
        ("172.31.255.255", False),
        ("169.254.169.254", False),  # AWS / cloud metadata
        ("169.254.170.2", False),
        ("fd00:ec2::254", False),
        ("0.0.0.0", False),
        ("224.0.0.1", False),  # Multicast
    ],
)
def test_is_safe_network_ip(ip_str: str, is_safe: bool):
    assert is_safe_network_ip(ip_str) is is_safe


def test_redirect_checker_follows_safe_redirect():
    class MockDns:
        def resolve(self, host: str):
            return ["93.184.216.34"]

    mock_client = MagicMock(spec=httpx.Client)
    resp1 = MagicMock()
    resp1.status_code = 301
    resp1.headers = {"location": "https://landing.example.com/home"}

    resp2 = MagicMock()
    resp2.status_code = 200
    resp2.headers = {}

    mock_client.head.side_effect = [resp1, resp2]

    checker = SafeRedirectChecker(dns_resolver=MockDns(), client=mock_client)
    final = checker.final_url("https://start.example.com")
    assert final == "https://landing.example.com/home"


def test_redirect_checker_blocks_redirect_to_loopback_or_private():
    class MockDns:
        def resolve(self, host: str):
            if "private" in host:
                return ["10.0.0.5"]
            if "metadata" in host:
                return ["169.254.169.254"]
            return ["93.184.216.34"]

    mock_client = MagicMock(spec=httpx.Client)
    resp1 = MagicMock()
    resp1.status_code = 302
    resp1.headers = {"location": "http://private.internal/admin"}
    mock_client.head.return_value = resp1

    checker = SafeRedirectChecker(dns_resolver=MockDns(), client=mock_client)
    assert checker.final_url("https://safe.example.com") is None


def test_redirect_checker_blocks_initial_private_destination():
    class MockDns:
        def resolve(self, host: str):
            return ["127.0.0.1"]

    checker = SafeRedirectChecker(dns_resolver=MockDns())
    assert checker.final_url("http://localhost:8080/secret") is None


def test_redirect_checker_blocks_non_http_schemes():
    checker = SafeRedirectChecker()
    assert checker.final_url("file:///etc/passwd") is None
    assert checker.final_url("gopher://evil.com") is None
    assert checker.final_url("javascript:alert(1)") is None


def test_redirect_checker_exceeding_max_hops_returns_none():
    class MockDns:
        def resolve(self, host: str):
            return ["93.184.216.34"]

    mock_client = MagicMock(spec=httpx.Client)
    loop_resp = MagicMock()
    loop_resp.status_code = 302
    loop_resp.headers = {"location": "https://example.com/loop"}
    mock_client.head.return_value = loop_resp

    checker = SafeRedirectChecker(max_hops=2, dns_resolver=MockDns(), client=mock_client)
    assert checker.final_url("https://example.com/start") is None


# --- Factory & Integration Tests --------------------------------------------


def test_get_resolvers_factory_disabled_by_default():
    settings = Settings(evidence_enable_live_resolvers=False)
    dns, rdap, redirects = get_resolvers(settings)
    assert isinstance(dns, UnavailableDns)
    assert isinstance(rdap, UnavailableRdap)
    assert isinstance(redirects, UnavailableRedirect)


def test_get_resolvers_factory_enabled_without_redirects():
    settings = Settings(
        evidence_enable_live_resolvers=True,
        evidence_enable_redirects=False,
    )
    dns, rdap, redirects = get_resolvers(settings)
    assert isinstance(dns, SystemDnsResolver)
    assert isinstance(rdap, HttpRdapClient)
    assert isinstance(redirects, UnavailableRedirect)


def test_get_resolvers_factory_enabled_with_redirects():
    settings = Settings(
        evidence_enable_live_resolvers=True,
        evidence_enable_redirects=True,
    )
    dns, rdap, redirects = get_resolvers(settings)
    assert isinstance(dns, SystemDnsResolver)
    assert isinstance(rdap, HttpRdapClient)
    assert isinstance(redirects, SafeRedirectChecker)


def test_url_analyzer_integrates_with_domain_age_observation():
    class MockRdap:
        def registration(self, domain: str) -> dict[str, Any]:
            return {
                "domain": domain,
                "created": "2024-01-01T00:00:00Z",
                "domain_age_days": 180,
                "registrar": "Test Registrar",
            }

    class MockDns:
        def resolve(self, host: str):
            return ["93.184.216.34"]

    analyzer = UrlDomainAnalyzer(dns=MockDns(), rdap=MockRdap(), redirects=UnavailableRedirect())
    result = analyzer.analyze("https://example.com")

    obs_kinds = [o["kind"] for o in result.observations]
    assert "dns_addresses" in obs_kinds
    assert "registration" in obs_kinds
    assert "domain_age_days" in obs_kinds

    age_obs = next(o for o in result.observations if o["kind"] == "domain_age_days")
    assert age_obs["value"] == 180
    assert age_obs["method"] == "rdap_client"
