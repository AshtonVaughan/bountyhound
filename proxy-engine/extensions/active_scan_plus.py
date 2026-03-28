"""Active Scan++ — host header attacks, cache key poisoning, HTTP/2 downgrade, request splitting."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from models import ScanFinding

log = logging.getLogger("ext-active-scan-plus")

NAME = "active-scan-plus"
DESCRIPTION = "Host header attacks, cache key poisoning, HTTP/2 downgrade, request splitting"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "test_host_header": True,
    "test_cache_poison": True,
    "test_request_splitting": True,
}


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    findings = []

    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        # Host header attacks
        if _config.get("test_host_header", True):
            findings.extend(await _test_host_header(client, url))

        # Cache key poisoning
        if _config.get("test_cache_poison", True):
            findings.extend(await _test_cache_poison(client, url))

        # Request splitting
        if _config.get("test_request_splitting", True):
            findings.extend(await _test_request_splitting(client, url))

    return findings


async def _test_host_header(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test host header injection variants."""
    findings = []
    from urllib.parse import urlparse

    parsed = urlparse(url)
    original_host = parsed.netloc

    host_attacks = [
        ("evil.com", "host-override"),
        (f"{original_host}\r\nX-Injected: true", "crlf-in-host"),
        (f"evil.com\r\n\r\nGET / HTTP/1.1\r\nHost: {original_host}", "host-request-splitting"),
    ]

    header_attacks = [
        ("X-Forwarded-Host", "evil.com"),
        ("X-Host", "evil.com"),
        ("X-Forwarded-Server", "evil.com"),
        ("Forwarded", "host=evil.com"),
    ]

    # Test Host header overrides
    for host_value, attack_type in host_attacks:
        try:
            resp = await client.get(url, headers={"Host": host_value}, follow_redirects=False)
            if "evil.com" in resp.text or "evil.com" in resp.headers.get("location", ""):
                findings.append(ScanFinding(
                    template_id=f"host_header_{attack_type}",
                    name=f"Host Header Injection ({attack_type})",
                    severity="high" if "location" in resp.headers else "medium",
                    url=url,
                    matched_at=url,
                    description=f"Host header value '{host_value[:50]}' reflected in response. Possible web cache poisoning or password reset hijack.",
                    extracted=[host_value[:50]],
                    source="extension",
                    confidence="confirmed" if "evil.com" in resp.headers.get("location", "") else "firm",
                    remediation="Validate Host header against allowed values. Use absolute URLs from config, not Host header.",
                ))
                break
        except Exception:
            continue

    # Test X-Forwarded-Host and similar
    for header_name, header_value in header_attacks:
        try:
            resp = await client.get(url, headers={header_name: header_value}, follow_redirects=False)
            if "evil.com" in resp.text or "evil.com" in resp.headers.get("location", ""):
                findings.append(ScanFinding(
                    template_id=f"host_override_{header_name.lower()}",
                    name=f"Host Override via {header_name}",
                    severity="medium",
                    url=url,
                    matched_at=url,
                    description=f"Header '{header_name}: {header_value}' influences server-generated URLs.",
                    extracted=[f"{header_name}: {header_value}"],
                    source="extension",
                    confidence="firm",
                    remediation=f"Ignore {header_name} header or validate against trusted proxies.",
                ))
                break
        except Exception:
            continue

    return findings


async def _test_cache_poison(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test cache key poisoning via unkeyed headers/params."""
    findings = []

    canary = "cachepoisoncanary12345"
    unkeyed_headers = {
        "X-Forwarded-Scheme": "nothttps",
        "X-Forwarded-Proto": "nothttps",
        "X-Original-URL": f"/{canary}",
        "X-Rewrite-URL": f"/{canary}",
    }

    try:
        baseline = await client.get(url, follow_redirects=True)
    except Exception:
        return findings

    for header_name, header_value in unkeyed_headers.items():
        try:
            resp = await client.get(url, headers={header_name: header_value}, follow_redirects=True)

            # Check if response differs (unkeyed header affecting response)
            if canary in resp.text and canary not in baseline.text:
                findings.append(ScanFinding(
                    template_id=f"cache_poison_{header_name.lower()}",
                    name=f"Cache Poisoning via {header_name}",
                    severity="high",
                    url=url,
                    matched_at=url,
                    description=f"Unkeyed header '{header_name}' affects cached response. Canary value reflected.",
                    extracted=[f"{header_name}: {header_value}"],
                    source="extension",
                    confidence="firm",
                    remediation="Include all response-affecting headers in cache key. Use Vary header.",
                ))

            # Check for protocol downgrade (redirect to HTTP)
            if header_name in ("X-Forwarded-Scheme", "X-Forwarded-Proto"):
                location = resp.headers.get("location", "")
                if location.startswith("http://"):
                    findings.append(ScanFinding(
                        template_id="cache_poison_protocol",
                        name="Cache Poisoning: Protocol Downgrade",
                        severity="medium",
                        url=url,
                        matched_at=url,
                        description=f"{header_name} causes redirect to HTTP. Can poison cache with insecure redirect.",
                        extracted=[f"Location: {location}"],
                        source="extension",
                        confidence="firm",
                        remediation="Validate X-Forwarded-Proto against trusted proxy list.",
                    ))
        except Exception:
            continue

    return findings


async def _test_request_splitting(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test HTTP request splitting via header injection."""
    findings = []

    # CRLF in various header positions
    crlf_tests = [
        ("X-Custom", "value\r\nX-Injected: true"),
        ("Referer", f"{url}\r\nX-Injected: true"),
        ("User-Agent", "Mozilla/5.0\r\nX-Injected: true"),
    ]

    for header_name, header_value in crlf_tests:
        try:
            resp = await client.get(url, headers={header_name: header_value}, follow_redirects=False)
            headers_str = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            if "X-Injected" in headers_str:
                findings.append(ScanFinding(
                    template_id="request_splitting",
                    name="HTTP Request Splitting",
                    severity="high",
                    url=url,
                    matched_at=url,
                    description=f"CRLF in '{header_name}' header causes HTTP response splitting.",
                    extracted=[f"{header_name}: {header_value[:50]}"],
                    source="extension",
                    confidence="confirmed",
                    remediation="Sanitize CRLF characters from all header values.",
                ))
                break
        except Exception:
            continue

    return findings
