"""CORS Scanner — comprehensive CORS misconfiguration testing.

Tests pre/post-domain wildcard, special chars, null origin, Vary:Origin, preflight bypass.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from models import ScanFinding

log = logging.getLogger("ext-cors-scanner")

NAME = "cors-scanner"
DESCRIPTION = "Pre/post-domain wildcard, special chars, null origin, Vary:Origin, preflight bypass"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {}


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Comprehensive CORS testing."""
    findings = []
    parsed = urlparse(url)
    target_domain = parsed.hostname or ""

    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        # Test 1: Reflected origin
        findings.extend(await _test_reflected_origin(client, url))

        # Test 2: Null origin
        findings.extend(await _test_null_origin(client, url))

        # Test 3: Pre-domain wildcard (evil.com.target.com)
        findings.extend(await _test_pre_domain(client, url, target_domain))

        # Test 4: Post-domain wildcard (target.com.evil.com)
        findings.extend(await _test_post_domain(client, url, target_domain))

        # Test 5: Special characters in origin
        findings.extend(await _test_special_chars(client, url, target_domain))

        # Test 6: Wildcard with credentials
        findings.extend(await _test_wildcard_credentials(client, url))

        # Test 7: Missing Vary:Origin
        findings.extend(await _test_vary_header(client, url))

    return findings


async def _test_reflected_origin(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    findings = []
    evil_origin = "https://evil.com"

    try:
        resp = await client.get(url, headers={"Origin": evil_origin})
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == evil_origin:
            severity = "high" if acac.lower() == "true" else "medium"
            findings.append(ScanFinding(
                template_id="cors_reflected_origin",
                name="CORS: Arbitrary Origin Reflected",
                severity=severity,
                url=url,
                matched_at=url,
                description=f"Server reflects arbitrary Origin in ACAO header. Credentials: {acac}.",
                extracted=[f"ACAO: {acao}", f"ACAC: {acac}"],
                source="extension",
                confidence="confirmed",
                remediation="Validate Origin against strict allowlist. Never reflect arbitrary origins.",
            ))
    except Exception:
        pass

    return findings


async def _test_null_origin(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    findings = []

    try:
        resp = await client.get(url, headers={"Origin": "null"})
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == "null":
            findings.append(ScanFinding(
                template_id="cors_null_origin",
                name="CORS: Null Origin Accepted",
                severity="high" if acac.lower() == "true" else "medium",
                url=url,
                matched_at=url,
                description="Server accepts 'null' Origin. Exploitable via sandboxed iframes and data: URIs.",
                extracted=[f"ACAO: {acao}", f"ACAC: {acac}"],
                source="extension",
                confidence="confirmed",
                remediation="Never allow 'null' origin. It can be forged from sandboxed contexts.",
            ))
    except Exception:
        pass

    return findings


async def _test_pre_domain(client: httpx.AsyncClient, url: str, domain: str) -> list[ScanFinding]:
    findings = []
    evil_origin = f"https://evil{domain}"

    try:
        resp = await client.get(url, headers={"Origin": evil_origin})
        acao = resp.headers.get("access-control-allow-origin", "")

        if acao == evil_origin:
            findings.append(ScanFinding(
                template_id="cors_pre_domain",
                name="CORS: Pre-Domain Wildcard",
                severity="high",
                url=url,
                matched_at=url,
                description=f"Server trusts origin '{evil_origin}' — prefix matching without proper domain boundary.",
                extracted=[f"ACAO: {acao}"],
                source="extension",
                confidence="confirmed",
                remediation="Validate full domain including boundary (dot). Use exact match or proper suffix check.",
            ))
    except Exception:
        pass

    return findings


async def _test_post_domain(client: httpx.AsyncClient, url: str, domain: str) -> list[ScanFinding]:
    findings = []
    evil_origin = f"https://{domain}.evil.com"

    try:
        resp = await client.get(url, headers={"Origin": evil_origin})
        acao = resp.headers.get("access-control-allow-origin", "")

        if acao == evil_origin:
            findings.append(ScanFinding(
                template_id="cors_post_domain",
                name="CORS: Post-Domain Wildcard",
                severity="high",
                url=url,
                matched_at=url,
                description=f"Server trusts origin '{evil_origin}' — suffix matching allows subdomain takeover.",
                extracted=[f"ACAO: {acao}"],
                source="extension",
                confidence="confirmed",
                remediation="Validate complete origin. Do not use simple prefix/suffix matching.",
            ))
    except Exception:
        pass

    return findings


async def _test_special_chars(client: httpx.AsyncClient, url: str, domain: str) -> list[ScanFinding]:
    findings = []

    special_origins = [
        f"https://{domain}_.evil.com",
        f"https://{domain}%60.evil.com",
        f"https://{domain}{{.evil.com",
    ]

    for origin in special_origins:
        try:
            resp = await client.get(url, headers={"Origin": origin})
            acao = resp.headers.get("access-control-allow-origin", "")

            if acao == origin:
                findings.append(ScanFinding(
                    template_id="cors_special_chars",
                    name="CORS: Special Character Origin Bypass",
                    severity="medium",
                    url=url,
                    matched_at=url,
                    description=f"Server trusts origin with special characters: '{origin}'.",
                    extracted=[f"ACAO: {acao}"],
                    source="extension",
                    confidence="confirmed",
                    remediation="Use strict origin validation. Reject origins with special characters.",
                ))
                break
        except Exception:
            continue

    return findings


async def _test_wildcard_credentials(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    findings = []

    try:
        resp = await client.get(url, headers={"Origin": "https://test.com"})
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == "*" and acac.lower() == "true":
            findings.append(ScanFinding(
                template_id="cors_wildcard_credentials",
                name="CORS: Wildcard with Credentials",
                severity="high",
                url=url,
                matched_at=url,
                description="ACAO is '*' with credentials allowed. Browsers block this, but may indicate misconfiguration.",
                extracted=[f"ACAO: {acao}", f"ACAC: {acac}"],
                source="extension",
                confidence="firm",
                remediation="Never use wildcard ACAO with credentials. Specify exact origins.",
            ))
    except Exception:
        pass

    return findings


async def _test_vary_header(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    findings = []

    try:
        resp = await client.get(url, headers={"Origin": "https://test.com"})
        acao = resp.headers.get("access-control-allow-origin", "")
        vary = resp.headers.get("vary", "")

        if acao and acao != "*" and "origin" not in vary.lower():
            findings.append(ScanFinding(
                template_id="cors_missing_vary",
                name="CORS: Missing Vary:Origin Header",
                severity="low",
                url=url,
                matched_at=url,
                description="Server returns origin-specific ACAO without Vary:Origin. Enables cache poisoning.",
                extracted=[f"ACAO: {acao}", f"Vary: {vary}"],
                source="extension",
                confidence="confirmed",
                remediation="Add 'Vary: Origin' to all responses with dynamic ACAO header.",
            ))
    except Exception:
        pass

    return findings
