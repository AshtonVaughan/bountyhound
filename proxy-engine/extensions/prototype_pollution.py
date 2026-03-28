"""Prototype Pollution — inject __proto__ and constructor.prototype payloads in JSON bodies and query params."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.prototype-pollution")

NAME = "prototype-pollution"
DESCRIPTION = "Inject __proto__ and constructor.prototype payloads in JSON bodies and query params"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "timeout": 10.0,
}

# Canary value to check for pollution
CANARY = "ppolluted_9x7k"

# Payloads for query parameter injection
QUERY_PAYLOADS = [
    ("__proto__[polluted]", CANARY),
    ("__proto__.polluted", CANARY),
    ("constructor[prototype][polluted]", CANARY),
    ("constructor.prototype.polluted", CANARY),
    ("__proto__[toString]", CANARY),
    ("__proto__[constructor]", CANARY),
    ("__proto__[__proto__][polluted]", CANARY),
]

# JSON body payloads
JSON_PAYLOADS = [
    {"__proto__": {"polluted": CANARY}},
    {"constructor": {"prototype": {"polluted": CANARY}}},
    {"__proto__": {"toString": CANARY}},
    {"__proto__": {"polluted": CANARY, "isAdmin": True}},
    {"a": {"__proto__": {"polluted": CANARY}}},
    {"a": 1, "__proto__": {"polluted": CANARY}},
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Test for prototype pollution via query params and JSON bodies."""
    findings: list[ScanFinding] = []
    timeout = _config.get("timeout", 10.0)

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        # Get baseline response
        try:
            baseline = await client.get(url)
        except Exception as e:
            log.debug(f"Baseline request failed: {e}")
            return findings

        # Test query parameter pollution
        findings.extend(await _test_query_params(client, url, baseline))

        # Test JSON body pollution
        findings.extend(await _test_json_body(client, url, baseline))

        # Test via URL path segments
        findings.extend(await _test_path_pollution(client, url, baseline))

    return findings


async def _test_query_params(
    client: httpx.AsyncClient, url: str, baseline: httpx.Response
) -> list[ScanFinding]:
    """Inject prototype pollution payloads via query parameters."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)

    for param_name, param_value in QUERY_PAYLOADS:
        # Merge with existing query params
        existing_params = parse_qs(parsed.query, keep_blank_values=True)
        existing_params[param_name] = [param_value]
        new_query = urlencode(existing_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            resp = await client.get(test_url)
            body = resp.text

            # Check if canary appears in response
            if CANARY in body and CANARY not in baseline.text:
                findings.append(ScanFinding(
                    template_id="prototype_pollution_query",
                    name="Prototype Pollution via Query Parameter",
                    severity="high",
                    url=url,
                    matched_at=test_url,
                    description=(
                        f"Prototype pollution canary '{CANARY}' reflected in response after "
                        f"injecting '{param_name}={param_value}' in query parameters. "
                        "Server-side prototype pollution can lead to RCE, privilege escalation, "
                        "or authentication bypass."
                    ),
                    extracted=[
                        f"Parameter: {param_name}={param_value}",
                        f"Canary found in response body",
                    ],
                    source="extension",
                    confidence="confirmed",
                    remediation=(
                        "Sanitize JSON parsing: reject keys containing '__proto__', 'constructor', "
                        "or 'prototype'. Use Object.create(null) for plain objects."
                    ),
                ))
                break

            # Check for error messages that indicate prototype access
            pollution_indicators = [
                "prototype", "__proto__", "constructor",
                "polluted", "object Object",
            ]
            if any(ind in body.lower() for ind in pollution_indicators):
                if not any(ind in baseline.text.lower() for ind in pollution_indicators):
                    findings.append(ScanFinding(
                        template_id="prototype_pollution_query_indicator",
                        name="Prototype Pollution Indicator (Query Parameter)",
                        severity="medium",
                        url=url,
                        matched_at=test_url,
                        description=(
                            f"Prototype-related keywords appeared in response after injecting "
                            f"'{param_name}'. Further investigation recommended."
                        ),
                        extracted=[f"Parameter: {param_name}={param_value}"],
                        source="extension",
                        confidence="tentative",
                        remediation="Review server-side object merging logic for prototype pollution.",
                    ))
                    break

        except Exception as e:
            log.debug(f"Query param pollution test error: {e}")

    return findings


async def _test_json_body(
    client: httpx.AsyncClient, url: str, baseline: httpx.Response
) -> list[ScanFinding]:
    """Inject prototype pollution payloads via JSON request body."""
    findings: list[ScanFinding] = []

    for payload in JSON_PAYLOADS:
        try:
            resp = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            body = resp.text

            if CANARY in body and CANARY not in baseline.text:
                findings.append(ScanFinding(
                    template_id="prototype_pollution_json",
                    name="Prototype Pollution via JSON Body",
                    severity="high",
                    url=url,
                    matched_at=url,
                    description=(
                        f"Prototype pollution canary '{CANARY}' reflected after sending "
                        f"malicious JSON payload. Payload: {json.dumps(payload)[:200]}"
                    ),
                    extracted=[
                        f"Payload: {json.dumps(payload)[:200]}",
                        "Canary reflected in response",
                    ],
                    source="extension",
                    confidence="confirmed",
                    remediation=(
                        "Use safe JSON parsing that strips __proto__ and constructor keys. "
                        "Consider using JSON.parse with a reviver function or a safe merge library."
                    ),
                ))
                break

            # Check for server-side effects (different status, new headers)
            if resp.status_code != baseline.status_code:
                findings.append(ScanFinding(
                    template_id="prototype_pollution_json_status",
                    name="Prototype Pollution: Status Code Change (JSON)",
                    severity="medium",
                    url=url,
                    matched_at=url,
                    description=(
                        f"Status code changed from {baseline.status_code} to {resp.status_code} "
                        f"after sending __proto__ payload. Possible server-side prototype pollution."
                    ),
                    extracted=[
                        f"Payload: {json.dumps(payload)[:200]}",
                        f"Baseline status: {baseline.status_code}",
                        f"Pollution status: {resp.status_code}",
                    ],
                    source="extension",
                    confidence="tentative",
                    remediation="Investigate status code change — may indicate prototype pollution affecting control flow.",
                ))
                break

        except Exception as e:
            log.debug(f"JSON body pollution test error: {e}")

    return findings


async def _test_path_pollution(
    client: httpx.AsyncClient, url: str, baseline: httpx.Response
) -> list[ScanFinding]:
    """Test pollution via URL path-based parameter parsing."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)

    # Some frameworks parse path segments as key-value
    pollution_paths = [
        f"{parsed.path}/__proto__/polluted/{CANARY}",
        f"{parsed.path}/__proto__[polluted]/{CANARY}",
    ]

    for path in pollution_paths:
        test_url = urlunparse(parsed._replace(path=path))
        try:
            resp = await client.get(test_url)
            if CANARY in resp.text and CANARY not in baseline.text:
                findings.append(ScanFinding(
                    template_id="prototype_pollution_path",
                    name="Prototype Pollution via URL Path",
                    severity="high",
                    url=url,
                    matched_at=test_url,
                    description=(
                        f"Prototype pollution canary reflected after injecting __proto__ "
                        f"in URL path segment."
                    ),
                    extracted=[f"Path: {path}"],
                    source="extension",
                    confidence="confirmed",
                    remediation="Sanitize URL path parsing. Block __proto__ and constructor in path segments.",
                ))
                break
        except Exception:
            continue

    return findings
