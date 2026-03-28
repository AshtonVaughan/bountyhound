"""WebSocket Scanner — test for XSS/SQLi injection and origin bypass on WebSocket endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from urllib.parse import urlparse

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.websocket-scanner")

NAME = "websocket-scanner"
DESCRIPTION = "WebSocket XSS/SQLi injection, origin bypass, and protocol abuse testing"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "timeout": 10.0,
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><svg/onload=alert(1)>",
    "javascript:alert(1)",
    "${7*7}",
    "{{7*7}}",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1' OR '1'='1' --",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL,NULL--",
    "1 AND SLEEP(3)",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Test WebSocket endpoint for injection and origin bypass."""
    findings: list[ScanFinding] = []
    timeout = _config.get("timeout", 10.0)

    # Derive WebSocket URL
    parsed = urlparse(url)
    if parsed.scheme == "https":
        ws_url = url.replace("https://", "wss://", 1)
    elif parsed.scheme == "http":
        ws_url = url.replace("http://", "ws://", 1)
    elif parsed.scheme in ("ws", "wss"):
        ws_url = url
    else:
        ws_url = f"ws://{parsed.netloc}{parsed.path}"

    # Test origin bypass
    findings.extend(await _test_origin_bypass(ws_url, parsed, timeout))

    # Test XSS payloads
    findings.extend(await _test_xss(ws_url, parsed, timeout))

    # Test SQLi payloads
    findings.extend(await _test_sqli(ws_url, parsed, timeout))

    # Test unauthenticated access
    findings.extend(await _test_no_auth(ws_url, parsed, timeout))

    return findings


async def _ws_connect_and_send(
    ws_url: str, message: str, origin: str | None = None, timeout: float = 10.0
) -> tuple[bool, str]:
    """Connect to WebSocket, send message, return (connected, response)."""
    try:
        import websockets
    except ImportError:
        try:
            import aiohttp

            return await _ws_via_aiohttp(ws_url, message, origin, timeout)
        except ImportError:
            log.debug("Neither websockets nor aiohttp installed; skipping WS tests")
            return False, ""

    import websockets.client

    extra_headers = {}
    if origin:
        extra_headers["Origin"] = origin

    try:
        async with websockets.client.connect(
            ws_url,
            additional_headers=extra_headers,
            open_timeout=timeout,
            close_timeout=5,
        ) as ws:
            await ws.send(message)
            try:
                response = await asyncio.wait_for(ws.recv(), timeout=timeout)
                return True, str(response)
            except asyncio.TimeoutError:
                return True, ""
    except Exception as e:
        log.debug(f"WS connect error: {e}")
        return False, str(e)


async def _ws_via_aiohttp(
    ws_url: str, message: str, origin: str | None, timeout: float
) -> tuple[bool, str]:
    """Fallback WebSocket testing via aiohttp."""
    import aiohttp

    headers = {}
    if origin:
        headers["Origin"] = origin

    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(
                ws_url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as ws:
                await ws.send_str(message)
                try:
                    msg = await asyncio.wait_for(ws.receive(), timeout=timeout)
                    if msg.type in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                        return True, str(msg.data)
                    return True, ""
                except asyncio.TimeoutError:
                    return True, ""
    except Exception as e:
        log.debug(f"aiohttp WS error: {e}")
        return False, str(e)


async def _test_origin_bypass(
    ws_url: str, parsed: Any, timeout: float
) -> list[ScanFinding]:
    """Test if WebSocket accepts connections from arbitrary Origin."""
    findings: list[ScanFinding] = []

    evil_origins = [
        "https://evil.com",
        "https://attacker.example.com",
        "null",
    ]

    for origin in evil_origins:
        connected, response = await _ws_connect_and_send(
            ws_url, "ping", origin=origin, timeout=timeout
        )

        if connected:
            findings.append(ScanFinding(
                template_id="ws_origin_bypass",
                name="WebSocket Origin Bypass",
                severity="high",
                url=ws_url,
                matched_at=ws_url,
                description=(
                    f"WebSocket endpoint accepted connection from Origin: '{origin}'. "
                    "Cross-Site WebSocket Hijacking (CSWSH) is possible."
                ),
                extracted=[
                    f"Origin: {origin}",
                    f"Response: {response[:200]}" if response else "No response data",
                ],
                source="extension",
                confidence="confirmed",
                remediation=(
                    "Validate Origin header on WebSocket handshake. "
                    "Reject connections from untrusted origins."
                ),
            ))
            break  # One proof is enough

    return findings


async def _test_xss(
    ws_url: str, parsed: Any, timeout: float
) -> list[ScanFinding]:
    """Send XSS payloads and check for reflection."""
    findings: list[ScanFinding] = []

    for payload in XSS_PAYLOADS:
        # Try as plain text
        connected, response = await _ws_connect_and_send(ws_url, payload, timeout=timeout)
        if not connected:
            break

        if payload in response or (payload.replace("'", "&#39;") not in response and payload in response):
            findings.append(ScanFinding(
                template_id="ws_xss_reflection",
                name="WebSocket XSS: Payload Reflected",
                severity="high",
                url=ws_url,
                matched_at=ws_url,
                description=(
                    f"XSS payload reflected in WebSocket response without encoding. "
                    f"Payload: {payload}"
                ),
                extracted=[f"Payload: {payload}", f"Response: {response[:300]}"],
                source="extension",
                confidence="firm",
                remediation="Sanitize and encode all user input in WebSocket messages before rendering.",
            ))
            break

        # Try as JSON
        json_msg = json.dumps({"message": payload, "data": payload})
        connected, response = await _ws_connect_and_send(ws_url, json_msg, timeout=timeout)
        if connected and payload in response:
            findings.append(ScanFinding(
                template_id="ws_xss_json_reflection",
                name="WebSocket XSS: JSON Payload Reflected",
                severity="high",
                url=ws_url,
                matched_at=ws_url,
                description=(
                    f"XSS payload in JSON message reflected in WebSocket response. "
                    f"Payload: {payload}"
                ),
                extracted=[f"Sent: {json_msg[:200]}", f"Response: {response[:300]}"],
                source="extension",
                confidence="firm",
                remediation="Sanitize user-controlled fields in JSON WebSocket messages.",
            ))
            break

    return findings


async def _test_sqli(
    ws_url: str, parsed: Any, timeout: float
) -> list[ScanFinding]:
    """Send SQLi payloads and check for error-based indicators."""
    findings: list[ScanFinding] = []

    sql_errors = [
        "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
        "unclosed quotation", "syntax error", "ORA-", "PG::",
        "microsoft sql", "odbc", "jdbc", "you have an error in your sql",
    ]

    for payload in SQLI_PAYLOADS:
        connected, response = await _ws_connect_and_send(ws_url, payload, timeout=timeout)
        if not connected:
            break

        response_lower = response.lower()
        for error_pattern in sql_errors:
            if error_pattern.lower() in response_lower:
                findings.append(ScanFinding(
                    template_id="ws_sqli",
                    name="WebSocket SQL Injection",
                    severity="high",
                    url=ws_url,
                    matched_at=ws_url,
                    description=(
                        f"SQL error message detected in WebSocket response after injection. "
                        f"Payload: {payload}. Error indicator: '{error_pattern}'"
                    ),
                    extracted=[
                        f"Payload: {payload}",
                        f"Error: {error_pattern}",
                        f"Response: {response[:300]}",
                    ],
                    source="extension",
                    confidence="firm",
                    remediation="Use parameterized queries for all database operations in WebSocket handlers.",
                ))
                return findings

    return findings


async def _test_no_auth(
    ws_url: str, parsed: Any, timeout: float
) -> list[ScanFinding]:
    """Test if WebSocket accepts connections without authentication."""
    findings: list[ScanFinding] = []

    # Try connecting with no cookies or auth headers at all
    connected, response = await _ws_connect_and_send(
        ws_url, '{"action":"list","type":"users"}', timeout=timeout
    )

    if connected and response:
        # Check if response contains sensitive data indicators
        sensitive_indicators = [
            "password", "email", "token", "secret", "admin",
            "user_id", "session", "credit_card", "ssn",
        ]
        response_lower = response.lower()
        found_sensitive = [ind for ind in sensitive_indicators if ind in response_lower]

        if found_sensitive:
            findings.append(ScanFinding(
                template_id="ws_no_auth",
                name="WebSocket: Unauthenticated Data Access",
                severity="high",
                url=ws_url,
                matched_at=ws_url,
                description=(
                    "WebSocket endpoint responds with potentially sensitive data "
                    f"without authentication. Indicators: {', '.join(found_sensitive)}"
                ),
                extracted=[
                    f"Indicators: {', '.join(found_sensitive)}",
                    f"Response: {response[:500]}",
                ],
                source="extension",
                confidence="firm",
                remediation="Require authentication for all WebSocket connections. Validate session tokens.",
            ))

    return findings
