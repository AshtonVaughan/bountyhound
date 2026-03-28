"""Session Fixation — detect if session cookies persist across authentication boundaries."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.session-fixation")

NAME = "session-fixation"
DESCRIPTION = "Detect session fixation by comparing session cookies before and after authentication"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "timeout": 10.0,
    "auth_header": "",        # e.g., "Bearer <token>"
    "auth_cookie": "",        # e.g., "session=abc123"
    "login_url": "",          # optional login endpoint
    "login_body": "",         # optional login POST body
}

# Common session cookie names
SESSION_COOKIE_NAMES = [
    "sessionid", "session_id", "session", "sid", "sess",
    "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
    "connect.sid", "laravel_session", "ci_session",
    "CFID", "CFTOKEN", "_session_id", "rack.session",
    "express.sid", "token", "auth_token", "jwt",
    "_csrf_token", "csrftoken", "XSRF-TOKEN",
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Test for session fixation vulnerability."""
    findings: list[ScanFinding] = []
    timeout = _config.get("timeout", 10.0)

    async with httpx.AsyncClient(
        verify=False, timeout=timeout, follow_redirects=True
    ) as client:
        # ── Step 1: Get pre-auth session cookies ─────────────────────────
        pre_auth_cookies = await _get_session_cookies(client, url)
        if not pre_auth_cookies:
            log.debug(f"No session cookies found for {url}")
            return findings

        log.debug(f"Pre-auth cookies: {list(pre_auth_cookies.keys())}")

        # ── Step 2: Make authenticated request ───────────────────────────
        auth_headers = {}
        auth_cookie_header = _config.get("auth_cookie", "")
        auth_header = _config.get("auth_header", "")

        if auth_header:
            auth_headers["Authorization"] = auth_header
        if auth_cookie_header:
            auth_headers["Cookie"] = auth_cookie_header

        if not auth_headers:
            # Try login endpoint if configured
            login_url = _config.get("login_url", "")
            login_body = _config.get("login_body", "")

            if login_url and login_body:
                post_auth_cookies = await _login_and_get_cookies(
                    client, login_url, login_body, pre_auth_cookies
                )
            else:
                # No auth config — test with pre-auth cookies to see if they're accepted
                # This tests whether the server regenerates session on any state change
                post_auth_cookies = await _get_session_cookies(
                    client, url, extra_cookies=pre_auth_cookies
                )
        else:
            # Set pre-auth cookies and make authenticated request
            cookie_jar = httpx.Cookies()
            for name, value in pre_auth_cookies.items():
                cookie_jar.set(name, value)

            try:
                resp = await client.get(url, headers=auth_headers, cookies=cookie_jar)
                post_auth_cookies = _extract_session_cookies(resp)

                # If no new cookies set, check if old ones are still accepted
                if not post_auth_cookies:
                    post_auth_cookies = pre_auth_cookies
            except Exception as e:
                log.debug(f"Auth request error: {e}")
                return findings

        if not post_auth_cookies:
            return findings

        # ── Step 3: Compare session cookies ──────────────────────────────
        for cookie_name in pre_auth_cookies:
            pre_value = pre_auth_cookies[cookie_name]
            post_value = post_auth_cookies.get(cookie_name)

            if post_value is None:
                # Cookie was removed — not fixation
                continue

            if pre_value == post_value:
                findings.append(ScanFinding(
                    template_id="session_fixation",
                    name=f"Session Fixation: '{cookie_name}' Not Regenerated",
                    severity="high",
                    url=url,
                    matched_at=url,
                    description=(
                        f"Session cookie '{cookie_name}' was not regenerated after authentication. "
                        f"Pre-auth value: {pre_value[:20]}... "
                        f"Post-auth value: {post_value[:20]}... "
                        "An attacker can fixate a session and hijack the victim's authenticated session."
                    ),
                    extracted=[
                        f"Cookie: {cookie_name}",
                        f"Pre-auth: {pre_value[:30]}",
                        f"Post-auth: {post_value[:30]}",
                        "Values match: YES (vulnerable)",
                    ],
                    source="extension",
                    confidence="firm",
                    remediation=(
                        "Regenerate session ID after authentication (e.g., session.invalidate() + new session). "
                        "Set Secure, HttpOnly, and SameSite attributes on session cookies."
                    ),
                ))

        # ── Step 4: Check cookie attributes ──────────────────────────────
        findings.extend(await _check_cookie_attributes(client, url))

    return findings


async def _get_session_cookies(
    client: httpx.AsyncClient, url: str, extra_cookies: dict[str, str] | None = None
) -> dict[str, str]:
    """Make a request and extract session cookies."""
    try:
        cookies = httpx.Cookies()
        if extra_cookies:
            for name, value in extra_cookies.items():
                cookies.set(name, value)

        resp = await client.get(url, cookies=cookies)
        return _extract_session_cookies(resp)
    except Exception as e:
        log.debug(f"Get session cookies error: {e}")
        return {}


def _extract_session_cookies(resp: httpx.Response) -> dict[str, str]:
    """Extract session-like cookies from response."""
    session_cookies: dict[str, str] = {}

    for cookie_header in resp.headers.get_list("set-cookie"):
        parts = cookie_header.split(";")[0].strip()
        if "=" in parts:
            name, _, value = parts.partition("=")
            name = name.strip()
            value = value.strip()

            # Check if this looks like a session cookie
            if name.lower() in [n.lower() for n in SESSION_COOKIE_NAMES]:
                session_cookies[name] = value
            elif len(value) >= 16:
                # Long random-looking values are likely session IDs
                session_cookies[name] = value

    return session_cookies


async def _login_and_get_cookies(
    client: httpx.AsyncClient,
    login_url: str,
    login_body: str,
    pre_auth_cookies: dict[str, str],
) -> dict[str, str]:
    """Perform login with pre-auth cookies and return post-auth cookies."""
    try:
        cookies = httpx.Cookies()
        for name, value in pre_auth_cookies.items():
            cookies.set(name, value)

        resp = await client.post(
            login_url,
            content=login_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            cookies=cookies,
        )

        post_cookies = _extract_session_cookies(resp)
        # If no new cookies, the pre-auth ones may still be valid
        if not post_cookies:
            return pre_auth_cookies
        return post_cookies
    except Exception as e:
        log.debug(f"Login error: {e}")
        return {}


async def _check_cookie_attributes(
    client: httpx.AsyncClient, url: str
) -> list[ScanFinding]:
    """Check session cookie security attributes."""
    findings: list[ScanFinding] = []

    try:
        resp = await client.get(url)

        for cookie_header in resp.headers.get_list("set-cookie"):
            parts = cookie_header.split(";")
            if len(parts) < 1 or "=" not in parts[0]:
                continue

            name = parts[0].split("=")[0].strip()
            if name.lower() not in [n.lower() for n in SESSION_COOKIE_NAMES]:
                continue

            header_lower = cookie_header.lower()
            issues: list[str] = []

            if "secure" not in header_lower:
                issues.append("Missing 'Secure' flag")
            if "httponly" not in header_lower:
                issues.append("Missing 'HttpOnly' flag")
            if "samesite" not in header_lower:
                issues.append("Missing 'SameSite' attribute")
            elif "samesite=none" in header_lower:
                issues.append("SameSite=None (allows cross-site sending)")

            if issues:
                findings.append(ScanFinding(
                    template_id="session_cookie_attributes",
                    name=f"Session Cookie '{name}': Insecure Attributes",
                    severity="low",
                    url=url,
                    matched_at=url,
                    description=(
                        f"Session cookie '{name}' has insecure attributes: "
                        f"{'; '.join(issues)}"
                    ),
                    extracted=[f"Cookie: {name}", f"Issues: {'; '.join(issues)}"],
                    source="extension",
                    confidence="confirmed",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict/Lax on all session cookies.",
                ))

    except Exception as e:
        log.debug(f"Cookie attribute check error: {e}")

    return findings
