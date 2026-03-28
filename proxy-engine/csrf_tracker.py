"""Auto-CSRF Token Tracking — zero-config extraction and injection.

Automatically detects CSRF tokens in responses and injects them into subsequent requests.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

# CSRF token storage: host -> {param_name: value}
_tokens: dict[str, dict[str, str]] = {}

# Known CSRF patterns to look for in HTML forms and meta tags
_CSRF_PATTERNS = [
    # HTML form hidden fields
    (r'<input[^>]+name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)', 'csrf_token'),
    (r'<input[^>]+name=["\']_token["\'][^>]*value=["\']([^"\']+)', '_token'),
    (r'<input[^>]+name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)', 'authenticity_token'),
    (r'<input[^>]+name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)', '__RequestVerificationToken'),
    (r'<input[^>]+name=["\']_csrf["\'][^>]*value=["\']([^"\']+)', '_csrf'),
    (r'<input[^>]+name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)', 'csrfmiddlewaretoken'),
    (r'<input[^>]+name=["\']nonce["\'][^>]*value=["\']([^"\']+)', 'nonce'),
    # Reverse order (value before name)
    (r'<input[^>]+value=["\']([^"\']{20,})["\'][^>]*name=["\']csrf[_-]?token["\']', 'csrf_token'),
    (r'<input[^>]+value=["\']([^"\']{20,})["\'][^>]*name=["\']_token["\']', '_token'),
    # Meta tags
    (r'<meta[^>]+name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)', 'X-CSRF-TOKEN'),
    (r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*name=["\']csrf-token["\']', 'X-CSRF-TOKEN'),
    # JSON responses
    (r'"csrf[_-]?[Tt]oken"\s*:\s*"([^"]+)"', 'csrf_token'),
    (r'"_token"\s*:\s*"([^"]+)"', '_token'),
]

# Headers that commonly carry CSRF tokens
_CSRF_HEADERS = [
    'x-csrf-token', 'x-xsrf-token', 'csrf-token', 'x-csrftoken',
]

# Cookies that commonly carry CSRF tokens
_CSRF_COOKIES = [
    'csrf', 'csrftoken', 'xsrf-token', '_csrf', 'csrf_token',
]

enabled: bool = True


def extract_from_response(host: str, headers: dict[str, str], body: str | None) -> list[dict]:
    """Extract CSRF tokens from response. Called in addon.py response()."""
    if not enabled:
        return []

    extracted: list[dict] = []

    # Check Set-Cookie headers for CSRF cookies
    for k, v in headers.items():
        if k.lower() == 'set-cookie':
            cookie_name = v.split('=')[0].strip()
            if any(csrf.lower() in cookie_name.lower() for csrf in _CSRF_COOKIES):
                cookie_value = v.split('=', 1)[1].split(';')[0].strip() if '=' in v else ''
                if cookie_value:
                    _store_token(host, cookie_name, cookie_value, 'cookie')
                    extracted.append({'name': cookie_name, 'value': cookie_value[:20] + '...', 'source': 'cookie'})

    # Check response headers
    for k, v in headers.items():
        if k.lower() in _CSRF_HEADERS:
            _store_token(host, k, v, 'header')
            extracted.append({'name': k, 'value': v[:20] + '...', 'source': 'header'})

    # Check body for CSRF patterns
    if body:
        for pattern, param_name in _CSRF_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if match:
                value = match.group(1)
                _store_token(host, param_name, value, 'body')
                extracted.append({'name': param_name, 'value': value[:20] + '...', 'source': 'body'})

    return extracted


def inject_into_request(host: str, method: str, headers: dict[str, str], body: str | None) -> tuple[dict[str, str], str | None]:
    """Inject stored CSRF tokens into request. Called in addon.py request()."""
    if not enabled or method.upper() in ('GET', 'HEAD', 'OPTIONS'):
        return headers, body

    tokens = _tokens.get(host, {})
    if not tokens:
        return headers, body

    headers = dict(headers)  # copy

    for name, info in tokens.items():
        source = info.get('source', '')
        value = info.get('value', '')

        if source == 'header' or name.startswith('X-') or name.startswith('x-'):
            # Inject as header
            headers[name] = value
        elif source == 'body' and body:
            # Try to update in form body
            if f'{name}=' in body:
                body = re.sub(
                    rf'{re.escape(name)}=[^&]*',
                    f'{name}={value}',
                    body
                )
            elif 'application/x-www-form-urlencoded' in headers.get('content-type', headers.get('Content-Type', '')):
                body = f"{body}&{name}={value}" if body else f"{name}={value}"

    return headers, body


def _store_token(host: str, name: str, value: str, source: str) -> None:
    if host not in _tokens:
        _tokens[host] = {}
    _tokens[host][name] = {'value': value, 'source': source, 'updated': time.time()}


def get_tokens(host: str | None = None) -> dict:
    """Get all stored CSRF tokens, optionally filtered by host."""
    if host:
        return {host: _tokens.get(host, {})}
    return dict(_tokens)


def clear_tokens(host: str | None = None) -> int:
    """Clear stored tokens."""
    if host:
        removed = host in _tokens
        _tokens.pop(host, None)
        return 1 if removed else 0
    count = len(_tokens)
    _tokens.clear()
    return count


def toggle(value: bool) -> dict:
    global enabled
    enabled = value
    return {"enabled": enabled, "hosts_tracked": len(_tokens)}
