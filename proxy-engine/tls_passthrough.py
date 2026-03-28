"""TLS Pass-through — skip interception for specific domains."""

from __future__ import annotations

import logging
import re

log = logging.getLogger("proxy-engine.tls_passthrough")

# Domains to pass through without intercepting
_passthrough_domains: list[str] = []

# Compiled patterns
_compiled: list[re.Pattern] = []


def add_domain(pattern: str) -> list[str]:
    """Add a domain pattern to the pass-through list."""
    _passthrough_domains.append(pattern)
    try:
        _compiled.append(re.compile(pattern, re.IGNORECASE))
    except re.error:
        log.warning(f"[tls_passthrough] Invalid regex: {pattern}")
    log.info(f"[tls_passthrough] Added: {pattern}")
    return list(_passthrough_domains)


def remove_domain(index: int) -> list[str]:
    """Remove a domain pattern by index."""
    if 0 <= index < len(_passthrough_domains):
        _passthrough_domains.pop(index)
        _compiled.pop(index)
    return list(_passthrough_domains)


def get_domains() -> list[str]:
    return list(_passthrough_domains)


def should_passthrough(host: str) -> bool:
    """Check if a host should bypass TLS interception."""
    for pattern in _compiled:
        if pattern.search(host):
            return True
    return False


def tls_start_client(tls_start):
    """mitmproxy hook: configure TLS passthrough at the TLS level.

    Wire this into the addon's tls_start_client method. When a domain
    matches a passthrough pattern, ignore the connection entirely so
    mitmproxy doesn't MITM the TLS handshake.
    """
    ctx = tls_start.context
    sni = ctx.client.sni or ""
    if sni and should_passthrough(sni):
        log.info(f"[tls_passthrough] Passing through TLS for: {sni}")
        tls_start.ignore_connection = True
