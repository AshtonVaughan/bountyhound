"""Live Audit Engine — auto-scan flows as they pass through the proxy.

Runs a configurable subset of fast checks with rate limiting and dedup.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import Any

import httpx

from models import Flow, ScanFinding

log = logging.getLogger("live-audit")

# ── Configuration ────────────────────────────────────────────────────────────

enabled: bool = False

_fast_checks: list[str] = ["sqli", "xss", "ssti", "cors", "open_redirect"]
_severity_threshold: str = "medium"  # only store medium+ findings
_rate_limit_per_host: float = 2.0    # max checks/sec per host
_scanned_urls: OrderedDict[str, float] = OrderedDict()
_max_scanned: int = 10000
_host_last_check: dict[str, float] = {}

# Live audit findings (separate from main scanner)
findings: list[ScanFinding] = []

# Severity ordering for threshold comparison
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def configure(
    checks: list[str] | None = None,
    severity: str | None = None,
    rate: float | None = None,
) -> dict:
    """Update live audit configuration."""
    global _fast_checks, _severity_threshold, _rate_limit_per_host

    if checks is not None:
        _fast_checks = checks
    if severity is not None:
        _severity_threshold = severity
    if rate is not None:
        _rate_limit_per_host = rate

    return get_config()


def get_config() -> dict:
    """Get current live audit configuration."""
    return {
        "enabled": enabled,
        "checks": _fast_checks,
        "severity_threshold": _severity_threshold,
        "rate_limit_per_host": _rate_limit_per_host,
        "scanned_count": len(_scanned_urls),
        "findings_count": len(findings),
    }


def toggle(enable: bool) -> dict:
    """Enable/disable live audit."""
    global enabled
    enabled = enable
    log.info(f"[live-audit] {'Enabled' if enabled else 'Disabled'}")
    return {"enabled": enabled}


def clear_findings() -> dict:
    """Clear all live audit findings."""
    count = len(findings)
    findings.clear()
    return {"cleared": count}


def _meets_severity(finding_severity: str) -> bool:
    """Check if finding severity meets the threshold."""
    return _SEVERITY_ORDER.get(finding_severity, 0) >= _SEVERITY_ORDER.get(_severity_threshold, 2)


def _is_rate_limited(host: str) -> bool:
    """Check if host is rate-limited."""
    now = time.time()
    last = _host_last_check.get(host, 0)
    if now - last < (1.0 / _rate_limit_per_host):
        return True
    _host_last_check[host] = now
    return False


def _already_scanned(url: str) -> bool:
    """Check if URL was already scanned (with LRU eviction)."""
    if url in _scanned_urls:
        return True

    _scanned_urls[url] = time.time()

    # LRU eviction
    while len(_scanned_urls) > _max_scanned:
        _scanned_urls.popitem(last=False)

    return False


async def audit_flow(flow: Flow) -> None:
    """Main entry point — called from addon.py response()."""
    if not enabled:
        return

    if not flow.response or not flow.request:
        return

    url = flow.request.url
    host = flow.host

    # Skip if already scanned
    if _already_scanned(url):
        return

    # Skip static assets
    path = flow.path.lower()
    skip_extensions = (".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map", ".ttf")
    if any(path.endswith(ext) for ext in skip_extensions):
        return

    # Rate limit per host
    if _is_rate_limited(host):
        return

    # Fire-and-forget
    asyncio.ensure_future(_run_live_checks(flow))


async def _run_live_checks(flow: Flow) -> None:
    """Run fast checks against a flow."""
    try:
        # Import scanner checks
        from scanner import CUSTOM_CHECKS

        url = flow.request.url
        new_findings: list[ScanFinding] = []

        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            for check_name in _fast_checks:
                if check_name not in CUSTOM_CHECKS:
                    continue
                try:
                    results = await CUSTOM_CHECKS[check_name](client, url)
                    for finding in results:
                        if _meets_severity(finding.severity):
                            finding.source = "live_audit"
                            new_findings.append(finding)
                except Exception as e:
                    log.debug(f"[live-audit] Check {check_name} error: {e}")

        if new_findings:
            findings.extend(new_findings)
            # Cap findings at 10,000
            if len(findings) > 10_000:
                findings[:] = findings[-5_000:]
            log.info(f"[live-audit] {len(new_findings)} findings for {url}")

    except Exception as e:
        log.debug(f"[live-audit] Error: {e}")
