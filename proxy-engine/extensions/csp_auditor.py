"""CSP Auditor — Content Security Policy bypass analysis.

Parses CSP directives, identifies bypasses (unsafe-inline+nonce, JSONP on whitelisted
domains, missing base-uri/object-src), and scores policy strength.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from models import Flow, PassiveFinding

log = logging.getLogger("ext-csp-auditor")

NAME = "csp-auditor"
DESCRIPTION = "Parse CSP directives, identify bypasses, score policy strength"
CHECK_TYPE = "passive"
ENABLED = False

_config: dict[str, Any] = {}

# Domains known to host JSONP endpoints (CSP bypass via script-src)
JSONP_BYPASS_DOMAINS = [
    "accounts.google.com", "maps.googleapis.com", "ajax.googleapis.com",
    "www.google.com", "www.googleapis.com", "translate.googleapis.com",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "www.googletagmanager.com", "www.google-analytics.com",
    "connect.facebook.net", "platform.twitter.com",
    "cdn.shopify.com", "js.stripe.com",
]

# Angular CSP bypass domains
ANGULAR_BYPASS_DOMAINS = [
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "ajax.googleapis.com",
    "unpkg.com", "code.angularjs.org",
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


def _parse_csp(csp_header: str) -> dict[str, list[str]]:
    """Parse CSP header into directive → values mapping."""
    directives: dict[str, list[str]] = {}
    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directive = tokens[0].lower()
            values = tokens[1:]
            directives[directive] = values
    return directives


def _score_csp(directives: dict[str, list[str]]) -> tuple[int, list[str]]:
    """Score CSP strength (0-100) and return list of issues."""
    score = 100
    issues = []

    # Missing critical directives
    if "default-src" not in directives and "script-src" not in directives:
        score -= 30
        issues.append("Missing both default-src and script-src")

    if "script-src" not in directives and "default-src" in directives:
        # Falls back to default-src, check that
        pass

    script_sources = directives.get("script-src", directives.get("default-src", []))

    # Check for unsafe-inline
    if "'unsafe-inline'" in script_sources:
        has_nonce = any(s.startswith("'nonce-") for s in script_sources)
        has_hash = any(s.startswith("'sha256-") or s.startswith("'sha384-") for s in script_sources)
        if not has_nonce and not has_hash:
            score -= 30
            issues.append("script-src allows 'unsafe-inline' without nonce/hash (XSS trivial)")
        else:
            score -= 5
            issues.append("script-src has 'unsafe-inline' with nonce/hash (inline ignored per spec, but review)")

    # Check for unsafe-eval
    if "'unsafe-eval'" in script_sources:
        score -= 20
        issues.append("script-src allows 'unsafe-eval' (enables eval(), Function(), etc.)")

    # Check for wildcard
    if "*" in script_sources:
        score -= 25
        issues.append("script-src allows wildcard '*' (loads scripts from any domain)")

    # Check for data: URI
    if "data:" in script_sources:
        score -= 20
        issues.append("script-src allows 'data:' URI (XSS via data:text/html)")

    # Check for JSONP bypass domains
    for source in script_sources:
        source_clean = source.strip("'\"")
        for jsonp_domain in JSONP_BYPASS_DOMAINS:
            if jsonp_domain in source_clean:
                score -= 15
                issues.append(f"script-src includes JSONP-capable domain: {jsonp_domain}")
                break

    # Check for Angular bypass domains
    for source in script_sources:
        source_clean = source.strip("'\"")
        for angular_domain in ANGULAR_BYPASS_DOMAINS:
            if angular_domain in source_clean:
                if "'unsafe-eval'" in script_sources:
                    score -= 10
                    issues.append(f"script-src includes Angular-hosting CDN with unsafe-eval: {angular_domain}")
                break

    # Missing object-src
    if "object-src" not in directives:
        score -= 10
        issues.append("Missing object-src (allows Flash/Java plugin abuse)")

    # Missing base-uri
    if "base-uri" not in directives:
        score -= 10
        issues.append("Missing base-uri (allows <base> tag hijacking for relative URL abuse)")

    # Missing frame-ancestors
    if "frame-ancestors" not in directives:
        score -= 5
        issues.append("Missing frame-ancestors (clickjacking not prevented by CSP)")

    # Check for report-only (not enforced)
    # This is checked at header level, not directive level

    # Check for overly broad sources
    for source in script_sources:
        if source.startswith("https:") or source.startswith("http:"):
            score -= 15
            issues.append(f"script-src allows entire scheme '{source}' (too broad)")
            break
        if source.startswith("*."):
            score -= 10
            issues.append(f"script-src wildcard subdomain: {source}")

    return max(0, score), issues


def passive_check(flow: Flow) -> list[PassiveFinding]:
    """Analyze CSP headers in responses."""
    if not flow.response:
        return []

    findings = []
    csp_header = ""
    is_report_only = False

    for name, value in flow.response.headers.items():
        if name.lower() == "content-security-policy":
            csp_header = value
        elif name.lower() == "content-security-policy-report-only":
            csp_header = value
            is_report_only = True

    if not csp_header:
        # Check if HTML page without CSP
        ct = flow.response.headers.get("content-type", "")
        if "text/html" in ct and flow.response.status_code == 200:
            findings.append(PassiveFinding(
                flow_id=flow.id,
                check_id="csp-missing",
                name="Missing Content-Security-Policy Header",
                severity="medium",
                description="HTML response has no CSP header. XSS attacks have no CSP mitigation.",
                evidence="No CSP header present",
                url=flow.request.url,
            ))
        return findings

    # Parse and score
    directives = _parse_csp(csp_header)
    score, issues = _score_csp(directives)

    if is_report_only:
        findings.append(PassiveFinding(
            flow_id=flow.id,
            check_id="csp-report-only",
            name="CSP in Report-Only Mode",
            severity="medium",
            description="CSP is in report-only mode — violations are logged but not blocked.",
            evidence="Content-Security-Policy-Report-Only header",
            url=flow.request.url,
        ))

    # Report issues
    if score < 50:
        severity = "high"
    elif score < 70:
        severity = "medium"
    elif score < 90:
        severity = "low"
    else:
        severity = "info"

    if issues:
        findings.append(PassiveFinding(
            flow_id=flow.id,
            check_id="csp-audit",
            name=f"CSP Audit: Score {score}/100",
            severity=severity,
            description=f"CSP policy analysis ({len(issues)} issues):\n" + "\n".join(f"  - {i}" for i in issues),
            evidence=csp_header[:200],
            url=flow.request.url,
        ))

    return findings
