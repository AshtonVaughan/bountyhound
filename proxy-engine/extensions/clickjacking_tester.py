"""Clickjacking Tester — check for missing X-Frame-Options and CSP frame-ancestors."""

from __future__ import annotations

import logging
import re
from typing import Any

from models import Flow, PassiveFinding

log = logging.getLogger("proxy-engine.ext.clickjacking-tester")

NAME = "clickjacking-tester"
DESCRIPTION = "Check for missing or misconfigured X-Frame-Options and CSP frame-ancestors"
CHECK_TYPE = "passive"
ENABLED = False

_config: dict[str, Any] = {}


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


def passive_check(flow: Flow) -> list[PassiveFinding]:
    """Analyze response for clickjacking protections."""
    if not flow.response:
        return []

    findings: list[PassiveFinding] = []

    # Only check HTML responses
    ct = flow.response.headers.get("content-type", "")
    if "text/html" not in ct.lower():
        return []

    # Skip non-200 responses (error pages less interesting)
    if flow.response.status_code != 200:
        return []

    # Check headers
    xfo = flow.response.headers.get("x-frame-options", "").strip().upper()
    csp = flow.response.headers.get("content-security-policy", "")
    csp_ro = flow.response.headers.get("content-security-policy-report-only", "")

    # Parse frame-ancestors from CSP
    frame_ancestors = _parse_frame_ancestors(csp)
    frame_ancestors_ro = _parse_frame_ancestors(csp_ro)

    has_xfo = bool(xfo)
    has_frame_ancestors = frame_ancestors is not None
    has_frame_ancestors_ro_only = frame_ancestors_ro is not None and not has_frame_ancestors

    # ── Missing both protections ─────────────────────────────────────────
    if not has_xfo and not has_frame_ancestors:
        severity = "medium"

        # Check if the page has sensitive forms or actions that make clickjacking impactful
        body = (flow.response.body or "")[:10000].lower()
        has_forms = "<form" in body
        has_buttons = "<button" in body or "type=\"submit\"" in body
        has_sensitive = any(w in body for w in [
            "password", "transfer", "payment", "delete", "remove",
            "confirm", "authorize", "approve", "submit",
        ])

        if has_sensitive and (has_forms or has_buttons):
            severity = "high"
        elif has_forms or has_buttons:
            severity = "medium"
        else:
            severity = "low"

        findings.append(PassiveFinding(
            flow_id=flow.id,
            check_id="clickjacking-no-protection",
            name="Clickjacking: No Frame Protection",
            severity=severity,
            description=(
                "Response has neither X-Frame-Options nor CSP frame-ancestors directive. "
                "The page can be embedded in an attacker-controlled iframe for clickjacking."
                + (" Page contains forms/sensitive actions, increasing impact." if has_sensitive else "")
            ),
            evidence=(
                f"X-Frame-Options: (missing) | "
                f"CSP frame-ancestors: (missing) | "
                f"Forms: {has_forms} | Sensitive actions: {has_sensitive}"
            ),
            url=flow.request.url,
        ))

        return findings

    # ── XFO misconfiguration checks ──────────────────────────────────────
    if has_xfo:
        if xfo == "ALLOWALL":
            findings.append(PassiveFinding(
                flow_id=flow.id,
                check_id="clickjacking-xfo-allowall",
                name="Clickjacking: X-Frame-Options ALLOWALL",
                severity="medium",
                description=(
                    "X-Frame-Options is set to 'ALLOWALL' which permits framing from any origin. "
                    "This provides no clickjacking protection."
                ),
                evidence=f"X-Frame-Options: {xfo}",
                url=flow.request.url,
            ))

        elif xfo.startswith("ALLOW-FROM"):
            # ALLOW-FROM is deprecated and not supported by modern browsers
            findings.append(PassiveFinding(
                flow_id=flow.id,
                check_id="clickjacking-xfo-allow-from",
                name="Clickjacking: X-Frame-Options ALLOW-FROM (Deprecated)",
                severity="low",
                description=(
                    f"X-Frame-Options uses deprecated ALLOW-FROM directive: '{xfo}'. "
                    "This is NOT supported by Chrome, Firefox, or Edge. Use CSP frame-ancestors instead."
                ),
                evidence=f"X-Frame-Options: {xfo}",
                url=flow.request.url,
            ))

        elif xfo not in ("DENY", "SAMEORIGIN"):
            findings.append(PassiveFinding(
                flow_id=flow.id,
                check_id="clickjacking-xfo-invalid",
                name="Clickjacking: Invalid X-Frame-Options Value",
                severity="medium",
                description=(
                    f"X-Frame-Options has unrecognized value '{xfo}'. "
                    "Browsers may ignore invalid values, leaving the page unprotected."
                ),
                evidence=f"X-Frame-Options: {xfo}",
                url=flow.request.url,
            ))

    # ── CSP frame-ancestors checks ───────────────────────────────────────
    if has_frame_ancestors:
        if "*" in frame_ancestors:
            findings.append(PassiveFinding(
                flow_id=flow.id,
                check_id="clickjacking-csp-wildcard",
                name="Clickjacking: CSP frame-ancestors Wildcard",
                severity="medium",
                description=(
                    "CSP frame-ancestors contains wildcard '*', allowing framing from any origin. "
                    "This provides no clickjacking protection."
                ),
                evidence=f"frame-ancestors: {' '.join(frame_ancestors)}",
                url=flow.request.url,
            ))

        # Check for overly broad allowed origins
        broad_origins = [fa for fa in frame_ancestors if fa.startswith("https:") or fa.startswith("http:")]
        if broad_origins:
            findings.append(PassiveFinding(
                flow_id=flow.id,
                check_id="clickjacking-csp-broad",
                name="Clickjacking: CSP frame-ancestors Too Broad",
                severity="low",
                description=(
                    f"CSP frame-ancestors allows entire schemes: {', '.join(broad_origins)}. "
                    "This permits any site using that scheme to embed this page."
                ),
                evidence=f"frame-ancestors: {' '.join(frame_ancestors)}",
                url=flow.request.url,
            ))

    # ── Report-only CSP (not enforced) ───────────────────────────────────
    if has_frame_ancestors_ro_only and not has_xfo:
        findings.append(PassiveFinding(
            flow_id=flow.id,
            check_id="clickjacking-csp-report-only",
            name="Clickjacking: frame-ancestors in Report-Only CSP",
            severity="medium",
            description=(
                "CSP frame-ancestors is only in Content-Security-Policy-Report-Only header. "
                "Violations are logged but NOT blocked. No X-Frame-Options fallback present."
            ),
            evidence=f"CSP-Report-Only frame-ancestors: {' '.join(frame_ancestors_ro)}",
            url=flow.request.url,
        ))

    # ── Missing XFO when only CSP is present (older browser fallback) ────
    if has_frame_ancestors and not has_xfo:
        findings.append(PassiveFinding(
            flow_id=flow.id,
            check_id="clickjacking-no-xfo-fallback",
            name="Clickjacking: No X-Frame-Options Fallback",
            severity="info",
            description=(
                "CSP frame-ancestors is set but X-Frame-Options is missing. "
                "Very old browsers that don't support CSP will have no clickjacking protection."
            ),
            evidence=f"frame-ancestors: {' '.join(frame_ancestors)} | X-Frame-Options: (missing)",
            url=flow.request.url,
        ))

    return findings


def _parse_frame_ancestors(csp: str) -> list[str] | None:
    """Extract frame-ancestors values from CSP header."""
    if not csp:
        return None

    for directive in csp.split(";"):
        directive = directive.strip()
        if directive.lower().startswith("frame-ancestors"):
            tokens = directive.split()[1:]  # Skip "frame-ancestors" itself
            if tokens:
                return tokens

    return None
