"""Passive scanner — analyze responses as they flow through the proxy."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from models import Flow, PassiveFinding
from safe_regex import safe_findall, safe_search

log = logging.getLogger("proxy-engine.passive")

# Collected findings
findings: list[PassiveFinding] = []
enabled: bool = True


def scan_flow(flow: Flow) -> list[PassiveFinding]:
    """Run all passive checks on a flow. Called from the addon on each response."""
    if not enabled or not flow.response:
        return []

    new_findings = []
    for check_fn in _CHECKS:
        try:
            result = check_fn(flow)
            if result:
                new_findings.extend(result)
        except Exception as e:
            log.debug(f"[passive] Check {check_fn.__name__} error: {e}")

    # Apply severity overrides
    for f in new_findings:
        if f.check_id in _severity_overrides:
            f.severity = _severity_overrides[f.check_id]

    # Run custom rules
    for rule in _custom_rules:
        result = _run_custom_rule(flow, rule)
        if result:
            # Apply severity override
            if result.check_id in _severity_overrides:
                result.severity = _severity_overrides[result.check_id]
            new_findings.append(result)

    findings.extend(new_findings)
    # Bound findings list
    if len(findings) > 50_000:
        findings[:] = findings[-25_000:]
    return new_findings


def get_findings() -> list[PassiveFinding]:
    return list(findings)


def clear_findings() -> int:
    count = len(findings)
    findings.clear()
    return count


# ── Individual checks ────────────────────────────────────────────────────────

def _check_missing_security_headers(flow: Flow) -> list[PassiveFinding]:
    """Check for missing security headers."""
    if not flow.response:
        return []

    results = []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "")

    if "html" not in ct:
        return []

    checks = {
        "x-content-type-options": ("Missing X-Content-Type-Options header", "low"),
        "x-frame-options": ("Missing X-Frame-Options header (clickjacking risk)", "low"),
        "strict-transport-security": ("Missing Strict-Transport-Security header", "medium"),
        "content-security-policy": ("Missing Content-Security-Policy header", "low"),
        "x-xss-protection": ("Missing X-XSS-Protection header", "info"),
        "referrer-policy": ("Missing Referrer-Policy header", "info"),
        "permissions-policy": ("Missing Permissions-Policy header", "info"),
    }

    for header, (desc, severity) in checks.items():
        if header not in headers:
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id=f"missing-header-{header}",
                name=desc,
                severity=severity,
                description=f"The response from {flow.host}{flow.path} does not include the {header} header.",
                url=flow.request.url,
            ))

    return results


def _check_information_disclosure(flow: Flow) -> list[PassiveFinding]:
    """Check for server/technology information disclosure."""
    if not flow.response:
        return []

    results = []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}

    server = headers.get("server", "")
    if server and safe_search(r"\d+\.\d+", server):
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="server-version-disclosure",
            name="Server Version Disclosed",
            severity="info",
            description=f"Server header reveals version: {server}",
            evidence=f"Server: {server}",
            url=flow.request.url,
        ))

    powered = headers.get("x-powered-by", "")
    if powered:
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="x-powered-by-disclosure",
            name="Technology Stack Disclosed",
            severity="info",
            description=f"X-Powered-By header reveals: {powered}",
            evidence=f"X-Powered-By: {powered}",
            url=flow.request.url,
        ))

    aspnet = headers.get("x-aspnet-version", "") or headers.get("x-aspnetmvc-version", "")
    if aspnet:
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="aspnet-version-disclosure",
            name="ASP.NET Version Disclosed",
            severity="low",
            description=f"ASP.NET version header found: {aspnet}",
            evidence=aspnet,
            url=flow.request.url,
        ))

    return results


def _check_cookie_security(flow: Flow) -> list[PassiveFinding]:
    """Check for insecure cookie attributes."""
    if not flow.response:
        return []

    results = []
    headers = flow.response.headers

    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue

        cookie_name = value.split("=", 1)[0].strip()
        value_lower = value.lower()

        if "secure" not in value_lower and flow.request.url.startswith("https"):
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id=f"cookie-no-secure-{cookie_name}",
                name=f"Cookie Without Secure Flag: {cookie_name}",
                severity="low",
                description=f"Cookie '{cookie_name}' is set over HTTPS but lacks the Secure flag.",
                evidence=value[:200],
                url=flow.request.url,
            ))

        session_patterns = ("session", "token", "auth", "jwt", "sid", "csrf")
        if any(p in cookie_name.lower() for p in session_patterns):
            if "httponly" not in value_lower:
                results.append(PassiveFinding(
                    flow_id=flow.id,
                    check_id=f"cookie-no-httponly-{cookie_name}",
                    name=f"Session Cookie Without HttpOnly: {cookie_name}",
                    severity="medium",
                    description=f"Cookie '{cookie_name}' appears session-related but lacks HttpOnly flag (XSS risk).",
                    evidence=value[:200],
                    url=flow.request.url,
                ))

            if "samesite" not in value_lower:
                results.append(PassiveFinding(
                    flow_id=flow.id,
                    check_id=f"cookie-no-samesite-{cookie_name}",
                    name=f"Cookie Without SameSite: {cookie_name}",
                    severity="low",
                    description=f"Cookie '{cookie_name}' lacks SameSite attribute (CSRF risk).",
                    evidence=value[:200],
                    url=flow.request.url,
                ))

    return results


def _check_cors_misconfiguration(flow: Flow) -> list[PassiveFinding]:
    """Check for permissive CORS headers."""
    if not flow.response:
        return []

    results = []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()

    if acao == "*" and acac == "true":
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="cors-wildcard-credentials",
            name="CORS: Wildcard Origin with Credentials",
            severity="high",
            description="Access-Control-Allow-Origin is * with Allow-Credentials: true.",
            evidence=f"ACAO: {acao}, ACAC: {acac}",
            url=flow.request.url,
        ))
    elif acao == "*":
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="cors-wildcard",
            name="CORS: Wildcard Origin",
            severity="info",
            description="Access-Control-Allow-Origin is set to wildcard (*).",
            evidence=f"ACAO: {acao}",
            url=flow.request.url,
        ))

    request_origin = flow.request.headers.get("origin", "") or flow.request.headers.get("Origin", "")
    if request_origin and acao == request_origin and acao != "*":
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="cors-origin-reflection",
            name="CORS: Origin Reflected",
            severity="medium",
            description=f"The server reflects the Origin header ({request_origin}) in ACAO.",
            evidence=f"Origin: {request_origin} -> ACAO: {acao}",
            url=flow.request.url,
        ))

    return results


def _check_sensitive_data(flow: Flow) -> list[PassiveFinding]:
    """Check for sensitive data in responses."""
    if not flow.response or not flow.response.body:
        return []

    results = []
    body = flow.response.body

    patterns = {
        "email-disclosure": (r"\b[a-zA-Z0-9._%+-]{2,}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b", "Email Address in Response", "info"),
        "private-ip-disclosure": (r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "Internal IP Address Disclosed", "low"),
        "aws-key-disclosure": (r"AKIA[0-9A-Z]{16}", "Possible AWS Access Key", "high"),
        "jwt-in-response": (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+", "JWT Token in Response Body", "info"),
        "stacktrace-disclosure": (r"(?:Traceback \(most recent|at .+\(.+\.java:\d+\)|\.php on line \d+|Error in .+\.rb)", "Stack Trace Disclosed", "low"),
        # Task #25 — new patterns
        "credit-card": (r"\b(?:4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5})\b", "Possible Credit Card Number", "high"),
        "private-key": (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key in Response", "critical"),
        "api-key-generic": (r"(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?", "API Key/Secret in Response", "medium"),
        "google-api-key": (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", "medium"),
        "github-token": (r"gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub Token", "high"),
        "slack-token": (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "Slack Token", "high"),
        "stripe-key": (r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}", "Stripe API Key", "high"),
        "password-field": (r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{3,})['\"]", "Password in Response", "medium"),
        "ssn-disclosure": (r"\b\d{3}-\d{2}-\d{4}\b", "Possible SSN", "high"),
    }

    for check_id, (pattern, name, severity) in patterns.items():
        matches = safe_findall(pattern, body[:10000])
        if matches:
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id=check_id,
                name=name,
                severity=severity,
                description=f"Found {len(matches)} match(es) in response body.",
                evidence=", ".join(str(m)[:50] for m in matches[:3]),
                url=flow.request.url,
            ))

    return results


def _check_csp_issues(flow: Flow) -> list[PassiveFinding]:
    """Check for weak CSP directives."""
    if not flow.response:
        return []

    results = []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    csp = headers.get("content-security-policy", "")

    if not csp:
        return []

    weak_patterns = {
        "unsafe-inline": ("CSP: unsafe-inline Allowed", "medium", "script-src or style-src allows 'unsafe-inline'"),
        "unsafe-eval": ("CSP: unsafe-eval Allowed", "medium", "script-src allows 'unsafe-eval'"),
        "data:": ("CSP: data: URI Allowed", "low", "CSP allows data: URIs which can be abused for XSS"),
        "*.amazonaws.com": ("CSP: Broad AWS Domain", "low", "CSP allows any amazonaws.com subdomain"),
        "*.cloudfront.net": ("CSP: Broad CloudFront Domain", "info", "CSP allows any cloudfront.net subdomain"),
    }

    csp_lower = csp.lower()
    for pattern, (name, severity, desc) in weak_patterns.items():
        if pattern.lower() in csp_lower:
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id=f"csp-{pattern.replace(':', '').replace('*', 'wildcard').replace('.', '-')}",
                name=name,
                severity=severity,
                description=desc,
                evidence=csp[:300],
                url=flow.request.url,
            ))

    return results


# ── Task #25: New passive checks ─────────────────────────────────────────────

def _check_mixed_content(flow: Flow) -> list[PassiveFinding]:
    """Check for mixed content (HTTP resources loaded over HTTPS)."""
    if not flow.response or not flow.response.body:
        return []
    if not flow.request.url.startswith("https://"):
        return []

    results = []
    ct = flow.response.headers.get("content-type", "")
    if "html" not in ct:
        return []

    http_refs = safe_findall(r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']', flow.response.body[:20000])
    if http_refs:
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="mixed-content",
            name="Mixed Content (HTTP over HTTPS)",
            severity="medium",
            description=f"Found {len(http_refs)} HTTP resource(s) loaded on HTTPS page.",
            evidence=", ".join(str(r)[:60] for r in http_refs[:3]),
            url=flow.request.url,
        ))
    return results


def _check_autocomplete(flow: Flow) -> list[PassiveFinding]:
    """Check for sensitive forms without autocomplete=off."""
    if not flow.response or not flow.response.body:
        return []

    results = []
    ct = flow.response.headers.get("content-type", "")
    if "html" not in ct:
        return []

    body = flow.response.body[:20000].lower()
    sensitive_inputs = safe_findall(r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>', body)
    for inp in sensitive_inputs:
        if "autocomplete" not in inp.lower() or 'autocomplete="off"' not in inp.lower():
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id="autocomplete-password",
                name="Password Field Without autocomplete=off",
                severity="info",
                description="Password input field without autocomplete=off attribute.",
                evidence=str(inp)[:100],
                url=flow.request.url,
            ))
            break
    return results


def _check_cache_control(flow: Flow) -> list[PassiveFinding]:
    """Check for missing cache-control on sensitive responses."""
    if not flow.response:
        return []

    results = []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}

    # Check responses that set auth-related cookies
    set_cookie = headers.get("set-cookie", "")
    has_auth_cookie = any(p in set_cookie.lower() for p in ("session", "token", "auth", "jwt"))

    if has_auth_cookie:
        cc = headers.get("cache-control", "")
        if "no-store" not in cc.lower() and "no-cache" not in cc.lower():
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id="cache-control-sensitive",
                name="Sensitive Response Without Cache-Control",
                severity="low",
                description="Response sets auth cookie but lacks Cache-Control: no-store.",
                evidence=f"Cache-Control: {cc}" if cc else "No Cache-Control header",
                url=flow.request.url,
            ))
    return results


def _check_directory_listing(flow: Flow) -> list[PassiveFinding]:
    """Check for directory listing enabled."""
    if not flow.response or not flow.response.body:
        return []

    results = []
    body = flow.response.body[:5000].lower()
    ct = flow.response.headers.get("content-type", "")

    if "html" in ct and ("index of /" in body or "directory listing for" in body or "<title>directory" in body):
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="directory-listing",
            name="Directory Listing Enabled",
            severity="low",
            description="Server appears to have directory listing enabled.",
            url=flow.request.url,
        ))
    return results


def _check_error_pages(flow: Flow) -> list[PassiveFinding]:
    """Check for verbose error pages."""
    if not flow.response or not flow.response.body:
        return []
    if flow.response.status_code < 400:
        return []

    results = []
    body = flow.response.body[:10000]

    debug_indicators = [
        "django.core", "werkzeug.debug", "laravel", "symfony/debug",
        "express-handlebars", "500 Internal Server Error", "Application Trace",
        "SQLSTATE[", "pg_query()", "mysql_", "Microsoft OLE DB",
    ]

    for indicator in debug_indicators:
        if indicator.lower() in body.lower():
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id="verbose-error-page",
                name="Verbose Error Page / Debug Mode",
                severity="medium",
                description=f"Error page contains debug information: {indicator}",
                evidence=indicator,
                url=flow.request.url,
            ))
            break

    return results


# ── New passive checks (25 additional) ───────────────────────────────────────

# --- Security Headers (5) ---

def _check_clickjacking_protection(flow: Flow) -> list[PassiveFinding]:
    """Flag only when BOTH X-Frame-Options AND CSP frame-ancestors are missing."""
    if not flow.response:
        return []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "")
    if "html" not in ct:
        return []

    has_xfo = "x-frame-options" in headers
    csp = headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower() if csp else False

    if not has_xfo and not has_frame_ancestors:
        return [PassiveFinding(
            flow_id=flow.id,
            check_id="clickjacking-no-protection",
            name="Clickjacking: No X-Frame-Options or CSP frame-ancestors",
            severity="medium",
            description=(
                f"The response from {flow.host}{flow.path} lacks both X-Frame-Options and "
                "CSP frame-ancestors, making it vulnerable to clickjacking attacks."
            ),
            url=flow.request.url,
        )]
    return []


def _check_hsts_issues(flow: Flow) -> list[PassiveFinding]:
    """HSTS present but max-age too low or missing includeSubDomains."""
    if not flow.response:
        return []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    hsts = headers.get("strict-transport-security", "")
    if not hsts:
        return []

    results = []
    hsts_lower = hsts.lower()

    max_age_match = safe_search(r"max-age\s*=\s*(\d+)", hsts_lower)
    if max_age_match:
        max_age = int(max_age_match.group(1))
        if max_age < 31536000:
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id="hsts-low-max-age",
                name="HSTS max-age Below Recommended Minimum",
                severity="low",
                description=(
                    f"HSTS max-age is {max_age} seconds (recommended minimum: 31536000 / 1 year)."
                ),
                evidence=f"Strict-Transport-Security: {hsts}",
                url=flow.request.url,
            ))

    if "includesubdomains" not in hsts_lower:
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="hsts-missing-includesubdomains",
            name="HSTS Missing includeSubDomains",
            severity="info",
            description="HSTS header is present but does not include the includeSubDomains directive.",
            evidence=f"Strict-Transport-Security: {hsts}",
            url=flow.request.url,
        ))

    return results


def _check_referrer_leakage(flow: Flow) -> list[PassiveFinding]:
    """Sensitive params in Referer header sent to third-party."""
    if not flow.request:
        return []
    referer = flow.request.headers.get("referer", "") or flow.request.headers.get("Referer", "")
    if not referer:
        return []

    sensitive_params = ("token", "key", "session", "password", "secret", "auth")
    referer_lower = referer.lower()

    has_sensitive = any(p in referer_lower for p in sensitive_params)
    if not has_sensitive:
        return []

    # Check if request is going to a third-party (different host than Referer)
    referer_host = urlparse(referer).hostname or ""
    request_host = urlparse(flow.request.url).hostname or ""

    if referer_host and request_host and referer_host != request_host:
        leaked = [p for p in sensitive_params if p in referer_lower]
        return [PassiveFinding(
            flow_id=flow.id,
            check_id="referrer-sensitive-leakage",
            name="Sensitive Parameters Leaked via Referer Header",
            severity="medium",
            description=(
                f"Referer header contains sensitive parameter(s) ({', '.join(leaked)}) "
                f"sent to third-party host {request_host}."
            ),
            evidence=f"Referer: {referer[:200]}",
            url=flow.request.url,
        )]
    return []


def _check_duplicate_security_headers(flow: Flow) -> list[PassiveFinding]:
    """Same security header appearing multiple times (causes parser confusion)."""
    if not flow.response:
        return []

    security_headers = {
        "content-security-policy", "x-frame-options", "x-content-type-options",
        "strict-transport-security", "x-xss-protection", "referrer-policy",
        "permissions-policy", "access-control-allow-origin",
    }

    # Count header occurrences (headers dict is flat, but raw response may have dupes)
    # We check the response body for HTTP header-like patterns if available,
    # but primarily use the dict approach — duplicates in dict means last-wins already.
    # Instead, check if comma-separated values indicate merged duplicates for
    # headers that should NOT be comma-joined (like X-Frame-Options).
    results = []
    headers = flow.response.headers

    # For headers that should have a single value, check for comma-separated values
    single_value_headers = {
        "x-frame-options": ["deny", "sameorigin"],
        "x-content-type-options": ["nosniff"],
    }

    for hdr_name, valid_values in single_value_headers.items():
        for key, val in headers.items():
            if key.lower() == hdr_name:
                # If value contains comma, likely duplicated/merged
                if "," in val:
                    results.append(PassiveFinding(
                        flow_id=flow.id,
                        check_id=f"duplicate-header-{hdr_name}",
                        name=f"Duplicate Security Header: {hdr_name}",
                        severity="low",
                        description=(
                            f"The {hdr_name} header appears to have multiple values ({val}), "
                            "which can cause browser parser confusion and security bypass."
                        ),
                        evidence=f"{key}: {val}",
                        url=flow.request.url,
                    ))

    return results


def _check_permissions_policy_missing(flow: Flow) -> list[PassiveFinding]:
    """Permissions-Policy absent on HTML responses — checks for dangerous permissions."""
    if not flow.response:
        return []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "")
    if "html" not in ct:
        return []

    pp = headers.get("permissions-policy", "")
    if not pp:
        return [PassiveFinding(
            flow_id=flow.id,
            check_id="permissions-policy-missing-dangerous",
            name="Permissions-Policy Missing (Camera/Mic/Geolocation Unrestricted)",
            severity="low",
            description=(
                "No Permissions-Policy header is set. Dangerous browser features "
                "(camera, microphone, geolocation, payment, usb) are unrestricted by default."
            ),
            url=flow.request.url,
        )]

    # Check if dangerous permissions are not restricted
    results = []
    dangerous = ["camera", "microphone", "geolocation", "payment", "usb"]
    pp_lower = pp.lower()
    unrestricted = [p for p in dangerous if p not in pp_lower]
    if unrestricted:
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="permissions-policy-dangerous-unrestricted",
            name=f"Permissions-Policy: Dangerous Features Unrestricted",
            severity="info",
            description=(
                f"Permissions-Policy is set but does not restrict: {', '.join(unrestricted)}."
            ),
            evidence=f"Permissions-Policy: {pp[:200]}",
            url=flow.request.url,
        ))
    return results


# --- Information Disclosure (8) ---

def _check_source_map_disclosure(flow: Flow) -> list[PassiveFinding]:
    """Detect .js.map URLs or sourceMappingURL comments in JS responses."""
    if not flow.response or not flow.response.body:
        return []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "")
    if "javascript" not in ct and "json" not in ct and not flow.path.endswith(".js"):
        return []

    results = []
    body = flow.response.body[:50000]

    # Check for sourceMappingURL in body
    mapping_matches = safe_findall(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", body)
    if mapping_matches:
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="source-map-comment",
            name="JavaScript Source Map Reference Found",
            severity="low",
            description=(
                f"sourceMappingURL comment found in JavaScript response, potentially exposing "
                "original source code."
            ),
            evidence=", ".join(str(m)[:80] for m in mapping_matches[:3]),
            url=flow.request.url,
        ))

    # Check SourceMap header
    sm_header = headers.get("sourcemap", "") or headers.get("x-sourcemap", "")
    if sm_header:
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="source-map-header",
            name="SourceMap Header Exposes Source Map URL",
            severity="low",
            description=f"SourceMap header points to: {sm_header}",
            evidence=f"SourceMap: {sm_header}",
            url=flow.request.url,
        ))

    return results


def _check_git_svn_exposed(flow: Flow) -> list[PassiveFinding]:
    """References to .git/, .svn/, .hg/ in response bodies."""
    if not flow.response or not flow.response.body:
        return []

    body = flow.response.body[:20000]
    results = []

    patterns = {
        "git-exposed": (r'(?:href|src|action)\s*=\s*["\']?[^"\']*\.git/', ".git/ directory reference"),
        "svn-exposed": (r'(?:href|src|action)\s*=\s*["\']?[^"\']*\.svn/', ".svn/ directory reference"),
        "hg-exposed": (r'(?:href|src|action)\s*=\s*["\']?[^"\']*\.hg/', ".hg/ directory reference"),
    }

    # Also check plain text references
    vcs_dirs = {
        "git-exposed": (".git/config", ".git/HEAD", ".git/index"),
        "svn-exposed": (".svn/entries", ".svn/wc.db"),
        "hg-exposed": (".hg/store",),
    }

    for check_id, keywords in vcs_dirs.items():
        for kw in keywords:
            if kw in body:
                results.append(PassiveFinding(
                    flow_id=flow.id,
                    check_id=check_id,
                    name=f"Version Control Directory Exposed ({kw.split('/')[0]})",
                    severity="high",
                    description=f"Response body contains reference to {kw}, indicating exposed VCS data.",
                    evidence=kw,
                    url=flow.request.url,
                ))
                break

    if not results:
        for check_id, (pattern, desc) in patterns.items():
            if safe_search(pattern, body):
                results.append(PassiveFinding(
                    flow_id=flow.id,
                    check_id=check_id,
                    name=f"VCS Directory Reference: {desc}",
                    severity="medium",
                    description=f"Response contains {desc}.",
                    url=flow.request.url,
                ))

    return results


def _check_backup_file_reference(flow: Flow) -> list[PassiveFinding]:
    """References to .bak, .old, .orig, .backup, .save files."""
    if not flow.response or not flow.response.body:
        return []

    body = flow.response.body[:20000]
    backup_exts = r"\.[a-zA-Z0-9_-]+\.(?:bak|old|orig|backup|save|swp|tmp|copy)\b"
    matches = safe_findall(backup_exts, body)
    if matches:
        unique = list(set(str(m)[:60] for m in matches[:5]))
        return [PassiveFinding(
            flow_id=flow.id,
            check_id="backup-file-reference",
            name="Backup File Reference in Response",
            severity="low",
            description=f"Response contains {len(matches)} reference(s) to backup/temp files.",
            evidence=", ".join(unique),
            url=flow.request.url,
        )]
    return []


def _check_path_disclosure(flow: Flow) -> list[PassiveFinding]:
    """Filesystem paths like /home/, C:\\Users\\, /var/www/, /opt/ in responses."""
    if not flow.response or not flow.response.body:
        return []

    body = flow.response.body[:20000]
    results = []

    path_patterns = {
        "unix-path": r"(?:/home/[a-zA-Z0-9._-]+|/var/www/[a-zA-Z0-9._/-]+|/opt/[a-zA-Z0-9._/-]+|/etc/[a-zA-Z0-9._/-]+|/usr/(?:local/)?[a-zA-Z0-9._/-]+)",
        "windows-path": r"[A-Z]:\\(?:Users|Windows|inetpub|Program Files)[\\a-zA-Z0-9._\s-]+",
    }

    for check_id, pattern in path_patterns.items():
        matches = safe_findall(pattern, body)
        if matches:
            unique = list(set(str(m)[:80] for m in matches[:5]))
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id=f"path-disclosure-{check_id}",
                name="Filesystem Path Disclosed in Response",
                severity="low",
                description=f"Response contains {len(matches)} filesystem path(s).",
                evidence=", ".join(unique),
                url=flow.request.url,
            ))

    return results


def _check_database_connection_string(flow: Flow) -> list[PassiveFinding]:
    """jdbc:, mongodb://, postgres://, mysql://, redis:// URLs in responses."""
    if not flow.response or not flow.response.body:
        return []

    body = flow.response.body[:20000]
    pattern = r"(?:jdbc:[a-zA-Z0-9:]+://[^\s\"'<>]+|mongodb(?:\+srv)?://[^\s\"'<>]+|postgres(?:ql)?://[^\s\"'<>]+|mysql://[^\s\"'<>]+|redis://[^\s\"'<>]+|mssql://[^\s\"'<>]+)"
    matches = safe_findall(pattern, body)
    if matches:
        # Truncate each match to avoid leaking full credentials in evidence
        unique = list(set(str(m)[:60] for m in matches[:5]))
        return [PassiveFinding(
            flow_id=flow.id,
            check_id="database-connection-string",
            name="Database Connection String in Response",
            severity="high",
            description=f"Found {len(matches)} database connection string(s) in response body.",
            evidence=", ".join(unique),
            url=flow.request.url,
        )]
    return []


def _check_internal_ip_expanded(flow: Flow) -> list[PassiveFinding]:
    """Check for link-local (169.254.x.x), IPv6 ULA (fd00::/8), and IPv6 loopback (::1)."""
    if not flow.response or not flow.response.body:
        return []

    body = flow.response.body[:20000]
    results = []

    patterns = {
        "link-local-ip": (
            r"\b169\.254\.\d{1,3}\.\d{1,3}\b",
            "Link-Local IP Address (169.254.x.x)",
        ),
        "ipv6-ula": (
            r"\bfd[0-9a-f]{2}(?::[0-9a-f]{1,4}){1,7}\b",
            "IPv6 ULA Address (fd00::/8)",
        ),
        "ipv6-loopback": (
            r"(?<![:\w])::1(?![:\w])",
            "IPv6 Loopback Address (::1)",
        ),
    }

    for check_id, (pattern, name) in patterns.items():
        matches = safe_findall(pattern, body)
        if matches:
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id=f"internal-ip-{check_id}",
                name=name,
                severity="low",
                description=f"Found {len(matches)} {name} reference(s) in response.",
                evidence=", ".join(str(m)[:40] for m in matches[:3]),
                url=flow.request.url,
            ))

    return results


def _check_framework_debug_expanded(flow: Flow) -> list[PassiveFinding]:
    """Detect Laravel debug, Express errors, Spring Boot actuator, Flask debug, Django DEBUG."""
    if not flow.response or not flow.response.body:
        return []

    body = flow.response.body[:30000]
    body_lower = body.lower()
    results = []

    indicators = [
        ("laravel-debug", "Laravel Debug Mode", "medium", [
            "laravel_session", "whoops, looks like something went wrong",
            "illuminate\\", "barryvdh/laravel-debugbar",
        ]),
        ("express-error", "Express.js Error Page", "low", [
            "cannot get /", "cannot post /", "expresserror",
            "at layer.handle [as handle_request]",
        ]),
        ("spring-actuator", "Spring Boot Actuator Exposed", "medium", [
            "/actuator/health", "/actuator/env", "/actuator/beans",
            "/actuator/configprops", "/actuator/mappings",
        ]),
        ("flask-debug", "Flask Debug Mode / Toolbar", "medium", [
            "flaskdebugtoolbar", "werkzeug debugger",
            "debugger: pin required", "the debugger caught an exception",
        ]),
        ("django-debug", "Django DEBUG=True", "medium", [
            "you're seeing this error because you have <code>debug = true</code>",
            "django.setup()", "using the urlconf defined in",
            "traceback (most recent call last)", "django/core/handlers",
        ]),
    ]

    for check_id, name, severity, patterns_list in indicators:
        for pat in patterns_list:
            if pat.lower() in body_lower:
                results.append(PassiveFinding(
                    flow_id=flow.id,
                    check_id=f"framework-debug-{check_id}",
                    name=name,
                    severity=severity,
                    description=f"Response contains debug/framework indicator: {pat}",
                    evidence=pat,
                    url=flow.request.url,
                ))
                break  # One match per framework is enough

    return results


def _check_robots_sensitive_paths(flow: Flow) -> list[PassiveFinding]:
    """When URL is /robots.txt, parse Disallow entries for sensitive paths."""
    if not flow.response or not flow.response.body:
        return []
    if not flow.path.rstrip("/").endswith("/robots.txt") and flow.path != "/robots.txt":
        return []

    body = flow.response.body[:10000]
    disallow_paths = safe_findall(r"Disallow:\s*(/\S+)", body)
    if not disallow_paths:
        return []

    sensitive_keywords = (
        "admin", "internal", "api", "backup", "config", "private",
        "secret", "debug", "test", "staging", "dev", "console",
        "phpmyadmin", "manager", "dashboard", "cgi-bin", "wp-admin",
    )

    sensitive_found = []
    for path in disallow_paths:
        path_lower = path.lower()
        if any(kw in path_lower for kw in sensitive_keywords):
            sensitive_found.append(path)

    if sensitive_found:
        return [PassiveFinding(
            flow_id=flow.id,
            check_id="robots-sensitive-paths",
            name="Sensitive Paths in robots.txt",
            severity="info",
            description=f"robots.txt Disallow entries reveal {len(sensitive_found)} sensitive path(s).",
            evidence=", ".join(sensitive_found[:10]),
            url=flow.request.url,
        )]
    return []


# --- Content Security (6) ---

def _check_content_type_mismatch(flow: Flow) -> list[PassiveFinding]:
    """Response body looks like HTML/JS but Content-Type says text/plain or similar mismatch."""
    if not flow.response or not flow.response.body:
        return []

    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "").lower()
    body_start = flow.response.body[:500].strip().lower()

    results = []

    # Body looks like HTML but content-type is not HTML
    if body_start.startswith(("<!doctype html", "<html", "<head", "<body")):
        if "html" not in ct and ct and "text/plain" in ct:
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id="content-type-mismatch-html",
                name="Content-Type Mismatch: HTML Body with Non-HTML Content-Type",
                severity="low",
                description=f"Response body appears to be HTML but Content-Type is '{ct}'.",
                evidence=f"Content-Type: {ct}, Body starts: {body_start[:80]}",
                url=flow.request.url,
            ))

    # Body looks like JS but content-type says text/plain
    if ("function " in body_start or "var " in body_start or "const " in body_start
            or body_start.startswith("(function") or body_start.startswith("!function")):
        if "javascript" not in ct and "text/plain" in ct:
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id="content-type-mismatch-js",
                name="Content-Type Mismatch: JavaScript Body Served as text/plain",
                severity="low",
                description=f"Response body appears to be JavaScript but Content-Type is '{ct}'.",
                evidence=f"Content-Type: {ct}, Body starts: {body_start[:80]}",
                url=flow.request.url,
            ))

    return results


def _check_mime_sniffing_risk(flow: Flow) -> list[PassiveFinding]:
    """HTML or JS content served without X-Content-Type-Options: nosniff."""
    if not flow.response:
        return []

    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "").lower()
    xcto = headers.get("x-content-type-options", "").lower()

    if xcto == "nosniff":
        return []

    # Only flag for content types browsers would sniff
    if "html" in ct or "javascript" in ct or "xml" in ct:
        return [PassiveFinding(
            flow_id=flow.id,
            check_id="mime-sniffing-risk",
            name="MIME Sniffing Risk: No X-Content-Type-Options: nosniff",
            severity="low",
            description=(
                f"Response serves {ct} content without X-Content-Type-Options: nosniff, "
                "allowing browsers to MIME-sniff the content and potentially execute it."
            ),
            evidence=f"Content-Type: {ct}, X-Content-Type-Options: {xcto or '(missing)'}",
            url=flow.request.url,
        )]
    return []


def _check_subresource_integrity_missing(flow: Flow) -> list[PassiveFinding]:
    """External scripts (src pointing to CDN/third-party) without integrity attribute."""
    if not flow.response or not flow.response.body:
        return []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "")
    if "html" not in ct:
        return []

    body = flow.response.body[:50000]
    request_host = urlparse(flow.request.url).hostname or ""

    # Find all <script src="..."> tags
    script_tags = safe_findall(r"<script[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>", body)
    if not script_tags:
        return []

    results = []
    external_no_sri = []
    for src in script_tags:
        src_str = str(src)
        parsed_src = urlparse(src_str)
        src_host = parsed_src.hostname or ""

        # If external (different host or CDN-like URL)
        if src_host and src_host != request_host:
            # Check if this script tag has integrity attribute
            # We need to find the full tag to check for integrity
            tag_pattern = f'<script[^>]*src\\s*=\\s*["\']' + src_str.replace(".", "\\.").replace("/", "\\/")[:60]
            tag_matches = safe_findall(tag_pattern + r'[^>]*>', body)
            has_integrity = False
            for tag in tag_matches:
                if "integrity" in str(tag).lower():
                    has_integrity = True
                    break
            if not has_integrity:
                external_no_sri.append(src_str[:100])

    if external_no_sri:
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="subresource-integrity-missing",
            name="External Script Without Subresource Integrity (SRI)",
            severity="low",
            description=f"Found {len(external_no_sri)} external script(s) without integrity attribute.",
            evidence=", ".join(external_no_sri[:3]),
            url=flow.request.url,
        ))

    return results


def _check_cross_domain_script_include(flow: Flow) -> list[PassiveFinding]:
    """Scripts loaded from third-party domains without integrity hash."""
    if not flow.response or not flow.response.body:
        return []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "")
    if "html" not in ct:
        return []

    body = flow.response.body[:50000]
    request_host = urlparse(flow.request.url).hostname or ""

    # Find script tags with full attributes
    script_re = r"<script[^>]+>"
    script_tags = safe_findall(script_re, body)
    if not script_tags:
        return []

    results = []
    dangerous_includes = []

    for tag in script_tags:
        tag_str = str(tag)
        src_match = safe_search(r'src\s*=\s*["\']([^"\']+)["\']', tag_str)
        if not src_match:
            continue
        src = src_match.group(1)
        parsed_src = urlparse(src)
        src_host = parsed_src.hostname or ""

        if src_host and src_host != request_host and "integrity" not in tag_str.lower():
            dangerous_includes.append(f"{src_host}: {src[:80]}")

    if dangerous_includes:
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="cross-domain-script-no-integrity",
            name="Third-Party Script Without Integrity Hash",
            severity="medium",
            description=(
                f"Found {len(dangerous_includes)} third-party script include(s) without SRI hash. "
                "A compromised CDN could inject malicious code."
            ),
            evidence="; ".join(dangerous_includes[:3]),
            url=flow.request.url,
        ))

    return results


def _check_json_hijacking(flow: Flow) -> list[PassiveFinding]:
    """JSON array response without proper CSRF protection."""
    if not flow.response or not flow.response.body:
        return []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "").lower()
    if "json" not in ct:
        return []

    body = flow.response.body.strip()
    if not body.startswith("["):
        return []

    # Check if there's CSRF protection via custom header requirement
    # If the request used standard cookies without a custom header, it's vulnerable
    req_headers = {k.lower(): v for k, v in flow.request.headers.items()}
    custom_headers = ("x-csrf-token", "x-xsrf-token", "x-requested-with",
                      "authorization", "x-api-key")
    has_custom_header = any(h in req_headers for h in custom_headers)

    if not has_custom_header:
        return [PassiveFinding(
            flow_id=flow.id,
            check_id="json-hijacking-risk",
            name="JSON Array Response Without CSRF Protection",
            severity="medium",
            description=(
                "Response returns a JSON array without requiring custom request headers. "
                "This may be vulnerable to JSON hijacking if the endpoint relies on cookies."
            ),
            evidence=f"Content-Type: {ct}, Body starts with: {body[:60]}",
            url=flow.request.url,
        )]
    return []


def _check_cacheable_auth_response(flow: Flow) -> list[PassiveFinding]:
    """Response with Set-Cookie (session-related) but without Cache-Control: no-store."""
    if not flow.response:
        return []

    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    set_cookie = headers.get("set-cookie", "")
    if not set_cookie:
        return []

    session_keywords = ("session", "sess", "sid", "auth", "token", "jwt", "login")
    cookie_lower = set_cookie.lower()
    if not any(kw in cookie_lower for kw in session_keywords):
        return []

    cc = headers.get("cache-control", "").lower()
    if "no-store" in cc:
        return []

    return [PassiveFinding(
        flow_id=flow.id,
        check_id="cacheable-auth-response",
        name="Session Cookie Set Without Cache-Control: no-store",
        severity="low",
        description=(
            "Response sets a session-related cookie but does not include Cache-Control: no-store. "
            "Authenticated responses may be cached by proxies or the browser."
        ),
        evidence=f"Set-Cookie: {set_cookie[:100]}, Cache-Control: {cc or '(missing)'}",
        url=flow.request.url,
    )]


# --- Session (4) ---

def _check_session_cookie_unencrypted(flow: Flow) -> list[PassiveFinding]:
    """Session cookies set on HTTP (not HTTPS) responses."""
    if not flow.response:
        return []
    if flow.request.url.startswith("https://"):
        return []  # Only flag HTTP

    headers = flow.response.headers
    results = []

    session_keywords = ("session", "sess", "sid", "auth", "token", "jwt", "phpsessid", "jsessionid")

    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        cookie_name = value.split("=", 1)[0].strip().lower()
        if any(kw in cookie_name for kw in session_keywords):
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id=f"session-cookie-unencrypted-{cookie_name}",
                name=f"Session Cookie Set Over HTTP: {cookie_name}",
                severity="high",
                description=(
                    f"Session cookie '{cookie_name}' is set over unencrypted HTTP, "
                    "making it vulnerable to interception."
                ),
                evidence=value[:150],
                url=flow.request.url,
            ))

    return results


def _check_login_form_unencrypted(flow: Flow) -> list[PassiveFinding]:
    """Login form with action URL using HTTP instead of HTTPS."""
    if not flow.response or not flow.response.body:
        return []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "")
    if "html" not in ct:
        return []

    body = flow.response.body[:30000].lower()

    # Find forms with password fields
    form_re = r"<form[^>]*action\s*=\s*[\"']http://[^\"']+[\"'][^>]*>"
    insecure_forms = safe_findall(form_re, body)
    if not insecure_forms:
        return []

    # Check if any form contains a password field nearby
    results = []
    for form_tag in insecure_forms:
        form_str = str(form_tag)
        # Look for password input after this form tag
        form_start = body.find(form_str)
        if form_start == -1:
            continue
        form_section = body[form_start:form_start + 3000]
        if 'type="password"' in form_section or "type='password'" in form_section:
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id="login-form-unencrypted",
                name="Login Form Submits Over HTTP",
                severity="high",
                description=(
                    "A login form with a password field submits to an HTTP (unencrypted) URL."
                ),
                evidence=form_str[:150],
                url=flow.request.url,
            ))
            break

    return results


def _check_session_id_in_url(flow: Flow) -> list[PassiveFinding]:
    """Session tokens appearing in URL query parameters."""
    if not flow.request:
        return []

    url = flow.request.url
    parsed = urlparse(url)
    query = parsed.query.lower()
    if not query:
        return []

    session_params = ("sessionid", "jsessionid", "phpsessid", "sid", "token",
                      "session_id", "sess_id", "aspsessionid")

    found = []
    for param in session_params:
        if param in query:
            found.append(param)

    if found:
        return [PassiveFinding(
            flow_id=flow.id,
            check_id="session-id-in-url",
            name="Session Token in URL Query Parameter",
            severity="medium",
            description=(
                f"Session parameter(s) ({', '.join(found)}) found in URL query string. "
                "Session tokens in URLs can be leaked via Referer headers, logs, and browser history."
            ),
            evidence=parsed.query[:150],
            url=flow.request.url,
        )]
    return []


def _check_open_redirect_passive(flow: Flow) -> list[PassiveFinding]:
    """3xx redirect where Location header contains user-controlled URL."""
    if not flow.response:
        return []
    if flow.response.status_code < 300 or flow.response.status_code >= 400:
        return []

    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    location = headers.get("location", "")
    if not location:
        return []

    # Check if the redirect target seems to be from user input
    # 1. Check if Location contains a domain from query parameters
    parsed_req = urlparse(flow.request.url)
    query_params = parsed_req.query
    if not query_params:
        return []

    # Extract URLs/domains from query parameters
    param_urls = safe_findall(r"(?:https?://|//)[a-zA-Z0-9.-]+", query_params)
    param_domains = safe_findall(r"[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}", query_params)

    redirect_host = urlparse(location).hostname or ""
    request_host = parsed_req.hostname or ""

    if redirect_host and redirect_host != request_host:
        # Check if the redirect target domain appears in a query param
        for domain in param_domains:
            domain_str = str(domain)
            if domain_str.lower() in redirect_host.lower():
                return [PassiveFinding(
                    flow_id=flow.id,
                    check_id="open-redirect-passive",
                    name="Possible Open Redirect",
                    severity="medium",
                    description=(
                        f"3xx redirect to {location[:100]} appears to be controlled by "
                        f"query parameter containing '{domain_str}'."
                    ),
                    evidence=f"Location: {location[:150]}, Query: {query_params[:100]}",
                    url=flow.request.url,
                )]

    return []


# --- Other (2) ---

def _check_html_form_no_csrf(flow: Flow) -> list[PassiveFinding]:
    """POST forms in HTML responses that lack hidden CSRF token fields."""
    if not flow.response or not flow.response.body:
        return []
    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "")
    if "html" not in ct:
        return []

    body = flow.response.body[:50000]

    import re as _re
    form_re = _re.compile(r"<form([^>]*)>(.*?)</form>", _re.IGNORECASE | _re.DOTALL)

    results = []
    csrf_field_names = (
        "csrf", "_token", "csrf_token", "__requestverificationtoken",
        "_csrf", "authenticity_token", "csrfmiddlewaretoken", "antiforgery",
        "xsrf", "__csrf",
    )

    for match in form_re.finditer(body):
        attrs = match.group(1).lower()
        form_body = match.group(2).lower()

        # Only check POST forms
        if 'method' not in attrs:
            continue
        method_match = safe_search(r'method\s*=\s*["\'](\w+)["\']', attrs)
        if not method_match or method_match.group(1).lower() != "post":
            continue

        # Check for CSRF token hidden field
        has_csrf = False
        for csrf_name in csrf_field_names:
            if csrf_name in form_body:
                has_csrf = True
                break

        if not has_csrf:
            action_match = safe_search(r'action\s*=\s*["\']([^"\']*)["\']', attrs)
            action = action_match.group(1) if action_match else "(same page)"
            results.append(PassiveFinding(
                flow_id=flow.id,
                check_id="form-no-csrf-token",
                name="POST Form Without CSRF Token",
                severity="medium",
                description=(
                    f"POST form (action: {action[:80]}) does not contain a CSRF token field. "
                    "This may be vulnerable to cross-site request forgery."
                ),
                evidence=f"Form action: {action[:100]}",
                url=flow.request.url,
            ))

    return results[:3]  # Limit to 3 per page to avoid noise


def _check_email_address_expanded(flow: Flow) -> list[PassiveFinding]:
    """Broader email detection in HTML comments, JS code, and JSON responses."""
    if not flow.response or not flow.response.body:
        return []

    headers = {k.lower(): v for k, v in flow.response.headers.items()}
    ct = headers.get("content-type", "").lower()

    # Only run on HTML, JS, and JSON (the existing check in _check_sensitive_data covers general)
    if not any(t in ct for t in ("html", "javascript", "json")):
        return []

    body = flow.response.body[:30000]
    results = []

    # Check HTML comments for emails
    comment_emails = safe_findall(r"<!--[^>]*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})[^>]*?-->", body)
    if comment_emails:
        unique = list(set(str(e)[:60] for e in comment_emails[:5]))
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="email-in-html-comment",
            name="Email Address in HTML Comment",
            severity="info",
            description=f"Found {len(comment_emails)} email address(es) in HTML comments.",
            evidence=", ".join(unique),
            url=flow.request.url,
        ))

    # Check for developer/internal emails (patterns like @company-internal.com, dev@, admin@)
    internal_pattern = r"\b(?:admin|dev|developer|root|support|info|test|debug|staging|internal|ops|sysadmin|webmaster|postmaster)[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b"
    internal_emails = safe_findall(internal_pattern, body)
    if internal_emails:
        unique = list(set(str(e)[:60] for e in internal_emails[:5]))
        results.append(PassiveFinding(
            flow_id=flow.id,
            check_id="email-internal-disclosure",
            name="Internal/Developer Email Address Disclosed",
            severity="low",
            description=f"Found {len(internal_emails)} internal/developer email(s) in response.",
            evidence=", ".join(unique),
            url=flow.request.url,
        ))

    return results


# Registry of all passive checks
_CHECKS = [
    _check_missing_security_headers,
    _check_information_disclosure,
    _check_cookie_security,
    _check_cors_misconfiguration,
    _check_sensitive_data,
    _check_csp_issues,
    # Task #25: new checks
    _check_mixed_content,
    _check_autocomplete,
    _check_cache_control,
    _check_directory_listing,
    _check_error_pages,
    # Security Headers (5)
    _check_clickjacking_protection,
    _check_hsts_issues,
    _check_referrer_leakage,
    _check_duplicate_security_headers,
    _check_permissions_policy_missing,
    # Information Disclosure (8)
    _check_source_map_disclosure,
    _check_git_svn_exposed,
    _check_backup_file_reference,
    _check_path_disclosure,
    _check_database_connection_string,
    _check_internal_ip_expanded,
    _check_framework_debug_expanded,
    _check_robots_sensitive_paths,
    # Content Security (6)
    _check_content_type_mismatch,
    _check_mime_sniffing_risk,
    _check_subresource_integrity_missing,
    _check_cross_domain_script_include,
    _check_json_hijacking,
    _check_cacheable_auth_response,
    # Session (4)
    _check_session_cookie_unencrypted,
    _check_login_form_unencrypted,
    _check_session_id_in_url,
    _check_open_redirect_passive,
    # Other (2)
    _check_html_form_no_csrf,
    _check_email_address_expanded,
]


# ── Custom rules (Phase 9A) ─────────────────────────────────────────────────

_custom_rules: list[dict] = []

def load_custom_rules(path: str) -> int:
    """Load custom passive scan rules from YAML or JSON file."""
    from pathlib import Path

    rule_path = Path(path)
    if not rule_path.exists():
        return 0

    content = rule_path.read_text(encoding="utf-8")
    rules = []

    if path.endswith((".yml", ".yaml")):
        try:
            import yaml
            rules = yaml.safe_load(content)
        except ImportError:
            import json
            rules = json.loads(content)
    else:
        import json
        rules = json.loads(content)

    if isinstance(rules, list):
        _custom_rules.extend(rules)
        return len(rules)
    return 0


def _run_custom_rule(flow: Flow, rule: dict) -> PassiveFinding | None:
    """Run a single custom rule against a flow."""
    from safe_regex import safe_search

    pattern = rule.get("pattern", "")
    location = rule.get("location", "body")

    text = ""
    if location == "body" and flow.response and flow.response.body:
        text = flow.response.body[:10000]
    elif location == "header" and flow.response:
        text = "\n".join(f"{k}: {v}" for k, v in flow.response.headers.items())
    elif location == "url":
        text = flow.request.url

    if pattern and safe_search(pattern, text):
        return PassiveFinding(
            flow_id=flow.id,
            check_id=rule.get("id", "custom-rule"),
            name=rule.get("name", "Custom Rule Match"),
            severity=rule.get("severity", "info"),
            description=rule.get("description", f"Custom rule matched: {pattern}"),
            url=flow.request.url,
        )
    return None


# ── Severity override (Phase 9B) ────────────────────────────────────────────

_severity_overrides: dict[str, str] = {}

def set_severity_override(check_id: str, severity: str) -> None:
    """Override severity for a specific check."""
    _severity_overrides[check_id] = severity


# ── False positive marking (Phase 9C) ───────────────────────────────────────

def mark_false_positive(finding_index: int, reason: str = "") -> bool:
    """Mark a finding as false positive."""
    if 0 <= finding_index < len(findings):
        findings[finding_index].false_positive = True
        findings[finding_index].fp_reason = reason
        return True
    return False


def get_custom_rules() -> list[dict]:
    """Get loaded custom rules."""
    return list(_custom_rules)
