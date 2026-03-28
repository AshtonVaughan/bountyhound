"""Scanner — nuclei wrapper + expanded custom active checks with dedup and auth support."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
import time
import uuid
from urllib.parse import quote

import httpx

from models import ScanFinding, ScanJob, ScanRequest, ScanTask
from state import state

log = logging.getLogger("proxy-engine.scanner")

NUCLEI_BIN = shutil.which("nuclei") or "nuclei"


# ── Auth headers helper (Task #22) ──────────────────────────────────────────

def _get_auth_headers(url: str) -> dict[str, str]:
    """Get auth headers from session handler for a URL."""
    try:
        from urllib.parse import urlparse
        from session_handler import get_injection_headers
        host = urlparse(url).hostname or ""
        return get_injection_headers(host)
    except Exception:
        return {}


# ── Deduplication (Task #24) ────────────────────────────────────────────────

def _dedup_key(finding: ScanFinding) -> str:
    """Generate a dedup key for a finding."""
    from urllib.parse import urlparse
    parsed = urlparse(finding.url)
    # Dedup by template + host + path (ignore query params)
    key_parts = [finding.template_id, parsed.hostname or "", parsed.path or "/"]
    return hashlib.md5("|".join(key_parts).encode()).hexdigest()[:16]


def _dedup_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Remove duplicate findings based on template + host + path."""
    seen = set()
    deduped = []
    for f in findings:
        key = _dedup_key(f)
        f.dedup_key = key
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def _consolidate_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Group findings by vuln_type + host + path pattern, merge duplicates."""
    from urllib.parse import urlparse
    groups: dict[str, list[ScanFinding]] = {}
    for f in findings:
        parsed = urlparse(f.url)
        # Normalize path: remove trailing digits/UUIDs
        import re
        path_pattern = re.sub(r'/\d+', '/{id}', parsed.path or '/')
        key = f"{f.template_id}|{parsed.hostname}|{path_pattern}"
        groups.setdefault(key, []).append(f)

    consolidated = []
    for key, group in groups.items():
        if len(group) == 1:
            consolidated.append(group[0])
            continue
        # Keep highest confidence/severity finding, collect URLs
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        conf_order = {"confirmed": 0, "firm": 1, "tentative": 2, "": 3}
        best = min(group, key=lambda f: (severity_order.get(f.severity.lower(), 5), conf_order.get(f.confidence.lower(), 3)))
        best.related_urls = list(set(f.url for f in group if f.url != best.url))
        best.occurrence_count = len(group)
        consolidated.append(best)
    return consolidated


# ── Remediation mapping (Task #24) ─────────────────────────────────────────

_REMEDIATION = {
    "custom-sqli-error": "Parameterize all SQL queries. Use prepared statements or ORM.",
    "custom-xss-reflection": "HTML-encode all user input before reflecting in responses. Use CSP headers.",
    "custom-open-redirect": "Validate redirect targets against an allowlist. Don't accept full URLs.",
    "custom-ssrf": "Validate and restrict URLs server-side. Block internal IP ranges and metadata endpoints.",
    "custom-crlf-injection": "Strip CR/LF characters from user input before including in HTTP headers.",
    "custom-header-injection": "Validate and sanitize all user input used in HTTP headers.",
    "custom-path-traversal": "Use a whitelist of allowed files. Never use user input in file paths directly.",
    "custom-ssti": "Avoid passing user input into template engines. Use sandboxed templates.",
    "custom-command-injection": "Never pass user input to shell commands. Use parameterized APIs instead.",
    "custom-timing-sqli": "Parameterize all SQL queries. The timing difference suggests injectable parameters.",
    "custom-verb-tampering": "Enforce access controls for all HTTP methods, not just GET/POST.",
    "custom-web-cache-deception": "Configure cache to key on full URL path. Set Cache-Control: no-store for dynamic content.",
    "custom-cors-arbitrary-origin": "Validate Origin header against an allowlist. Never reflect arbitrary origins with credentials.",
    "custom-prototype-pollution": "Sanitize user input, reject __proto__ and constructor.prototype keys. Use Object.create(null).",
    "custom-dom-xss-sources": "Sanitize all DOM source inputs before passing to dangerous sinks. Use textContent instead of innerHTML.",
    # Extended checks remediation
    "custom-http-smuggling-clte": "Normalize Transfer-Encoding handling. Reject ambiguous requests at the reverse proxy.",
    "custom-http-smuggling-tecl": "Normalize Transfer-Encoding handling. Reject ambiguous requests at the reverse proxy.",
    "custom-hpp": "Use a consistent parameter parsing strategy. Validate and deduplicate parameters server-side.",
    "custom-mass-assignment": "Use allowlists for accepted fields. Never bind request data directly to models without filtering.",
    "custom-bola-idor": "Implement object-level authorization checks. Verify the requesting user owns the resource.",
    "custom-graphql-introspection": "Disable introspection in production. Use persisted queries and query depth limits.",
    "custom-graphql-batch": "Limit batch query size. Implement rate limiting per query operation.",
    "custom-ldap-injection": "Escape LDAP metacharacters in user input. Use parameterized LDAP queries.",
    "custom-xxe": "Disable external entity processing in XML parsers. Use JSON instead of XML where possible.",
    "custom-xml-injection": "Disable DTD processing. Use defusedxml or equivalent safe XML parser.",
    "custom-email-header-injection": "Strip CR/LF characters from email header fields. Validate email addresses strictly.",
    "custom-ssi-injection": "Disable SSI processing. Never include user input in SSI directives.",
    "custom-xpath-injection": "Parameterize XPath queries. Validate and escape user input.",
    "custom-jwt-alg-none": "Reject tokens with alg:none. Always verify JWT signatures server-side.",
    "custom-jwt-expired": "Enforce token expiry. Reject expired JWTs.",
    "custom-jwt-kid-injection": "Validate KID values against an allowlist. Never use KID in file paths.",
    "custom-deserialization-java": "Avoid native deserialization. Use JSON/XML with strict schema validation.",
    "custom-deserialization-php": "Avoid unserialize() on user input. Use JSON instead.",
    "custom-deserialization-python": "Never unpickle untrusted data. Use JSON or MessagePack.",
    "custom-deserialization-dotnet": "Disable TypeNameHandling. Use safe serialization settings.",
    "custom-file-upload": "Validate file type by content (magic bytes), not extension or MIME type. Store uploads outside webroot.",
    "custom-cors-subdomain": "Validate origins against a strict allowlist. Don't reflect subdomains or variations.",
    "custom-api-version-exposure": "Deprecate and remove old API versions. Ensure all versions have consistent security controls.",
    "differential-anomaly": "Investigate the parameter for potential injection vulnerabilities. The response deviation suggests server-side processing of the input.",
}


# ── Custom checks ────────────────────────────────────────────────────────────

async def _check_sqli_error(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Error-based SQLi detection."""
    findings = []
    error_patterns = [
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "pg_query",
        "mysql_fetch",
        "ORA-01756",
        "SQLite3::",
        "Microsoft OLE DB Provider",
        "ODBC SQL Server Driver",
        "sqlite_error",
        "org.postgresql",
        "com.mysql.jdbc",
    ]
    payloads = ["'", "\"", "' OR '1'='1", "1 AND 1=CONVERT(int,(SELECT @@version))--"]

    for payload in payloads:
        test_url = url + ("&" if "?" in url else "?") + f"test={quote(payload, safe='')}"
        try:
            resp = await client.get(test_url, follow_redirects=True)
            body_lower = resp.text.lower()
            for pattern in error_patterns:
                if pattern.lower() in body_lower:
                    findings.append(ScanFinding(
                        template_id="custom-sqli-error",
                        name="SQL Injection (Error-Based)",
                        severity="high",
                        url=test_url,
                        matched_at=test_url,
                        description=f"DB error pattern '{pattern}' triggered by payload: {payload}",
                        extracted=[pattern],
                        confidence="confirmed",
                        remediation=_REMEDIATION.get("custom-sqli-error", ""),
                        source="custom",
                    ))
                    break
        except Exception:
            pass
    return findings


async def _check_xss_reflection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Reflected XSS detection."""
    findings = []
    canary = "pxe7k<>\"'&"

    test_url = url + ("&" if "?" in url else "?") + f"test={canary}"
    try:
        resp = await client.get(test_url, follow_redirects=True)
        ct = resp.headers.get("content-type", "")
        if "html" in ct and canary in resp.text:
            findings.append(ScanFinding(
                template_id="custom-xss-reflection",
                name="Reflected XSS (Unescaped Input)",
                severity="medium",
                url=test_url,
                matched_at=test_url,
                description=f"Canary '{canary}' reflected unescaped in HTML response",
                extracted=[canary],
                confidence="confirmed",
                remediation=_REMEDIATION.get("custom-xss-reflection", ""),
                source="custom",
            ))
    except Exception:
        pass
    return findings


async def _check_open_redirect(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Open redirect detection."""
    findings = []
    redirect_payloads = [
        "//evil.com", "https://evil.com", "/\\evil.com",
        "//evil.com/%2f..", "https:evil.com",
    ]
    redirect_params = ["url", "redirect", "next", "return", "returnUrl", "goto", "redirect_uri"]

    for param in redirect_params:
        for payload in redirect_payloads:
            test_url = url + ("&" if "?" in url else "?") + f"{param}={payload}"
            try:
                resp = await client.get(test_url, follow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if "evil.com" in location:
                        findings.append(ScanFinding(
                            template_id="custom-open-redirect",
                            name="Open Redirect",
                            severity="medium",
                            url=test_url,
                            matched_at=test_url,
                            description=f"Redirect to external domain via {param}={payload} -> {location}",
                            extracted=[location],
                            confidence="confirmed",
                            remediation=_REMEDIATION.get("custom-open-redirect", ""),
                            source="custom",
                        ))
                        return findings
            except Exception:
                pass
    return findings


async def _check_ssrf(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Basic SSRF detection."""
    findings = []
    ssrf_params = ["url", "uri", "path", "src", "dest", "redirect", "file", "page", "load"]
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80",
        "http://[::1]:80",
    ]

    for param in ssrf_params:
        for payload in ssrf_payloads:
            test_url = url + ("&" if "?" in url else "?") + f"{param}={payload}"
            try:
                resp = await client.get(test_url, follow_redirects=True, timeout=5.0)
                if "ami-id" in resp.text or "instance-id" in resp.text or "iam" in resp.text.lower():
                    findings.append(ScanFinding(
                        template_id="custom-ssrf",
                        name="Server-Side Request Forgery",
                        severity="critical",
                        url=test_url,
                        matched_at=test_url,
                        description=f"Possible SSRF via {param} — metadata-like content in response",
                        extracted=[resp.text[:200]],
                        confidence="tentative",
                        remediation=_REMEDIATION.get("custom-ssrf", ""),
                        source="custom",
                    ))
                    return findings
            except Exception:
                pass
    return findings


# ── Task #23: Expanded custom checks ────────────────────────────────────────

async def _check_crlf_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """CRLF injection detection."""
    findings = []
    payloads = [
        "%0d%0aX-Injected: true",
        "%0AX-Injected:%20true",
        "\\r\\nX-Injected: true",
    ]

    for payload in payloads:
        test_url = url + ("&" if "?" in url else "?") + f"test={payload}"
        try:
            resp = await client.get(test_url, follow_redirects=False)
            if "x-injected" in {k.lower() for k in resp.headers.keys()}:
                findings.append(ScanFinding(
                    template_id="custom-crlf-injection",
                    name="CRLF Injection",
                    severity="medium",
                    url=test_url,
                    matched_at=test_url,
                    description=f"CRLF injection allowed header injection via payload: {payload}",
                    confidence="confirmed",
                    remediation=_REMEDIATION.get("custom-crlf-injection", ""),
                    source="custom",
                ))
                return findings
        except Exception:
            pass
    return findings


async def _check_timing_sqli(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Time-based blind SQLi detection."""
    findings = []
    payloads = [
        ("1' AND SLEEP(3)--", 3),
        ("1; WAITFOR DELAY '0:0:3'--", 3),
        ("1' AND pg_sleep(3)--", 3),
    ]

    # Baseline timing
    try:
        start = time.monotonic()
        await client.get(url, follow_redirects=True, timeout=10.0)
        baseline = time.monotonic() - start
    except Exception:
        return findings

    for payload, delay in payloads:
        test_url = url + ("&" if "?" in url else "?") + f"test={quote(payload, safe='')}"
        try:
            start = time.monotonic()
            await client.get(test_url, follow_redirects=True, timeout=delay + 10)
            elapsed = time.monotonic() - start

            # If response took significantly longer than baseline
            if elapsed > baseline + delay - 0.5:
                findings.append(ScanFinding(
                    template_id="custom-timing-sqli",
                    name="SQL Injection (Time-Based Blind)",
                    severity="high",
                    url=test_url,
                    matched_at=test_url,
                    description=f"Response delayed by ~{elapsed:.1f}s (baseline: {baseline:.1f}s) with payload: {payload}",
                    confidence="tentative",
                    remediation=_REMEDIATION.get("custom-timing-sqli", ""),
                    source="custom",
                ))
                return findings
        except Exception:
            pass
    return findings


async def _check_header_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Host header injection detection."""
    findings = []
    test_headers = {"Host": "evil.com", "X-Forwarded-Host": "evil.com"}

    try:
        resp = await client.get(url, headers=test_headers, follow_redirects=False)
        if "evil.com" in resp.text or "evil.com" in resp.headers.get("location", ""):
            findings.append(ScanFinding(
                template_id="custom-header-injection",
                name="Host Header Injection",
                severity="medium",
                url=url,
                matched_at=url,
                description="Application uses Host header in response content or redirects",
                confidence="tentative",
                remediation=_REMEDIATION.get("custom-header-injection", ""),
                source="custom",
            ))
    except Exception:
        pass
    return findings


async def _check_path_traversal(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Path traversal detection."""
    findings = []
    payloads = [
        ("../../../etc/passwd", ["root:", "bin:", "/bin/bash"]),
        ("....//....//....//etc/passwd", ["root:", "bin:"]),
        ("..%2f..%2f..%2fetc%2fpasswd", ["root:", "bin:"]),
    ]
    path_params = ["file", "path", "page", "template", "include", "doc", "folder"]

    for param in path_params:
        for payload, indicators in payloads:
            test_url = url + ("&" if "?" in url else "?") + f"{param}={quote(payload, safe='')}"
            try:
                resp = await client.get(test_url, follow_redirects=True)
                if any(ind in resp.text for ind in indicators):
                    findings.append(ScanFinding(
                        template_id="custom-path-traversal",
                        name="Path Traversal / Local File Inclusion",
                        severity="high",
                        url=test_url,
                        matched_at=test_url,
                        description=f"File content indicators found with payload: {payload}",
                        confidence="confirmed",
                        remediation=_REMEDIATION.get("custom-path-traversal", ""),
                        source="custom",
                    ))
                    return findings
            except Exception:
                pass
    return findings


async def _check_ssti(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Server-Side Template Injection detection."""
    findings = []
    payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
    ]

    for payload, expected in payloads:
        test_url = url + ("&" if "?" in url else "?") + f"test={quote(payload, safe='')}"
        try:
            resp = await client.get(test_url, follow_redirects=True)
            if expected in resp.text and payload not in resp.text:
                findings.append(ScanFinding(
                    template_id="custom-ssti",
                    name="Server-Side Template Injection",
                    severity="high",
                    url=test_url,
                    matched_at=test_url,
                    description=f"Template expression '{payload}' evaluated to '{expected}'",
                    confidence="confirmed",
                    remediation=_REMEDIATION.get("custom-ssti", ""),
                    source="custom",
                ))
                return findings
        except Exception:
            pass
    return findings


async def _check_command_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """OS Command injection detection via timing."""
    findings = []
    cmd_params = ["cmd", "exec", "command", "ping", "query", "ip", "host"]
    payloads = [
        ("; sleep 3", 3),
        ("| sleep 3", 3),
        ("` sleep 3`", 3),
        ("$(sleep 3)", 3),
    ]

    # Baseline timing
    try:
        start = time.monotonic()
        await client.get(url, follow_redirects=True, timeout=10.0)
        baseline = time.monotonic() - start
    except Exception:
        return findings

    for param in cmd_params:
        for payload, delay in payloads:
            test_url = url + ("&" if "?" in url else "?") + f"{param}={quote(payload, safe='')}"
            try:
                start = time.monotonic()
                await client.get(test_url, follow_redirects=True, timeout=delay + 10)
                elapsed = time.monotonic() - start

                if elapsed > baseline + delay - 0.5:
                    findings.append(ScanFinding(
                        template_id="custom-command-injection",
                        name="OS Command Injection (Time-Based)",
                        severity="critical",
                        url=test_url,
                        matched_at=test_url,
                        description=f"Response delayed by ~{elapsed:.1f}s with payload: {payload}",
                        confidence="tentative",
                        remediation=_REMEDIATION.get("custom-command-injection", ""),
                        source="custom",
                    ))
                    return findings
            except Exception:
                pass
    return findings


async def _check_verb_tampering(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """HTTP verb tampering — test if restricted endpoints allow alternate methods."""
    findings = []
    # First, check if GET is forbidden/restricted
    try:
        resp_get = await client.get(url, follow_redirects=True)
        if resp_get.status_code not in (401, 403, 405):
            return findings  # not restricted, nothing to test
    except Exception:
        return findings

    tamper_methods = ["HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]
    for method in tamper_methods:
        try:
            resp = await client.request(method, url, follow_redirects=True)
            if resp.status_code == 200 and method != "OPTIONS":
                findings.append(ScanFinding(
                    template_id="custom-verb-tampering",
                    name="HTTP Verb Tampering",
                    severity="medium",
                    url=url,
                    matched_at=url,
                    description=f"Endpoint returns 401/403 for GET but 200 for {method}",
                    confidence="confirmed",
                    remediation="Enforce access controls for all HTTP methods, not just GET/POST.",
                    source="custom",
                ))
                return findings
            if method == "TRACE" and resp.status_code == 200 and "TRACE" in resp.text:
                findings.append(ScanFinding(
                    template_id="custom-trace-enabled",
                    name="HTTP TRACE Enabled",
                    severity="low",
                    url=url,
                    matched_at=url,
                    description="TRACE method is enabled — potential for Cross-Site Tracing (XST)",
                    confidence="confirmed",
                    remediation="Disable TRACE method on the web server.",
                    source="custom",
                ))
        except Exception:
            pass
    return findings


async def _check_web_cache_deception(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Web cache deception — test if adding static file extensions causes caching of dynamic content."""
    findings = []
    static_extensions = ["/nonexistent.css", "/..%2ftest.js", "/test.jpg", "/.css"]

    try:
        baseline = await client.get(url, follow_redirects=True)
        baseline_ct = baseline.headers.get("content-type", "")
        if "html" not in baseline_ct and "json" not in baseline_ct:
            return findings  # not a dynamic page
    except Exception:
        return findings

    for ext in static_extensions:
        test_url = url.rstrip("/") + ext
        try:
            resp = await client.get(test_url, follow_redirects=True)
            cache_header = resp.headers.get("x-cache", "").lower()
            cache_control = resp.headers.get("cache-control", "").lower()
            age = resp.headers.get("age", "")

            is_cached = (
                "hit" in cache_header
                or (age and int(age) > 0)
                or ("public" in cache_control and "no-cache" not in cache_control and "no-store" not in cache_control)
            )

            # If the response has similar content to original AND is cached
            if is_cached and resp.status_code == 200:
                resp_ct = resp.headers.get("content-type", "")
                if "html" in resp_ct or "json" in resp_ct:
                    findings.append(ScanFinding(
                        template_id="custom-web-cache-deception",
                        name="Web Cache Deception",
                        severity="high",
                        url=test_url,
                        matched_at=test_url,
                        description=f"Dynamic content cached with static extension: {ext}. Cache indicators: x-cache={cache_header}, age={age}",
                        confidence="tentative",
                        remediation="Configure cache to key on full URL path. Set Cache-Control: no-store for dynamic content.",
                        source="custom",
                    ))
                    return findings
        except Exception:
            pass
    return findings


async def _check_cors_exploitation(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """CORS misconfiguration — test for overly permissive Access-Control-Allow-Origin."""
    findings = []
    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
    ]

    for origin in test_origins:
        try:
            resp = await client.get(url, headers={"Origin": origin}, follow_redirects=True)
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            if acao == origin and origin != "null":
                severity = "high" if acac == "true" else "medium"
                findings.append(ScanFinding(
                    template_id="custom-cors-arbitrary-origin",
                    name="CORS Arbitrary Origin Reflection",
                    severity=severity,
                    url=url,
                    matched_at=url,
                    description=f"Origin '{origin}' reflected in ACAO. Credentials: {acac}. Attacker can read authenticated responses cross-origin.",
                    extracted=[f"ACAO: {acao}", f"ACAC: {acac}"],
                    confidence="confirmed",
                    remediation="Validate Origin header against an allowlist. Never reflect arbitrary origins with credentials.",
                    source="custom",
                ))
                return findings

            if acao == "null" and origin == "null":
                findings.append(ScanFinding(
                    template_id="custom-cors-null-origin",
                    name="CORS Null Origin Allowed",
                    severity="medium",
                    url=url,
                    matched_at=url,
                    description="Server accepts null origin — exploitable via sandboxed iframes or data: URIs.",
                    confidence="confirmed",
                    remediation="Never allow null as a trusted origin.",
                    source="custom",
                ))
                return findings
        except Exception:
            pass

    # Check for wildcard with credentials
    try:
        resp = await client.get(url, headers={"Origin": "https://test.com"}, follow_redirects=True)
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            findings.append(ScanFinding(
                template_id="custom-cors-wildcard-credentials",
                name="CORS Wildcard with Credentials",
                severity="high",
                url=url,
                matched_at=url,
                description="ACAO is * with credentials=true — browsers block this but indicates misconfiguration.",
                confidence="tentative",
                remediation="Don't combine wildcard origin with credentials.",
                source="custom",
            ))
    except Exception:
        pass

    return findings


async def _check_prototype_pollution(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Server-side prototype pollution via JSON body injection."""
    findings = []
    payloads = [
        {"__proto__": {"polluted": "true"}},
        {"constructor": {"prototype": {"polluted": "true"}}},
    ]

    for payload in payloads:
        test_url = url + ("&" if "?" in url else "?") + "__proto__[polluted]=true"
        try:
            # Test via query parameter
            resp = await client.get(test_url, follow_redirects=True)
            if "polluted" in resp.text and resp.status_code == 500:
                findings.append(ScanFinding(
                    template_id="custom-prototype-pollution",
                    name="Prototype Pollution (Query Parameter)",
                    severity="high",
                    url=test_url,
                    matched_at=test_url,
                    description="Server error when injecting __proto__ via query parameter — possible prototype pollution",
                    confidence="tentative",
                    remediation="Sanitize user input, reject __proto__ and constructor.prototype keys. Use Object.create(null) for lookup objects.",
                    source="custom",
                ))
                return findings
        except Exception:
            pass

        # Test via JSON body
        try:
            resp = await client.post(
                url, json=payload,
                headers={"Content-Type": "application/json"},
                follow_redirects=True,
            )
            if resp.status_code == 500:
                findings.append(ScanFinding(
                    template_id="custom-prototype-pollution-json",
                    name="Prototype Pollution (JSON Body)",
                    severity="high",
                    url=url,
                    matched_at=url,
                    description=f"Server error on __proto__ injection via JSON body: {json.dumps(payload)}",
                    confidence="tentative",
                    remediation="Sanitize user input, reject __proto__ and constructor.prototype keys.",
                    source="custom",
                ))
                return findings
        except Exception:
            pass

    return findings


async def _check_dom_xss_sources(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Detect potential DOM XSS by finding dangerous JS sinks in page source."""
    findings = []
    try:
        resp = await client.get(url, follow_redirects=True)
        ct = resp.headers.get("content-type", "")
        if "html" not in ct:
            return findings
    except Exception:
        return findings

    body = resp.text

    # Dangerous sinks
    sinks = {
        r"\.innerHTML\s*=": "innerHTML assignment",
        r"\.outerHTML\s*=": "outerHTML assignment",
        r"document\.write\s*\(": "document.write()",
        r"document\.writeln\s*\(": "document.writeln()",
        r"eval\s*\(": "eval()",
        r"setTimeout\s*\(\s*['\"]": "setTimeout with string",
        r"setInterval\s*\(\s*['\"]": "setInterval with string",
        r"new\s+Function\s*\(": "new Function()",
        r"\.insertAdjacentHTML\s*\(": "insertAdjacentHTML()",
    }

    # Sources (user-controlled input flowing into JS)
    sources = {
        r"location\.hash": "location.hash",
        r"location\.search": "location.search",
        r"location\.href": "location.href",
        r"document\.URL": "document.URL",
        r"document\.referrer": "document.referrer",
        r"window\.name": "window.name",
        r"document\.cookie": "document.cookie (in JS)",
        r"postMessage": "postMessage handler",
    }

    found_sinks = []
    found_sources = []

    import re as _re
    for pattern, desc in sinks.items():
        if _re.search(pattern, body):
            found_sinks.append(desc)

    for pattern, desc in sources.items():
        if _re.search(pattern, body):
            found_sources.append(desc)

    if found_sinks and found_sources:
        findings.append(ScanFinding(
            template_id="custom-dom-xss-sources",
            name="Potential DOM XSS (Sources + Sinks Found)",
            severity="medium",
            url=url,
            matched_at=url,
            description=f"JS sources ({', '.join(found_sources[:3])}) and sinks ({', '.join(found_sinks[:3])}) found in page. Manual verification needed.",
            extracted=found_sinks[:3] + found_sources[:3],
            confidence="tentative",
            remediation="Sanitize all DOM source inputs before passing to dangerous sinks. Use textContent instead of innerHTML.",
            source="custom",
        ))

    return findings


def _assign_confidence(evidence_type: str) -> str:
    """Assign confidence level based on evidence type."""
    confirmed = {"error_message", "reflected_payload", "collaborator", "dialog_fired", "computed_result"}
    firm = {"status_diff", "timing_delta_5s", "header_diff_significant"}
    # Everything else is tentative
    if evidence_type in confirmed:
        return "confirmed"
    if evidence_type in firm:
        return "firm"
    return "tentative"


async def _check_http_method_override(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Check for HTTP method override headers."""
    findings = []
    override_headers = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"]
    for hdr in override_headers:
        try:
            resp = await client.get(url, headers={hdr: "DELETE"})
            baseline = await client.get(url)
            if resp.status_code != baseline.status_code:
                findings.append(ScanFinding(
                    template_id="http_method_override", name="HTTP Method Override Accepted",
                    severity="medium", url=url, matched_at=url,
                    description=f"Server accepts {hdr} header (sent DELETE via GET, got {resp.status_code} vs {baseline.status_code})",
                    source="custom", confidence=_assign_confidence("status_diff"),
                    remediation="Disable HTTP method override headers or restrict accepted methods.",
                ))
                break
        except Exception:
            pass
    return findings

async def _check_cache_poisoning(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Check for web cache poisoning via unkeyed headers."""
    findings = []
    canary = "pxe7kcachetest"
    unkeyed_headers = {
        "X-Forwarded-Host": f"{canary}.evil.com",
        "X-Original-URL": f"/{canary}",
        "X-Forwarded-Scheme": "nothttps",
    }
    try:
        baseline = await client.get(url)
        for hdr, val in unkeyed_headers.items():
            resp = await client.get(url, headers={hdr: val})
            if canary in resp.text and canary not in baseline.text:
                findings.append(ScanFinding(
                    template_id="cache_poisoning", name="Web Cache Poisoning",
                    severity="high", url=url, matched_at=url,
                    description=f"Unkeyed header {hdr} reflected in response body (cache poisoning risk).",
                    source="custom", confidence=_assign_confidence("reflected_payload"),
                    remediation="Ensure caches key on all headers that affect response content.",
                ))
                break
    except Exception:
        pass
    return findings

async def _check_host_header_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Check for host header injection."""
    findings = []
    canary = "pxe7khost.evil.com"
    try:
        resp = await client.get(url, headers={"Host": canary})
        if canary in resp.text:
            findings.append(ScanFinding(
                template_id="host_header_injection", name="Host Header Injection",
                severity="medium", url=url, matched_at=url,
                description=f"Injected Host header '{canary}' reflected in response.",
                source="custom", confidence=_assign_confidence("reflected_payload"),
                remediation="Do not trust the Host header for generating URLs or links.",
            ))
    except Exception:
        pass
    return findings

async def _check_blind_ssrf_collaborator(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Check for blind SSRF using collaborator payloads."""
    findings = []
    try:
        from collaborator_server import generate_unique_payload, get_interactions
        payload = generate_unique_payload(context=f"scanner:blind_ssrf:{url}")

        # Inject collaborator domain into common SSRF params
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        ssrf_params = ["url", "uri", "path", "dest", "redirect", "next", "target", "rurl", "return_url", "callback"]

        for param in ssrf_params:
            test_params = dict(params)
            test_params[param] = [payload.full_url]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            try:
                await client.get(test_url)
            except Exception:
                pass

        # Wait and check for interactions
        await asyncio.sleep(5)
        interactions = get_interactions(payload.correlation_id)
        if interactions:
            findings.append(ScanFinding(
                template_id="blind_ssrf", name="Blind SSRF (Collaborator Confirmed)",
                severity="high", url=url, matched_at=url,
                description=f"Out-of-band interaction detected ({interactions[0].protocol}) confirming blind SSRF.",
                source="custom", confidence=_assign_confidence("collaborator"),
                remediation="Validate and whitelist all URLs accessed by the server.",
            ))
    except ImportError:
        pass
    except Exception:
        pass
    return findings

async def _check_stored_xss_probe(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Inject unique XSS canary and check if it appears in later responses."""
    findings = []
    canary = f"pxe7k{uuid.uuid4().hex[:6]}"
    xss_payload = f'"><img src=x onerror=alert("{canary}")>'

    try:
        # Inject canary via POST
        await client.post(url, data={"comment": xss_payload, "name": canary, "message": xss_payload})

        # Check if canary appears in GET response
        await asyncio.sleep(1)
        resp = await client.get(url)
        if canary in resp.text and "onerror" in resp.text:
            findings.append(ScanFinding(
                template_id="stored_xss_probe", name="Potential Stored XSS",
                severity="high", url=url, matched_at=url,
                description=f"Injected XSS canary '{canary}' found unescaped in response. Confirm with browser test.",
                source="custom", confidence=_assign_confidence("reflected_payload"),
                remediation="Sanitize all user input before storing. Encode output appropriately.",
            ))
    except Exception:
        pass
    return findings


CUSTOM_CHECKS = {
    "sqli": _check_sqli_error,
    "xss": _check_xss_reflection,
    "open_redirect": _check_open_redirect,
    "ssrf": _check_ssrf,
    "crlf": _check_crlf_injection,
    "timing_sqli": _check_timing_sqli,
    "header_injection": _check_header_injection,
    "path_traversal": _check_path_traversal,
    "ssti": _check_ssti,
    "command_injection": _check_command_injection,
    "verb_tampering": _check_verb_tampering,
    "web_cache_deception": _check_web_cache_deception,
    "cors": _check_cors_exploitation,
    "prototype_pollution": _check_prototype_pollution,
    "dom_xss": _check_dom_xss_sources,
    "http_method_override": _check_http_method_override,
    "cache_poisoning": _check_cache_poisoning,
    "host_header_injection": _check_host_header_injection,
    "blind_ssrf_collaborator": _check_blind_ssrf_collaborator,
    "stored_xss_probe": _check_stored_xss_probe,
}

# Merge extended checks (15 new)
try:
    from scanner_checks_extended import EXTENDED_CHECKS
    CUSTOM_CHECKS.update(EXTENDED_CHECKS)
except ImportError:
    pass

# Merge differential analysis
try:
    from differential import DIFFERENTIAL_CHECK
    CUSTOM_CHECKS.update(DIFFERENTIAL_CHECK)
except ImportError:
    pass

# Merge expanded payload checks (15 new)
try:
    from scanner_payloads import PAYLOAD_CHECKS
    CUSTOM_CHECKS.update(PAYLOAD_CHECKS)
except ImportError:
    pass

# Merge pro checks (50 new — Phase 1)
try:
    from scanner_checks_pro import CUSTOM_CHECKS_PRO
    CUSTOM_CHECKS.update(CUSTOM_CHECKS_PRO)
except ImportError:
    pass


# ── Scan-from-flow: per-parameter testing ──────────────────────────────────

async def _inject_at_point(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    point: "InsertionPoint",
    payload: str,
) -> httpx.Response | None:
    """Inject a payload at a specific insertion point and return the response."""
    from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
    import copy

    try:
        if point.location == "url_param":
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[point.name] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            return await client.request(method, new_url, headers=headers, content=body, follow_redirects=True)

        elif point.location == "body_param":
            params = parse_qs(body or "", keep_blank_values=True)
            params[point.name] = [payload]
            new_body = urlencode(params, doseq=True)
            return await client.request(method, url, headers=headers, content=new_body, follow_redirects=True)

        elif point.location == "json_key":
            data = json.loads(body or "{}")
            _set_json_path(data, point.path, payload)
            new_body = json.dumps(data)
            return await client.request(method, url, headers=headers, content=new_body, follow_redirects=True)

        elif point.location == "cookie":
            h = copy.deepcopy(headers)
            cookies = h.get("Cookie", h.get("cookie", ""))
            new_cookies = []
            for pair in cookies.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    n, _, v = pair.partition("=")
                    if n.strip() == point.name:
                        new_cookies.append(f"{n.strip()}={payload}")
                    else:
                        new_cookies.append(pair)
                else:
                    new_cookies.append(pair)
            for k in list(h.keys()):
                if k.lower() == "cookie":
                    h[k] = "; ".join(new_cookies)
            return await client.request(method, url, headers=h, content=body, follow_redirects=True)

        elif point.location == "header":
            h = copy.deepcopy(headers)
            h[point.name] = payload
            return await client.request(method, url, headers=h, content=body, follow_redirects=True)

        elif point.location == "url_path":
            parsed = urlparse(url)
            segments = parsed.path.split("/")
            for i, seg in enumerate(segments):
                if seg == point.value:
                    segments[i] = payload
                    break
            new_path = "/".join(segments)
            new_url = urlunparse(parsed._replace(path=new_path))
            return await client.request(method, new_url, headers=headers, content=body, follow_redirects=True)

    except Exception as e:
        log.debug(f"[scan-from-flow] Injection error at {point.name}: {e}")
    return None


def _set_json_path(data: dict, path: str, value: str) -> None:
    """Set a value at a dotted JSON path like 'user.name' or 'items[0].id'."""
    import re
    parts = re.split(r"\.(?![^\[]*\])", path)
    current = data
    for i, part in enumerate(parts[:-1]):
        m = re.match(r"(.+)\[(\d+)\]$", part)
        if m:
            current = current[m.group(1)][int(m.group(2))]
        else:
            current = current[part]
    last = parts[-1]
    m = re.match(r"(.+)\[(\d+)\]$", last)
    if m:
        current[m.group(1)][int(m.group(2))] = value
    else:
        current[last] = value


# Payloads for per-parameter scan-from-flow
_PARAM_SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1 AND 1=1--", "1' AND SLEEP(2)--"]
_PARAM_XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "'-alert(1)-'", "{{7*7}}"]
_PARAM_SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
_PARAM_PATH_PAYLOADS = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//etc/passwd"]
_PARAM_CMDI_PAYLOADS = ["; sleep 2", "| sleep 2", "$(sleep 2)", "`sleep 2`"]

_SQL_ERROR_PATTERNS = [
    "sql syntax", "unclosed quotation", "pg_query", "mysql_fetch",
    "ora-01756", "sqlite3::", "microsoft ole db", "odbc sql",
    "org.postgresql", "com.mysql.jdbc",
]


async def _scan_point(
    client: httpx.AsyncClient,
    method: str, url: str, headers: dict[str, str], body: str | None,
    point: "InsertionPoint",
    checks: list[str],
    baseline_resp: httpx.Response | None,
) -> list[ScanFinding]:
    """Test a single insertion point against selected check types."""
    findings: list[ScanFinding] = []
    baseline_length = len(baseline_resp.text) if baseline_resp else 0
    baseline_time = 0.0

    for check in checks:
        if check in ("sqli", "timing_sqli"):
            for payload in _PARAM_SQLI_PAYLOADS:
                resp = await _inject_at_point(client, method, url, headers, body, point, payload)
                if not resp:
                    continue
                body_lower = resp.text.lower()
                for pat in _SQL_ERROR_PATTERNS:
                    if pat in body_lower:
                        findings.append(ScanFinding(
                            template_id="flow-sqli-error",
                            name=f"SQL Injection (Error) — {point.name}",
                            severity="high",
                            url=url,
                            matched_at=f"{point.location}:{point.name}",
                            description=f"DB error '{pat}' via payload '{payload}' at {point.location} param '{point.name}'",
                            extracted=[pat],
                            confidence="confirmed",
                            remediation=_REMEDIATION.get("custom-sqli-error", ""),
                            source="flow_scan",
                        ))
                        break

        if check == "xss":
            canary = "pxe7k<>\"'&"
            resp = await _inject_at_point(client, method, url, headers, body, point, canary)
            if resp:
                ct = resp.headers.get("content-type", "")
                if "html" in ct and canary in resp.text:
                    findings.append(ScanFinding(
                        template_id="flow-xss-reflection",
                        name=f"Reflected XSS — {point.name}",
                        severity="medium",
                        url=url,
                        matched_at=f"{point.location}:{point.name}",
                        description=f"Canary '{canary}' reflected unescaped at {point.location} param '{point.name}'",
                        extracted=[canary],
                        confidence="confirmed",
                        remediation=_REMEDIATION.get("custom-xss-reflection", ""),
                        source="flow_scan",
                    ))

        if check == "ssti":
            for payload, expected in [("{{7*7}}", "49"), ("${7*7}", "49"), ("{{7*'7'}}", "7777777")]:
                resp = await _inject_at_point(client, method, url, headers, body, point, payload)
                if resp and expected in resp.text and payload not in resp.text:
                    findings.append(ScanFinding(
                        template_id="flow-ssti",
                        name=f"SSTI — {point.name}",
                        severity="high",
                        url=url,
                        matched_at=f"{point.location}:{point.name}",
                        description=f"Template expr '{payload}' evaluated to '{expected}' at {point.location} param '{point.name}'",
                        confidence="confirmed",
                        remediation=_REMEDIATION.get("custom-ssti", ""),
                        source="flow_scan",
                    ))
                    break

        if check == "path_traversal":
            for payload in _PARAM_PATH_PAYLOADS:
                resp = await _inject_at_point(client, method, url, headers, body, point, payload)
                if resp and any(ind in resp.text for ind in ["root:", "bin:", "[extensions]"]):
                    findings.append(ScanFinding(
                        template_id="flow-path-traversal",
                        name=f"Path Traversal — {point.name}",
                        severity="high",
                        url=url,
                        matched_at=f"{point.location}:{point.name}",
                        description=f"File content found with payload '{payload}' at {point.location} param '{point.name}'",
                        confidence="confirmed",
                        remediation=_REMEDIATION.get("custom-path-traversal", ""),
                        source="flow_scan",
                    ))
                    break

        if check == "command_injection":
            if baseline_resp:
                start = time.monotonic()
                await _inject_at_point(client, method, url, headers, body, point, "test")
                baseline_time = time.monotonic() - start

            for payload in _PARAM_CMDI_PAYLOADS:
                start = time.monotonic()
                resp = await _inject_at_point(client, method, url, headers, body, point, payload)
                elapsed = time.monotonic() - start
                if resp and elapsed > baseline_time + 1.5:
                    findings.append(ScanFinding(
                        template_id="flow-command-injection",
                        name=f"Command Injection — {point.name}",
                        severity="critical",
                        url=url,
                        matched_at=f"{point.location}:{point.name}",
                        description=f"Response delayed ~{elapsed:.1f}s with payload '{payload}' at {point.location} param '{point.name}'",
                        confidence="tentative",
                        remediation=_REMEDIATION.get("custom-command-injection", ""),
                        source="flow_scan",
                    ))
                    break

    return findings


async def scan_flow(flow_id: str, checks: list[str] | None = None) -> ScanJob:
    """Scan a captured flow by testing all its insertion points individually."""
    from insertion_points import extract_from_flow

    flow = state.get_flow(flow_id)
    if not flow:
        job = ScanJob(scan_id="error", status="error", error=f"Flow {flow_id} not found")
        return job

    flow_dict = flow.model_dump()
    parsed = extract_from_flow(flow_dict)

    if not parsed.insertion_points:
        job = ScanJob(scan_id="error", status="error", error="No insertion points found in flow")
        return job

    checks = checks or ["sqli", "xss", "ssti", "path_traversal", "command_injection"]

    scan_id = str(uuid.uuid4())[:8]
    job = ScanJob(scan_id=scan_id, urls=[parsed.url])
    state.scanner_jobs[scan_id] = job

    log.info(f"[scan-from-flow] Scan {scan_id}: {len(parsed.insertion_points)} insertion points, checks={checks}")
    asyncio.create_task(_run_flow_scan(job, parsed, checks, flow_dict))
    return job


async def _run_flow_scan(job: ScanJob, parsed: "ParsedRequest", checks: list[str], flow_dict: dict) -> None:
    """Run per-parameter scanning on all insertion points."""
    from insertion_points import InsertionPoint

    try:
        auth_headers = _get_auth_headers(parsed.url)
        req_headers = {**parsed.headers, **auth_headers}

        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            # Get baseline
            try:
                baseline = await client.request(
                    parsed.method, parsed.url,
                    headers=req_headers, content=parsed.body,
                    follow_redirects=True,
                )
            except Exception:
                baseline = None

            all_findings: list[ScanFinding] = []
            for point in parsed.insertion_points:
                try:
                    results = await _scan_point(
                        client, parsed.method, parsed.url, req_headers, parsed.body,
                        point, checks, baseline,
                    )
                    all_findings.extend(results)
                except Exception as e:
                    log.warning(f"[scan-from-flow] Error scanning point {point.name}: {e}")

        job.findings = _dedup_findings(all_findings)
        job.status = "completed"
        log.info(f"[scan-from-flow] Scan {job.scan_id} completed: {len(job.findings)} findings")

    except Exception as e:
        job.status = "error"
        job.error = str(e)
        log.error(f"[scan-from-flow] Scan {job.scan_id} error: {e}")


# ── Nuclei wrapper ───────────────────────────────────────────────────────────

async def _run_nuclei(urls: list[str], req: ScanRequest) -> list[ScanFinding]:
    """Run nuclei and parse JSON output."""
    findings = []

    cmd = [NUCLEI_BIN, "-jsonl", "-silent", "-no-color", "-disable-update-check"]

    if req.templates:
        for t in req.templates:
            cmd.extend(["-t", t])

    if req.severity:
        cmd.extend(["-severity", req.severity])

    cmd.extend(["-c", str(req.concurrency)])

    url_input = "\n".join(urls)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=url_input.encode()),
                timeout=300,
            )
        except asyncio.TimeoutError:
            proc.kill()
            log.error("[scanner] nuclei timed out after 300s, killed process")
            return findings

        for line in stdout.decode("utf-8", errors="replace").strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append(ScanFinding(
                    template_id=data.get("template-id", ""),
                    name=data.get("info", {}).get("name", ""),
                    severity=data.get("info", {}).get("severity", ""),
                    url=data.get("host", ""),
                    matched_at=data.get("matched-at", ""),
                    description=data.get("info", {}).get("description", ""),
                    extracted=data.get("extracted-results", []),
                    curl_command=data.get("curl-command", ""),
                    raw=line,
                    source="nuclei",
                    remediation=data.get("info", {}).get("remediation", ""),
                ))
            except json.JSONDecodeError:
                pass

        if stderr:
            log.warning(f"[scanner] nuclei stderr: {stderr.decode()[:500]}")

    except FileNotFoundError:
        log.error("[scanner] nuclei binary not found")
    except asyncio.TimeoutError:
        log.error("[scanner] nuclei timed out after 300s")
    except Exception as e:
        log.error(f"[scanner] nuclei error: {e}")

    return findings


# ── Scan orchestration ───────────────────────────────────────────────────────

async def _run_scan(job: ScanJob, req: ScanRequest) -> None:
    """Run the full scan (nuclei + custom checks) with auth and dedup."""
    try:
        all_findings = []

        # Phase 1: Run nuclei binary (external)
        nuclei_findings = await _run_nuclei(req.urls, req)
        all_findings.extend(nuclei_findings)

        # Phase 2: Native nuclei template runtime
        try:
            from nuclei_runtime import NucleiRuntime
            runtime = NucleiRuntime.get_instance()
            if runtime.has_templates():
                native_findings = await runtime.scan(
                    req.urls,
                    severity=req.severity if hasattr(req, 'severity') and req.severity else None,
                    tags=req.templates if req.templates else None,
                )
                all_findings.extend(native_findings)
        except Exception as e:
            log.debug(f"[scanner] Native nuclei runtime error: {e}")

        # Get auth headers for custom checks (Task #22)
        auth_headers = {}
        if req.urls:
            auth_headers = _get_auth_headers(req.urls[0])

        # Run custom checks
        checks_to_run = req.custom_checks or list(CUSTOM_CHECKS.keys())
        async with httpx.AsyncClient(
            verify=False, timeout=10.0,
            headers=auth_headers,
        ) as client:
            for url in req.urls:
                for check_name in checks_to_run:
                    if check_name in CUSTOM_CHECKS:
                        try:
                            results = await CUSTOM_CHECKS[check_name](client, url)
                            all_findings.extend(results)
                        except Exception as e:
                            log.warning(f"[scanner] Custom check {check_name} failed: {e}")

        # Dedup findings (Task #24)
        all_findings = _dedup_findings(all_findings)

        job.findings = all_findings
        job.status = "completed"
        log.info(f"[scanner] Scan {job.scan_id} completed: {len(all_findings)} findings")

    except Exception as e:
        job.status = "error"
        job.error = str(e)
        log.error(f"[scanner] Scan {job.scan_id} error: {e}")


# ── Scan task pause/resume/cancel ─────────────────────────────────────────

_scan_task_events: dict[str, asyncio.Event] = {}

def pause_scan_task(scan_id: str, task_id: str) -> bool:
    """Pause a specific scan task."""
    job = state.scanner_jobs.get(scan_id)
    if not job:
        return False
    for task in job.tasks:
        if task.task_id == task_id and task.status == "running":
            key = f"{scan_id}:{task_id}"
            if key in _scan_task_events:
                _scan_task_events[key].clear()  # pause by clearing event
            task.status = "paused"
            return True
    return False

def resume_scan_task(scan_id: str, task_id: str) -> bool:
    """Resume a paused scan task."""
    job = state.scanner_jobs.get(scan_id)
    if not job:
        return False
    for task in job.tasks:
        if task.task_id == task_id and task.status == "paused":
            key = f"{scan_id}:{task_id}"
            if key in _scan_task_events:
                _scan_task_events[key].set()
            task.status = "running"
            return True
    return False

def cancel_scan_task(scan_id: str, task_id: str) -> bool:
    """Cancel a specific scan task."""
    job = state.scanner_jobs.get(scan_id)
    if not job:
        return False
    for task in job.tasks:
        if task.task_id == task_id and task.status in ("pending", "running", "paused"):
            task.status = "cancelled"
            key = f"{scan_id}:{task_id}"
            if key in _scan_task_events:
                _scan_task_events[key].set()  # unblock if waiting
            return True
    return False


async def start_incremental_scan(req: ScanRequest) -> ScanJob:
    """Start scan but skip URLs that have been scanned recently."""
    fresh_urls = []
    now = time.time()
    checks_str = ",".join(sorted(req.custom_checks or []))
    for url in req.urls:
        key = f"{url}|{checks_str}"
        last = state.scanned_endpoints.get(key, 0)
        if now - last > 3600:  # re-scan if >1 hour old
            fresh_urls.append(url)
            state.scanned_endpoints[key] = now

    if not fresh_urls:
        job_id = str(uuid.uuid4())[:8]
        job = ScanJob(scan_id=job_id, status="completed", urls=req.urls)
        state.scanner_jobs[job_id] = job
        return job

    req_copy = ScanRequest(
        urls=fresh_urls,
        templates=req.templates,
        custom_checks=req.custom_checks,
        severity=req.severity,
        concurrency=req.concurrency,
        profile=req.profile,
        crawl_first=req.crawl_first,
    )
    return await start_scan(req_copy)


async def start_scan(req: ScanRequest) -> ScanJob:
    """Start a scan job. Supports profiles and crawl-first."""
    if req.profile:
        try:
            from scan_profiles import get_profile, profile_to_scan_request
            profile = get_profile(req.profile)
            if profile:
                base = profile_to_scan_request(profile, req.urls)
                if not req.templates:
                    req.templates = base.templates
                if not req.custom_checks:
                    req.custom_checks = base.custom_checks
                if not req.severity:
                    req.severity = base.severity
                req.concurrency = base.concurrency
        except Exception as e:
            log.warning(f"[scanner] Profile error: {e}")

    scan_id = str(uuid.uuid4())[:8]
    job = ScanJob(scan_id=scan_id, urls=req.urls)
    state.scanner_jobs[scan_id] = job

    if req.crawl_first:
        log.info(f"[scanner] Crawl+audit mode: crawling {req.urls[0]} first")
        asyncio.create_task(_crawl_then_scan(job, req))
    else:
        log.info(f"[scanner] Starting scan {scan_id} on {len(req.urls)} URLs")
        asyncio.create_task(_run_scan(job, req))
    return job


async def _crawl_then_scan(job: ScanJob, req: ScanRequest) -> None:
    """Crawl target URLs first, then scan all discovered endpoints."""
    try:
        from crawler import start_crawl
        all_urls = set(req.urls)
        for url in req.urls:
            crawl_job = await start_crawl(url, max_depth=2, concurrency=5)
            for _ in range(120):
                await asyncio.sleep(1)
                if crawl_job.status != "running":
                    break
            for result in crawl_job.results:
                all_urls.add(result.url)

        job.urls = list(all_urls)
        log.info(f"[scanner] Crawl complete: {len(all_urls)} URLs. Starting scan.")
        req.urls = list(all_urls)
        await _run_scan(job, req)
    except Exception as e:
        job.status = "error"
        job.error = str(e)
        log.error(f"[scanner] Crawl+scan error: {e}")
