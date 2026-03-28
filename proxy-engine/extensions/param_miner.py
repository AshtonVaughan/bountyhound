"""Param Miner — brute-force hidden query/header parameters.

Sends batched requests with candidate parameters and detects response differences.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from models import ScanFinding

log = logging.getLogger("ext-param-miner")

NAME = "param-miner"
DESCRIPTION = "Brute-force hidden query/header params (batched 10/req), detect by response diff"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "batch_size": 10,
    "max_params": 200,
    "diff_threshold": 50,       # min body length diff to flag
    "test_headers": True,
    "test_query": True,
    "wordlist": "default",
}

# Common hidden parameters
PARAM_WORDLIST = [
    "debug", "test", "admin", "internal", "verbose", "dev", "source", "format",
    "callback", "jsonp", "cors", "origin", "redirect", "url", "next", "return",
    "ref", "token", "key", "api_key", "apikey", "secret", "password", "passwd",
    "user", "username", "email", "id", "uid", "role", "type", "action", "method",
    "cmd", "command", "exec", "run", "query", "search", "q", "s", "filter",
    "sort", "order", "limit", "offset", "page", "per_page", "fields", "include",
    "exclude", "expand", "select", "columns", "view", "template", "render",
    "file", "path", "dir", "directory", "folder", "filename", "upload", "download",
    "lang", "language", "locale", "region", "country", "currency", "timezone",
    "version", "v", "api_version", "X-Forwarded-For", "X-Forwarded-Host",
    "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
    "_method", "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    "cache", "nocache", "no-cache", "pragma", "x-cache", "x-debug",
    "x-forwarded-proto", "x-forwarded-port", "x-forwarded-scheme",
    "transfer-encoding", "content-encoding", "content-type",
    "x-request-id", "x-correlation-id", "x-trace-id",
    "authorization", "x-api-key", "x-auth-token", "x-csrf-token",
    "accept", "accept-language", "accept-encoding",
    "host", "connection", "te", "upgrade",
    "wsdl", "wadl", "raml", "swagger", "openapi",
    "metrics", "health", "healthcheck", "status", "info",
    "env", "environment", "config", "settings", "setup",
    "reset", "clear", "flush", "purge", "refresh",
    "batch", "bulk", "async", "sync", "queue",
]

HEADER_WORDLIST = [
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
    "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
    "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    "X-Debug", "X-Debug-Token", "X-Requested-With",
    "True-Client-IP", "Client-IP", "Forwarded",
    "X-Real-IP", "CF-Connecting-IP", "X-Client-IP",
    "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-ProxyUser-Ip", "Via", "X-Cluster-Client-IP",
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Brute-force hidden parameters."""
    findings = []

    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        # Get baseline response
        try:
            baseline = await client.get(url, follow_redirects=True)
        except Exception:
            return findings

        baseline_len = len(baseline.content)
        baseline_status = baseline.status_code

        # Test query parameters in batches
        if _config.get("test_query", True):
            batch_size = _config.get("batch_size", 10)
            params_to_test = PARAM_WORDLIST[:_config.get("max_params", 200)]

            for i in range(0, len(params_to_test), batch_size):
                batch = params_to_test[i:i + batch_size]
                query_params = {p: "1" for p in batch}

                try:
                    resp = await client.get(url, params=query_params, follow_redirects=True)
                    diff = abs(len(resp.content) - baseline_len)

                    if diff > _config.get("diff_threshold", 50) or resp.status_code != baseline_status:
                        # Narrow down which parameter caused the diff
                        for param in batch:
                            try:
                                single_resp = await client.get(url, params={param: "1"}, follow_redirects=True)
                                single_diff = abs(len(single_resp.content) - baseline_len)

                                if single_diff > _config.get("diff_threshold", 50) or single_resp.status_code != baseline_status:
                                    findings.append(ScanFinding(
                                        template_id=f"hidden_param_{param}",
                                        name=f"Hidden Parameter Discovered: {param}",
                                        severity="low" if single_resp.status_code == baseline_status else "medium",
                                        url=url,
                                        matched_at=f"{url}?{param}=1",
                                        description=f"Hidden query parameter '{param}' affects response. Length diff: {single_diff}, Status: {single_resp.status_code}.",
                                        extracted=[f"param={param}", f"diff={single_diff}", f"status={single_resp.status_code}"],
                                        source="extension",
                                        confidence="firm",
                                        remediation="Review if hidden parameters expose debug/admin functionality.",
                                    ))
                            except Exception:
                                continue
                except Exception:
                    continue

        # Test header parameters
        if _config.get("test_headers", True):
            for header_name in HEADER_WORDLIST:
                try:
                    resp = await client.get(
                        url,
                        headers={header_name: "127.0.0.1"},
                        follow_redirects=True,
                    )
                    diff = abs(len(resp.content) - baseline_len)

                    if diff > _config.get("diff_threshold", 50) or resp.status_code != baseline_status:
                        findings.append(ScanFinding(
                            template_id=f"hidden_header_{header_name.lower()}",
                            name=f"Hidden Header Affects Response: {header_name}",
                            severity="medium",
                            url=url,
                            matched_at=url,
                            description=f"Header '{header_name}' changes server behavior. Length diff: {diff}, Status: {resp.status_code}.",
                            extracted=[f"header={header_name}", f"diff={diff}"],
                            source="extension",
                            confidence="firm",
                            remediation="Review header processing. Hidden headers may enable access control bypass.",
                        ))
                except Exception:
                    continue

    return findings
