"""Race Condition — send parallel identical requests and detect response inconsistencies."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.race-condition")

NAME = "race-condition"
DESCRIPTION = "Send N parallel identical requests to detect race conditions via response inconsistencies"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "parallel_requests": 10,
    "timeout": 15.0,
    "methods": ["GET", "POST"],
}


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Send parallel requests and analyze for race condition indicators."""
    findings: list[ScanFinding] = []
    n = _config.get("parallel_requests", 10)
    timeout = _config.get("timeout", 15.0)
    methods = _config.get("methods", ["GET", "POST"])

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        for method in methods:
            findings.extend(await _test_race(client, url, method, n))

    return findings


async def _test_race(
    client: httpx.AsyncClient, url: str, method: str, n: int
) -> list[ScanFinding]:
    """Send N parallel requests and compare responses."""
    findings: list[ScanFinding] = []

    try:
        if method == "POST":
            baseline = await client.post(url)
        else:
            baseline = await client.get(url)
    except Exception as e:
        log.debug("Race condition baseline error: %s", e)
        return findings

    async def send_request(idx: int) -> dict:
        start = time.monotonic()
        try:
            if method == "POST":
                resp = await client.post(url)
            else:
                resp = await client.get(url)
            elapsed = time.monotonic() - start
            return {
                "index": idx,
                "status": resp.status_code,
                "length": len(resp.text),
                "body_hash": hash(resp.text[:2000]),
                "elapsed": elapsed,
                "headers": dict(resp.headers),
                "body_preview": resp.text[:500],
                "error": None,
            }
        except Exception as e:
            elapsed = time.monotonic() - start
            return {
                "index": idx,
                "status": 0,
                "length": 0,
                "body_hash": 0,
                "elapsed": elapsed,
                "headers": {},
                "body_preview": "",
                "error": str(e),
            }

    tasks = [send_request(i) for i in range(n)]
    results = await asyncio.gather(*tasks)

    successful = [r for r in results if r["error"] is None]

    if len(successful) < 2:
        return findings

    # 1. Status code inconsistencies
    status_codes = [r["status"] for r in successful]
    unique_statuses = set(status_codes)
    if len(unique_statuses) > 1:
        status_counts = {s: status_codes.count(s) for s in unique_statuses}
        findings.append(ScanFinding(
            template_id="race_condition_status",
            name="Race Condition: Inconsistent Status Codes (" + method + ")",
            severity="medium",
            url=url,
            matched_at=url,
            description=(
                "Sending " + str(n) + " parallel " + method + " requests produced "
                "inconsistent status codes: " + str(status_counts) + ". "
                "This may indicate a race condition in request handling."
            ),
            extracted=[
                "Method: " + method,
                "Parallel requests: " + str(n),
                "Status distribution: " + str(status_counts),
                "Successful responses: " + str(len(successful)) + "/" + str(n),
            ],
            source="extension",
            confidence="firm",
            remediation=(
                "Implement proper locking/synchronization for state-changing operations. "
                "Use database-level constraints and transactions."
            ),
        ))

    # 2. Response body inconsistencies
    body_hashes = [r["body_hash"] for r in successful]
    unique_bodies = set(body_hashes)
    if len(unique_bodies) > 1 and len(unique_statuses) == 1:
        lengths = [r["length"] for r in successful]
        findings.append(ScanFinding(
            template_id="race_condition_body",
            name="Race Condition: Inconsistent Response Bodies (" + method + ")",
            severity="medium",
            url=url,
            matched_at=url,
            description=(
                "Sending " + str(n) + " parallel " + method + " requests with same "
                "status code (" + str(status_codes[0]) + ") but " +
                str(len(unique_bodies)) + " different response bodies. "
                "Body lengths: min=" + str(min(lengths)) + ", max=" + str(max(lengths)) + ". "
                "This strongly indicates a race condition."
            ),
            extracted=[
                "Method: " + method,
                "Unique bodies: " + str(len(unique_bodies)),
                "Body length range: " + str(min(lengths)) + "-" + str(max(lengths)),
            ],
            source="extension",
            confidence="firm",
            remediation="Add mutex/locking around state-changing operations. Use idempotency keys.",
        ))

    # 3. Timing analysis
    times = [r["elapsed"] for r in successful]
    avg_time = sum(times) / len(times)
    max_time = max(times)
    min_time = min(times)
    variance = max_time - min_time

    if variance > avg_time * 2 and variance > 1.0:
        findings.append(ScanFinding(
            template_id="race_condition_timing",
            name="Race Condition: High Timing Variance (" + method + ")",
            severity="low",
            url=url,
            matched_at=url,
            description=(
                "Parallel " + method + " requests show high timing variance: "
                "min=" + "{:.2f}".format(min_time) + "s, "
                "max=" + "{:.2f}".format(max_time) + "s, "
                "avg=" + "{:.2f}".format(avg_time) + "s, "
                "variance=" + "{:.2f}".format(variance) + "s. "
                "May indicate resource contention or lock waits."
            ),
            extracted=[
                "Min time: " + "{:.3f}".format(min_time) + "s",
                "Max time: " + "{:.3f}".format(max_time) + "s",
                "Average: " + "{:.3f}".format(avg_time) + "s",
                "Variance: " + "{:.3f}".format(variance) + "s",
            ],
            source="extension",
            confidence="tentative",
            remediation="Investigate server-side locking behavior under concurrent access.",
        ))

    # 4. Partial failures under concurrency
    error_count = sum(1 for r in results if r["error"] is not None)
    if error_count > 0 and error_count < n:
        error_samples = [r["error"][:100] for r in results if r["error"]][:3]
        findings.append(ScanFinding(
            template_id="race_condition_errors",
            name="Race Condition: Partial Failures Under Concurrency (" + method + ")",
            severity="medium",
            url=url,
            matched_at=url,
            description=(
                str(error_count) + "/" + str(n) + " parallel " + method +
                " requests failed. Partial failures under concurrency may indicate "
                "resource exhaustion or unhandled concurrent access."
            ),
            extracted=[
                "Success: " + str(len(successful)) + "/" + str(n),
                "Failures: " + str(error_count) + "/" + str(n),
                "Error samples: " + str(error_samples),
            ],
            source="extension",
            confidence="tentative",
            remediation="Implement proper concurrency handling. Add rate limiting and resource pooling.",
        ))

    # 5. Duplicate operation indicators
    if len(unique_bodies) > 1:
        id_pattern = re.compile(r'"(?:id|order_id|transaction_id|ref)":\s*(\d+)')
        ids: list[int] = []
        for r in successful:
            matches = id_pattern.findall(r["body_preview"])
            for m in matches:
                try:
                    ids.append(int(m))
                except ValueError:
                    pass

        if len(ids) > 1 and len(set(ids)) > 1:
            sorted_ids = sorted(set(ids))
            findings.append(ScanFinding(
                template_id="race_condition_duplicate_ops",
                name="Race Condition: Multiple Operations Created (" + method + ")",
                severity="high",
                url=url,
                matched_at=url,
                description=(
                    "Parallel requests created multiple distinct resources (IDs: " +
                    str(sorted_ids) + "). This indicates a TOCTOU race condition -- "
                    "operations that should be idempotent are being duplicated."
                ),
                extracted=[
                    "Unique IDs: " + str(sorted_ids),
                    "Total requests: " + str(n),
                    "Resources created: " + str(len(set(ids))),
                ],
                source="extension",
                confidence="confirmed",
                remediation=(
                    "Use database-level unique constraints and transactions. "
                    "Implement idempotency keys for all state-changing operations."
                ),
            ))

    return findings
