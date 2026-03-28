"""Turbo Intruder — race condition testing via parallel requests.

Uses asyncio.gather() for concurrent requests to detect TOCTOU and race conditions.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from models import ScanFinding

log = logging.getLogger("ext-turbo-intruder")

NAME = "turbo-intruder"
DESCRIPTION = "Race condition testing via asyncio.gather() parallel requests, TOCTOU detection"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "concurrency": 20,          # Number of parallel requests
    "method": "GET",
    "body": None,
    "headers": {},
    "rounds": 3,                # Number of race rounds
}


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Test for race conditions by sending parallel requests."""
    findings = []
    concurrency = _config.get("concurrency", 20)
    rounds = _config.get("rounds", 3)
    method = _config.get("method", "GET")
    body = _config.get("body")
    extra_headers = _config.get("headers", {})

    async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
        for round_num in range(rounds):
            # Fire parallel requests simultaneously
            async def _make_request(idx: int) -> dict:
                start = time.time()
                try:
                    resp = await client.request(
                        method, url,
                        headers=extra_headers if extra_headers else None,
                        content=body,
                        follow_redirects=True,
                    )
                    return {
                        "idx": idx,
                        "status": resp.status_code,
                        "length": len(resp.content),
                        "time": time.time() - start,
                        "headers": dict(resp.headers),
                    }
                except Exception as e:
                    return {"idx": idx, "error": str(e), "time": time.time() - start}

            tasks = [_make_request(i) for i in range(concurrency)]
            results = await asyncio.gather(*tasks)

            # Analyze results for race condition indicators
            valid = [r for r in results if "status" in r]
            if len(valid) < 2:
                continue

            statuses = {r["status"] for r in valid}
            lengths = [r["length"] for r in valid]
            times = [r["time"] for r in valid]

            # Inconsistent statuses suggest race condition
            if len(statuses) > 1:
                findings.append(ScanFinding(
                    template_id="race_condition_status",
                    name="Race Condition: Inconsistent Status Codes",
                    severity="medium",
                    url=url,
                    matched_at=url,
                    description=f"Parallel requests yielded different status codes: {statuses}. Round {round_num + 1}/{rounds}.",
                    extracted=[f"statuses={statuses}", f"concurrency={concurrency}"],
                    source="extension",
                    confidence="firm",
                    remediation="Implement proper locking for state-changing operations. Use database-level constraints.",
                ))
                break

            # Large response length variance
            if lengths:
                variance = max(lengths) - min(lengths)
                if variance > 500:
                    findings.append(ScanFinding(
                        template_id="race_condition_length",
                        name="Race Condition: Response Length Variance",
                        severity="low",
                        url=url,
                        matched_at=url,
                        description=f"Parallel requests show {variance}B response variance. May indicate TOCTOU.",
                        extracted=[f"min={min(lengths)}", f"max={max(lengths)}", f"variance={variance}"],
                        source="extension",
                        confidence="tentative",
                        remediation="Review endpoint for time-of-check/time-of-use vulnerabilities.",
                    ))
                    break

    return findings
