"""
Race Condition Tester - Finds TOCTOU and parallel execution vulnerabilities.

High-value targets:
- Coupon/promo code redemption
- Funds transfer / withdrawal
- Like/vote counting
- Inventory/stock purchase
- Account creation (duplicate accounts)

Uses asyncio + aiohttp for true concurrent request firing.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


@dataclass
class RaceRequest:
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[Dict] = None


class RaceConditionTester:
    """Tests for race conditions via concurrent request firing."""

    def prepare_race(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict] = None,
        concurrency: int = 10,
    ) -> List[Dict[str, Any]]:
        """Prepare N identical requests for concurrent execution."""
        return [
            {
                "url": url,
                "method": method,
                "headers": headers or {},
                "body": body,
            }
            for _ in range(concurrency)
        ]

    async def fire_race(self, requests: List[Dict[str, Any]], timeout: float = 10.0) -> List[Dict[str, Any]]:
        """Fire all requests concurrently and collect results."""
        if not HAS_AIOHTTP:
            raise ImportError("aiohttp required for race condition testing: pip install aiohttp")

        results = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for req in requests:
                tasks.append(self._send_request(session, req, timeout))

            start = time.monotonic()
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.monotonic() - start

            for i, resp in enumerate(responses):
                if isinstance(resp, Exception):
                    results.append({"status": 0, "body": str(resp), "error": True})
                else:
                    results.append(resp)

            # Log timing - all requests should land within ~50ms for effective race
            results_meta = {"total_time_ms": round(elapsed * 1000, 2)}

        return results

    async def _send_request(self, session: aiohttp.ClientSession, req: Dict, timeout: float) -> Dict:
        """Send a single request."""
        method = req["method"].upper()
        kwargs = {
            "url": req["url"],
            "headers": req["headers"],
            "timeout": aiohttp.ClientTimeout(total=timeout),
            "ssl": False,
        }
        if req.get("body"):
            kwargs["json"] = req["body"]

        async with session.request(method, **kwargs) as resp:
            try:
                body = await resp.json()
            except Exception:
                body = await resp.text()
            return {"status": resp.status, "body": body}

    def analyze_results(
        self,
        results: List[Dict[str, Any]],
        expected_successes: Optional[int] = 1,
    ) -> Dict[str, Any]:
        """Analyze race condition test results."""
        successes = [r for r in results if r.get("status") == 200 and not r.get("error")]
        failures = [r for r in results if r.get("status") != 200 or r.get("error")]

        # Check if responses are all identical (idempotent = no race condition)
        if len(successes) > 1:
            bodies = [str(r.get("body", "")) for r in successes]
            all_identical = len(set(bodies)) == 1

            if all_identical and expected_successes is None:
                return {
                    "race_detected": False,
                    "actual_successes": len(successes),
                    "expected_successes": expected_successes,
                    "reason": "All responses identical - likely idempotent operation",
                }

        race_detected = False
        if expected_successes is not None and len(successes) > expected_successes:
            race_detected = True

        return {
            "race_detected": race_detected,
            "actual_successes": len(successes),
            "expected_successes": expected_successes,
            "total_requests": len(results),
            "failures": len(failures),
            "reason": self._build_reason(race_detected, len(successes), expected_successes),
        }

    def _build_reason(self, detected: bool, actual: int, expected: Optional[int]) -> str:
        if detected:
            return f"RACE CONDITION: {actual} successes when only {expected} expected"
        return f"No race condition: {actual} successes"
