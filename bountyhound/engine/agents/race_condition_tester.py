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
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


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

        start_time = time.monotonic()
        async with session.request(method, **kwargs) as resp:
            try:
                body = await resp.json()
            except Exception:
                body = await resp.text()
            body_str = str(body) if not isinstance(body, str) else body
            return {
                "status": resp.status,
                "body": body,
                "body_hash": hashlib.md5(body_str.encode()).hexdigest(),
                "start_time": start_time,
                "elapsed_ms": round((time.monotonic() - start_time) * 1000, 1),
            }

    def analyze_results(self, results: list[dict], expected_successes: int = 1) -> dict:
        """Analyze with timing window validation and confidence scoring."""
        successes = [r for r in results if r.get("status") == 200 and not r.get("error")]
        actual = len(successes)

        # Unique response check (duplicate bodies = no race)
        unique_bodies = set(r.get("body_hash") for r in successes if r.get("body_hash"))

        # Timing window: were requests actually concurrent?
        start_times = sorted(r.get("start_time", 0) for r in results if r.get("start_time"))
        window_ms = round((start_times[-1] - start_times[0]) * 1000, 1) if len(start_times) >= 2 else 0

        detected = actual > expected_successes

        # Confidence scoring
        if detected and window_ms < 50:
            confidence = "HIGH"
        elif detected and window_ms < 200:
            confidence = "MEDIUM"
        elif detected:
            confidence = "LOW"  # Requests too spread out
        else:
            confidence = "NONE"

        return {
            "race_detected": detected,
            "actual_successes": actual,
            "expected_successes": expected_successes,
            "unique_responses": len(unique_bodies),
            "total_requests": len(results),
            "request_window_ms": window_ms,
            "concurrent": window_ms < 100,
            "confidence": confidence,
            "reason": self._build_reason(detected, actual, expected_successes),
        }

    async def fire_race_with_retry(
        self, requests: list, timeout: int = 10, retries: int = 3, expected_successes: int = 1
    ) -> dict:
        """Run race test multiple times to confirm consistency."""
        attempts = []
        detected_count = 0

        for i in range(retries):
            results = await self.fire_race(requests, timeout)
            analysis = self.analyze_results(results, expected_successes)
            attempts.append(analysis)
            if analysis["race_detected"]:
                detected_count += 1

        return {
            "confirmed": detected_count >= 2,  # 2/3 = consistent
            "detection_rate": f"{detected_count}/{retries}",
            "confidence": "HIGH" if detected_count == retries else "MEDIUM" if detected_count >= 2 else "NONE",
            "attempts": attempts,
        }

    def _build_reason(self, detected: bool, actual: int, expected: int) -> str:
        if detected:
            return f"Race condition detected: {actual} successful operations (expected max {expected}). {actual - expected} duplicate operations executed."
        return f"No race condition: {actual} successes within expected range (max {expected})"
