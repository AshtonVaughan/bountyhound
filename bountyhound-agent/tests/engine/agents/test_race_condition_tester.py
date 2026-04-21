import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from engine.agents.race_condition_tester import RaceConditionTester

class TestRaceConditionTester:
    def setup_method(self):
        self.tester = RaceConditionTester()

    def test_generates_concurrent_requests(self):
        """Should create N concurrent identical requests."""
        requests = self.tester.prepare_race(
            url="https://example.com/api/redeem",
            method="POST",
            headers={"Authorization": "Bearer token123"},
            body={"coupon": "SAVE50"},
            concurrency=10,
        )
        assert len(requests) == 10
        assert all(r["method"] == "POST" for r in requests)

    def test_detects_race_condition(self):
        """When multiple requests succeed that should only succeed once, flag it."""
        results = [
            {"status": 200, "body": {"success": True, "discount": 50}},
            {"status": 200, "body": {"success": True, "discount": 50}},
            {"status": 200, "body": {"success": True, "discount": 50}},
            {"status": 400, "body": {"error": "Already redeemed"}},
        ]
        analysis = self.tester.analyze_results(results, expected_successes=1)
        assert analysis["race_detected"] is True
        assert analysis["actual_successes"] == 3
        assert analysis["expected_successes"] == 1

    def test_no_false_positive_on_idempotent(self):
        """Idempotent operations returning 200 are not race conditions."""
        results = [
            {"status": 200, "body": {"data": "same"}},
            {"status": 200, "body": {"data": "same"}},
        ]
        analysis = self.tester.analyze_results(results, expected_successes=None)
        assert analysis["race_detected"] is False
