#!/usr/bin/env python3
"""Quick test runner to verify api_rate_limit_tester works."""

import asyncio
import sys
from engine.agents.api_rate_limit_tester import (
    ApiRateLimitTester,
    RateLimitProfile,
    RateLimitVulnerability,
    RateLimitSeverity,
    RateLimitVulnType
)

def test_initialization():
    """Test basic initialization."""
    print("Test 1: Initialization...")
    tester = ApiRateLimitTester("example.com")
    assert tester.target_domain == "example.com"
    assert tester.base_url == "https://example.com"
    assert tester.api_key is None
    print("[PASS] Initialization works")

def test_data_classes():
    """Test data classes."""
    print("\nTest 2: Data classes...")

    # Test profile
    profile = RateLimitProfile(
        endpoint="/api/test",
        threshold=100,
        window_seconds=60,
        reset_behavior="sliding",
        headers_present=True
    )
    assert profile.endpoint == "/api/test"
    assert profile.threshold == 100

    # Test vulnerability
    vuln = RateLimitVulnerability(
        endpoint="/api/login",
        vuln_type=RateLimitVulnType.MISSING_RATE_LIMIT,
        severity=RateLimitSeverity.HIGH,
        description="No rate limit",
        poc="curl test",
        remediation="Add rate limit",
        bounty_estimate="$1000-$5000",
        exploit_complexity="Low"
    )
    assert vuln.endpoint == "/api/login"
    assert vuln.vuln_type == RateLimitVulnType.MISSING_RATE_LIMIT

    # Test serialization
    data = vuln.to_dict()
    assert data['severity'] == 'HIGH'
    assert data['vuln_type'] == 'MISSING_RATE_LIMIT'

    print("[PASS] Data classes work")

def test_constants():
    """Test class constants."""
    print("\nTest 3: Constants...")
    assert len(ApiRateLimitTester.SPOOFING_HEADERS) >= 8
    assert len(ApiRateLimitTester.USER_AGENTS) >= 7
    assert "X-Forwarded-For" in ApiRateLimitTester.SPOOFING_HEADERS
    print("[PASS] Constants defined")

async def test_context_manager():
    """Test async context manager."""
    print("\nTest 4: Async context manager...")
    tester = ApiRateLimitTester("example.com")

    async with tester:
        assert tester.session is not None
        session = tester.session

    # Session should be closed
    assert session.closed
    print("[PASS] Context manager works")

def test_summary():
    """Test summary generation."""
    print("\nTest 5: Summary generation...")
    tester = ApiRateLimitTester("example.com")

    # Empty summary
    summary = tester.get_summary()
    assert summary['target'] == "example.com"
    assert summary['total_findings'] == 0
    assert summary['vulnerable'] is False

    # Add a finding
    tester.findings.append(RateLimitVulnerability(
        endpoint="/api/test",
        vuln_type=RateLimitVulnType.MISSING_RATE_LIMIT,
        severity=RateLimitSeverity.CRITICAL,
        description="Test",
        poc="Test",
        remediation="Test",
        bounty_estimate="$1000",
        exploit_complexity="Low"
    ))

    summary = tester.get_summary()
    assert summary['total_findings'] == 1
    assert summary['vulnerable'] is True
    assert summary['critical_count'] == 1

    print("[PASS] Summary generation works")

def main():
    """Run all tests."""
    print("="*60)
    print("API Rate Limit Tester - Quick Test Suite")
    print("="*60)

    try:
        test_initialization()
        test_data_classes()
        test_constants()
        asyncio.run(test_context_manager())
        test_summary()

        print("\n" + "="*60)
        print("[SUCCESS] ALL TESTS PASSED")
        print("="*60)
        return 0

    except Exception as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
