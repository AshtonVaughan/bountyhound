"""
NoSQL Injection Tester - Usage Example

Demonstrates how to use the NoSQL injection tester agent to test
web applications for NoSQL injection vulnerabilities.

Author: BountyHound Team
"""

import asyncio
import json
from engine.agents.nosql_injection_tester import NoSQLInjectionTester


async def test_mongodb_login():
    """Test a MongoDB-backed login endpoint."""
    print("=" * 70)
    print("EXAMPLE 1: Testing MongoDB Login Endpoint")
    print("=" * 70)

    # Create tester instance
    tester = NoSQLInjectionTester(
        target_url="https://vulnerable-app.example.com/api/login",
        target="vulnerable-app.example.com",
        timeout=10
    )

    # Run all tests
    findings = await tester.test_all()

    # Print results
    print(f"\n[+] Testing complete!")
    print(f"[+] Tests run: {tester.tests_run}")
    print(f"[+] Findings: {len(findings)}")

    if findings:
        print("\n[!] VULNERABILITIES FOUND:")
        for finding in findings:
            print(f"\n  Finding ID: {finding.finding_id}")
            print(f"  Severity: {finding.severity}")
            print(f"  Title: {finding.title}")
            print(f"  Database: {finding.db_type.value}")
            print(f"  Injection Type: {finding.injection_type.value}")
            print(f"  Payload: {finding.payload[:80]}...")
            print(f"  Bounty Estimate: {finding.bounty_estimate}")

    # Get summary
    summary = tester.get_summary()
    print("\n[+] SUMMARY:")
    print(json.dumps(summary, indent=2))


async def test_redis_endpoint():
    """Test a Redis-backed caching endpoint."""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: Testing Redis Cache Endpoint")
    print("=" * 70)

    tester = NoSQLInjectionTester(
        target_url="https://api.example.com/cache",
        target="api.example.com"
    )

    findings = await tester.test_all()

    # Filter Redis findings
    redis_findings = [f for f in findings if f.db_type.value == "redis"]

    if redis_findings:
        print(f"\n[!] Found {len(redis_findings)} Redis vulnerabilities:")
        for finding in redis_findings:
            print(f"\n  - {finding.title}")
            print(f"    Impact: {finding.impact}")
            print(f"    Remediation: {finding.remediation}")


async def test_elasticsearch_api():
    """Test an Elasticsearch-backed search API."""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: Testing Elasticsearch Search API")
    print("=" * 70)

    tester = NoSQLInjectionTester(
        target_url="https://search.example.com/_search",
        target="search.example.com",
        max_payloads=20  # Limit payloads for faster testing
    )

    findings = await tester.test_all()

    # Get critical findings
    critical = tester.get_findings_by_severity("CRITICAL")
    high = tester.get_findings_by_severity("HIGH")

    print(f"\n[+] Critical findings: {len(critical)}")
    print(f"[+] High findings: {len(high)}")

    if critical:
        print("\n[!] CRITICAL VULNERABILITIES:")
        for finding in critical:
            print(f"\n  {finding.title}")
            print(f"  Evidence: {json.dumps(finding.evidence, indent=4)}")


async def test_multiple_databases():
    """Test an endpoint that might use multiple NoSQL databases."""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: Comprehensive Multi-Database Testing")
    print("=" * 70)

    tester = NoSQLInjectionTester(
        target_url="https://api.example.com/data",
        target="api.example.com"
    )

    findings = await tester.test_all()

    # Group findings by database type
    by_db = {}
    for finding in findings:
        db_type = finding.db_type.value
        if db_type not in by_db:
            by_db[db_type] = []
        by_db[db_type].append(finding)

    print(f"\n[+] Findings by database type:")
    for db_type, db_findings in by_db.items():
        print(f"\n  {db_type.upper()}: {len(db_findings)} vulnerabilities")
        for f in db_findings:
            print(f"    - {f.severity}: {f.title}")


async def test_auth_bypass_specific():
    """Test specifically for authentication bypass vulnerabilities."""
    print("\n" + "=" * 70)
    print("EXAMPLE 5: Authentication Bypass Testing")
    print("=" * 70)

    tester = NoSQLInjectionTester(
        target_url="https://app.example.com/api/auth/login",
        target="app.example.com"
    )

    # Run all tests
    findings = await tester.test_all()

    # Filter authentication bypass findings
    auth_bypass = [
        f for f in findings
        if f.injection_type.value == "auth_bypass"
    ]

    if auth_bypass:
        print(f"\n[!] CRITICAL: Found {len(auth_bypass)} authentication bypass vulnerabilities!")
        for finding in auth_bypass:
            print(f"\n  {finding.title}")
            print(f"  Severity: {finding.severity}")
            print(f"  Payload: {finding.payload}")
            print(f"  Impact: {finding.impact}")
            print(f"\n  POC - How to exploit:")
            print(f"  1. Send POST request to: {finding.endpoint}")
            print(f"  2. Use payload: {finding.payload}")
            print(f"  3. Expected result: Authentication bypass")
    else:
        print("\n[+] No authentication bypass vulnerabilities found.")


async def test_with_timing_analysis():
    """Test for blind injection using timing analysis."""
    print("\n" + "=" * 70)
    print("EXAMPLE 6: Blind NoSQL Injection (Time-Based)")
    print("=" * 70)

    tester = NoSQLInjectionTester(
        target_url="https://api.example.com/search",
        target="api.example.com",
        timeout=15  # Longer timeout for timing tests
    )

    findings = await tester.test_all()

    # Filter timing-based findings
    timing_findings = [
        f for f in findings
        if f.injection_type.value == "timing_injection"
    ]

    if timing_findings:
        print(f"\n[!] Found {len(timing_findings)} time-based blind injection vulnerabilities:")
        for finding in timing_findings:
            print(f"\n  {finding.title}")
            print(f"  Evidence: {finding.evidence}")
    else:
        print("\n[+] No time-based blind injection found.")


async def main():
    """Run all examples."""
    print("\n")
    print("*" * 70)
    print("*" + " " * 68 + "*")
    print("*" + " NoSQL Injection Tester - Usage Examples ".center(68) + "*")
    print("*" + " " * 68 + "*")
    print("*" * 70)

    # Note: These are examples only. Replace URLs with actual targets.
    print("\nNOTE: These are example demonstrations.")
    print("Replace target URLs with actual endpoints to test.")
    print("\nExamples will not execute against real endpoints.")

    # Uncomment to run specific examples:
    # await test_mongodb_login()
    # await test_redis_endpoint()
    # await test_elasticsearch_api()
    # await test_multiple_databases()
    # await test_auth_bypass_specific()
    # await test_with_timing_analysis()

    print("\n" + "=" * 70)
    print("Examples complete. Modify and uncomment to test real endpoints.")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
