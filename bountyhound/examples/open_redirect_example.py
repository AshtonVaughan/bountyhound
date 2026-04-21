#!/usr/bin/env python3
"""
Open Redirect Tester - Usage Example

Demonstrates how to use the OpenRedirectTester agent to find
open redirect vulnerabilities.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.agents.open_redirect_tester import (
    OpenRedirectTester,
    PayloadGenerator,
    RedirectAnalyzer,
    run_open_redirect_tests
)


def example_basic_usage():
    """Basic usage example"""
    print("=" * 60)
    print("Example 1: Basic Open Redirect Testing")
    print("=" * 60)

    # Initialize tester
    tester = OpenRedirectTester(
        target="example.com",
        timeout=10,
        attacker_domain="evil.com"
    )

    # Test a URL with existing parameters
    print("\n[*] Testing URL with parameters...")
    findings = tester.test_url(
        "https://example.com/login",
        parameters={"redirect": "/dashboard"}
    )

    # Display results
    print(f"\n[+] Found {len(findings)} vulnerabilities")
    for finding in findings:
        print(f"\n  Severity: {finding.severity.upper()}")
        print(f"  Parameter: {finding.parameter}")
        print(f"  Payload: {finding.payload}")
        print(f"  POC: {finding.poc}")

    # Get statistics
    stats = tester.get_statistics()
    print(f"\n[*] Statistics:")
    print(f"  Tests run: {stats['tests_run']}")
    print(f"  Tests passed: {stats['tests_passed']}")
    print(f"  Critical: {stats['critical']}")
    print(f"  High: {stats['high']}")
    print(f"  Medium: {stats['medium']}")


def example_payload_generation():
    """Payload generation example"""
    print("\n" + "=" * 60)
    print("Example 2: Payload Generation")
    print("=" * 60)

    gen = PayloadGenerator("evil.com")

    # Basic payloads
    print("\n[*] Basic Payloads:")
    basic = gen.generate_basic_payloads()
    for i, payload in enumerate(basic[:3], 1):
        print(f"  {i}. {payload.payload} ({payload.bypass_technique})")

    # Filter bypass payloads
    print("\n[*] Filter Bypass Payloads:")
    bypass = gen.generate_filter_bypass_payloads("legitimate.com")
    for i, payload in enumerate(bypass[:5], 1):
        print(f"  {i}. {payload.payload[:60]}... ({payload.bypass_technique})")

    # Protocol bypass
    print("\n[*] Protocol Bypass Payloads:")
    protocol = gen.generate_protocol_bypass_payloads()
    for i, payload in enumerate(protocol, 1):
        print(f"  {i}. {payload.bypass_technique}")

    # OAuth payloads
    print("\n[*] OAuth Payloads:")
    oauth = gen.generate_oauth_payloads("client_123")
    for i, payload in enumerate(oauth, 1):
        print(f"  {i}. {payload.bypass_technique}")

    print(f"\n[+] Total unique payloads: {len(basic) + len(bypass) + len(protocol) + len(oauth)}")


def example_redirect_analysis():
    """Redirect analysis example"""
    print("\n" + "=" * 60)
    print("Example 3: Redirect Analysis")
    print("=" * 60)

    analyzer = RedirectAnalyzer()

    # Mock response for demonstration
    from unittest.mock import Mock

    # HTTP 302 redirect
    print("\n[*] Analyzing HTTP 302 redirect...")
    response = Mock()
    response.status_code = 302
    response.headers = {'Location': 'https://evil.com'}
    response.url = 'https://evil.com'
    response.history = []
    response.text = ""

    result = analyzer.analyze_response(response, "https://example.com", "https://evil.com")
    if result:
        print(f"  Redirected: {result['redirected']}")
        print(f"  Method: {result['method']}")
        print(f"  Destination: {result['destination']}")

    # Meta refresh
    print("\n[*] Analyzing meta refresh redirect...")
    response.status_code = 200
    response.text = '<meta http-equiv="refresh" content="0;url=https://evil.com">'

    result = analyzer.analyze_response(response, "https://example.com", "https://evil.com")
    if result:
        print(f"  Redirected: {result['redirected']}")
        print(f"  Method: {result['method']}")
        print(f"  Destination: {result['destination']}")

    # External redirect check
    print("\n[*] Checking external redirects...")
    is_external = analyzer.is_external_redirect("example.com", "https://evil.com")
    print(f"  example.com -> evil.com: External = {is_external}")

    is_external = analyzer.is_external_redirect("example.com", "https://sub.example.com")
    print(f"  example.com -> sub.example.com: External = {is_external}")


def example_wrapper_function():
    """Using the wrapper function"""
    print("\n" + "=" * 60)
    print("Example 4: Wrapper Function")
    print("=" * 60)

    print("\n[*] Testing using wrapper function...")

    # This would make actual HTTP requests
    # result = run_open_redirect_tests(
    #     "https://example.com/login",
    #     parameters={"next": "/dashboard"}
    # )

    # For demonstration, show what the structure would be
    print("\n[+] Expected result structure:")
    print("""
    {
        'findings': [
            {
                'url': 'https://example.com/login',
                'parameter': 'next',
                'redirect_type': 'parameter',
                'severity': 'medium',
                'impact': 'Open redirect enables phishing...',
                'poc': 'https://example.com/login?next=...',
                ...
            }
        ],
        'stats': {
            'total_findings': 1,
            'critical': 0,
            'high': 0,
            'medium': 1,
            'oauth_redirects': 0,
            'header_redirects': 0
        }
    }
    """)


def example_oauth_testing():
    """OAuth redirect_uri testing example"""
    print("\n" + "=" * 60)
    print("Example 5: OAuth Redirect Testing")
    print("=" * 60)

    print("\n[*] Common OAuth endpoints to test:")
    oauth_endpoints = [
        "https://example.com/oauth/authorize?client_id=123&redirect_uri=...",
        "https://example.com/auth/login?redirect_uri=...",
        "https://example.com/connect/oauth?redirect_uri=...",
    ]

    for endpoint in oauth_endpoints:
        print(f"  - {endpoint}")

    print("\n[*] OAuth-specific bypass techniques:")
    gen = PayloadGenerator("evil.com")
    oauth_payloads = gen.generate_oauth_payloads("client_123")

    for payload in oauth_payloads:
        print(f"\n  Technique: {payload.bypass_technique}")
        print(f"  Payload: {payload.payload[:60]}...")
        print(f"  Description: {payload.description}")


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("OPEN REDIRECT TESTER - EXAMPLES")
    print("=" * 60)

    # Note: Most examples use mocks to avoid actual HTTP requests
    # In production, the agent would make real requests to test targets

    example_payload_generation()
    example_redirect_analysis()
    example_wrapper_function()
    example_oauth_testing()

    # Skip example_basic_usage() as it requires database setup
    print("\n" + "=" * 60)
    print("Note: example_basic_usage() skipped (requires database)")
    print("To use: Initialize database and provide valid target URL")
    print("=" * 60)


if __name__ == "__main__":
    main()
