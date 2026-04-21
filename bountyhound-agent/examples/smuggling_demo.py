#!/usr/bin/env python3
"""
HTTP Request Smuggling Tester Demo

Demonstrates the smuggling tester capabilities and integration
with the phased hunter.
"""

from engine.agents.smuggling_tester import SmugglingTester


def demo_standalone_usage():
    """Demo standalone smuggling tester usage"""
    print("=" * 80)
    print("HTTP REQUEST SMUGGLING TESTER DEMO")
    print("=" * 80)
    print()

    tester = SmugglingTester()

    print("1. PAYLOAD GENERATION")
    print("-" * 80)
    payloads = tester.generate_smuggling_payloads()
    print(f"Generated {len(payloads)} smuggling payloads:")
    for i, payload in enumerate(payloads, 1):
        print(f"\nPayload {i}:")
        print(payload[:200] + "..." if len(payload) > 200 else payload)

    print("\n\n2. DETECTION TECHNIQUES")
    print("-" * 80)
    print("[+] CL.TE (Content-Length vs Transfer-Encoding)")
    print("  - Frontend uses Content-Length")
    print("  - Backend uses Transfer-Encoding")
    print("  - Smuggled request after chunked terminator")
    print()
    print("[+] TE.CL (Transfer-Encoding vs Content-Length)")
    print("  - Frontend uses Transfer-Encoding")
    print("  - Backend uses Content-Length")
    print("  - Smuggled request hidden in chunk")
    print()
    print("[+] TE.TE (Obfuscated Transfer-Encoding)")
    print("  - Multiple Transfer-Encoding headers")
    print("  - Case variations (Transfer-encoding)")
    print("  - Identity encoding obfuscation")
    print()
    print("[+] Timing-based Detection")
    print("  - Measures response time differences")
    print("  - Detects blind smuggling via delays")
    print("  - Threshold: 5 seconds")

    print("\n\n3. SMUGGLING INDICATORS")
    print("-" * 80)

    # Test smuggling indicators
    class MockResponse:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text

    test_cases = [
        (MockResponse(404, "Not Found"), "404 - Smuggled request to non-existent endpoint"),
        (MockResponse(403, "Forbidden"), "403 - Smuggled request to admin endpoint"),
        (MockResponse(400, "Unrecognized method POST"), "Unrecognized method error"),
        (MockResponse(400, "Invalid request format"), "Invalid request error"),
        (MockResponse(200, "OK"), "Normal response (no smuggling)"),
    ]

    for response, description in test_cases:
        indicator = tester._indicates_smuggling(response)
        status = "[!] SMUGGLING DETECTED" if indicator else "[ ] No smuggling"
        print(f"{status}: {description}")

    print("\n\n4. HOST EXTRACTION")
    print("-" * 80)
    test_urls = [
        "https://example.com/api",
        "http://api.example.com:8080/path",
        "https://sub.domain.example.com/",
    ]

    for url in test_urls:
        host = tester._get_host(url)
        print(f"{url} -> {host}")

    print("\n\n5. CONFIGURATION")
    print("-" * 80)
    print(f"Timeout: {tester.timeout} seconds")
    print(f"Timing Threshold: {tester.timing_threshold} seconds")

    print("\n\n6. INTEGRATION")
    print("-" * 80)
    print("The smuggling tester is integrated into the phased hunter:")
    print()
    print("  /hunt example.com")
    print("      |")
    print("  Phase 1: Recon (discover endpoints)")
    print("      |")
    print("  Phase 2: Discovery (generate hypotheses)")
    print("      |")
    print("  Phase 3: Validation")
    print("      |-- Test hypotheses")
    print("      +-- Test HTTP Request Smuggling <- AUTOMATIC")
    print("          |-- CL.TE tests")
    print("          |-- TE.CL tests")
    print("          |-- TE.TE tests")
    print("          +-- Timing-based tests")
    print("      |")
    print("  Phase 4: Exploitation (generate POCs)")
    print("      |")
    print("  Phase 5: Reporting (structured findings)")

    print("\n\n7. EXPECTED REVENUE")
    print("-" * 80)
    print("Priority: HIGH")
    print("Revenue Impact: $1,500-$3,000/month")
    print()
    print("Bounty Ranges:")
    print("  - Critical (CVSS 9.0+): $3,000-$10,000")
    print("  - High (CVSS 7.0-8.9): $1,500-$3,000")
    print("  - Medium (CVSS 4.0-6.9): $500-$1,500")
    print()
    print("Success Rate:")
    print("  - ~5% of applications vulnerable")
    print("  - 10-15% on complex architectures")
    print("  - >80% acceptance rate for CRITICAL findings")

    print("\n\n8. HIGH-VALUE TARGETS")
    print("-" * 80)
    high_value_targets = [
        "AWS CloudFront + ALB/ELB",
        "Nginx + Apache",
        "HAProxy + Nginx",
        "Akamai CDN + Origin",
        "Cloudflare + Backend",
        "F5 BIG-IP + Application",
        "IIS + ASP.NET",
    ]

    for target in high_value_targets:
        print(f"  - {target}")

    print("\n\n" + "=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)
    print()
    print("For full usage guide, see: docs/smuggling-tester-usage.md")
    print("For implementation details, see: engine/agents/smuggling_tester.py")
    print("For tests, see: tests/engine/agents/test_smuggling_tester.py")
    print()


if __name__ == "__main__":
    demo_standalone_usage()
