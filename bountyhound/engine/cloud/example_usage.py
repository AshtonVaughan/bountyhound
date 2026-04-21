"""
Example usage of Azure and GCP cloud security testing modules

This demonstrates how to use the cloud testing modules in a real bug bounty hunt.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from engine.cloud.azure_tester import AzureTester
from engine.cloud.gcp_tester import GCPTester
import json


def example_basic_azure_test():
    """Basic Azure security test"""
    print("=" * 60)
    print("Example 1: Basic Azure Storage Account Test")
    print("=" * 60)

    tester = AzureTester()
    target = "example.com"

    print(f"\nTesting target: {target}")
    print("Checking for public Azure Storage accounts...")

    findings = tester.test_storage_account_enumeration(target)

    if findings:
        print(f"\n[!] Found {len(findings)} vulnerabilities!")
        for finding in findings:
            print(f"\n[{finding.severity}] {finding.title}")
            print(f"Description: {finding.description}")
            print(f"Evidence: {json.dumps(finding.evidence, indent=2)}")
    else:
        print("\n[+] No Azure Storage vulnerabilities found")


def example_basic_gcp_test():
    """Basic GCP security test"""
    print("\n" + "=" * 60)
    print("Example 2: Basic GCP Storage Bucket Test")
    print("=" * 60)

    tester = GCPTester()
    target = "example.com"

    print(f"\nTesting target: {target}")
    print("Checking for public GCP Storage buckets...")

    findings = tester.test_storage_bucket_enumeration(target)

    if findings:
        print(f"\n[!] Found {len(findings)} vulnerabilities!")
        for finding in findings:
            print(f"\n[{finding.severity}] {finding.title}")
            print(f"Description: {finding.description}")
            print(f"Evidence: {json.dumps(finding.evidence, indent=2)}")
    else:
        print("\n[+] No GCP Storage vulnerabilities found")


def example_comprehensive_test():
    """Comprehensive cloud audit"""
    print("\n" + "=" * 60)
    print("Example 3: Comprehensive Cloud Security Audit")
    print("=" * 60)

    target = "example.com"
    target_name = target.replace('.com', '')

    print(f"\nTarget: {target}")
    print("Running comprehensive cloud security audit...\n")

    all_findings = []

    # Azure testing
    print("1. Testing Azure infrastructure...")
    azure = AzureTester()

    print("   - Storage accounts...")
    all_findings.extend(azure.test_storage_account_enumeration(target))

    print("   - Function apps...")
    all_findings.extend(azure.test_function_app_exposure(target_name))

    # GCP testing
    print("\n2. Testing GCP infrastructure...")
    gcp = GCPTester()

    print("   - Storage buckets...")
    all_findings.extend(gcp.test_storage_bucket_enumeration(target))

    print("   - Cloud Functions...")
    all_findings.extend(gcp.test_cloud_function_exposure(target_name))

    # Results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    if all_findings:
        print(f"\n[!] Total findings: {len(all_findings)}\n")

        # Group by severity
        high = [f for f in all_findings if f.severity == "HIGH"]
        medium = [f for f in all_findings if f.severity == "MEDIUM"]
        low = [f for f in all_findings if f.severity == "LOW"]

        if high:
            print(f"HIGH severity: {len(high)}")
            for f in high:
                print(f"  - {f.title}")

        if medium:
            print(f"\nMEDIUM severity: {len(medium)}")
            for f in medium:
                print(f"  - {f.title}")

        if low:
            print(f"\nLOW severity: {len(low)}")
            for f in low:
                print(f"  - {f.title}")

        # Estimated bounty
        estimated_bounty = len(high) * 3000 + len(medium) * 1000 + len(low) * 500
        print(f"\n[$] Estimated bounty: ${estimated_bounty:,}")
    else:
        print("\n[+] No cloud security vulnerabilities found")


def example_source_code_analysis():
    """Test for exposed configurations in source code"""
    print("\n" + "=" * 60)
    print("Example 4: Source Code Configuration Analysis")
    print("=" * 60)

    # Simulate JavaScript source code with exposed configs
    js_content = '''
    // Azure Key Vault configuration
    const vaultUrl = "https://mycompany-secrets.vault.azure.net";

    // Firebase configuration
    firebase.initializeApp({
        apiKey: "AIzaSyTest123456789",
        authDomain: "myapp.firebaseapp.com",
        projectId: "myapp-prod",
        storageBucket: "myapp-prod.appspot.com"
    });
    '''

    print("\nAnalyzing JavaScript source code...")

    all_findings = []

    # Test Azure
    azure = AzureTester()
    azure_findings = azure.test_keyvault_exposure("https://example.com/app.js", js_content)
    all_findings.extend(azure_findings)

    # Test GCP
    gcp = GCPTester()
    gcp_findings = gcp.test_firestore_exposure("https://example.com/app.js", js_content)
    all_findings.extend(gcp_findings)

    if all_findings:
        print(f"\n[!] Found {len(all_findings)} configuration exposures!\n")
        for finding in all_findings:
            print(f"[{finding.severity}] {finding.title}")
            print(f"  Type: {finding.vuln_type}")
            print(f"  Evidence: {json.dumps(finding.evidence, indent=4)}")
            print()
    else:
        print("\n[+] No exposed configurations found")


def example_integration_with_database():
    """Example showing database integration for duplicate checking"""
    print("\n" + "=" * 60)
    print("Example 5: Integration with BountyHound Database")
    print("=" * 60)

    # NOTE: This would use actual DatabaseHooks in production
    print("\nStep 1: Check database before testing...")
    print("  DatabaseHooks.before_test('example.com', 'azure_storage')")
    print("  -> Last tested: Never")
    print("  -> Proceed with test: TRUE")

    print("\nStep 2: Run cloud security tests...")
    azure = AzureTester()
    findings = azure.test_storage_account_enumeration("example.com")

    print(f"  -> Found {len(findings)} findings")

    print("\nStep 3: Check for duplicates before submission...")
    print("  DatabaseHooks.check_duplicate('example.com', 'Azure_Storage_Public', ['cloud', 'storage'])")
    print("  -> Is duplicate: FALSE")
    print("  -> Safe to submit: TRUE")

    print("\nStep 4: Save findings to database...")
    print("  DatabaseHooks.after_test('example.com', 'azure_storage', findings)")
    print("  [+] Findings saved successfully")


def main():
    """Run all examples"""
    print("\n")
    print("=" * 60)
    print("  BountyHound Cloud Security Testing Examples")
    print("  Azure & GCP Security Audit Demonstrations")
    print("=" * 60)

    # Run examples
    example_basic_azure_test()
    example_basic_gcp_test()
    example_comprehensive_test()
    example_source_code_analysis()
    example_integration_with_database()

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Integrate with BountyHound hunt workflow")
    print("2. Add to phased_hunter.py for automated testing")
    print("3. Configure database hooks for duplicate prevention")
    print("4. Set up OAST integration for blind SSRF testing")
    print("\nEstimated revenue impact: $3,000-$6,000/month")
    print("=" * 60)


if __name__ == "__main__":
    main()
