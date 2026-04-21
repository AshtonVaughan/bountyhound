"""
Google Cloud Storage (GCS) Bucket Scanner
Find publicly accessible GCS buckets and test security configurations
"""

from google.cloud import storage
from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import DefaultCredentialsError
from typing import List, Dict, Optional
from colorama import Fore, Style
import time
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class GCSScanner:
    """Google Cloud Storage bucket enumeration and security testing"""

    def __init__(self, rate_limit: float = 1.0, max_retries: int = 3, project_id: Optional[str] = None):
        """
        Initialize GCS scanner with rate limiting.

        Args:
            rate_limit: Seconds to wait between requests (default: 1.0)
            max_retries: Maximum retries for throttled requests (default: 3)
            project_id: GCP project ID (optional, uses default credentials)
        """
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.project_id = project_id
        self.findings = []
        self._last_request_time = None

        try:
            # Initialize GCS client with default credentials
            self.storage_client = storage.Client(project=project_id)
            print(f"{Fore.GREEN}[+] GCS client initialized{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s between requests{Style.RESET_ALL}")
            if project_id:
                print(f"{Fore.CYAN}[*] Project ID: {project_id}{Style.RESET_ALL}")
        except DefaultCredentialsError:
            print(f"{Fore.YELLOW}[!] No default credentials found{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Anonymous mode - testing public access only{Style.RESET_ALL}")
            self.storage_client = storage.Client.create_anonymous_client()
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize GCS client: {e}{Style.RESET_ALL}")
            raise

    def _rate_limited_call(self, func, *args, **kwargs):
        """
        Execute a function with rate limiting and exponential backoff.

        Args:
            func: Function to call
            *args, **kwargs: Arguments to pass to function

        Returns:
            Function result or None on failure
        """
        for attempt in range(self.max_retries):
            try:
                # Add delay before request (except first call)
                if attempt > 0:
                    backoff_time = min(2 ** attempt, 30)  # Max 30s
                    print(f"{Fore.YELLOW}[*] Retry {attempt}, waiting {backoff_time}s...{Style.RESET_ALL}")
                    time.sleep(backoff_time)
                elif self._last_request_time is not None:
                    # Rate limit between normal requests
                    elapsed = time.time() - self._last_request_time
                    if elapsed < self.rate_limit:
                        time.sleep(self.rate_limit - elapsed)

                # Make the request
                result = func(*args, **kwargs)
                self._last_request_time = time.time()
                return result

            except gcp_exceptions.TooManyRequests:
                if attempt < self.max_retries - 1:
                    print(f"{Fore.YELLOW}[!] Rate limited, retrying...{Style.RESET_ALL}")
                    continue
                else:
                    print(f"{Fore.RED}[!] Max retries reached{Style.RESET_ALL}")
                    return None

            except (gcp_exceptions.NotFound, gcp_exceptions.Forbidden):
                # Don't retry on these errors
                return None

            except Exception as e:
                print(f"{Fore.YELLOW}[*] Error: {e}{Style.RESET_ALL}")
                return None

        return None

    def enumerate_buckets(self, domain: str) -> List[Dict]:
        """
        Enumerate GCS buckets for a domain

        Args:
            domain: Target domain (e.g., example.com)

        Returns:
            List of findings
        """
        print(f"{Fore.CYAN}[*] Enumerating GCS buckets for: {domain}{Style.RESET_ALL}")

        # DATABASE CHECK - Prevent redundant testing
        print(f"{Fore.CYAN}[DATABASE] Checking history...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(domain, 'gcs_scanner')

        if context['should_skip']:
            print(f"{Fore.YELLOW}⚠️  SKIPPING: {context['reason']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Previous findings:{Style.RESET_ALL}")
            for finding in context.get('previous_findings', [])[:3]:
                print(f"  - {finding.get('title', 'N/A')} ({finding.get('status', 'N/A')})")

            if context.get('last_tool_run'):
                print(f"{Fore.CYAN}Last run found {context['last_tool_run']['findings_count']} bucket(s){Style.RESET_ALL}")

            print(f"{Fore.YELLOW}💡 Recommendations:{Style.RESET_ALL}")
            for rec in context['recommendations']:
                print(f"   {rec}")

            print(f"\n{Fore.YELLOW}Use --force flag to override if needed{Style.RESET_ALL}")
            return []

        # Database check passed - proceed with enumeration
        print(f"{Fore.GREEN}✓ {context['reason']}{Style.RESET_ALL}")
        if context['recommendations']:
            print(f"{Fore.CYAN}💡 {context['recommendations'][0]}{Style.RESET_ALL}")

        # Generate bucket name variations
        bucket_patterns = self.generate_bucket_names(domain)

        results = []

        for bucket_name in bucket_patterns:
            finding = self.check_bucket(bucket_name)
            if finding:
                results.append(finding)

        # Record tool run in database
        db = BountyHoundDB()
        db.record_tool_run(domain, 'gcs_scanner', findings_count=len(results), success=True)
        print(f"{Fore.GREEN}[DATABASE] Recorded tool run: {len(results)} bucket(s) found{Style.RESET_ALL}")

        return results

    def generate_bucket_names(self, domain: str) -> List[str]:
        """Generate common bucket name patterns for GCS"""
        base = domain.replace('.com', '').replace('.', '-')
        company = domain.split('.')[0]

        patterns = [
            # Direct patterns
            domain,
            base,
            company,

            # Environment suffixes
            f"{base}-backup",
            f"{base}-backups",
            f"{base}-prod",
            f"{base}-production",
            f"{base}-stage",
            f"{base}-staging",
            f"{base}-dev",
            f"{base}-development",
            f"{base}-test",

            # Asset patterns
            f"{base}-assets",
            f"{base}-static",
            f"{base}-media",
            f"{base}-images",
            f"{base}-files",
            f"{base}-uploads",
            f"{base}-data",
            f"{base}-logs",

            # Web patterns
            f"{base}-www",
            f"www-{base}",
            f"{base}-webapp",
            f"{base}-api",

            # GCP-specific patterns
            f"{base}-appspot",
            f"{base}-cloudfunctions",
            f"{base}-firebase",
            f"{company}-terraform-state",
            f"{company}-gcs",

            # Artifact patterns
            f"{base}-artifacts",
            f"{base}-build",
            f"{base}-deploy",
            f"{base}-releases",
        ]

        return patterns

    def check_bucket(self, bucket_name: str) -> Optional[Dict]:
        """
        Check if bucket exists and is accessible

        Returns:
            Finding dict if vulnerable, None otherwise
        """
        try:
            bucket = self.storage_client.bucket(bucket_name)

            # Try to check if bucket exists with rate limiting
            exists_result = self._rate_limited_call(bucket.exists)

            if exists_result is None:
                return None

            if not exists_result:
                return None

            # Bucket exists - check if we can list it
            try:
                blobs_iter = self._rate_limited_call(bucket.list_blobs, max_results=10)

                if blobs_iter is None:
                    return None

                blobs = list(blobs_iter)

                # Bucket is publicly listable!
                print(f"{Fore.RED}[!] CRITICAL: {bucket_name} is PUBLICLY LISTABLE!{Style.RESET_ALL}")
                print(f"    Objects: {len(blobs)}")

                finding = {
                    "bucket": bucket_name,
                    "severity": "CRITICAL",
                    "status": "publicly_listable",
                    "object_count": len(blobs),
                    "description": f"GCS bucket {bucket_name} is publicly listable with {len(blobs)} objects"
                }

                # Try to get some objects
                if blobs:
                    sample_objects = [blob.name for blob in blobs[:5]]
                    finding['sample_objects'] = sample_objects
                    print(f"    Sample objects: {sample_objects}")

                # Check IAM policy
                iam_finding = self.check_bucket_iam(bucket_name)
                if iam_finding:
                    finding['iam_issues'] = iam_finding

                return finding

            except gcp_exceptions.Forbidden:
                # Bucket exists but is private
                print(f"{Fore.YELLOW}[+] {bucket_name} exists (private){Style.RESET_ALL}")

                return {
                    "bucket": bucket_name,
                    "severity": "INFO",
                    "status": "exists_private",
                    "description": f"Bucket exists but is properly secured"
                }

        except gcp_exceptions.NotFound:
            # Bucket doesn't exist
            return None

        except gcp_exceptions.Forbidden:
            # No permission to check
            return None

        except Exception as e:
            print(f"{Fore.YELLOW}[!] {bucket_name}: {e}{Style.RESET_ALL}")
            return None

    def check_bucket_iam(self, bucket_name: str) -> Optional[Dict]:
        """
        Check bucket IAM policy for misconfigurations

        Args:
            bucket_name: Bucket name to check

        Returns:
            Dict of IAM issues or None
        """
        try:
            bucket = self.storage_client.bucket(bucket_name)
            policy = self._rate_limited_call(bucket.get_iam_policy)

            if policy is None:
                return None

            issues = []

            # Check for allUsers or allAuthenticatedUsers
            for binding in policy.bindings:
                if 'allUsers' in binding.get('members', []):
                    issues.append({
                        "severity": "CRITICAL",
                        "issue": "Public access to allUsers",
                        "role": binding['role'],
                        "description": f"Bucket grants {binding['role']} to allUsers"
                    })
                    print(f"{Fore.RED}[!] IAM: allUsers has {binding['role']}{Style.RESET_ALL}")

                if 'allAuthenticatedUsers' in binding.get('members', []):
                    issues.append({
                        "severity": "HIGH",
                        "issue": "Public access to all authenticated users",
                        "role": binding['role'],
                        "description": f"Bucket grants {binding['role']} to allAuthenticatedUsers"
                    })
                    print(f"{Fore.RED}[!] IAM: allAuthenticatedUsers has {binding['role']}{Style.RESET_ALL}")

            return issues if issues else None

        except gcp_exceptions.Forbidden:
            return None
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to check IAM: {e}{Style.RESET_ALL}")
            return None

    def check_bucket_lifecycle(self, bucket_name: str) -> Optional[Dict]:
        """
        Check bucket lifecycle configuration

        Args:
            bucket_name: Bucket name to check

        Returns:
            Dict of lifecycle info or None
        """
        try:
            bucket = self.storage_client.bucket(bucket_name)
            bucket.reload()

            lifecycle_rules = bucket.lifecycle_rules

            if not lifecycle_rules:
                return {
                    "severity": "LOW",
                    "issue": "No lifecycle management",
                    "description": "Bucket has no lifecycle rules configured - old data may accumulate"
                }

            return {
                "status": "configured",
                "rules_count": len(lifecycle_rules),
                "rules": lifecycle_rules
            }

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to check lifecycle: {e}{Style.RESET_ALL}")
            return None

    def check_bucket_versioning(self, bucket_name: str) -> Optional[Dict]:
        """
        Check bucket versioning configuration

        Args:
            bucket_name: Bucket name to check

        Returns:
            Dict of versioning info or None
        """
        try:
            bucket = self.storage_client.bucket(bucket_name)
            bucket.reload()

            versioning_enabled = bucket.versioning_enabled

            if not versioning_enabled:
                return {
                    "severity": "MEDIUM",
                    "issue": "Versioning disabled",
                    "description": "Bucket versioning is disabled - accidental deletions are permanent"
                }

            return {
                "status": "enabled",
                "description": "Bucket versioning is enabled"
            }

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to check versioning: {e}{Style.RESET_ALL}")
            return None

    def check_bucket_encryption(self, bucket_name: str) -> Optional[Dict]:
        """
        Check bucket encryption configuration

        Args:
            bucket_name: Bucket name to check

        Returns:
            Dict of encryption info or None
        """
        try:
            bucket = self.storage_client.bucket(bucket_name)
            bucket.reload()

            default_kms_key_name = bucket.default_kms_key_name

            if not default_kms_key_name:
                return {
                    "severity": "LOW",
                    "issue": "No custom encryption key",
                    "description": "Bucket uses Google-managed encryption keys (not customer-managed)"
                }

            return {
                "status": "cmek_enabled",
                "kms_key": default_kms_key_name,
                "description": "Bucket uses customer-managed encryption key"
            }

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to check encryption: {e}{Style.RESET_ALL}")
            return None

    def test_object_upload(self, bucket_name: str) -> Optional[Dict]:
        """
        Test if we can upload objects to the bucket

        Args:
            bucket_name: Bucket name to test

        Returns:
            Finding dict if vulnerable, None otherwise
        """
        try:
            bucket = self.storage_client.bucket(bucket_name)
            blob = bucket.blob('security-test.txt')

            # Try to upload a test file
            test_content = b'BountyHound security test - please delete'

            result = self._rate_limited_call(
                blob.upload_from_string,
                test_content,
                content_type='text/plain'
            )

            if result is not None:
                print(f"{Fore.RED}[!] CRITICAL: Can upload to {bucket_name}!{Style.RESET_ALL}")

                # Clean up - try to delete
                try:
                    blob.delete()
                    print(f"{Fore.GREEN}[+] Cleaned up test file{Style.RESET_ALL}")
                except:
                    print(f"{Fore.YELLOW}[!] Failed to clean up test file{Style.RESET_ALL}")

                return {
                    "bucket": bucket_name,
                    "severity": "CRITICAL",
                    "issue": "Unauthorized upload",
                    "description": f"Unauthenticated users can upload objects to {bucket_name}"
                }

            return None

        except gcp_exceptions.Forbidden:
            # Expected - upload denied
            return None
        except Exception as e:
            return None


def main():
    """CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description='GCS Bucket Scanner')
    parser.add_argument('domain', help='Target domain (e.g., example.com)')
    parser.add_argument('--rate-limit', type=float, default=1.0,
                        help='Seconds to wait between requests (default: 1.0)')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='Maximum retries for throttled requests (default: 3)')
    parser.add_argument('--project-id', help='GCP project ID')

    args = parser.parse_args()

    scanner = GCSScanner(
        rate_limit=args.rate_limit,
        max_retries=args.max_retries,
        project_id=args.project_id
    )
    findings = scanner.enumerate_buckets(args.domain)

    print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
    print(f"Total findings: {len(findings)}")

    critical = [f for f in findings if f.get('severity') == 'CRITICAL']
    if critical:
        print(f"{Fore.RED}CRITICAL issues: {len(critical)}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
