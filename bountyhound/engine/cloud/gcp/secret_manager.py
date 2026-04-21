"""
Google Cloud Secret Manager Security Tester
Test Secret Manager for unauthorized access to secrets
"""

from google.cloud import secretmanager
from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import DefaultCredentialsError
from google.auth import default
from typing import List, Dict, Optional
from colorama import Fore, Style
import time

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class SecretManagerTester:
    """
    Test Google Cloud Secret Manager for security vulnerabilities
    """

    def __init__(self, rate_limit: float = 1.0, max_retries: int = 3, project_id: Optional[str] = None):
        """
        Initialize Secret Manager tester with rate limiting.

        Args:
            rate_limit: Seconds to wait between requests (default: 1.0)
            max_retries: Maximum retries for throttled requests (default: 3)
            project_id: GCP project ID (optional, detected from credentials)
        """
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.project_id = project_id
        self._last_request_time = None
        self.findings = []

        try:
            # Use default credentials
            self.credentials, self.default_project = default()

            if not self.project_id:
                self.project_id = self.default_project

            print(f"{Fore.GREEN}[+] Secret Manager client initialized{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s between requests{Style.RESET_ALL}")
            if self.project_id:
                print(f"{Fore.CYAN}[*] Project ID: {self.project_id}{Style.RESET_ALL}")

            # Initialize Secret Manager client
            self.client = secretmanager.SecretManagerServiceClient()

        except DefaultCredentialsError:
            print(f"{Fore.RED}[!] Failed to load GCP credentials{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Please configure credentials using gcloud auth{Style.RESET_ALL}")
            raise
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize Secret Manager client: {e}{Style.RESET_ALL}")
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

            except (gcp_exceptions.PermissionDenied, gcp_exceptions.Forbidden):
                return None

            except Exception as e:
                print(f"{Fore.YELLOW}[*] Error: {e}{Style.RESET_ALL}")
                return None

        return None

    def enumerate_secrets(self) -> List[Dict]:
        """
        Enumerate all secrets in the project

        Returns:
            List of secret information
        """
        if not self.project_id:
            print(f"{Fore.YELLOW}[!] No project ID specified{Style.RESET_ALL}")
            return []

        target = f"gcp-{self.project_id}"

        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(target, 'secret_manager_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}⚠️  SKIP: {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}✓ {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Enumerating secrets...{Style.RESET_ALL}")

        parent = f"projects/{self.project_id}"

        try:
            result = self._rate_limited_call(self.client.list_secrets, parent=parent)

            if result is None:
                print(f"{Fore.YELLOW}[!] Cannot list secrets{Style.RESET_ALL}")
                return []

            secrets = []
            for secret in result:
                secret_info = self.extract_secret_info(secret)
                secrets.append(secret_info)

                print(f"{Fore.GREEN}[+] Secret: {secret_info['name']}{Style.RESET_ALL}")

                # Test access to the secret
                self.test_secret_access(secret.name)

            # Record tool run
            db = BountyHoundDB()
            db.record_tool_run(
                target,
                'secret_manager_tester',
                findings_count=len(self.findings),
                success=True
            )

            return secrets

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to enumerate secrets: {e}{Style.RESET_ALL}")
            return []

    def extract_secret_info(self, secret) -> Dict:
        """
        Extract relevant information from a secret

        Args:
            secret: Secret object

        Returns:
            Dict of secret information
        """
        # Extract secret name (last component)
        secret_id = secret.name.split('/')[-1]

        info = {
            "name": secret_id,
            "full_name": secret.name,
            "create_time": str(secret.create_time),
        }

        # Check replication
        if secret.replication:
            if secret.replication.automatic:
                info["replication"] = "automatic"
            elif secret.replication.user_managed:
                info["replication"] = "user_managed"

        # Check labels
        if secret.labels:
            info["labels"] = dict(secret.labels)

        return info

    def test_secret_access(self, secret_name: str) -> Optional[Dict]:
        """
        Test if we can access a secret's value

        Args:
            secret_name: Full secret name (projects/*/secrets/*)

        Returns:
            Finding dict if accessible, None otherwise
        """
        try:
            # Get the latest version
            version_name = f"{secret_name}/versions/latest"

            result = self._rate_limited_call(
                self.client.access_secret_version,
                name=version_name
            )

            if result is not None:
                # We can access the secret!
                secret_id = secret_name.split('/')[-1]

                print(f"{Fore.RED}[!] Can access secret '{secret_id}'!{Style.RESET_ALL}")

                # Don't log the actual secret value
                payload_length = len(result.payload.data)

                self.add_finding(
                    "CRITICAL",
                    f"Unauthorized Secret Access: {secret_id}",
                    f"Can read secret '{secret_id}' (payload length: {payload_length} bytes)"
                )

                return {
                    "secret": secret_id,
                    "severity": "CRITICAL",
                    "issue": "unauthorized_access",
                    "payload_length": payload_length,
                    "description": f"Secret '{secret_id}' is accessible without proper authorization"
                }

            return None

        except gcp_exceptions.PermissionDenied:
            # Expected - secret is protected
            secret_id = secret_name.split('/')[-1]
            print(f"{Fore.GREEN}[+] Secret '{secret_id}' is protected{Style.RESET_ALL}")
            return None

        except Exception as e:
            return None

    def test_secret_iam(self, secret_name: str) -> Optional[Dict]:
        """
        Check IAM policy for a secret

        Args:
            secret_name: Full secret name (projects/*/secrets/*)

        Returns:
            Dict of IAM issues or None
        """
        try:
            result = self._rate_limited_call(
                self.client.get_iam_policy,
                resource=secret_name
            )

            if result is None:
                return None

            issues = []

            # Check for public access
            for binding in result.bindings:
                if 'allUsers' in binding.members:
                    issues.append({
                        "severity": "CRITICAL",
                        "issue": "Public secret access",
                        "role": binding.role,
                        "description": f"Secret is accessible by anyone (allUsers has {binding.role})"
                    })
                    print(f"{Fore.RED}[!] IAM: allUsers has {binding.role}{Style.RESET_ALL}")

                    self.add_finding(
                        "CRITICAL",
                        f"Public Secret: {secret_name.split('/')[-1]}",
                        f"Secret grants {binding.role} to allUsers"
                    )

                if 'allAuthenticatedUsers' in binding.members:
                    issues.append({
                        "severity": "HIGH",
                        "issue": "Authenticated users can access",
                        "role": binding.role,
                        "description": f"Any authenticated Google user can access (allAuthenticatedUsers has {binding.role})"
                    })
                    print(f"{Fore.YELLOW}[!] IAM: allAuthenticatedUsers has {binding.role}{Style.RESET_ALL}")

                    self.add_finding(
                        "HIGH",
                        f"Overly Permissive Secret: {secret_name.split('/')[-1]}",
                        f"Secret grants {binding.role} to allAuthenticatedUsers"
                    )

            return issues if issues else None

        except Exception as e:
            return None

    def test_secret_versions(self, secret_name: str) -> List[Dict]:
        """
        List all versions of a secret

        Args:
            secret_name: Full secret name (projects/*/secrets/*)

        Returns:
            List of version information
        """
        try:
            result = self._rate_limited_call(
                self.client.list_secret_versions,
                parent=secret_name
            )

            if result is None:
                return []

            versions = []
            for version in result:
                version_info = {
                    "name": version.name,
                    "state": version.state.name if hasattr(version.state, 'name') else str(version.state),
                    "create_time": str(version.create_time)
                }

                versions.append(version_info)

            secret_id = secret_name.split('/')[-1]
            print(f"{Fore.CYAN}[*] Secret '{secret_id}' has {len(versions)} version(s){Style.RESET_ALL}")

            # Check for old enabled versions
            enabled_versions = [v for v in versions if v['state'] == 'ENABLED']
            if len(enabled_versions) > 1:
                self.add_finding(
                    "LOW",
                    f"Multiple Secret Versions: {secret_id}",
                    f"Secret has {len(enabled_versions)} enabled versions - consider disabling old versions"
                )

            return versions

        except Exception as e:
            return []

    def test_common_secret_names(self) -> List[Dict]:
        """
        Test for commonly named secrets that might exist

        Returns:
            List of findings
        """
        if not self.project_id:
            return []

        common_names = [
            'api-key',
            'api_key',
            'database-password',
            'db-password',
            'admin-password',
            'jwt-secret',
            'oauth-secret',
            'stripe-key',
            'slack-token',
            'github-token',
            'service-account-key',
            'encryption-key',
            'private-key'
        ]

        findings = []

        for secret_name in common_names:
            full_name = f"projects/{self.project_id}/secrets/{secret_name}"

            try:
                result = self._rate_limited_call(self.client.get_secret, name=full_name)

                if result is not None:
                    print(f"{Fore.YELLOW}[+] Found common secret: {secret_name}{Style.RESET_ALL}")

                    # Test if we can access it
                    access_finding = self.test_secret_access(full_name)
                    if access_finding:
                        findings.append(access_finding)

            except gcp_exceptions.NotFound:
                # Secret doesn't exist
                pass
            except:
                pass

        return findings

    def add_finding(self, severity: str, title: str, description: str):
        """Add security finding"""
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description
        })


def main():
    """CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description='GCP Secret Manager Security Tester')
    parser.add_argument('--rate-limit', type=float, default=1.0,
                        help='Seconds to wait between requests (default: 1.0)')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='Maximum retries for throttled requests (default: 3)')
    parser.add_argument('--project-id', required=True, help='GCP project ID')

    args = parser.parse_args()

    tester = SecretManagerTester(
        rate_limit=args.rate_limit,
        max_retries=args.max_retries,
        project_id=args.project_id
    )

    # Enumerate all secrets
    secrets = tester.enumerate_secrets()

    # Test common secret names
    common_findings = tester.test_common_secret_names()

    print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
    print(f"Secrets found: {len(secrets)}")
    print(f"Common secrets found: {len(common_findings)}")
    print(f"Total findings: {len(tester.findings)}")


if __name__ == "__main__":
    main()
