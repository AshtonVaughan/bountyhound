"""
Google Cloud Platform IAM Privilege Escalation Tester
Test for IAM misconfigurations and privilege escalation paths
"""

from google.api_core import exceptions as gcp_exceptions
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
from typing import List, Dict, Optional
from colorama import Fore, Style
import time

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class GCPIAMTester:
    """
    Test GCP IAM for privilege escalation vulnerabilities
    """

    # Known privilege escalation permissions
    DANGEROUS_PERMISSIONS = {
        # Service Account Key Creation
        'iam.serviceAccountKeys.create': 'CRITICAL',
        'iam.serviceAccounts.actAs': 'HIGH',
        'iam.serviceAccounts.getAccessToken': 'HIGH',
        'iam.serviceAccounts.implicitDelegation': 'HIGH',

        # Role/Permission Modification
        'iam.roles.create': 'CRITICAL',
        'iam.roles.update': 'CRITICAL',
        'resourcemanager.projects.setIamPolicy': 'CRITICAL',
        'resourcemanager.organizations.setIamPolicy': 'CRITICAL',

        # Compute Engine
        'compute.instances.setMetadata': 'HIGH',
        'compute.instances.osLogin': 'MEDIUM',

        # Cloud Functions
        'cloudfunctions.functions.create': 'HIGH',
        'cloudfunctions.functions.update': 'HIGH',

        # Cloud Run
        'run.services.create': 'HIGH',
        'run.services.update': 'HIGH',

        # Deployment Manager
        'deploymentmanager.deployments.create': 'HIGH',

        # Storage Admin
        'storage.buckets.setIamPolicy': 'HIGH',
    }

    def __init__(self, rate_limit: float = 1.0, max_retries: int = 3, project_id: Optional[str] = None):
        """
        Initialize IAM tester with rate limiting using default credentials.

        Args:
            rate_limit: Seconds to wait between API calls (default: 1.0)
            max_retries: Maximum retries for throttled requests (default: 3)
            project_id: GCP project ID (optional, detected from credentials)

        Credentials are loaded from (in order):
        1. GOOGLE_APPLICATION_CREDENTIALS environment variable
        2. gcloud auth application-default login
        3. Service account on GCE/GKE/Cloud Run
        """
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.project_id = project_id
        self._last_request_time = None
        self.findings = []

        try:
            # Use default credentials - NEVER hardcode credentials
            self.credentials, self.default_project = default()

            if not self.project_id:
                self.project_id = self.default_project

            print(f"{Fore.GREEN}[+] GCP credentials loaded successfully{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s between requests{Style.RESET_ALL}")
            if self.project_id:
                print(f"{Fore.CYAN}[*] Project ID: {self.project_id}{Style.RESET_ALL}")

        except DefaultCredentialsError:
            print(f"{Fore.RED}[!] Failed to load GCP credentials{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Please configure credentials using one of:{Style.RESET_ALL}")
            print(f"    1. gcloud auth application-default login")
            print(f"    2. Set GOOGLE_APPLICATION_CREDENTIALS environment variable")
            print(f"    3. Run on GCE/GKE/Cloud Run with service account")
            raise
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize IAM client: {e}{Style.RESET_ALL}")
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
                # Return None for access denied
                return None

            except Exception as e:
                print(f"{Fore.YELLOW}[*] Error: {e}{Style.RESET_ALL}")
                return None

        return None

    def enumerate_permissions(self) -> Dict:
        """
        Enumerate current IAM permissions

        Returns:
            Dictionary of accessible actions and findings
        """
        target = f"gcp-{self.project_id}" if self.project_id else "gcp-unknown"

        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(target, 'gcp_iam_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}⚠️  SKIP: {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return {
                "project_id": self.project_id,
                "permissions": [],
                "findings": [],
                "skipped": True,
                "reason": context['reason']
            }
        else:
            print(f"{Fore.GREEN}✓ {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Enumerating IAM permissions...{Style.RESET_ALL}")

        # Get service account info
        service_account = self.get_service_account_info()

        # Test permissions
        permissions = self.test_permissions()

        # Check for privilege escalation
        escalation_paths = self.check_privilege_escalation_paths(permissions)

        print(f"{Fore.GREEN}[+] Accessible permissions: {len(permissions)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Escalation paths found: {len(escalation_paths)}{Style.RESET_ALL}")

        # Record tool run
        db = BountyHoundDB()
        db.record_tool_run(
            target,
            'gcp_iam_tester',
            findings_count=len(self.findings),
            success=True
        )

        return {
            "project_id": self.project_id,
            "service_account": service_account,
            "permissions": permissions,
            "escalation_paths": escalation_paths,
            "findings": self.findings
        }

    def get_service_account_info(self) -> Dict:
        """Get current service account information"""
        try:
            # Try to get service account email from credentials
            if hasattr(self.credentials, 'service_account_email'):
                email = self.credentials.service_account_email
                print(f"{Fore.GREEN}[+] Service Account: {email}{Style.RESET_ALL}")
                return {
                    "email": email,
                    "type": "service_account"
                }
            else:
                print(f"{Fore.CYAN}[*] User credentials (not service account){Style.RESET_ALL}")
                return {
                    "type": "user"
                }
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to get service account info: {e}{Style.RESET_ALL}")
            return {}

    def test_permissions(self) -> List[str]:
        """
        Test common IAM permissions to enumerate access

        Returns:
            List of allowed permissions
        """
        from google.cloud import storage
        from google.cloud import compute_v1
        from google.cloud import functions_v1

        permissions_to_test = []
        allowed_permissions = []

        # Storage permissions
        try:
            storage_client = storage.Client(project=self.project_id)
            result = self._rate_limited_call(storage_client.list_buckets)
            if result is not None:
                allowed_permissions.append('storage.buckets.list')
                print(f"{Fore.GREEN}[+] storage.buckets.list: ALLOWED{Style.RESET_ALL}")
        except:
            pass

        # Compute permissions
        try:
            compute_client = compute_v1.InstancesClient()
            result = self._rate_limited_call(
                compute_client.list,
                project=self.project_id,
                zone='us-central1-a'
            )
            if result is not None:
                allowed_permissions.append('compute.instances.list')
                print(f"{Fore.GREEN}[+] compute.instances.list: ALLOWED{Style.RESET_ALL}")
        except:
            pass

        # Cloud Functions permissions
        try:
            functions_client = functions_v1.CloudFunctionsServiceClient()
            parent = f"projects/{self.project_id}/locations/-"
            result = self._rate_limited_call(functions_client.list_functions, parent=parent)
            if result is not None:
                allowed_permissions.append('cloudfunctions.functions.list')
                print(f"{Fore.GREEN}[+] cloudfunctions.functions.list: ALLOWED{Style.RESET_ALL}")
        except:
            pass

        # Test dangerous permissions
        for permission, severity in self.DANGEROUS_PERMISSIONS.items():
            if self.test_single_permission(permission):
                allowed_permissions.append(permission)
                print(f"{Fore.RED}[!] {permission}: ALLOWED (Severity: {severity}){Style.RESET_ALL}")

                self.add_finding(
                    severity,
                    f"Dangerous Permission: {permission}",
                    f"Service account has {permission} which can be used for privilege escalation"
                )

        return allowed_permissions

    def test_single_permission(self, permission: str) -> bool:
        """
        Test a single permission

        Args:
            permission: Permission string to test

        Returns:
            True if permission is granted
        """
        if not self.project_id:
            return False

        try:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.ProjectsClient()

            # Use testIamPermissions API
            resource = f"projects/{self.project_id}"
            result = self._rate_limited_call(
                client.test_iam_permissions,
                resource=resource,
                permissions=[permission]
            )

            if result and permission in result.permissions:
                return True

        except:
            pass

        return False

    def check_privilege_escalation_paths(self, permissions: List[str]) -> List[Dict]:
        """
        Check for known privilege escalation techniques

        Args:
            permissions: List of allowed permissions

        Returns:
            List of escalation path findings
        """
        paths = []

        # Path 1: Create Service Account Keys
        if 'iam.serviceAccountKeys.create' in permissions:
            paths.append({
                "technique": "CreateServiceAccountKeys",
                "severity": "CRITICAL",
                "permissions_required": ['iam.serviceAccountKeys.create'],
                "description": "Can create service account keys for any service account",
                "exploitation": "Create key for admin service account, use it to escalate privileges"
            })

        # Path 2: Act As Service Account
        if 'iam.serviceAccounts.actAs' in permissions:
            paths.append({
                "technique": "ActAsServiceAccount",
                "severity": "HIGH",
                "permissions_required": ['iam.serviceAccounts.actAs'],
                "description": "Can impersonate other service accounts",
                "exploitation": "Deploy Cloud Function/Cloud Run as privileged service account"
            })

        # Path 3: Modify IAM Policy
        if 'resourcemanager.projects.setIamPolicy' in permissions:
            paths.append({
                "technique": "ModifyProjectIAM",
                "severity": "CRITICAL",
                "permissions_required": ['resourcemanager.projects.setIamPolicy'],
                "description": "Can modify project-level IAM policies",
                "exploitation": "Grant yourself Owner role on the project"
            })

        # Path 4: Create/Update Cloud Functions
        if 'cloudfunctions.functions.create' in permissions or 'cloudfunctions.functions.update' in permissions:
            paths.append({
                "technique": "MaliciousCloudFunction",
                "severity": "HIGH",
                "permissions_required": ['cloudfunctions.functions.create'],
                "description": "Can deploy malicious Cloud Functions",
                "exploitation": "Deploy function with higher privileges to exfiltrate data"
            })

        # Path 5: Set Compute Instance Metadata
        if 'compute.instances.setMetadata' in permissions:
            paths.append({
                "technique": "ComputeMetadataEscalation",
                "severity": "HIGH",
                "permissions_required": ['compute.instances.setMetadata'],
                "description": "Can modify compute instance metadata",
                "exploitation": "Add SSH keys or startup scripts to existing instances"
            })

        # Path 6: Create Deployment Manager Deployments
        if 'deploymentmanager.deployments.create' in permissions:
            paths.append({
                "technique": "DeploymentManagerEscalation",
                "severity": "HIGH",
                "permissions_required": ['deploymentmanager.deployments.create'],
                "description": "Can create Deployment Manager deployments",
                "exploitation": "Deploy infrastructure with elevated service account"
            })

        return paths

    def enumerate_service_accounts(self) -> List[Dict]:
        """
        Enumerate service accounts in the project

        Returns:
            List of service accounts
        """
        if not self.project_id:
            print(f"{Fore.YELLOW}[!] No project ID specified{Style.RESET_ALL}")
            return []

        try:
            from google.cloud import iam_admin_v1
        except ImportError:
            print(f"{Fore.YELLOW}[!] google-cloud-iam not installed{Style.RESET_ALL}")
            return []

        try:
            client = iam_admin_v1.IAMClient()
            parent = f"projects/{self.project_id}"

            result = self._rate_limited_call(client.list_service_accounts, name=parent)

            if result is None:
                print(f"{Fore.YELLOW}[!] Cannot list service accounts{Style.RESET_ALL}")
                return []

            service_accounts = []
            for account in result.accounts:
                service_accounts.append({
                    "email": account.email,
                    "display_name": account.display_name,
                    "unique_id": account.unique_id
                })
                print(f"{Fore.GREEN}[+] Service Account: {account.email}{Style.RESET_ALL}")

            return service_accounts

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to enumerate service accounts: {e}{Style.RESET_ALL}")
            return []

    def check_service_account_keys(self, service_account_email: str) -> List[Dict]:
        """
        List keys for a service account

        Args:
            service_account_email: Service account email

        Returns:
            List of keys
        """
        try:
            from google.cloud import iam_admin_v1
        except ImportError:
            return []

        try:
            client = iam_admin_v1.IAMClient()
            name = f"projects/-/serviceAccounts/{service_account_email}"

            result = self._rate_limited_call(client.list_service_account_keys, name=name)

            if result is None:
                return []

            keys = []
            for key in result.keys:
                keys.append({
                    "name": key.name,
                    "key_type": key.key_type.name,
                    "valid_after_time": str(key.valid_after_time),
                    "valid_before_time": str(key.valid_before_time)
                })

            print(f"{Fore.GREEN}[+] Found {len(keys)} key(s) for {service_account_email}{Style.RESET_ALL}")

            return keys

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to list keys: {e}{Style.RESET_ALL}")
            return []

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

    parser = argparse.ArgumentParser(description='GCP IAM Privilege Escalation Tester')
    parser.add_argument('--rate-limit', type=float, default=1.0,
                        help='Seconds to wait between API calls (default: 1.0)')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='Maximum retries for throttled requests (default: 3)')
    parser.add_argument('--project-id', help='GCP project ID')

    args = parser.parse_args()

    tester = GCPIAMTester(
        rate_limit=args.rate_limit,
        max_retries=args.max_retries,
        project_id=args.project_id
    )
    results = tester.enumerate_permissions()

    print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
    print(f"Permissions: {len(results['permissions'])}")
    print(f"Escalation Paths: {len(results['escalation_paths'])}")
    print(f"Findings: {len(results['findings'])}")


if __name__ == "__main__":
    main()
