"""
Google Cloud Functions Security Tester
Test Cloud Functions for authentication bypass and misconfigurations
"""

from google.cloud import functions_v1
from google.api_core import exceptions as gcp_exceptions
from google.auth.exceptions import DefaultCredentialsError
from google.auth import default
from typing import List, Dict, Optional
from colorama import Fore, Style
import time
import requests

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class CloudFunctionsTester:
    """
    Test Google Cloud Functions for security vulnerabilities
    """

    def __init__(self, rate_limit: float = 1.0, max_retries: int = 3, project_id: Optional[str] = None):
        """
        Initialize Cloud Functions tester with rate limiting.

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

            print(f"{Fore.GREEN}[+] Cloud Functions client initialized{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s between requests{Style.RESET_ALL}")
            if self.project_id:
                print(f"{Fore.CYAN}[*] Project ID: {self.project_id}{Style.RESET_ALL}")

            # Initialize Cloud Functions client
            self.functions_client = functions_v1.CloudFunctionsServiceClient()

        except DefaultCredentialsError:
            print(f"{Fore.RED}[!] Failed to load GCP credentials{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Please configure credentials using gcloud auth{Style.RESET_ALL}")
            raise
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize Cloud Functions client: {e}{Style.RESET_ALL}")
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

    def enumerate_functions(self) -> List[Dict]:
        """
        Enumerate all Cloud Functions in the project

        Returns:
            List of function information
        """
        if not self.project_id:
            print(f"{Fore.YELLOW}[!] No project ID specified{Style.RESET_ALL}")
            return []

        target = f"gcp-{self.project_id}"

        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(target, 'cloud_functions_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}⚠️  SKIP: {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}✓ {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Enumerating Cloud Functions...{Style.RESET_ALL}")

        # List all functions across all regions
        parent = f"projects/{self.project_id}/locations/-"

        try:
            result = self._rate_limited_call(self.functions_client.list_functions, parent=parent)

            if result is None:
                print(f"{Fore.YELLOW}[!] Cannot list functions{Style.RESET_ALL}")
                return []

            functions = []
            for function in result:
                func_info = self.extract_function_info(function)
                functions.append(func_info)

                print(f"{Fore.GREEN}[+] Function: {func_info['name']}{Style.RESET_ALL}")

                # Test the function
                self.test_function(func_info)

            # Record tool run
            db = BountyHoundDB()
            db.record_tool_run(
                target,
                'cloud_functions_tester',
                findings_count=len(self.findings),
                success=True
            )

            return functions

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to enumerate functions: {e}{Style.RESET_ALL}")
            return []

    def extract_function_info(self, function) -> Dict:
        """
        Extract relevant information from a Cloud Function

        Args:
            function: Cloud Function object

        Returns:
            Dict of function information
        """
        info = {
            "name": function.name,
            "runtime": function.runtime,
            "status": function.status.name if hasattr(function.status, 'name') else str(function.status),
            "entry_point": function.entry_point,
        }

        # HTTP trigger
        if function.https_trigger:
            info["trigger_type"] = "https"
            info["url"] = function.https_trigger.url
            info["security_level"] = function.https_trigger.security_level.name if hasattr(function.https_trigger.security_level, 'name') else str(function.https_trigger.security_level)

        # Event trigger
        elif function.event_trigger:
            info["trigger_type"] = "event"
            info["event_type"] = function.event_trigger.event_type
            info["resource"] = function.event_trigger.resource

        # Service account
        if function.service_account_email:
            info["service_account"] = function.service_account_email

        # Environment variables (check for secrets)
        if function.environment_variables:
            info["env_vars"] = list(function.environment_variables.keys())
            self.check_env_variables(function.name, function.environment_variables)

        return info

    def test_function(self, func_info: Dict):
        """
        Test a Cloud Function for vulnerabilities

        Args:
            func_info: Function information dict
        """
        # Test HTTP-triggered functions
        if func_info.get("trigger_type") == "https" and func_info.get("url"):
            self.test_http_function(func_info)

        # Check security level
        if func_info.get("security_level") == "SECURE_ALWAYS":
            print(f"{Fore.GREEN}[+] Function requires authentication{Style.RESET_ALL}")
        elif func_info.get("security_level") == "SECURE_OPTIONAL":
            print(f"{Fore.YELLOW}[!] Function allows unauthenticated access{Style.RESET_ALL}")

            self.add_finding(
                "MEDIUM",
                f"Unauthenticated Function: {func_info['name']}",
                f"Cloud Function allows invocation without authentication"
            )

    def test_http_function(self, func_info: Dict):
        """
        Test HTTP-triggered Cloud Function

        Args:
            func_info: Function information dict
        """
        url = func_info.get("url")
        if not url:
            return

        print(f"{Fore.CYAN}[*] Testing HTTP function: {url}{Style.RESET_ALL}")

        # Test 1: Unauthenticated GET request
        try:
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                print(f"{Fore.RED}[!] Function accessible without authentication!{Style.RESET_ALL}")
                print(f"    Status: {response.status_code}")

                self.add_finding(
                    "HIGH",
                    f"Unauthenticated Access: {func_info['name']}",
                    f"Cloud Function at {url} is accessible without authentication (HTTP {response.status_code})"
                )

            elif response.status_code == 401 or response.status_code == 403:
                print(f"{Fore.GREEN}[+] Function requires authentication (HTTP {response.status_code}){Style.RESET_ALL}")

            else:
                print(f"{Fore.YELLOW}[*] Unexpected response: {response.status_code}{Style.RESET_ALL}")

        except requests.exceptions.RequestException as e:
            print(f"{Fore.YELLOW}[!] Request failed: {e}{Style.RESET_ALL}")

        # Test 2: Check for CORS misconfigurations
        self.test_cors(url)

    def test_cors(self, url: str):
        """
        Test for CORS misconfigurations

        Args:
            url: Function URL
        """
        try:
            headers = {
                'Origin': 'https://evil.com'
            }

            response = requests.options(url, headers=headers, timeout=10)

            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')

            if acao == '*':
                print(f"{Fore.YELLOW}[!] CORS: Access-Control-Allow-Origin: *{Style.RESET_ALL}")

                self.add_finding(
                    "LOW",
                    f"CORS Wildcard: {url}",
                    "Function allows requests from any origin (ACAO: *)"
                )

            elif acao == 'https://evil.com':
                print(f"{Fore.RED}[!] CORS: Reflects arbitrary origin!{Style.RESET_ALL}")

                if acac == 'true':
                    self.add_finding(
                        "HIGH",
                        f"CORS with Credentials: {url}",
                        "Function reflects origin and allows credentials - enables CSRF attacks"
                    )
                else:
                    self.add_finding(
                        "MEDIUM",
                        f"CORS Origin Reflection: {url}",
                        "Function reflects arbitrary origins"
                    )

        except Exception as e:
            pass

    def check_env_variables(self, function_name: str, env_vars: Dict[str, str]):
        """
        Check environment variables for secrets

        Args:
            function_name: Function name
            env_vars: Environment variables dict
        """
        secret_patterns = [
            'password', 'passwd', 'pwd',
            'secret', 'key', 'token',
            'api_key', 'apikey',
            'credential', 'cred',
            'auth'
        ]

        for var_name, var_value in env_vars.items():
            var_lower = var_name.lower()

            for pattern in secret_patterns:
                if pattern in var_lower:
                    print(f"{Fore.YELLOW}[!] Potential secret in env var: {var_name}{Style.RESET_ALL}")

                    # Don't log the actual value
                    self.add_finding(
                        "MEDIUM",
                        f"Potential Secret in Environment: {function_name}",
                        f"Function has environment variable '{var_name}' which may contain secrets. Use Secret Manager instead."
                    )
                    break

    def test_function_invocation(self, func_info: Dict, payload: Dict = None):
        """
        Test function invocation with a payload

        Args:
            func_info: Function information
            payload: Test payload (optional)
        """
        url = func_info.get("url")
        if not url:
            return

        if payload is None:
            payload = {"test": "BountyHound security test"}

        try:
            response = requests.post(url, json=payload, timeout=10)

            print(f"{Fore.CYAN}[*] Invocation test: {response.status_code}{Style.RESET_ALL}")

            # Check for error messages that leak information
            if response.status_code >= 400:
                content = response.text[:500]  # First 500 chars

                if 'traceback' in content.lower() or 'exception' in content.lower():
                    print(f"{Fore.YELLOW}[!] Error response contains debugging info{Style.RESET_ALL}")

                    self.add_finding(
                        "LOW",
                        f"Information Disclosure: {func_info['name']}",
                        "Function error responses leak debugging information"
                    )

        except Exception as e:
            pass

    def check_function_iam(self, function_name: str) -> Optional[Dict]:
        """
        Check IAM policy for a function

        Args:
            function_name: Full function name (projects/*/locations/*/functions/*)

        Returns:
            Dict of IAM issues or None
        """
        try:
            result = self._rate_limited_call(
                self.functions_client.get_iam_policy,
                resource=function_name
            )

            if result is None:
                return None

            issues = []

            # Check for public access
            for binding in result.bindings:
                if 'allUsers' in binding.members:
                    issues.append({
                        "severity": "CRITICAL",
                        "issue": "Public function invocation",
                        "role": binding.role,
                        "description": f"Function can be invoked by anyone (allUsers has {binding.role})"
                    })
                    print(f"{Fore.RED}[!] IAM: allUsers has {binding.role}{Style.RESET_ALL}")

                if 'allAuthenticatedUsers' in binding.members:
                    issues.append({
                        "severity": "HIGH",
                        "issue": "Authenticated users can invoke",
                        "role": binding.role,
                        "description": f"Any authenticated Google user can invoke (allAuthenticatedUsers has {binding.role})"
                    })
                    print(f"{Fore.YELLOW}[!] IAM: allAuthenticatedUsers has {binding.role}{Style.RESET_ALL}")

            return issues if issues else None

        except Exception as e:
            return None

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

    parser = argparse.ArgumentParser(description='GCP Cloud Functions Security Tester')
    parser.add_argument('--rate-limit', type=float, default=1.0,
                        help='Seconds to wait between requests (default: 1.0)')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='Maximum retries for throttled requests (default: 3)')
    parser.add_argument('--project-id', required=True, help='GCP project ID')

    args = parser.parse_args()

    tester = CloudFunctionsTester(
        rate_limit=args.rate_limit,
        max_retries=args.max_retries,
        project_id=args.project_id
    )
    functions = tester.enumerate_functions()

    print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
    print(f"Functions found: {len(functions)}")
    print(f"Findings: {len(tester.findings)}")


if __name__ == "__main__":
    main()
