"""
AWS Lambda Security Tester
Test Lambda functions for security misconfigurations
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Optional
from colorama import Fore, Style
import time
import json

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class LambdaTester:
    """
    Test AWS Lambda functions for security issues
    """

    def __init__(self, rate_limit: float = 1.0, max_retries: int = 3, target: Optional[str] = None):
        """
        Initialize Lambda tester with rate limiting

        Args:
            rate_limit: Seconds to wait between API calls (default: 1.0)
            max_retries: Maximum retries for throttled requests (default: 3)
            target: Target identifier for database tracking (default: AWS account ID)
        """
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.target = target
        self._last_request_time = None

        try:
            self.lambda_client = boto3.client('lambda')
            self.sts = boto3.client('sts')

            print(f"{Fore.GREEN}[+] Lambda client initialized{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s between requests{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize Lambda client: {e}{Style.RESET_ALL}")
            raise

        self.findings = []

    def _rate_limited_call(self, func, *args, **kwargs):
        """
        Execute a function with rate limiting and exponential backoff
        """
        for attempt in range(self.max_retries):
            try:
                if attempt > 0:
                    backoff_time = min(2 ** attempt, 30)
                    print(f"{Fore.YELLOW}[*] Retry {attempt}, waiting {backoff_time}s...{Style.RESET_ALL}")
                    time.sleep(backoff_time)
                elif self._last_request_time is not None:
                    elapsed = time.time() - self._last_request_time
                    if elapsed < self.rate_limit:
                        time.sleep(self.rate_limit - elapsed)

                result = func(*args, **kwargs)
                self._last_request_time = time.time()
                return result

            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')

                if error_code in ['429', 'ThrottlingException', 'RequestLimitExceeded', 'TooManyRequestsException']:
                    if attempt < self.max_retries - 1:
                        print(f"{Fore.YELLOW}[!] Rate limited ({error_code}), retrying...{Style.RESET_ALL}")
                        continue
                    else:
                        print(f"{Fore.RED}[!] Max retries reached{Style.RESET_ALL}")
                        return None

                return None

        return None

    def enumerate_functions(self) -> List[Dict]:
        """
        Enumerate all Lambda functions

        Returns:
            List of function details
        """
        # Get AWS account ID for database tracking
        identity = self.sts.get_caller_identity()
        if not self.target and identity:
            self.target = f"aws-{identity.get('Account', 'unknown')}"

        # Database check
        if self.target:
            print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
            context = DatabaseHooks.before_test(self.target, 'lambda_tester')

            if context['should_skip']:
                print(f"{Fore.YELLOW}⚠️  SKIP: {context['reason']}{Style.RESET_ALL}")
                return []
            else:
                print(f"{Fore.GREEN}✓ {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Enumerating Lambda functions...{Style.RESET_ALL}")

        functions = []

        try:
            # List functions (paginated)
            paginator = self.lambda_client.get_paginator('list_functions')
            page_iterator = paginator.paginate()

            for page in page_iterator:
                for func in page.get('Functions', []):
                    functions.append({
                        'name': func['FunctionName'],
                        'arn': func['FunctionArn'],
                        'runtime': func.get('Runtime', 'Unknown'),
                        'handler': func.get('Handler', 'Unknown'),
                        'role': func.get('Role', ''),
                        'memory': func.get('MemorySize', 128),
                        'timeout': func.get('Timeout', 3),
                        'last_modified': func.get('LastModified', '')
                    })

                # Rate limiting between pages
                time.sleep(self.rate_limit)

            print(f"{Fore.GREEN}[+] Found {len(functions)} function(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to enumerate functions: {e.response['Error']['Code']}{Style.RESET_ALL}")

        # Record tool run
        if self.target:
            db = BountyHoundDB()
            db.record_tool_run(
                self.target,
                'lambda_tester',
                findings_count=len(self.findings),
                success=True
            )

        return functions

    def check_function_permissions(self, function_name: str) -> Dict:
        """
        Check Lambda function permissions and policy

        Args:
            function_name: Function name

        Returns:
            Permission analysis
        """
        result = {
            'function': function_name,
            'public': False,
            'cross_account': [],
            'issues': []
        }

        try:
            # Get function policy
            response = self._rate_limited_call(
                self.lambda_client.get_policy,
                FunctionName=function_name
            )

            if response:
                policy = json.loads(response['Policy'])

                for statement in policy.get('Statement', []):
                    principal = statement.get('Principal', {})
                    effect = statement.get('Effect', '')
                    action = statement.get('Action', '')

                    # Check for public access
                    if effect == 'Allow' and principal == '*':
                        result['public'] = True
                        result['issues'].append("CRITICAL: Function is publicly invocable")
                        print(f"{Fore.RED}[!] {function_name} is PUBLIC{Style.RESET_ALL}")

                        self.add_finding(
                            "CRITICAL",
                            f"Public Lambda: {function_name}",
                            "Function can be invoked by anyone"
                        )

                    # Check for cross-account access
                    if effect == 'Allow' and isinstance(principal, dict):
                        aws_principal = principal.get('AWS', '')
                        if aws_principal and ':' in str(aws_principal):
                            # Extract account ID
                            account_id = str(aws_principal).split(':')[4] if len(str(aws_principal).split(':')) > 4 else ''
                            if account_id:
                                result['cross_account'].append(account_id)
                                result['issues'].append(f"Cross-account access from {account_id}")

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                result['issues'].append("No resource policy")
            else:
                result['issues'].append(f"Error: {e.response['Error']['Code']}")

        return result

    def check_function_configuration(self, function_name: str) -> Dict:
        """
        Analyze function configuration for security issues

        Args:
            function_name: Function name

        Returns:
            Configuration analysis
        """
        result = {
            'function': function_name,
            'issues': []
        }

        try:
            # Get function configuration
            config = self._rate_limited_call(
                self.lambda_client.get_function_configuration,
                FunctionName=function_name
            )

            if config:
                # Check runtime
                runtime = config.get('Runtime', '')
                deprecated_runtimes = [
                    'python2.7', 'python3.6',
                    'nodejs4.3', 'nodejs6.10', 'nodejs8.10', 'nodejs10.x',
                    'dotnetcore1.0', 'dotnetcore2.0',
                    'ruby2.5'
                ]

                if any(dep in runtime for dep in deprecated_runtimes):
                    result['issues'].append(f"DEPRECATED RUNTIME: {runtime}")
                    self.add_finding(
                        "HIGH",
                        f"Deprecated Runtime: {function_name}",
                        f"Function uses deprecated runtime {runtime}"
                    )

                # Check environment variables for secrets
                env_vars = config.get('Environment', {}).get('Variables', {})
                sensitive_keys = ['password', 'secret', 'key', 'token', 'api_key', 'apikey', 'credential']

                for key in env_vars.keys():
                    if any(sensitive in key.lower() for sensitive in sensitive_keys):
                        result['issues'].append(f"SENSITIVE ENV VAR: {key}")
                        self.add_finding(
                            "MEDIUM",
                            f"Sensitive Env Var: {function_name}",
                            f"Function has potentially sensitive env var: {key}"
                        )

                # Check timeout
                timeout = config.get('Timeout', 3)
                if timeout > 300:
                    result['issues'].append(f"HIGH TIMEOUT: {timeout}s (DoS risk)")

                # Check memory
                memory = config.get('MemorySize', 128)
                result['runtime'] = runtime
                result['timeout'] = timeout
                result['memory'] = memory
                result['role'] = config.get('Role', '')

                # Check if tracing is enabled
                tracing = config.get('TracingConfig', {}).get('Mode', 'PassThrough')
                if tracing != 'Active':
                    result['issues'].append("X-Ray tracing not enabled")

        except ClientError as e:
            result['issues'].append(f"Error: {e.response['Error']['Code']}")

        return result

    def check_function_code(self, function_name: str) -> Dict:
        """
        Analyze function code for security issues (basic checks)

        Args:
            function_name: Function name

        Returns:
            Code analysis results
        """
        result = {
            'function': function_name,
            'code_location': '',
            'code_size': 0,
            'issues': []
        }

        try:
            # Get function code location
            func = self._rate_limited_call(
                self.lambda_client.get_function,
                FunctionName=function_name
            )

            if func:
                code = func.get('Code', {})
                result['code_location'] = code.get('Location', '')
                config = func.get('Configuration', {})
                result['code_size'] = config.get('CodeSize', 0)

                # Check for large code packages (potential security review needed)
                if result['code_size'] > 50 * 1024 * 1024:  # 50MB
                    result['issues'].append(f"LARGE CODE SIZE: {result['code_size'] / (1024*1024):.1f}MB")

                # Check layers
                layers = config.get('Layers', [])
                if layers:
                    result['layers'] = [layer['Arn'] for layer in layers]

                    # Check for third-party layers
                    for layer in layers:
                        layer_arn = layer['Arn']
                        if not layer_arn.startswith('arn:aws:lambda:'):
                            result['issues'].append(f"THIRD-PARTY LAYER: {layer_arn}")

        except ClientError as e:
            result['issues'].append(f"Error: {e.response['Error']['Code']}")

        return result

    def check_function_networking(self, function_name: str) -> Dict:
        """
        Check function VPC configuration

        Args:
            function_name: Function name

        Returns:
            Network configuration analysis
        """
        result = {
            'function': function_name,
            'vpc_configured': False,
            'issues': []
        }

        try:
            config = self._rate_limited_call(
                self.lambda_client.get_function_configuration,
                FunctionName=function_name
            )

            if config:
                vpc_config = config.get('VpcConfig', {})

                if vpc_config.get('VpcId'):
                    result['vpc_configured'] = True
                    result['vpc_id'] = vpc_config['VpcId']
                    result['subnets'] = vpc_config.get('SubnetIds', [])
                    result['security_groups'] = vpc_config.get('SecurityGroupIds', [])

                    # Check for public subnets (would require additional VPC API calls)
                    # For now, just note the VPC configuration exists

                else:
                    result['issues'].append("NO VPC: Function not in VPC (public internet access)")

        except ClientError as e:
            result['issues'].append(f"Error: {e.response['Error']['Code']}")

        return result

    def test_function_invocation(self, function_name: str, payload: dict = None) -> Dict:
        """
        Test function invocation (non-destructive)

        Args:
            function_name: Function name
            payload: Test payload (default: {})

        Returns:
            Invocation result
        """
        result = {
            'function': function_name,
            'invocable': False,
            'error': None
        }

        if payload is None:
            payload = {}

        try:
            response = self._rate_limited_call(
                self.lambda_client.invoke,
                FunctionName=function_name,
                InvocationType='RequestResponse',
                Payload=json.dumps(payload)
            )

            if response:
                result['invocable'] = True
                result['status_code'] = response.get('StatusCode', 0)

                # Check for errors
                if response.get('FunctionError'):
                    result['error'] = response.get('FunctionError')
                    print(f"{Fore.YELLOW}[*] {function_name}: Function error{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] {function_name}: Successfully invoked{Style.RESET_ALL}")

                    # This is interesting - function is invocable by our credentials
                    self.add_finding(
                        "INFO",
                        f"Invocable Function: {function_name}",
                        "Function can be invoked by current credentials"
                    )

        except ClientError as e:
            result['error'] = e.response['Error']['Code']

            if e.response['Error']['Code'] == 'AccessDeniedException':
                print(f"{Fore.CYAN}[*] {function_name}: Access denied (expected){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[*] {function_name}: {result['error']}{Style.RESET_ALL}")

        return result

    def analyze_function_role(self, role_arn: str) -> Dict:
        """
        Analyze the IAM role used by a function

        Args:
            role_arn: Role ARN

        Returns:
            Role analysis
        """
        result = {
            'role_arn': role_arn,
            'policies': [],
            'issues': []
        }

        try:
            iam = boto3.client('iam')

            # Extract role name from ARN
            role_name = role_arn.split('/')[-1]

            # Get attached policies
            response = self._rate_limited_call(
                iam.list_attached_role_policies,
                RoleName=role_name
            )

            if response:
                for policy in response.get('AttachedPolicies', []):
                    result['policies'].append(policy['PolicyArn'])

                    # Check for overly permissive managed policies
                    if 'AdministratorAccess' in policy['PolicyArn']:
                        result['issues'].append("ADMIN POLICY: Function has AdministratorAccess")
                        self.add_finding(
                            "CRITICAL",
                            f"Lambda Admin Role: {role_name}",
                            "Function role has AdministratorAccess policy"
                        )

                    if 'PowerUserAccess' in policy['PolicyArn']:
                        result['issues'].append("POWER USER POLICY: Overly permissive")

            # Get inline policies
            inline_response = self._rate_limited_call(
                iam.list_role_policies,
                RoleName=role_name
            )

            if inline_response:
                result['inline_policies'] = inline_response.get('PolicyNames', [])

        except ClientError as e:
            result['issues'].append(f"Error: {e.response['Error']['Code']}")

        return result

    def add_finding(self, severity: str, title: str, description: str):
        """Add security finding"""
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description
        })

    def comprehensive_function_analysis(self, function_name: str) -> Dict:
        """
        Run all security checks on a single function

        Args:
            function_name: Function name

        Returns:
            Comprehensive analysis report
        """
        print(f"\n{Fore.CYAN}[*] Analyzing function: {function_name}{Style.RESET_ALL}")

        report = {
            'function': function_name,
            'permissions': {},
            'configuration': {},
            'code': {},
            'networking': {},
            'role': {},
            'invocation': {},
            'severity': 'INFO'
        }

        # Run all checks
        report['permissions'] = self.check_function_permissions(function_name)
        report['configuration'] = self.check_function_configuration(function_name)
        report['code'] = self.check_function_code(function_name)
        report['networking'] = self.check_function_networking(function_name)

        # Analyze role if configured
        if report['configuration'].get('role'):
            report['role'] = self.analyze_function_role(report['configuration']['role'])

        # Test invocation (careful!)
        # report['invocation'] = self.test_function_invocation(function_name)

        # Determine overall severity
        all_issues = (
            report['permissions'].get('issues', []) +
            report['configuration'].get('issues', []) +
            report['code'].get('issues', []) +
            report['networking'].get('issues', []) +
            report['role'].get('issues', [])
        )

        if any('CRITICAL' in issue for issue in all_issues):
            report['severity'] = 'CRITICAL'
        elif any('HIGH' in issue for issue in all_issues):
            report['severity'] = 'HIGH'
        elif any('MEDIUM' in issue for issue in all_issues):
            report['severity'] = 'MEDIUM'

        print(f"{Fore.CYAN}[*] Function analysis complete: {report['severity']}{Style.RESET_ALL}")

        return report


def main():
    """CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description='AWS Lambda Security Tester')
    parser.add_argument('--rate-limit', type=float, default=1.0,
                        help='Seconds to wait between API calls (default: 1.0)')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='Maximum retries for throttled requests (default: 3)')
    parser.add_argument('--function', help='Analyze specific function')

    args = parser.parse_args()

    tester = LambdaTester(rate_limit=args.rate_limit, max_retries=args.max_retries)

    if args.function:
        # Analyze specific function
        report = tester.comprehensive_function_analysis(args.function)
        print(f"\n{Fore.CYAN}=== FUNCTION ANALYSIS ==={Style.RESET_ALL}")
        print(f"Severity: {report['severity']}")
        print(f"Issues: {len(tester.findings)}")
    else:
        # Enumerate all functions
        functions = tester.enumerate_functions()
        print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
        print(f"Functions: {len(functions)}")
        print(f"Findings: {len(tester.findings)}")


if __name__ == "__main__":
    main()
