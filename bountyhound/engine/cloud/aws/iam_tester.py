"""
AWS IAM Privilege Escalation Tester
Test for IAM misconfigurations and privilege escalation paths
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Optional
from colorama import Fore, Style
import time

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.cloud.aws.rate_limiter import AWSRateLimiterMixin


class IAMTester(AWSRateLimiterMixin):
    """
    Test AWS IAM for privilege escalation vulnerabilities
    """

    def __init__(self, rate_limit: float = 1.0, max_retries: int = 3, target: Optional[str] = None):
        """
        Initialize IAM tester with rate limiting using boto3's default credential chain.

        Args:
            rate_limit: Seconds to wait between API calls (default: 1.0)
            max_retries: Maximum retries for throttled requests (default: 3)
            target: Target identifier for database tracking (default: AWS account ID)

        Credentials are loaded from (in order):
        1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
        2. ~/.aws/credentials file
        3. IAM role (if running on EC2/Lambda/ECS)

        SECURITY: This class intentionally does NOT accept credentials as parameters
        to prevent hardcoded credentials in source code.
        """
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.target = target
        self._last_request_time = None

        try:
            # Use boto3's default credential chain - NEVER hardcode credentials
            self.iam = boto3.client('iam')
            self.sts = boto3.client('sts')

            print(f"{Fore.GREEN}[+] AWS credentials loaded successfully{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s between requests{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to load AWS credentials{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Please configure credentials using one of:{Style.RESET_ALL}")
            print(f"    1. Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            print(f"    2. AWS credentials file: ~/.aws/credentials")
            print(f"    3. IAM role (if running on EC2/Lambda/ECS)")
            print(f"{Fore.RED}[!] Error details: {e}{Style.RESET_ALL}")
            raise

        self.findings = []

    def enumerate_permissions(self) -> Dict:
        """
        Enumerate current IAM permissions

        Returns:
            Dictionary of accessible actions
        """
        # Get AWS account ID for database tracking
        identity = self.get_caller_identity()
        if not self.target and identity:
            self.target = f"aws-{identity.get('Account', 'unknown')}"

        # Database check
        if self.target:
            print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
            context = DatabaseHooks.before_test(self.target, 'iam_tester')

            if context['should_skip']:
                print(f"{Fore.YELLOW}[SKIP]  SKIP: {context['reason']}{Style.RESET_ALL}")
                if context.get('previous_findings'):
                    print(f"Previous findings: {len(context['previous_findings'])}")
                return {
                    "identity": identity,
                    "permissions": [],
                    "findings": [],
                    "skipped": True,
                    "reason": context['reason']
                }
            else:
                print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Enumerating IAM permissions...{Style.RESET_ALL}")

        permissions = self.test_permissions()

        print(f"{Fore.GREEN}[+] Identity: {identity['Arn']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Accessible actions: {len(permissions)}{Style.RESET_ALL}")

        # Record tool run
        if self.target:
            db = BountyHoundDB()
            db.record_tool_run(
                self.target,
                'iam_tester',
                findings_count=len(self.findings),
                success=True
            )

        return {
            "identity": identity,
            "permissions": permissions,
            "findings": self.findings
        }

    def get_caller_identity(self) -> Dict:
        """Get current IAM identity with rate limiting"""
        response = self._rate_limited_call(self.sts.get_caller_identity)
        if response:
            return {
                "UserId": response['UserId'],
                "Account": response['Account'],
                "Arn": response['Arn']
            }
        else:
            print(f"{Fore.RED}[-] Failed to get identity{Style.RESET_ALL}")
            return {}

    def test_permissions(self) -> List[str]:
        """
        Test common IAM actions to enumerate permissions
        """
        actions_to_test = [
            # IAM Read
            ("iam:ListUsers", lambda: self.iam.list_users()),
            ("iam:ListRoles", lambda: self.iam.list_roles()),
            ("iam:ListPolicies", lambda: self.iam.list_policies()),
            ("iam:GetUser", lambda: self.iam.get_user()),
            ("iam:GetPolicy", lambda: self.iam.get_policy(PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess')),

            # IAM Write (DANGEROUS)
            ("iam:CreateUser", lambda: self.iam.create_user(UserName='test-user-probe')),
            ("iam:CreateAccessKey", lambda: self.iam.create_access_key(UserName='test')),
            ("iam:AttachUserPolicy", lambda: None),  # Don't actually test

            # S3
            ("s3:ListBuckets", lambda: boto3.client('s3').list_buckets()),
            ("s3:GetObject", lambda: None),

            # EC2
            ("ec2:DescribeInstances", lambda: boto3.client('ec2').describe_instances()),
            ("ec2:DescribeSnapshots", lambda: boto3.client('ec2').describe_snapshots()),

            # Lambda
            ("lambda:ListFunctions", lambda: boto3.client('lambda').list_functions()),

            # Secrets Manager
            ("secretsmanager:ListSecrets", lambda: boto3.client('secretsmanager').list_secrets()),

            # SSM
            ("ssm:DescribeParameters", lambda: boto3.client('ssm').describe_parameters()),
        ]

        allowed_actions = []

        for action_name, action_func in actions_to_test:
            if action_func:
                # Use rate limiting for each permission check
                result = self._rate_limited_call(action_func)
                if result is not None:
                    allowed_actions.append(action_name)
                    print(f"{Fore.GREEN}[+] {action_name}: ALLOWED{Style.RESET_ALL}")

                    # Check for privilege escalation
                    if action_name in ['iam:CreateAccessKey', 'iam:CreateUser', 'iam:AttachUserPolicy']:
                        self.add_finding("HIGH", f"Privilege Escalation: {action_name}",
                                       f"Account has {action_name} permission - can escalate privileges")

        return allowed_actions

    def check_privilege_escalation_paths(self, permissions: List[str]) -> List[Dict]:
        """
        Check for known IAM privilege escalation techniques

        Based on Rhino Security Labs' research:
        https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

        Args:
            permissions: List of allowed IAM actions

        Returns:
            List of privilege escalation paths
        """
        paths = []

        # Path 1: iam:CreateAccessKey
        if "iam:CreateAccessKey" in permissions:
            paths.append({
                "id": "PE-1",
                "technique": "CreateAccessKey",
                "severity": "CRITICAL",
                "description": "Can create access keys for other users",
                "exploitation": "aws iam create-access-key --user-name <admin-user>",
                "impact": "Full account compromise if admin users accessible",
                "mitigation": "Restrict CreateAccessKey to self only"
            })

        # Path 2: iam:CreateLoginProfile
        if "iam:CreateLoginProfile" in permissions:
            paths.append({
                "id": "PE-2",
                "technique": "CreateLoginProfile",
                "severity": "CRITICAL",
                "description": "Can create console password for other users",
                "exploitation": "aws iam create-login-profile --user-name <admin-user> --password <pwd>",
                "impact": "Console access to other user accounts",
                "mitigation": "Restrict CreateLoginProfile to self only"
            })

        # Path 3: iam:UpdateLoginProfile
        if "iam:UpdateLoginProfile" in permissions:
            paths.append({
                "id": "PE-3",
                "technique": "UpdateLoginProfile",
                "severity": "CRITICAL",
                "description": "Can change console password for other users",
                "exploitation": "aws iam update-login-profile --user-name <admin-user> --password <new-pwd>",
                "impact": "Console access hijacking",
                "mitigation": "Restrict UpdateLoginProfile to self only"
            })

        # Path 4: iam:AttachUserPolicy
        if "iam:AttachUserPolicy" in permissions:
            paths.append({
                "id": "PE-4",
                "technique": "AttachUserPolicy",
                "severity": "CRITICAL",
                "description": "Can attach managed policies to users",
                "exploitation": "aws iam attach-user-policy --user-name <self> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                "impact": "Self-escalation to admin",
                "mitigation": "Use permission boundaries"
            })

        # Path 5: iam:AttachGroupPolicy
        if "iam:AttachGroupPolicy" in permissions:
            paths.append({
                "id": "PE-5",
                "technique": "AttachGroupPolicy",
                "severity": "CRITICAL",
                "description": "Can attach managed policies to groups",
                "exploitation": "aws iam attach-group-policy --group-name <my-group> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                "impact": "Escalate permissions for entire group",
                "mitigation": "Restrict group policy modifications"
            })

        # Path 6: iam:AttachRolePolicy + sts:AssumeRole
        if "iam:AttachRolePolicy" in permissions and "sts:AssumeRole" in permissions:
            paths.append({
                "id": "PE-6",
                "technique": "AttachRolePolicy + AssumeRole",
                "severity": "CRITICAL",
                "description": "Can attach policies to roles and assume them",
                "exploitation": "aws iam attach-role-policy --role-name <role> --policy-arn <admin-policy>\naws sts assume-role --role-arn <role-arn>",
                "impact": "Escalate via role assumption",
                "mitigation": "Separate AttachRolePolicy and AssumeRole permissions"
            })

        # Path 7: iam:PutUserPolicy
        if "iam:PutUserPolicy" in permissions:
            paths.append({
                "id": "PE-7",
                "technique": "PutUserPolicy",
                "severity": "CRITICAL",
                "description": "Can create inline policies on users",
                "exploitation": "aws iam put-user-policy --user-name <self> --policy-name Escalate --policy-document <admin-policy>",
                "impact": "Self-escalation via inline policy",
                "mitigation": "Use permission boundaries"
            })

        # Path 8: iam:PutGroupPolicy
        if "iam:PutGroupPolicy" in permissions:
            paths.append({
                "id": "PE-8",
                "technique": "PutGroupPolicy",
                "severity": "CRITICAL",
                "description": "Can create inline policies on groups",
                "exploitation": "aws iam put-group-policy --group-name <my-group> --policy-name Escalate --policy-document <admin-policy>",
                "impact": "Escalate permissions for group members",
                "mitigation": "Restrict group policy modifications"
            })

        # Path 9: iam:PutRolePolicy + sts:AssumeRole
        if "iam:PutRolePolicy" in permissions and "sts:AssumeRole" in permissions:
            paths.append({
                "id": "PE-9",
                "technique": "PutRolePolicy + AssumeRole",
                "severity": "CRITICAL",
                "description": "Can add inline policy to role and assume it",
                "exploitation": "aws iam put-role-policy --role-name <role> --policy-name Escalate --policy-document <admin-policy>",
                "impact": "Escalate via role modification",
                "mitigation": "Separate PutRolePolicy and AssumeRole permissions"
            })

        # Path 10: iam:AddUserToGroup
        if "iam:AddUserToGroup" in permissions:
            paths.append({
                "id": "PE-10",
                "technique": "AddUserToGroup",
                "severity": "HIGH",
                "description": "Can add users to privileged groups",
                "exploitation": "aws iam add-user-to-group --user-name <self> --group-name <admin-group>",
                "impact": "Inherit group permissions",
                "mitigation": "Restrict group membership changes"
            })

        # Path 11: iam:UpdateAssumeRolePolicy + sts:AssumeRole
        if "iam:UpdateAssumeRolePolicy" in permissions and "sts:AssumeRole" in permissions:
            paths.append({
                "id": "PE-11",
                "technique": "UpdateAssumeRolePolicy + AssumeRole",
                "severity": "CRITICAL",
                "description": "Can modify role trust policy to allow assumption",
                "exploitation": "aws iam update-assume-role-policy --role-name <admin-role> --policy-document <trust-self>",
                "impact": "Assume any role by modifying trust policy",
                "mitigation": "Separate trust policy and AssumeRole permissions"
            })

        # Path 12: iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
        if all(p in permissions for p in ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]):
            paths.append({
                "id": "PE-12",
                "technique": "PassRole + Lambda",
                "severity": "CRITICAL",
                "description": "Can create Lambda with privileged role and invoke it",
                "exploitation": "aws lambda create-function --function-name exploit --role <admin-role-arn> --code <malicious-code>\naws lambda invoke --function-name exploit",
                "impact": "Execute code with any IAM role's permissions",
                "mitigation": "Restrict PassRole to specific services"
            })

        # Path 13: iam:PassRole + ec2:RunInstances
        if "iam:PassRole" in permissions and "ec2:RunInstances" in permissions:
            paths.append({
                "id": "PE-13",
                "technique": "PassRole + EC2",
                "severity": "CRITICAL",
                "description": "Can launch EC2 with privileged instance profile",
                "exploitation": "aws ec2 run-instances --iam-instance-profile <admin-profile> --user-data <exfil-script>",
                "impact": "Execute code on EC2 with elevated permissions",
                "mitigation": "Restrict PassRole to specific roles"
            })

        # Path 14: iam:PassRole + glue:CreateDevEndpoint
        if "iam:PassRole" in permissions and "glue:CreateDevEndpoint" in permissions:
            paths.append({
                "id": "PE-14",
                "technique": "PassRole + Glue",
                "severity": "CRITICAL",
                "description": "Can create Glue dev endpoint with privileged role",
                "exploitation": "aws glue create-dev-endpoint --role-arn <admin-role-arn>",
                "impact": "SSH access to Glue endpoint with role permissions",
                "mitigation": "Restrict PassRole for Glue service"
            })

        # Path 15: iam:SetDefaultPolicyVersion
        if "iam:SetDefaultPolicyVersion" in permissions:
            paths.append({
                "id": "PE-15",
                "technique": "SetDefaultPolicyVersion",
                "severity": "HIGH",
                "description": "Can activate previous policy versions",
                "exploitation": "aws iam set-default-policy-version --policy-arn <policy> --version-id <old-permissive-version>",
                "impact": "Revert to more permissive policy version",
                "mitigation": "Delete old policy versions"
            })

        # Path 16: iam:PassRole + datapipeline:CreatePipeline
        if "iam:PassRole" in permissions and "datapipeline:CreatePipeline" in permissions:
            paths.append({
                "id": "PE-16",
                "technique": "PassRole + DataPipeline",
                "severity": "CRITICAL",
                "description": "Can create data pipeline with privileged role",
                "exploitation": "aws datapipeline create-pipeline --role <admin-role>",
                "impact": "Execute code via Data Pipeline with role permissions",
                "mitigation": "Restrict PassRole for DataPipeline"
            })

        # Path 17: iam:CreatePolicyVersion
        if "iam:CreatePolicyVersion" in permissions:
            paths.append({
                "id": "PE-17",
                "technique": "CreatePolicyVersion",
                "severity": "HIGH",
                "description": "Can create new policy version (up to 5 versions)",
                "exploitation": "aws iam create-policy-version --policy-arn <my-policy> --policy-document <admin-policy> --set-as-default",
                "impact": "Modify existing policies to gain permissions",
                "mitigation": "Restrict policy version creation"
            })

        # Path 18: cloudformation:CreateStack + iam:PassRole
        if "cloudformation:CreateStack" in permissions and "iam:PassRole" in permissions:
            paths.append({
                "id": "PE-18",
                "technique": "PassRole + CloudFormation",
                "severity": "CRITICAL",
                "description": "Can create CloudFormation stack with privileged role",
                "exploitation": "aws cloudformation create-stack --template-body <malicious-template> --role-arn <admin-role>",
                "impact": "Deploy infrastructure with admin permissions",
                "mitigation": "Restrict PassRole for CloudFormation"
            })

        # Path 19: iam:PassRole + codestar:CreateProject
        if "iam:PassRole" in permissions and "codestar:CreateProject" in permissions:
            paths.append({
                "id": "PE-19",
                "technique": "PassRole + CodeStar",
                "severity": "HIGH",
                "description": "Can create CodeStar project with toolchain role",
                "exploitation": "aws codestar create-project --toolchain-role-arn <privileged-role>",
                "impact": "CI/CD pipeline with elevated permissions",
                "mitigation": "Restrict PassRole for CodeStar"
            })

        # Path 20: sts:AssumeRole (without conditions)
        if "sts:AssumeRole" in permissions:
            paths.append({
                "id": "PE-20",
                "technique": "AssumeRole (unconstrained)",
                "severity": "HIGH",
                "description": "Can assume roles without resource restrictions",
                "exploitation": "aws sts assume-role --role-arn <any-role-that-trusts-me>",
                "impact": "Lateral movement to other roles",
                "mitigation": "Add resource-level conditions to AssumeRole"
            })

        # Path 21: iam:PassRole + sagemaker:CreateNotebookInstance
        if "iam:PassRole" in permissions and "sagemaker:CreateNotebookInstance" in permissions:
            paths.append({
                "id": "PE-21",
                "technique": "PassRole + SageMaker",
                "severity": "CRITICAL",
                "description": "Can create SageMaker notebook with privileged role",
                "exploitation": "aws sagemaker create-notebook-instance --role-arn <admin-role>",
                "impact": "Interactive Jupyter notebook with role permissions",
                "mitigation": "Restrict PassRole for SageMaker"
            })

        # Path 22: iam:PassRole + ecs:RegisterTaskDefinition + ecs:RunTask
        if all(p in permissions for p in ["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"]):
            paths.append({
                "id": "PE-22",
                "technique": "PassRole + ECS",
                "severity": "CRITICAL",
                "description": "Can run ECS task with privileged role",
                "exploitation": "aws ecs register-task-definition --task-role-arn <admin-role>\naws ecs run-task",
                "impact": "Container execution with role permissions",
                "mitigation": "Restrict PassRole for ECS"
            })

        # Path 23: iam:PassRole + ssm:SendCommand
        if "iam:PassRole" in permissions and "ssm:SendCommand" in permissions:
            paths.append({
                "id": "PE-23",
                "technique": "PassRole + SSM",
                "severity": "CRITICAL",
                "description": "Can execute commands on EC2 via SSM",
                "exploitation": "aws ssm send-command --document-name AWS-RunShellScript --parameters 'commands=[<malicious-cmd>]'",
                "impact": "Remote code execution on managed instances",
                "mitigation": "Restrict SSM SendCommand permissions"
            })

        # Path 24: secretsmanager:GetSecretValue
        if "secretsmanager:GetSecretValue" in permissions:
            paths.append({
                "id": "PE-24",
                "technique": "GetSecretValue",
                "severity": "HIGH",
                "description": "Can read secrets from Secrets Manager",
                "exploitation": "aws secretsmanager get-secret-value --secret-id <admin-credentials>",
                "impact": "Access to stored credentials and API keys",
                "mitigation": "Use resource-level restrictions on secrets"
            })

        # Path 25: ssm:GetParameter (with sensitive parameters)
        if "ssm:GetParameter" in permissions:
            paths.append({
                "id": "PE-25",
                "technique": "GetParameter",
                "severity": "HIGH",
                "description": "Can read parameters from Parameter Store",
                "exploitation": "aws ssm get-parameter --name <sensitive-param> --with-decryption",
                "impact": "Access to configuration secrets",
                "mitigation": "Use resource-level restrictions on parameters"
            })

        return paths

    def add_finding(self, severity: str, title: str, description: str):
        """Add security finding"""
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description
        })

    def enumerate_roles(self) -> List[Dict]:
        """
        Enumerate IAM roles

        Returns:
            List of role details
        """
        roles = []

        try:
            response = self._rate_limited_call(self.iam.list_roles)
            if response:
                for role in response.get('Roles', []):
                    role_info = {
                        'name': role['RoleName'],
                        'arn': role['Arn'],
                        'created': role['CreateDate'].isoformat(),
                        'path': role['Path'],
                        'max_session_duration': role.get('MaxSessionDuration', 3600)
                    }

                    # Try to get role policies
                    try:
                        policies_response = self._rate_limited_call(
                            self.iam.list_attached_role_policies,
                            RoleName=role['RoleName']
                        )
                        if policies_response:
                            role_info['attached_policies'] = [
                                p['PolicyArn'] for p in policies_response.get('AttachedPolicies', [])
                            ]
                    except ClientError:
                        pass

                    roles.append(role_info)

                print(f"{Fore.GREEN}[+] Found {len(roles)} role(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to enumerate roles: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return roles

    def enumerate_users(self) -> List[Dict]:
        """
        Enumerate IAM users

        Returns:
            List of user details
        """
        users = []

        try:
            response = self._rate_limited_call(self.iam.list_users)
            if response:
                for user in response.get('Users', []):
                    user_info = {
                        'name': user['UserName'],
                        'arn': user['Arn'],
                        'created': user['CreateDate'].isoformat(),
                        'path': user['Path']
                    }

                    # Check for access keys
                    try:
                        keys_response = self._rate_limited_call(
                            self.iam.list_access_keys,
                            UserName=user['UserName']
                        )
                        if keys_response:
                            user_info['access_keys'] = len(keys_response.get('AccessKeyMetadata', []))

                            # Flag users with multiple keys
                            if user_info['access_keys'] > 1:
                                self.add_finding(
                                    "MEDIUM",
                                    f"Multiple Access Keys: {user['UserName']}",
                                    f"User has {user_info['access_keys']} access keys (security risk)"
                                )
                    except ClientError:
                        pass

                    # Check for console access
                    try:
                        login_profile = self._rate_limited_call(
                            self.iam.get_login_profile,
                            UserName=user['UserName']
                        )
                        user_info['console_access'] = login_profile is not None
                    except ClientError:
                        user_info['console_access'] = False

                    # Check for MFA
                    try:
                        mfa_response = self._rate_limited_call(
                            self.iam.list_mfa_devices,
                            UserName=user['UserName']
                        )
                        mfa_devices = mfa_response.get('MFADevices', []) if mfa_response else []
                        user_info['mfa_enabled'] = len(mfa_devices) > 0

                        # Flag console users without MFA
                        if user_info.get('console_access') and not user_info['mfa_enabled']:
                            self.add_finding(
                                "HIGH",
                                f"No MFA: {user['UserName']}",
                                f"Console user without MFA enabled"
                            )
                    except ClientError:
                        user_info['mfa_enabled'] = False

                    users.append(user_info)

                print(f"{Fore.GREEN}[+] Found {len(users)} user(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to enumerate users: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return users

    def enumerate_policies(self, scope: str = 'Local') -> List[Dict]:
        """
        Enumerate IAM policies

        Args:
            scope: 'Local' for customer-managed, 'AWS' for AWS-managed, 'All' for both

        Returns:
            List of policy details
        """
        policies = []

        try:
            response = self._rate_limited_call(
                self.iam.list_policies,
                Scope=scope
            )

            if response:
                for policy in response.get('Policies', []):
                    policy_info = {
                        'name': policy['PolicyName'],
                        'arn': policy['Arn'],
                        'default_version': policy['DefaultVersionId'],
                        'attachment_count': policy['AttachmentCount'],
                        'created': policy['CreateDate'].isoformat()
                    }

                    # Flag overly permissive policies
                    if policy['AttachmentCount'] == 0:
                        self.add_finding(
                            "LOW",
                            f"Unused Policy: {policy['PolicyName']}",
                            "Policy is not attached to any entity (should be deleted)"
                        )

                    policies.append(policy_info)

                print(f"{Fore.GREEN}[+] Found {len(policies)} {scope.lower()} policies{Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to enumerate policies: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return policies

    def analyze_policy_permissions(self, policy_arn: str) -> Dict:
        """
        Analyze a policy's permissions for security issues

        Args:
            policy_arn: Policy ARN to analyze

        Returns:
            Analysis results
        """
        analysis = {
            'arn': policy_arn,
            'statements': [],
            'allows_all_resources': False,
            'allows_all_actions': False,
            'sensitive_actions': []
        }

        try:
            # Get policy
            policy = self._rate_limited_call(
                self.iam.get_policy,
                PolicyArn=policy_arn
            )

            if not policy:
                return analysis

            # Get policy version
            version = self._rate_limited_call(
                self.iam.get_policy_version,
                PolicyArn=policy_arn,
                VersionId=policy['Policy']['DefaultVersionId']
            )

            if not version:
                return analysis

            import json
            document = version['PolicyVersion']['Document']

            if isinstance(document, str):
                document = json.loads(document)

            # Analyze statements
            statements = document.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                if stmt.get('Effect') != 'Allow':
                    continue

                # Check for overly permissive resource
                resource = stmt.get('Resource', [])
                if resource == '*' or (isinstance(resource, list) and '*' in resource):
                    analysis['allows_all_resources'] = True

                # Check for overly permissive actions
                action = stmt.get('Action', [])
                if action == '*' or (isinstance(action, list) and '*' in action):
                    analysis['allows_all_actions'] = True

                # Check for sensitive actions
                sensitive_actions = [
                    'iam:*', 'iam:CreateUser', 'iam:CreateAccessKey', 'iam:AttachUserPolicy',
                    'iam:PutUserPolicy', 'iam:PassRole', 'sts:AssumeRole',
                    'secretsmanager:GetSecretValue', 'ssm:GetParameter'
                ]

                if isinstance(action, str):
                    action = [action]

                for act in action:
                    if any(sensitive in act for sensitive in sensitive_actions):
                        analysis['sensitive_actions'].append(act)

                analysis['statements'].append({
                    'effect': stmt.get('Effect'),
                    'actions': action,
                    'resources': resource
                })

            # Flag overly permissive policies
            if analysis['allows_all_resources'] and analysis['allows_all_actions']:
                self.add_finding(
                    "CRITICAL",
                    f"Wildcard Policy: {policy_arn}",
                    "Policy allows * actions on * resources (admin equivalent)"
                )

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to analyze policy: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return analysis

    def check_password_policy(self) -> Dict:
        """
        Check account password policy

        Returns:
            Password policy details and compliance
        """
        policy = {
            'exists': False,
            'compliant': False,
            'issues': []
        }

        try:
            response = self._rate_limited_call(self.iam.get_account_password_policy)

            if response:
                pwd_policy = response.get('PasswordPolicy', {})
                policy['exists'] = True
                policy['details'] = pwd_policy

                # Check for weak password requirements
                if pwd_policy.get('MinimumPasswordLength', 0) < 14:
                    policy['issues'].append("Minimum password length < 14")

                if not pwd_policy.get('RequireSymbols', False):
                    policy['issues'].append("Does not require symbols")

                if not pwd_policy.get('RequireNumbers', False):
                    policy['issues'].append("Does not require numbers")

                if not pwd_policy.get('RequireUppercaseCharacters', False):
                    policy['issues'].append("Does not require uppercase")

                if not pwd_policy.get('RequireLowercaseCharacters', False):
                    policy['issues'].append("Does not require lowercase")

                if not pwd_policy.get('ExpirePasswords', False):
                    policy['issues'].append("Passwords do not expire")

                if pwd_policy.get('MaxPasswordAge', 365) > 90:
                    policy['issues'].append(f"Password age too high ({pwd_policy['MaxPasswordAge']} days)")

                policy['compliant'] = len(policy['issues']) == 0

                if not policy['compliant']:
                    self.add_finding(
                        "MEDIUM",
                        "Weak Password Policy",
                        f"Account password policy does not meet best practices: {', '.join(policy['issues'])}"
                    )

                print(f"{Fore.GREEN}[+] Password policy configured{Style.RESET_ALL}")

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                policy['issues'].append("No password policy configured")
                self.add_finding(
                    "HIGH",
                    "No Password Policy",
                    "Account has no password policy configured"
                )
                print(f"{Fore.RED}[!] No password policy configured{Style.RESET_ALL}")

        return policy

    def check_root_account_usage(self) -> Dict:
        """
        Check for root account usage (requires CloudTrail access)

        Returns:
            Root account usage analysis
        """
        result = {
            'mfa_enabled': False,
            'access_keys': 0
        }

        try:
            # Check root MFA
            summary = self._rate_limited_call(self.iam.get_account_summary)

            if summary:
                account_mfa = summary.get('SummaryMap', {}).get('AccountMFAEnabled', 0)
                result['mfa_enabled'] = account_mfa == 1

                if not result['mfa_enabled']:
                    self.add_finding(
                        "CRITICAL",
                        "No Root MFA",
                        "Root account does not have MFA enabled"
                    )
                    print(f"{Fore.RED}[!] Root MFA not enabled{Style.RESET_ALL}")

                # Check for root access keys
                root_keys = summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)
                result['access_keys'] = root_keys

                if root_keys > 0:
                    self.add_finding(
                        "CRITICAL",
                        "Root Access Keys",
                        f"Root account has {root_keys} access key(s) (should be 0)"
                    )
                    print(f"{Fore.RED}[!] Root has {root_keys} access key(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check root usage: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return result


def main():
    """CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description='AWS IAM Privilege Escalation Tester')
    parser.add_argument('--rate-limit', type=float, default=1.0,
                        help='Seconds to wait between API calls (default: 1.0)')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='Maximum retries for throttled requests (default: 3)')

    args = parser.parse_args()

    tester = IAMTester(rate_limit=args.rate_limit, max_retries=args.max_retries)
    results = tester.enumerate_permissions()

    print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
    print(f"Permissions: {len(results['permissions'])}")
    print(f"Findings: {len(results['findings'])}")


if __name__ == "__main__":
    main()
