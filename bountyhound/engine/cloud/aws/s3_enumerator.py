"""
AWS S3 Bucket Enumerator
Find publicly accessible S3 buckets for a target domain
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Optional
from colorama import Fore, Style
import time
from engine.core.proxy_config import ProxyConfig
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.cloud.aws.rate_limiter import AWSRateLimiterMixin


class S3Enumerator(AWSRateLimiterMixin):
    """AWS S3 bucket enumeration and security testing"""

    def __init__(self, rate_limit: float = 1.0, max_retries: int = 3, proxy_config: ProxyConfig = None):
        """
        Initialize S3 bucket enumerator with rate limiting and proxy support.

        Args:
            rate_limit: Seconds to wait between requests (default: 1.0)
            max_retries: Maximum retries for throttled requests (default: 3)
            proxy_config: Proxy configuration (optional)
        """
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.proxy_config = proxy_config or ProxyConfig()
        self.findings = []
        self._last_request_time = None

        try:
            # Apply proxy configuration to boto3
            self.s3_client = boto3.client('s3', config=self.proxy_config.to_boto3_config())
            print(f"{Fore.GREEN}[+] S3 client initialized{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s between requests{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize S3 client: {e}{Style.RESET_ALL}")
            raise

    def enumerate_buckets(self, domain: str) -> List[Dict]:
        """
        Enumerate S3 buckets for a domain

        Args:
            domain: Target domain (e.g., example.com)

        Returns:
            List of findings
        """
        print(f"{Fore.CYAN}[*] Enumerating S3 buckets for: {domain}{Style.RESET_ALL}")

        # DATABASE CHECK - Prevent redundant testing
        print(f"{Fore.CYAN}[DATABASE] Checking history...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(domain, 's3_enumerator')

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
        db.record_tool_run(domain, 's3_enumerator', findings_count=len(results), success=True)
        print(f"{Fore.GREEN}[DATABASE] Recorded tool run: {len(results)} bucket(s) found{Style.RESET_ALL}")

        return results

    def _check_bucket_exists(self, bucket_name: str):
        """
        Check if bucket exists with rate limiting.
        Used for testing rate limiting behavior.
        """
        return self._rate_limited_call(self.s3_client.list_objects_v2, Bucket=bucket_name, MaxKeys=1)

    def generate_bucket_names(self, domain: str) -> List[str]:
        """Generate common bucket name patterns"""
        base = domain.replace('.com', '').replace('.', '-')

        patterns = [
            domain,
            base,
            f"{base}-backup",
            f"{base}-backups",
            f"{base}-prod",
            f"{base}-production",
            f"{base}-stage",
            f"{base}-staging",
            f"{base}-dev",
            f"{base}-development",
            f"{base}-test",
            f"{base}-assets",
            f"{base}-static",
            f"{base}-media",
            f"{base}-images",
            f"{base}-files",
            f"{base}-uploads",
            f"{base}-data",
            f"{base}-logs",
            f"{base}-www",
            f"www-{base}",
            f"{base}-webapp",
            f"{base}-api"
        ]

        return patterns

    def check_bucket(self, bucket_name: str) -> Optional[Dict]:
        """
        Check if bucket exists and is accessible

        Returns:
            Finding dict if vulnerable, None otherwise
        """
        try:
            # Try to list objects with rate limiting
            response = self._rate_limited_call(
                self.s3_client.list_objects_v2,
                Bucket=bucket_name,
                MaxKeys=10
            )

            if response is None:
                return None

            # Bucket is publicly listable!
            object_count = response.get('KeyCount', 0)

            print(f"{Fore.RED}[!] CRITICAL: {bucket_name} is PUBLICLY LISTABLE!{Style.RESET_ALL}")
            print(f"    Objects: {object_count}")

            finding = {
                "bucket": bucket_name,
                "severity": "CRITICAL",
                "status": "publicly_listable",
                "object_count": object_count,
                "description": f"S3 bucket {bucket_name} is publicly listable with {object_count} objects"
            }

            # Try to list some objects
            if 'Contents' in response:
                objects = [obj['Key'] for obj in response['Contents'][:5]]
                finding['sample_objects'] = objects
                print(f"    Sample objects: {objects}")

            return finding

        except ClientError as e:
            error_code = e.response['Error']['Code']

            if error_code == 'NoSuchBucket':
                # Bucket doesn't exist
                return None

            elif error_code == 'AccessDenied':
                # Bucket exists but is private
                print(f"{Fore.YELLOW}[+] {bucket_name} exists (private){Style.RESET_ALL}")

                return {
                    "bucket": bucket_name,
                    "severity": "INFO",
                    "status": "exists_private",
                    "description": f"Bucket exists but is properly secured"
                }

            else:
                print(f"{Fore.YELLOW}[!] {bucket_name}: {error_code}{Style.RESET_ALL}")
                return None

        except Exception as e:
            return None

    def check_bucket_permissions(self, bucket_name: str) -> Dict:
        """
        Comprehensive bucket security analysis

        Returns:
            Dict with security findings
        """
        findings = {
            "bucket": bucket_name,
            "public_acl": False,
            "public_policy": False,
            "versioning": None,
            "encryption": None,
            "logging": None,
            "lifecycle": None,
            "cors": None,
            "website": None,
            "replication": None,
            "public_access_block": None,
            "object_lock": None,
            "issues": []
        }

        try:
            # 1. Check bucket ACL
            acl = self._rate_limited_call(self.s3_client.get_bucket_acl, Bucket=bucket_name)
            if acl:
                for grant in acl['Grants']:
                    grantee = grant['Grantee']
                    permission = grant['Permission']

                    if grantee.get('Type') == 'Group':
                        uri = grantee.get('URI', '')
                        if 'AllUsers' in uri:
                            findings['public_acl'] = True
                            findings['issues'].append(f"PUBLIC ACL: {permission} granted to AllUsers")
                            print(f"{Fore.RED}[!] PUBLIC ACL: {permission} to AllUsers{Style.RESET_ALL}")
                        elif 'AuthenticatedUsers' in uri:
                            findings['issues'].append(f"AUTH USERS ACL: {permission} granted to AuthenticatedUsers")
                            print(f"{Fore.YELLOW}[!] AUTH USERS ACL: {permission}{Style.RESET_ALL}")

            # 2. Check bucket policy
            try:
                policy_response = self._rate_limited_call(self.s3_client.get_bucket_policy, Bucket=bucket_name)
                if policy_response:
                    import json
                    policy = json.loads(policy_response['Policy'])

                    # Check for public access in policy
                    for statement in policy.get('Statements', []):
                        principal = statement.get('Principal', {})
                        effect = statement.get('Effect', '')

                        if effect == 'Allow' and (principal == '*' or principal.get('AWS') == '*'):
                            findings['public_policy'] = True
                            findings['issues'].append("POLICY: Public access via bucket policy")
                            print(f"{Fore.RED}[!] PUBLIC POLICY detected{Style.RESET_ALL}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    pass

            # 3. Check versioning
            try:
                versioning = self._rate_limited_call(self.s3_client.get_bucket_versioning, Bucket=bucket_name)
                if versioning:
                    status = versioning.get('Status', 'Disabled')
                    findings['versioning'] = status
                    if status != 'Enabled':
                        findings['issues'].append("VERSIONING: Not enabled (data loss risk)")
                        print(f"{Fore.YELLOW}[*] Versioning: {status}{Style.RESET_ALL}")
            except ClientError:
                findings['versioning'] = 'Error'

            # 4. Check encryption
            try:
                encryption = self._rate_limited_call(self.s3_client.get_bucket_encryption, Bucket=bucket_name)
                if encryption:
                    rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                    if rules:
                        sse_algorithm = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', 'Unknown')
                        findings['encryption'] = sse_algorithm
                        print(f"{Fore.GREEN}[+] Encryption: {sse_algorithm}{Style.RESET_ALL}")
                    else:
                        findings['encryption'] = 'None'
                        findings['issues'].append("ENCRYPTION: Not configured")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    findings['encryption'] = 'None'
                    findings['issues'].append("ENCRYPTION: Not enabled")
                    print(f"{Fore.RED}[!] No encryption configured{Style.RESET_ALL}")

            # 5. Check logging
            try:
                logging = self._rate_limited_call(self.s3_client.get_bucket_logging, Bucket=bucket_name)
                if logging and logging.get('LoggingEnabled'):
                    findings['logging'] = True
                    print(f"{Fore.GREEN}[+] Logging enabled{Style.RESET_ALL}")
                else:
                    findings['logging'] = False
                    findings['issues'].append("LOGGING: Not enabled (no audit trail)")
            except ClientError:
                findings['logging'] = False

            # 6. Check lifecycle policies
            try:
                lifecycle = self._rate_limited_call(self.s3_client.get_bucket_lifecycle_configuration, Bucket=bucket_name)
                if lifecycle and lifecycle.get('Rules'):
                    findings['lifecycle'] = len(lifecycle['Rules'])
                    print(f"{Fore.GREEN}[+] Lifecycle: {findings['lifecycle']} rule(s){Style.RESET_ALL}")
                else:
                    findings['lifecycle'] = 0
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                    findings['lifecycle'] = 0

            # 7. Check CORS configuration
            try:
                cors = self._rate_limited_call(self.s3_client.get_bucket_cors, Bucket=bucket_name)
                if cors and cors.get('CORSRules'):
                    findings['cors'] = len(cors['CORSRules'])

                    # Check for overly permissive CORS
                    for rule in cors['CORSRules']:
                        allowed_origins = rule.get('AllowedOrigins', [])
                        if '*' in allowed_origins:
                            findings['issues'].append("CORS: Allows all origins (*)")
                            print(f"{Fore.YELLOW}[!] CORS: Allows all origins{Style.RESET_ALL}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchCORSConfiguration':
                    findings['cors'] = 0

            # 8. Check website configuration
            try:
                website = self._rate_limited_call(self.s3_client.get_bucket_website, Bucket=bucket_name)
                if website:
                    findings['website'] = True
                    print(f"{Fore.CYAN}[*] Website hosting enabled{Style.RESET_ALL}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchWebsiteConfiguration':
                    findings['website'] = False

            # 9. Check replication
            try:
                replication = self._rate_limited_call(self.s3_client.get_bucket_replication, Bucket=bucket_name)
                if replication and replication.get('ReplicationConfiguration'):
                    findings['replication'] = True
                    print(f"{Fore.GREEN}[+] Replication configured{Style.RESET_ALL}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ReplicationConfigurationNotFoundError':
                    findings['replication'] = False

            # 10. Check Public Access Block
            try:
                pab = self._rate_limited_call(self.s3_client.get_public_access_block, Bucket=bucket_name)
                if pab:
                    config = pab.get('PublicAccessBlockConfiguration', {})
                    findings['public_access_block'] = config

                    # Check if all protections are enabled
                    all_blocked = all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ])

                    if not all_blocked:
                        findings['issues'].append("PUBLIC ACCESS BLOCK: Not fully enabled")
                        print(f"{Fore.YELLOW}[!] Public Access Block not fully enabled{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}[+] Public Access Block fully enabled{Style.RESET_ALL}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    findings['public_access_block'] = None
                    findings['issues'].append("PUBLIC ACCESS BLOCK: Not configured")

            # 11. Check Object Lock
            try:
                lock = self._rate_limited_call(self.s3_client.get_object_lock_configuration, Bucket=bucket_name)
                if lock and lock.get('ObjectLockConfiguration', {}).get('ObjectLockEnabled') == 'Enabled':
                    findings['object_lock'] = True
                    print(f"{Fore.GREEN}[+] Object Lock enabled{Style.RESET_ALL}")
                else:
                    findings['object_lock'] = False
            except ClientError as e:
                if e.response['Error']['Code'] == 'ObjectLockConfigurationNotFoundError':
                    findings['object_lock'] = False

        except ClientError as e:
            findings['issues'].append(f"ERROR: {e.response['Error']['Code']}")

        return findings

    def test_bucket_write_permissions(self, bucket_name: str) -> Dict:
        """
        Test if bucket allows write operations (non-destructive)

        Returns:
            Dict with write test results
        """
        result = {
            "bucket": bucket_name,
            "can_upload": False,
            "can_delete": False,
            "test_performed": False
        }

        # WARNING: This is a destructive test - only enable if explicitly requested
        # For now, just check ACL permissions
        print(f"{Fore.CYAN}[*] Write test skipped (destructive){Style.RESET_ALL}")

        return result

    def enumerate_objects(self, bucket_name: str, max_keys: int = 100) -> List[Dict]:
        """
        Enumerate objects in a bucket

        Args:
            bucket_name: Bucket name
            max_keys: Maximum objects to retrieve

        Returns:
            List of object details
        """
        objects = []

        try:
            response = self._rate_limited_call(
                self.s3_client.list_objects_v2,
                Bucket=bucket_name,
                MaxKeys=max_keys
            )

            if response and 'Contents' in response:
                for obj in response['Contents']:
                    objects.append({
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'].isoformat(),
                        'storage_class': obj.get('StorageClass', 'STANDARD')
                    })

                print(f"{Fore.GREEN}[+] Found {len(objects)} object(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[!] Failed to enumerate objects: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return objects

    def check_object_permissions(self, bucket_name: str, object_key: str) -> Dict:
        """
        Check permissions on a specific object

        Args:
            bucket_name: Bucket name
            object_key: Object key

        Returns:
            Dict with object ACL details
        """
        result = {
            "bucket": bucket_name,
            "key": object_key,
            "public_read": False,
            "public_write": False
        }

        try:
            acl = self._rate_limited_call(
                self.s3_client.get_object_acl,
                Bucket=bucket_name,
                Key=object_key
            )

            if acl:
                for grant in acl['Grants']:
                    grantee = grant['Grantee']
                    permission = grant['Permission']

                    if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                        if permission in ['READ', 'FULL_CONTROL']:
                            result['public_read'] = True
                        if permission in ['WRITE', 'FULL_CONTROL']:
                            result['public_write'] = True

                if result['public_read'] or result['public_write']:
                    print(f"{Fore.RED}[!] Object has public ACL: {object_key}{Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.YELLOW}[*] Failed to get object ACL: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return result

    def analyze_bucket_security(self, bucket_name: str) -> Dict:
        """
        Comprehensive security analysis of a bucket

        Combines all checks into a single security assessment

        Returns:
            Comprehensive security report
        """
        print(f"{Fore.CYAN}[*] Analyzing bucket security: {bucket_name}{Style.RESET_ALL}")

        report = {
            "bucket": bucket_name,
            "severity": "INFO",
            "permissions": {},
            "objects": [],
            "vulnerabilities": [],
            "recommendations": []
        }

        # Run all checks
        permissions = self.check_bucket_permissions(bucket_name)
        report['permissions'] = permissions

        # Determine severity based on findings
        if permissions.get('public_acl') or permissions.get('public_policy'):
            report['severity'] = "CRITICAL"
            report['vulnerabilities'].append("Bucket is publicly accessible")

        if permissions.get('encryption') in [None, 'None']:
            if report['severity'] == "INFO":
                report['severity'] = "MEDIUM"
            report['vulnerabilities'].append("No encryption configured")
            report['recommendations'].append("Enable server-side encryption")

        if not permissions.get('logging'):
            report['recommendations'].append("Enable access logging")

        if permissions.get('versioning') != 'Enabled':
            report['recommendations'].append("Enable versioning for data protection")

        # Try to enumerate objects if accessible
        try:
            objects = self.enumerate_objects(bucket_name, max_keys=10)
            report['objects'] = objects[:5]  # Store first 5 as sample

            # Check permissions on first object
            if objects:
                obj_perm = self.check_object_permissions(bucket_name, objects[0]['key'])
                if obj_perm.get('public_read'):
                    report['vulnerabilities'].append("Objects are publicly readable")

        except Exception:
            pass

        print(f"{Fore.CYAN}[*] Analysis complete: {report['severity']}{Style.RESET_ALL}")

        return report


def main():
    """CLI interface"""
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='AWS S3 Bucket Enumerator')
    parser.add_argument('domain', help='Target domain (e.g., example.com)')
    parser.add_argument('--rate-limit', type=float, default=1.0,
                        help='Seconds to wait between requests (default: 1.0)')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='Maximum retries for throttled requests (default: 3)')
    parser.add_argument('--proxy', help='HTTP/HTTPS/SOCKS proxy URL')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')

    args = parser.parse_args()

    proxy_config = ProxyConfig(
        http_proxy=args.proxy,
        https_proxy=args.proxy,
        verify_ssl=not args.no_verify_ssl
    )

    enumerator = S3Enumerator(
        rate_limit=args.rate_limit,
        max_retries=args.max_retries,
        proxy_config=proxy_config
    )
    findings = enumerator.enumerate_buckets(args.domain)

    print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
    print(f"Total findings: {len(findings)}")

    critical = [f for f in findings if f['severity'] == 'CRITICAL']
    if critical:
        print(f"{Fore.RED}CRITICAL issues: {len(critical)}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
