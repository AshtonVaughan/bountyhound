"""
AWS RDS Security Analyzer
Test RDS instances for security misconfigurations
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Optional
from colorama import Fore, Style
import time

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class RDSAnalyzer:
    """
    Analyze RDS instances for security vulnerabilities
    """

    def __init__(self, rate_limit: float = 1.0, max_retries: int = 3, target: Optional[str] = None, region: str = 'us-east-1'):
        """
        Initialize RDS analyzer

        Args:
            rate_limit: Seconds to wait between API calls
            max_retries: Maximum retries for throttled requests
            target: Target identifier for database tracking
            region: AWS region to scan
        """
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.target = target
        self.region = region
        self._last_request_time = None

        try:
            self.rds = boto3.client('rds', region_name=region)
            self.sts = boto3.client('sts')

            print(f"{Fore.GREEN}[+] RDS client initialized (region: {region}){Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s between requests{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize RDS client: {e}{Style.RESET_ALL}")
            raise

        self.findings = []

    def _rate_limited_call(self, func, *args, **kwargs):
        """Execute a function with rate limiting"""
        for attempt in range(self.max_retries):
            try:
                if attempt > 0:
                    backoff_time = min(2 ** attempt, 30)
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

                if error_code in ['429', 'ThrottlingException', 'RequestLimitExceeded']:
                    if attempt < self.max_retries - 1:
                        continue
                    else:
                        return None

                return None

        return None

    def enumerate_db_instances(self) -> List[Dict]:
        """
        Enumerate all RDS instances

        Returns:
            List of DB instance details
        """
        # Get AWS account ID
        identity = self.sts.get_caller_identity()
        if not self.target and identity:
            self.target = f"aws-{identity.get('Account', 'unknown')}"

        # Database check
        if self.target:
            print(f"{Fore.CYAN}[DATABASE] Checking history...{Style.RESET_ALL}")
            context = DatabaseHooks.before_test(self.target, 'rds_analyzer')

            if context['should_skip']:
                print(f"{Fore.YELLOW}⚠️  SKIP: {context['reason']}{Style.RESET_ALL}")
                return []
            else:
                print(f"{Fore.GREEN}✓ {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Enumerating RDS instances in {self.region}...{Style.RESET_ALL}")

        instances = []

        try:
            response = self._rate_limited_call(self.rds.describe_db_instances)

            if response:
                for db in response.get('DBInstances', []):
                    instance_info = {
                        'id': db['DBInstanceIdentifier'],
                        'engine': db.get('Engine', 'unknown'),
                        'engine_version': db.get('EngineVersion', 'unknown'),
                        'class': db.get('DBInstanceClass', 'unknown'),
                        'status': db.get('DBInstanceStatus', 'unknown'),
                        'public': db.get('PubliclyAccessible', False),
                        'encrypted': db.get('StorageEncrypted', False),
                        'multi_az': db.get('MultiAZ', False),
                        'endpoint': None,
                        'port': db.get('Endpoint', {}).get('Port') if db.get('Endpoint') else None,
                        'vpc_id': None,
                        'security_groups': []
                    }

                    # Get endpoint info
                    if db.get('Endpoint'):
                        instance_info['endpoint'] = db['Endpoint'].get('Address')

                    # Get VPC info
                    if db.get('DBSubnetGroup'):
                        instance_info['vpc_id'] = db['DBSubnetGroup'].get('VpcId')

                    # Get security groups
                    for sg in db.get('VpcSecurityGroups', []):
                        instance_info['security_groups'].append(sg.get('VpcSecurityGroupId'))

                    # Security checks
                    if instance_info['public']:
                        self.add_finding(
                            "CRITICAL",
                            f"Public RDS: {db['DBInstanceIdentifier']}",
                            f"{instance_info['engine']} instance is publicly accessible"
                        )
                        print(f"{Fore.RED}[!] PUBLIC RDS: {db['DBInstanceIdentifier']}{Style.RESET_ALL}")

                    if not instance_info['encrypted']:
                        self.add_finding(
                            "HIGH",
                            f"Unencrypted RDS: {db['DBInstanceIdentifier']}",
                            f"{instance_info['engine']} instance is not encrypted"
                        )

                    if not instance_info['multi_az']:
                        self.add_finding(
                            "LOW",
                            f"No Multi-AZ: {db['DBInstanceIdentifier']}",
                            "Instance is not configured for Multi-AZ (availability risk)"
                        )

                    # Check for outdated engine versions
                    self._check_engine_version(db['DBInstanceIdentifier'], instance_info['engine'], instance_info['engine_version'])

                    instances.append(instance_info)

                print(f"{Fore.GREEN}[+] Found {len(instances)} DB instance(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to enumerate instances: {e.response['Error']['Code']}{Style.RESET_ALL}")

        # Record tool run
        if self.target:
            db = BountyHoundDB()
            db.record_tool_run(
                self.target,
                'rds_analyzer',
                findings_count=len(self.findings),
                success=True
            )

        return instances

    def _check_engine_version(self, instance_id: str, engine: str, version: str):
        """
        Check if database engine version is outdated

        Args:
            instance_id: Instance identifier
            engine: Database engine
            version: Current version
        """
        # Known outdated versions (not exhaustive)
        outdated_versions = {
            'postgres': ['9.6', '10', '11'],
            'mysql': ['5.5', '5.6', '5.7'],
            'mariadb': ['10.0', '10.1', '10.2', '10.3'],
            'oracle-ee': ['11.2', '12.1'],
            'sqlserver-ex': ['2012', '2014', '2016']
        }

        for eng, old_versions in outdated_versions.items():
            if eng in engine.lower():
                for old_ver in old_versions:
                    if version.startswith(old_ver):
                        self.add_finding(
                            "MEDIUM",
                            f"Outdated DB Version: {instance_id}",
                            f"{engine} {version} is outdated (security patches missing)"
                        )
                        print(f"{Fore.YELLOW}[!] Outdated version: {engine} {version}{Style.RESET_ALL}")
                        return

    def check_db_snapshots(self) -> List[Dict]:
        """
        Check RDS snapshots for public exposure

        Returns:
            List of snapshot details
        """
        print(f"{Fore.CYAN}[*] Checking DB snapshots...{Style.RESET_ALL}")

        snapshots = []

        try:
            response = self._rate_limited_call(self.rds.describe_db_snapshots)

            if response:
                for snap in response.get('DBSnapshots', []):
                    snapshot_info = {
                        'id': snap['DBSnapshotIdentifier'],
                        'instance_id': snap.get('DBInstanceIdentifier'),
                        'status': snap.get('Status'),
                        'encrypted': snap.get('Encrypted', False),
                        'public': False
                    }

                    # Check if snapshot is public
                    try:
                        attrs = self._rate_limited_call(
                            self.rds.describe_db_snapshot_attributes,
                            DBSnapshotIdentifier=snap['DBSnapshotIdentifier']
                        )

                        if attrs:
                            for attr in attrs.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', []):
                                if attr.get('AttributeName') == 'restore':
                                    values = attr.get('AttributeValues', [])
                                    if 'all' in values:
                                        snapshot_info['public'] = True

                                        self.add_finding(
                                            "CRITICAL",
                                            f"Public Snapshot: {snap['DBSnapshotIdentifier']}",
                                            "RDS snapshot is publicly restorable"
                                        )

                                        print(f"{Fore.RED}[!] PUBLIC SNAPSHOT: {snap['DBSnapshotIdentifier']}{Style.RESET_ALL}")

                    except ClientError:
                        pass

                    if not snapshot_info['encrypted']:
                        self.add_finding(
                            "HIGH",
                            f"Unencrypted Snapshot: {snap['DBSnapshotIdentifier']}",
                            "Snapshot is not encrypted"
                        )

                    snapshots.append(snapshot_info)

                print(f"{Fore.GREEN}[+] Found {len(snapshots)} snapshot(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check snapshots: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return snapshots

    def check_db_parameter_groups(self) -> List[Dict]:
        """
        Check DB parameter groups for insecure settings

        Returns:
            List of parameter group analyses
        """
        print(f"{Fore.CYAN}[*] Checking DB parameter groups...{Style.RESET_ALL}")

        groups = []

        try:
            response = self._rate_limited_call(self.rds.describe_db_parameter_groups)

            if response:
                for pg in response.get('DBParameterGroups', []):
                    group_info = {
                        'name': pg['DBParameterGroupName'],
                        'family': pg.get('DBParameterGroupFamily', 'unknown'),
                        'description': pg.get('Description', ''),
                        'issues': []
                    }

                    # Get parameters
                    params_response = self._rate_limited_call(
                        self.rds.describe_db_parameters,
                        DBParameterGroupName=pg['DBParameterGroupName']
                    )

                    if params_response:
                        parameters = params_response.get('Parameters', [])

                        # Check for insecure settings
                        for param in parameters:
                            param_name = param.get('ParameterName', '')
                            param_value = param.get('ParameterValue', '')

                            # PostgreSQL specific checks
                            if 'log_statement' in param_name and param_value != 'all':
                                group_info['issues'].append(f"AUDIT: log_statement={param_value} (should be 'all')")

                            if 'ssl' in param_name and param_value == '0':
                                group_info['issues'].append(f"ENCRYPTION: {param_name} disabled")

                            # MySQL specific checks
                            if param_name == 'require_secure_transport' and param_value != '1':
                                group_info['issues'].append("ENCRYPTION: require_secure_transport disabled")

                        if group_info['issues']:
                            self.add_finding(
                                "MEDIUM",
                                f"Insecure Params: {pg['DBParameterGroupName']}",
                                f"Parameter group has security issues: {', '.join(group_info['issues'][:3])}"
                            )

                    groups.append(group_info)

                print(f"{Fore.GREEN}[+] Analyzed {len(groups)} parameter group(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check parameter groups: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return groups

    def check_db_clusters(self) -> List[Dict]:
        """
        Check Aurora/RDS clusters

        Returns:
            List of cluster details
        """
        print(f"{Fore.CYAN}[*] Checking DB clusters...{Style.RESET_ALL}")

        clusters = []

        try:
            response = self._rate_limited_call(self.rds.describe_db_clusters)

            if response:
                for cluster in response.get('DBClusters', []):
                    cluster_info = {
                        'id': cluster['DBClusterIdentifier'],
                        'engine': cluster.get('Engine', 'unknown'),
                        'engine_version': cluster.get('EngineVersion', 'unknown'),
                        'status': cluster.get('Status', 'unknown'),
                        'encrypted': cluster.get('StorageEncrypted', False),
                        'multi_az': cluster.get('MultiAZ', False),
                        'endpoint': cluster.get('Endpoint'),
                        'backup_retention': cluster.get('BackupRetentionPeriod', 0)
                    }

                    # Security checks
                    if not cluster_info['encrypted']:
                        self.add_finding(
                            "HIGH",
                            f"Unencrypted Cluster: {cluster['DBClusterIdentifier']}",
                            f"Aurora cluster is not encrypted"
                        )

                    if cluster_info['backup_retention'] < 7:
                        self.add_finding(
                            "LOW",
                            f"Short Backup Retention: {cluster['DBClusterIdentifier']}",
                            f"Backup retention is {cluster_info['backup_retention']} days (recommend >= 7)"
                        )

                    # Check for deletion protection
                    if not cluster.get('DeletionProtection', False):
                        self.add_finding(
                            "MEDIUM",
                            f"No Deletion Protection: {cluster['DBClusterIdentifier']}",
                            "Cluster can be accidentally deleted"
                        )

                    clusters.append(cluster_info)

                print(f"{Fore.GREEN}[+] Found {len(clusters)} cluster(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check clusters: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return clusters

    def check_db_event_subscriptions(self) -> List[Dict]:
        """
        Check for event notification subscriptions

        Returns:
            List of event subscriptions
        """
        print(f"{Fore.CYAN}[*] Checking event subscriptions...{Style.RESET_ALL}")

        subscriptions = []

        try:
            response = self._rate_limited_call(self.rds.describe_event_subscriptions)

            if response:
                subscriptions = response.get('EventSubscriptionsList', [])

                if not subscriptions:
                    self.add_finding(
                        "LOW",
                        "No Event Subscriptions",
                        "No RDS event notifications configured (monitoring gap)"
                    )
                    print(f"{Fore.YELLOW}[!] No event subscriptions configured{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Found {len(subscriptions)} subscription(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check subscriptions: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return subscriptions

    def check_db_option_groups(self) -> List[Dict]:
        """
        Check DB option groups for security features

        Returns:
            List of option group details
        """
        print(f"{Fore.CYAN}[*] Checking option groups...{Style.RESET_ALL}")

        groups = []

        try:
            response = self._rate_limited_call(self.rds.describe_option_groups)

            if response:
                for og in response.get('OptionGroupsList', []):
                    group_info = {
                        'name': og['OptionGroupName'],
                        'engine': og.get('EngineName', 'unknown'),
                        'options': []
                    }

                    for option in og.get('Options', []):
                        group_info['options'].append({
                            'name': option.get('OptionName'),
                            'description': option.get('OptionDescription', '')
                        })

                    groups.append(group_info)

                print(f"{Fore.GREEN}[+] Found {len(groups)} option group(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check option groups: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return groups

    def check_automated_backups(self) -> List[Dict]:
        """
        Check automated backup configuration

        Returns:
            List of backup details
        """
        print(f"{Fore.CYAN}[*] Checking automated backups...{Style.RESET_ALL}")

        # This info is already in DB instances, just summarize
        try:
            response = self._rate_limited_call(self.rds.describe_db_instances)

            if response:
                backup_summary = []

                for db in response.get('DBInstances', []):
                    retention = db.get('BackupRetentionPeriod', 0)

                    if retention == 0:
                        self.add_finding(
                            "HIGH",
                            f"No Backups: {db['DBInstanceIdentifier']}",
                            "Automated backups are disabled (data loss risk)"
                        )
                        print(f"{Fore.RED}[!] No backups: {db['DBInstanceIdentifier']}{Style.RESET_ALL}")

                    elif retention < 7:
                        self.add_finding(
                            "MEDIUM",
                            f"Short Retention: {db['DBInstanceIdentifier']}",
                            f"Backup retention {retention} days (recommend >= 7)"
                        )

                    backup_summary.append({
                        'instance': db['DBInstanceIdentifier'],
                        'retention_days': retention,
                        'window': db.get('PreferredBackupWindow', 'N/A')
                    })

                print(f"{Fore.GREEN}[+] Checked {len(backup_summary)} instance(s){Style.RESET_ALL}")

                return backup_summary

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check backups: {e.response['Error']['Code']}{Style.RESET_ALL}")

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

    parser = argparse.ArgumentParser(description='AWS RDS Security Analyzer')
    parser.add_argument('--rate-limit', type=float, default=1.0,
                        help='Seconds to wait between API calls (default: 1.0)')
    parser.add_argument('--region', default='us-east-1',
                        help='AWS region to scan (default: us-east-1)')

    args = parser.parse_args()

    analyzer = RDSAnalyzer(rate_limit=args.rate_limit, region=args.region)

    # Run all checks
    instances = analyzer.enumerate_db_instances()
    snapshots = analyzer.check_db_snapshots()
    param_groups = analyzer.check_db_parameter_groups()
    clusters = analyzer.check_db_clusters()
    subscriptions = analyzer.check_db_event_subscriptions()
    option_groups = analyzer.check_db_option_groups()
    backups = analyzer.check_automated_backups()

    print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
    print(f"DB Instances: {len(instances)}")
    print(f"Snapshots: {len(snapshots)}")
    print(f"Parameter Groups: {len(param_groups)}")
    print(f"Clusters: {len(clusters)}")
    print(f"Event Subscriptions: {len(subscriptions)}")
    print(f"Option Groups: {len(option_groups)}")
    print(f"Total Findings: {len(analyzer.findings)}")


if __name__ == "__main__":
    main()
