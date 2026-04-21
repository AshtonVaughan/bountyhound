"""
AWS EC2 Security Scanner
Test EC2 instances, security groups, and related resources for misconfigurations
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


class EC2Scanner(AWSRateLimiterMixin):
    """
    Scan EC2 instances and security groups for vulnerabilities
    """

    def __init__(self, rate_limit: float = 1.0, max_retries: int = 3, target: Optional[str] = None, region: str = 'us-east-1'):
        """
        Initialize EC2 scanner

        Args:
            rate_limit: Seconds to wait between API calls
            max_retries: Maximum retries for throttled requests
            target: Target identifier for database tracking
            region: AWS region to scan (default: us-east-1)
        """
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.target = target
        self.region = region
        self._last_request_time = None

        try:
            self.ec2 = boto3.client('ec2', region_name=region)
            self.sts = boto3.client('sts')

            print(f"{Fore.GREEN}[+] EC2 client initialized (region: {region}){Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit}s between requests{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize EC2 client: {e}{Style.RESET_ALL}")
            raise

        self.findings = []

    def enumerate_instances(self) -> List[Dict]:
        """
        Enumerate all EC2 instances

        Returns:
            List of instance details
        """
        # Get AWS account ID for database tracking
        identity = self.sts.get_caller_identity()
        if not self.target and identity:
            self.target = f"aws-{identity.get('Account', 'unknown')}"

        # Database check
        if self.target:
            print(f"{Fore.CYAN}[DATABASE] Checking history...{Style.RESET_ALL}")
            context = DatabaseHooks.before_test(self.target, 'ec2_scanner')

            if context['should_skip']:
                print(f"{Fore.YELLOW}⚠️  SKIP: {context['reason']}{Style.RESET_ALL}")
                return []
            else:
                print(f"{Fore.GREEN}✓ {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Enumerating EC2 instances in {self.region}...{Style.RESET_ALL}")

        instances = []

        try:
            response = self._rate_limited_call(self.ec2.describe_instances)

            if response:
                for reservation in response.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        inst_info = {
                            'id': instance['InstanceId'],
                            'type': instance.get('InstanceType', 'unknown'),
                            'state': instance.get('State', {}).get('Name', 'unknown'),
                            'public_ip': instance.get('PublicIpAddress'),
                            'private_ip': instance.get('PrivateIpAddress'),
                            'vpc_id': instance.get('VpcId'),
                            'subnet_id': instance.get('SubnetId'),
                            'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                            'iam_role': instance.get('IamInstanceProfile', {}).get('Arn'),
                            'monitoring': instance.get('Monitoring', {}).get('State', 'disabled')
                        }

                        # Check for public IP
                        if inst_info['public_ip']:
                            self.add_finding(
                                "MEDIUM",
                                f"Public IP: {instance['InstanceId']}",
                                f"Instance has public IP {inst_info['public_ip']}"
                            )

                        # Check for detailed monitoring
                        if inst_info['monitoring'] != 'enabled':
                            self.add_finding(
                                "LOW",
                                f"No Detailed Monitoring: {instance['InstanceId']}",
                                "Detailed monitoring not enabled"
                            )

                        instances.append(inst_info)

                print(f"{Fore.GREEN}[+] Found {len(instances)} instance(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to enumerate instances: {e.response['Error']['Code']}{Style.RESET_ALL}")

        # Record tool run
        if self.target:
            db = BountyHoundDB()
            db.record_tool_run(
                self.target,
                'ec2_scanner',
                findings_count=len(self.findings),
                success=True
            )

        return instances

    def check_security_groups(self) -> List[Dict]:
        """
        Enumerate and analyze security groups for misconfigurations

        Returns:
            List of security group analyses
        """
        print(f"{Fore.CYAN}[*] Analyzing security groups...{Style.RESET_ALL}")

        groups = []

        try:
            response = self._rate_limited_call(self.ec2.describe_security_groups)

            if response:
                for sg in response.get('SecurityGroups', []):
                    group_info = {
                        'id': sg['GroupId'],
                        'name': sg['GroupName'],
                        'description': sg.get('Description', ''),
                        'vpc_id': sg.get('VpcId'),
                        'ingress_rules': [],
                        'egress_rules': [],
                        'issues': []
                    }

                    # Analyze ingress rules
                    for rule in sg.get('IpPermissions', []):
                        rule_info = self._parse_rule(rule)
                        group_info['ingress_rules'].append(rule_info)

                        # Check for dangerous ingress rules
                        if rule_info['from_port'] == 0 and rule_info['to_port'] == 65535:
                            group_info['issues'].append("CRITICAL: Allows ALL ports")

                        if rule_info['source'] == '0.0.0.0/0':
                            # Check for common dangerous ports
                            dangerous_ports = {
                                22: 'SSH',
                                3389: 'RDP',
                                3306: 'MySQL',
                                5432: 'PostgreSQL',
                                27017: 'MongoDB',
                                6379: 'Redis',
                                9200: 'Elasticsearch',
                                5984: 'CouchDB'
                            }

                            from_port = rule_info['from_port']
                            to_port = rule_info['to_port']

                            for port, service in dangerous_ports.items():
                                if from_port <= port <= to_port:
                                    group_info['issues'].append(f"CRITICAL: {service} ({port}) open to 0.0.0.0/0")

                                    self.add_finding(
                                        "CRITICAL",
                                        f"Public {service}: {sg['GroupId']}",
                                        f"{service} port {port} is publicly accessible"
                                    )

                            # Generic warning for any public access
                            if not group_info['issues']:
                                group_info['issues'].append(f"HIGH: Ports {from_port}-{to_port} open to 0.0.0.0/0")

                    # Analyze egress rules
                    for rule in sg.get('IpPermissionsEgress', []):
                        rule_info = self._parse_rule(rule)
                        group_info['egress_rules'].append(rule_info)

                        # Check for unrestricted egress
                        if rule_info['source'] == '0.0.0.0/0' and rule_info['from_port'] == 0:
                            group_info['issues'].append("INFO: Unrestricted egress (common)")

                    groups.append(group_info)

                print(f"{Fore.GREEN}[+] Analyzed {len(groups)} security group(s){Style.RESET_ALL}")

                # Count vulnerable groups
                vulnerable = [g for g in groups if g['issues']]
                if vulnerable:
                    print(f"{Fore.RED}[!] {len(vulnerable)} group(s) have security issues{Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check security groups: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return groups

    def _parse_rule(self, rule: Dict) -> Dict:
        """
        Parse a security group rule

        Args:
            rule: Raw rule from AWS API

        Returns:
            Parsed rule information
        """
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 65535)
        protocol = rule.get('IpProtocol', '-1')

        # Get source (IP ranges or security groups)
        sources = []

        for ip_range in rule.get('IpRanges', []):
            sources.append(ip_range.get('CidrIp', ''))

        for ip_range in rule.get('Ipv6Ranges', []):
            sources.append(ip_range.get('CidrIpv6', ''))

        for sg_ref in rule.get('UserIdGroupPairs', []):
            sources.append(f"sg:{sg_ref.get('GroupId', '')}")

        source = ', '.join(sources) if sources else 'N/A'

        return {
            'from_port': from_port,
            'to_port': to_port,
            'protocol': protocol,
            'source': source
        }

    def check_snapshots(self) -> List[Dict]:
        """
        Check EBS snapshots for public exposure

        Returns:
            List of snapshot details
        """
        print(f"{Fore.CYAN}[*] Checking EBS snapshots...{Style.RESET_ALL}")

        snapshots = []

        try:
            # Get snapshots owned by this account
            response = self._rate_limited_call(
                self.ec2.describe_snapshots,
                OwnerIds=['self']
            )

            if response:
                for snap in response.get('Snapshots', []):
                    snapshot_info = {
                        'id': snap['SnapshotId'],
                        'volume_id': snap.get('VolumeId'),
                        'state': snap.get('State'),
                        'encrypted': snap.get('Encrypted', False),
                        'public': False
                    }

                    # Check if snapshot is public
                    try:
                        perms = self._rate_limited_call(
                            self.ec2.describe_snapshot_attribute,
                            SnapshotId=snap['SnapshotId'],
                            Attribute='createVolumePermission'
                        )

                        if perms:
                            for perm in perms.get('CreateVolumePermissions', []):
                                if perm.get('Group') == 'all':
                                    snapshot_info['public'] = True

                                    self.add_finding(
                                        "CRITICAL",
                                        f"Public Snapshot: {snap['SnapshotId']}",
                                        "EBS snapshot is publicly accessible"
                                    )

                                    print(f"{Fore.RED}[!] PUBLIC SNAPSHOT: {snap['SnapshotId']}{Style.RESET_ALL}")
                    except ClientError:
                        pass

                    # Check encryption
                    if not snapshot_info['encrypted']:
                        self.add_finding(
                            "MEDIUM",
                            f"Unencrypted Snapshot: {snap['SnapshotId']}",
                            "Snapshot is not encrypted"
                        )

                    snapshots.append(snapshot_info)

                print(f"{Fore.GREEN}[+] Found {len(snapshots)} snapshot(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check snapshots: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return snapshots

    def check_amis(self) -> List[Dict]:
        """
        Check AMIs for public exposure

        Returns:
            List of AMI details
        """
        print(f"{Fore.CYAN}[*] Checking AMIs...{Style.RESET_ALL}")

        amis = []

        try:
            response = self._rate_limited_call(
                self.ec2.describe_images,
                Owners=['self']
            )

            if response:
                for ami in response.get('Images', []):
                    ami_info = {
                        'id': ami['ImageId'],
                        'name': ami.get('Name', 'N/A'),
                        'state': ami.get('State'),
                        'public': ami.get('Public', False)
                    }

                    if ami_info['public']:
                        self.add_finding(
                            "CRITICAL",
                            f"Public AMI: {ami['ImageId']}",
                            f"AMI {ami.get('Name', 'N/A')} is publicly accessible"
                        )

                        print(f"{Fore.RED}[!] PUBLIC AMI: {ami['ImageId']} ({ami_info['name']}){Style.RESET_ALL}")

                    amis.append(ami_info)

                print(f"{Fore.GREEN}[+] Found {len(amis)} AMI(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check AMIs: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return amis

    def check_ebs_volumes(self) -> List[Dict]:
        """
        Check EBS volumes for encryption

        Returns:
            List of volume details
        """
        print(f"{Fore.CYAN}[*] Checking EBS volumes...{Style.RESET_ALL}")

        volumes = []

        try:
            response = self._rate_limited_call(self.ec2.describe_volumes)

            if response:
                for vol in response.get('Volumes', []):
                    volume_info = {
                        'id': vol['VolumeId'],
                        'size': vol.get('Size', 0),
                        'state': vol.get('State'),
                        'encrypted': vol.get('Encrypted', False),
                        'attachments': len(vol.get('Attachments', []))
                    }

                    if not volume_info['encrypted']:
                        self.add_finding(
                            "MEDIUM",
                            f"Unencrypted Volume: {vol['VolumeId']}",
                            f"EBS volume ({volume_info['size']}GB) is not encrypted"
                        )

                    volumes.append(volume_info)

                print(f"{Fore.GREEN}[+] Found {len(volumes)} volume(s){Style.RESET_ALL}")

                # Count unencrypted volumes
                unencrypted = [v for v in volumes if not v['encrypted']]
                if unencrypted:
                    print(f"{Fore.YELLOW}[!] {len(unencrypted)} unencrypted volume(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check volumes: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return volumes

    def check_elastic_ips(self) -> List[Dict]:
        """
        Check for unassociated Elastic IPs (cost waste)

        Returns:
            List of EIP details
        """
        print(f"{Fore.CYAN}[*] Checking Elastic IPs...{Style.RESET_ALL}")

        eips = []

        try:
            response = self._rate_limited_call(self.ec2.describe_addresses)

            if response:
                for eip in response.get('Addresses', []):
                    eip_info = {
                        'public_ip': eip.get('PublicIp'),
                        'allocation_id': eip.get('AllocationId'),
                        'associated': 'InstanceId' in eip or 'NetworkInterfaceId' in eip
                    }

                    if not eip_info['associated']:
                        self.add_finding(
                            "LOW",
                            f"Unassociated EIP: {eip['PublicIp']}",
                            "Elastic IP is not associated (incurs charges)"
                        )

                        print(f"{Fore.YELLOW}[!] Unassociated EIP: {eip['PublicIp']}{Style.RESET_ALL}")

                    eips.append(eip_info)

                print(f"{Fore.GREEN}[+] Found {len(eips)} Elastic IP(s){Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check Elastic IPs: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return eips

    def check_vpc_flow_logs(self) -> Dict:
        """
        Check if VPC Flow Logs are enabled

        Returns:
            Flow logs status
        """
        print(f"{Fore.CYAN}[*] Checking VPC Flow Logs...{Style.RESET_ALL}")

        result = {
            'vpcs': [],
            'flow_logs_enabled': 0
        }

        try:
            # Get all VPCs
            vpcs_response = self._rate_limited_call(self.ec2.describe_vpcs)

            if vpcs_response:
                vpcs = vpcs_response.get('Vpcs', [])

                # Get flow logs
                logs_response = self._rate_limited_call(self.ec2.describe_flow_logs)

                flow_logs = logs_response.get('FlowLogs', []) if logs_response else []
                logged_vpcs = {log['ResourceId'] for log in flow_logs}

                for vpc in vpcs:
                    vpc_id = vpc['VpcId']
                    has_logs = vpc_id in logged_vpcs

                    result['vpcs'].append({
                        'id': vpc_id,
                        'flow_logs': has_logs
                    })

                    if has_logs:
                        result['flow_logs_enabled'] += 1
                    else:
                        self.add_finding(
                            "MEDIUM",
                            f"No Flow Logs: {vpc_id}",
                            "VPC does not have Flow Logs enabled (no network visibility)"
                        )

                print(f"{Fore.GREEN}[+] {result['flow_logs_enabled']}/{len(vpcs)} VPCs have Flow Logs{Style.RESET_ALL}")

        except ClientError as e:
            print(f"{Fore.RED}[-] Failed to check Flow Logs: {e.response['Error']['Code']}{Style.RESET_ALL}")

        return result

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

    parser = argparse.ArgumentParser(description='AWS EC2 Security Scanner')
    parser.add_argument('--rate-limit', type=float, default=1.0,
                        help='Seconds to wait between API calls (default: 1.0)')
    parser.add_argument('--region', default='us-east-1',
                        help='AWS region to scan (default: us-east-1)')

    args = parser.parse_args()

    scanner = EC2Scanner(rate_limit=args.rate_limit, region=args.region)

    # Run all checks
    instances = scanner.enumerate_instances()
    security_groups = scanner.check_security_groups()
    snapshots = scanner.check_snapshots()
    amis = scanner.check_amis()
    volumes = scanner.check_ebs_volumes()
    eips = scanner.check_elastic_ips()
    flow_logs = scanner.check_vpc_flow_logs()

    print(f"\n{Fore.CYAN}=== RESULTS ==={Style.RESET_ALL}")
    print(f"Instances: {len(instances)}")
    print(f"Security Groups: {len(security_groups)}")
    print(f"Snapshots: {len(snapshots)}")
    print(f"AMIs: {len(amis)}")
    print(f"Volumes: {len(volumes)}")
    print(f"Elastic IPs: {len(eips)}")
    print(f"Total Findings: {len(scanner.findings)}")


if __name__ == "__main__":
    main()
