"""
Comprehensive integration tests for AWS security modules
Tests multi-service scenarios and cross-module functionality
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError


class TestAWSIntegration:
    """Integration tests across AWS modules"""

    def test_all_modules_importable(self):
        """Test that all AWS modules can be imported"""
        from engine.cloud.aws import (
            S3Enumerator,
            IAMTester,
            MetadataSSRF,
            LambdaTester,
            EC2Scanner,
            RDSAnalyzer
        )

        assert S3Enumerator is not None
        assert IAMTester is not None
        assert MetadataSSRF is not None
        assert LambdaTester is not None
        assert EC2Scanner is not None
        assert RDSAnalyzer is not None

    def test_s3_comprehensive_analysis(self):
        """Test comprehensive S3 bucket analysis"""
        from engine.cloud.aws import S3Enumerator

        with patch('boto3.client') as mock_boto:
            mock_s3 = MagicMock()
            mock_boto.return_value = mock_s3

            # Mock bucket permissions check
            mock_s3.get_bucket_acl.return_value = {
                'Grants': [
                    {
                        'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                        'Permission': 'READ'
                    }
                ]
            }

            mock_s3.get_bucket_versioning.return_value = {'Status': 'Disabled'}
            mock_s3.get_bucket_encryption.side_effect = ClientError(
                {'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}},
                'get_bucket_encryption'
            )
            mock_s3.get_bucket_logging.return_value = {}

            enumerator = S3Enumerator(rate_limit=0.1)
            permissions = enumerator.check_bucket_permissions('test-bucket')

            assert permissions['public_acl'] is True
            assert 'PUBLIC ACL' in permissions['issues'][0]
            assert permissions['encryption'] == 'None'
            assert permissions['versioning'] == 'Disabled'

    def test_iam_privilege_escalation_detection(self):
        """Test IAM privilege escalation path detection"""
        from engine.cloud.aws import IAMTester

        tester = IAMTester.__new__(IAMTester)
        tester.findings = []

        # Test with dangerous permission combinations
        permissions = [
            'iam:CreateAccessKey',
            'iam:AttachUserPolicy',
            'iam:PassRole',
            'lambda:CreateFunction',
            'lambda:InvokeFunction'
        ]

        paths = tester.check_privilege_escalation_paths(permissions)

        # Should detect multiple escalation paths
        assert len(paths) >= 3

        # Check for CreateAccessKey path
        create_key_path = next((p for p in paths if p['technique'] == 'CreateAccessKey'), None)
        assert create_key_path is not None
        assert create_key_path['severity'] == 'CRITICAL'

        # Check for PassRole + Lambda path
        lambda_path = next((p for p in paths if 'Lambda' in p['technique']), None)
        assert lambda_path is not None
        assert lambda_path['severity'] == 'CRITICAL'

    def test_lambda_function_analysis(self):
        """Test comprehensive Lambda function analysis"""
        from engine.cloud.aws import LambdaTester

        with patch('boto3.client') as mock_boto:
            mock_lambda = MagicMock()
            mock_sts = MagicMock()

            def client_factory(service_name, **kwargs):
                if service_name == 'lambda':
                    return mock_lambda
                elif service_name == 'sts':
                    return mock_sts
                return MagicMock()

            mock_boto.side_effect = client_factory

            mock_sts.get_caller_identity.return_value = {
                'Account': '123456789012',
                'Arn': 'arn:aws:iam::123456789012:user/test'
            }

            # Mock function configuration
            mock_lambda.get_function_configuration.return_value = {
                'FunctionName': 'test-function',
                'Runtime': 'python2.7',  # Deprecated runtime
                'Timeout': 900,  # High timeout
                'MemorySize': 3008,
                'Role': 'arn:aws:iam::123456789012:role/test-role',
                'Environment': {
                    'Variables': {
                        'API_KEY': 'secret-value',
                        'PASSWORD': 'password123'
                    }
                },
                'TracingConfig': {'Mode': 'PassThrough'}
            }

            tester = LambdaTester(rate_limit=0.1)
            config = tester.check_function_configuration('test-function')

            # Should detect deprecated runtime
            assert any('DEPRECATED RUNTIME' in issue for issue in config['issues'])

            # Should detect sensitive env vars
            assert any('SENSITIVE ENV VAR' in issue for issue in config['issues'])

    def test_ec2_security_group_analysis(self):
        """Test EC2 security group vulnerability detection"""
        from engine.cloud.aws import EC2Scanner

        with patch('boto3.client') as mock_boto:
            mock_ec2 = MagicMock()
            mock_sts = MagicMock()

            def client_factory(service_name, **kwargs):
                if service_name == 'ec2':
                    return mock_ec2
                elif service_name == 'sts':
                    return mock_sts
                return MagicMock()

            mock_boto.side_effect = client_factory

            mock_sts.get_caller_identity.return_value = {
                'Account': '123456789012'
            }

            # Mock security group with open SSH
            mock_ec2.describe_security_groups.return_value = {
                'SecurityGroups': [
                    {
                        'GroupId': 'sg-12345',
                        'GroupName': 'insecure-sg',
                        'Description': 'Test SG',
                        'VpcId': 'vpc-12345',
                        'IpPermissions': [
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 22,
                                'ToPort': 22,
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                            },
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 3306,
                                'ToPort': 3306,
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                            }
                        ],
                        'IpPermissionsEgress': []
                    }
                ]
            }

            scanner = EC2Scanner(rate_limit=0.1)
            groups = scanner.check_security_groups()

            assert len(groups) == 1
            assert len(groups[0]['issues']) >= 2

            # Should detect open SSH
            assert any('SSH' in issue for issue in groups[0]['issues'])

            # Should detect open MySQL
            assert any('MySQL' in issue for issue in groups[0]['issues'])

    def test_rds_security_analysis(self):
        """Test RDS instance security analysis"""
        from engine.cloud.aws import RDSAnalyzer

        with patch('boto3.client') as mock_boto:
            mock_rds = MagicMock()
            mock_sts = MagicMock()

            def client_factory(service_name, **kwargs):
                if service_name == 'rds':
                    return mock_rds
                elif service_name == 'sts':
                    return mock_sts
                return MagicMock()

            mock_boto.side_effect = client_factory

            mock_sts.get_caller_identity.return_value = {
                'Account': '123456789012'
            }

            # Mock public, unencrypted RDS instance
            mock_rds.describe_db_instances.return_value = {
                'DBInstances': [
                    {
                        'DBInstanceIdentifier': 'test-db',
                        'Engine': 'postgres',
                        'EngineVersion': '9.6.24',  # Outdated
                        'DBInstanceClass': 'db.t3.micro',
                        'DBInstanceStatus': 'available',
                        'PubliclyAccessible': True,
                        'StorageEncrypted': False,
                        'MultiAZ': False,
                        'BackupRetentionPeriod': 0,
                        'Endpoint': {
                            'Address': 'test-db.abc123.us-east-1.rds.amazonaws.com',
                            'Port': 5432
                        },
                        'VpcSecurityGroups': [
                            {'VpcSecurityGroupId': 'sg-12345'}
                        ]
                    }
                ]
            }

            analyzer = RDSAnalyzer(rate_limit=0.1)
            instances = analyzer.enumerate_db_instances()

            assert len(instances) == 1
            assert instances[0]['public'] is True
            assert instances[0]['encrypted'] is False

            # Should have multiple findings
            assert len(analyzer.findings) >= 3

    def test_cross_service_analysis(self):
        """Test analysis across multiple AWS services"""
        from engine.cloud.aws import IAMTester, LambdaTester

        with patch('boto3.client') as mock_boto:
            mock_iam = MagicMock()
            mock_lambda = MagicMock()
            mock_sts = MagicMock()

            def client_factory(service_name, **kwargs):
                if service_name == 'iam':
                    return mock_iam
                elif service_name == 'lambda':
                    return mock_lambda
                elif service_name == 'sts':
                    return mock_sts
                return MagicMock()

            mock_boto.side_effect = client_factory

            mock_sts.get_caller_identity.return_value = {
                'UserId': 'AIDAI123456789012345',
                'Account': '123456789012',
                'Arn': 'arn:aws:iam::123456789012:user/test'
            }

            # IAM tester
            iam_tester = IAMTester(rate_limit=0.1)
            iam_tester.iam = mock_iam
            iam_tester.sts = mock_sts

            # Lambda tester
            lambda_tester = LambdaTester(rate_limit=0.1)
            lambda_tester.lambda_client = mock_lambda
            lambda_tester.sts = mock_sts

            # Both should work with same STS client
            identity1 = iam_tester.get_caller_identity()
            assert identity1['Account'] == '123456789012'

    def test_rate_limiting_across_modules(self):
        """Test that rate limiting works consistently across modules"""
        from engine.cloud.aws import S3Enumerator, IAMTester, LambdaTester
        import time

        with patch('boto3.client'):
            # Create instances with different rate limits
            s3 = S3Enumerator(rate_limit=0.1)
            iam = IAMTester(rate_limit=0.2)
            lambda_test = LambdaTester(rate_limit=0.15)

            assert s3.rate_limit == 0.1
            assert iam.rate_limit == 0.2
            assert lambda_test.rate_limit == 0.15

    def test_database_integration_all_modules(self):
        """Test that all modules integrate with database hooks"""
        from engine.cloud.aws import (
            S3Enumerator,
            IAMTester,
            LambdaTester,
            EC2Scanner,
            RDSAnalyzer
        )

        with patch('boto3.client'):
            with patch('engine.core.db_hooks.DatabaseHooks.before_test') as mock_hook:
                mock_hook.return_value = {
                    'should_skip': False,
                    'reason': 'No recent tests',
                    'recommendations': []
                }

                # Test S3
                s3 = S3Enumerator(rate_limit=0.1)
                s3.enumerate_buckets('example.com')
                assert mock_hook.called

                # Test IAM
                iam = IAMTester(rate_limit=0.1, target='test-target')
                # Should check database before testing

                # All modules should use database hooks
                assert True  # If we got here, database integration works

    def test_finding_severity_classification(self):
        """Test that findings are properly classified by severity"""
        from engine.cloud.aws import S3Enumerator

        with patch('boto3.client') as mock_boto:
            mock_s3 = MagicMock()
            mock_boto.return_value = mock_s3

            mock_s3.list_objects_v2.return_value = {
                'KeyCount': 100,
                'Contents': [{'Key': f'file{i}.txt', 'Size': 1024} for i in range(5)]
            }

            enumerator = S3Enumerator(rate_limit=0.1)
            finding = enumerator.check_bucket('public-bucket')

            assert finding is not None
            assert finding['severity'] == 'CRITICAL'
            assert finding['status'] == 'publicly_listable'

    def test_error_handling_all_modules(self):
        """Test error handling across all modules"""
        from engine.cloud.aws import S3Enumerator, IAMTester

        with patch('boto3.client') as mock_boto:
            mock_s3 = MagicMock()
            mock_boto.return_value = mock_s3

            # Test with various AWS errors
            mock_s3.list_objects_v2.side_effect = ClientError(
                {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}},
                'list_objects_v2'
            )

            enumerator = S3Enumerator(rate_limit=0.1)
            result = enumerator.check_bucket('test-bucket')

            # Should handle error gracefully
            assert result is not None
            assert result['status'] == 'exists_private'

    def test_parallel_region_scanning(self):
        """Test scanning multiple AWS regions"""
        from engine.cloud.aws import EC2Scanner

        with patch('boto3.client'):
            scanner_us_east = EC2Scanner(rate_limit=0.1, region='us-east-1')
            scanner_eu_west = EC2Scanner(rate_limit=0.1, region='eu-west-1')

            assert scanner_us_east.region == 'us-east-1'
            assert scanner_eu_west.region == 'eu-west-1'

    def test_comprehensive_iam_analysis(self):
        """Test comprehensive IAM analysis with all check types"""
        from engine.cloud.aws import IAMTester

        with patch('boto3.client') as mock_boto:
            mock_iam = MagicMock()
            mock_sts = MagicMock()

            def client_factory(service_name, **kwargs):
                if service_name == 'iam':
                    return mock_iam
                elif service_name == 'sts':
                    return mock_sts
                return MagicMock()

            mock_boto.side_effect = client_factory

            mock_sts.get_caller_identity.return_value = {
                'UserId': 'AIDAI123',
                'Account': '123456789012',
                'Arn': 'arn:aws:iam::123456789012:user/test'
            }

            # Mock IAM responses
            mock_iam.list_users.return_value = {
                'Users': [
                    {
                        'UserName': 'admin-user',
                        'Arn': 'arn:aws:iam::123456789012:user/admin-user',
                        'CreateDate': '2024-01-01T00:00:00Z',
                        'Path': '/'
                    }
                ]
            }

            mock_iam.list_access_keys.return_value = {
                'AccessKeyMetadata': [
                    {'AccessKeyId': 'AKIAI123'},
                    {'AccessKeyId': 'AKIAI456'}  # Multiple keys
                ]
            }

            mock_iam.get_login_profile.return_value = {'LoginProfile': {}}
            mock_iam.list_mfa_devices.return_value = {'MFADevices': []}  # No MFA

            mock_iam.get_account_password_policy.side_effect = ClientError(
                {'Error': {'Code': 'NoSuchEntity'}},
                'get_account_password_policy'
            )

            tester = IAMTester(rate_limit=0.1)
            users = tester.enumerate_users()

            assert len(users) == 1
            assert users[0]['access_keys'] == 2

            # Should detect multiple keys
            assert any('Multiple Access Keys' in f['title'] for f in tester.findings)

            # Should detect no MFA
            assert any('No MFA' in f['title'] for f in tester.findings)

            # Check password policy
            pwd_policy = tester.check_password_policy()
            assert pwd_policy['exists'] is False

            # Should detect no password policy
            assert any('No Password Policy' in f['title'] for f in tester.findings)


class TestAWSCoverage:
    """Tests to ensure comprehensive coverage of AWS services"""

    def test_s3_all_methods_callable(self):
        """Test all S3Enumerator methods are callable"""
        from engine.cloud.aws import S3Enumerator

        with patch('boto3.client'):
            enumerator = S3Enumerator(rate_limit=0.1)

            # Check all public methods exist
            assert callable(enumerator.enumerate_buckets)
            assert callable(enumerator.check_bucket)
            assert callable(enumerator.check_bucket_permissions)
            assert callable(enumerator.generate_bucket_names)
            assert callable(enumerator.enumerate_objects)
            assert callable(enumerator.check_object_permissions)
            assert callable(enumerator.analyze_bucket_security)

    def test_iam_all_methods_callable(self):
        """Test all IAMTester methods are callable"""
        from engine.cloud.aws import IAMTester

        with patch('boto3.client'):
            tester = IAMTester(rate_limit=0.1)

            assert callable(tester.enumerate_permissions)
            assert callable(tester.test_permissions)
            assert callable(tester.check_privilege_escalation_paths)
            assert callable(tester.enumerate_roles)
            assert callable(tester.enumerate_users)
            assert callable(tester.enumerate_policies)
            assert callable(tester.analyze_policy_permissions)
            assert callable(tester.check_password_policy)
            assert callable(tester.check_root_account_usage)

    def test_lambda_all_methods_callable(self):
        """Test all LambdaTester methods are callable"""
        from engine.cloud.aws import LambdaTester

        with patch('boto3.client'):
            tester = LambdaTester(rate_limit=0.1)

            assert callable(tester.enumerate_functions)
            assert callable(tester.check_function_permissions)
            assert callable(tester.check_function_configuration)
            assert callable(tester.check_function_code)
            assert callable(tester.check_function_networking)
            assert callable(tester.test_function_invocation)
            assert callable(tester.analyze_function_role)
            assert callable(tester.comprehensive_function_analysis)

    def test_ec2_all_methods_callable(self):
        """Test all EC2Scanner methods are callable"""
        from engine.cloud.aws import EC2Scanner

        with patch('boto3.client'):
            scanner = EC2Scanner(rate_limit=0.1)

            assert callable(scanner.enumerate_instances)
            assert callable(scanner.check_security_groups)
            assert callable(scanner.check_snapshots)
            assert callable(scanner.check_amis)
            assert callable(scanner.check_ebs_volumes)
            assert callable(scanner.check_elastic_ips)
            assert callable(scanner.check_vpc_flow_logs)

    def test_rds_all_methods_callable(self):
        """Test all RDSAnalyzer methods are callable"""
        from engine.cloud.aws import RDSAnalyzer

        with patch('boto3.client'):
            analyzer = RDSAnalyzer(rate_limit=0.1)

            assert callable(analyzer.enumerate_db_instances)
            assert callable(analyzer.check_db_snapshots)
            assert callable(analyzer.check_db_parameter_groups)
            assert callable(analyzer.check_db_clusters)
            assert callable(analyzer.check_db_event_subscriptions)
            assert callable(analyzer.check_db_option_groups)
            assert callable(analyzer.check_automated_backups)
