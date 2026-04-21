"""
Comprehensive tests for Privilege Escalation Chain Builder Agent

Tests cover:
- Agent initialization
- Endpoint discovery
- Permission mapping
- Boundary testing
- IDOR discovery
- Chain building (5 strategies)
- Chain validation
- Report generation
- Database integration
- Edge cases and error handling

Target: 30+ tests with 95%+ coverage
"""

import pytest
import json
import asyncio
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime, date
from typing import Dict, Any

from engine.agents.privilege_escalation_chain_builder import (
    PrivilegeEscalationChainBuilder,
    PermissionLevel,
    Role,
    Permission,
    EscalationStep,
    EscalationChain,
    PermissionBoundary
)


class TestPrivilegeEscalationChainBuilder:
    """Test Privilege Escalation Chain Builder functionality."""

    @pytest.fixture
    def api_tokens(self):
        """Sample API tokens for testing."""
        return {
            Role.USER: 'user_token_123',
            Role.ADMIN: 'admin_token_456',
            Role.MODERATOR: 'mod_token_789'
        }

    @pytest.fixture
    def builder(self, api_tokens):
        """Create a builder instance for testing."""
        return PrivilegeEscalationChainBuilder(
            target_url="https://api.example.com",
            api_tokens=api_tokens,
            domain="example.com"
        )

    # ========== Initialization Tests ==========

    def test_initialization(self, builder, api_tokens):
        """Test builder initialization."""
        assert builder is not None
        assert builder.target_url == "https://api.example.com"
        assert builder.api_tokens == api_tokens
        assert builder.domain == "example.com"
        assert len(builder.endpoints) == 0
        assert len(builder.chains) == 0
        assert builder.db is not None

    def test_initialization_with_trailing_slash(self, api_tokens):
        """Test URL normalization with trailing slash."""
        builder = PrivilegeEscalationChainBuilder(
            target_url="https://api.example.com/",
            api_tokens=api_tokens
        )
        assert builder.target_url == "https://api.example.com"

    def test_domain_extraction(self, api_tokens):
        """Test domain extraction from URL."""
        builder = PrivilegeEscalationChainBuilder(
            target_url="https://subdomain.example.com/api/v1",
            api_tokens=api_tokens
        )
        assert builder.domain == "subdomain.example.com"

    def test_role_hierarchy_initialization(self, builder):
        """Test role hierarchy graph initialization."""
        assert builder.role_graph is not None
        # Verify some hierarchy relationships
        assert builder._is_lower_role(Role.USER, Role.ADMIN) is True
        assert builder._is_lower_role(Role.GUEST, Role.PREMIUM) is True
        assert builder._is_lower_role(Role.ADMIN, Role.USER) is False

    # ========== Permission Level Tests ==========

    def test_determine_permission_level_read(self, builder):
        """Test permission level determination for read access."""
        access_result = {'accessible': True, 'status_code': 200}
        level = builder._determine_permission_level(access_result)
        assert level == PermissionLevel.READ

    def test_determine_permission_level_write(self, builder):
        """Test permission level determination for write access."""
        access_result = {'accessible': True, 'status_code': 201}
        level = builder._determine_permission_level(access_result)
        assert level == PermissionLevel.WRITE

    def test_determine_permission_level_delete(self, builder):
        """Test permission level determination for delete access."""
        access_result = {'accessible': True, 'status_code': 204}
        level = builder._determine_permission_level(access_result)
        assert level == PermissionLevel.DELETE

    def test_determine_permission_level_none(self, builder):
        """Test permission level determination for no access."""
        access_result = {'accessible': False}
        level = builder._determine_permission_level(access_result)
        assert level == PermissionLevel.NONE

    # ========== Role Inference Tests ==========

    def test_infer_expected_role_admin(self, builder):
        """Test inferring admin role from endpoint."""
        assert builder._infer_expected_role('/api/admin/users') == Role.ADMIN
        assert builder._infer_expected_role('/api/superadmin/settings') == Role.ADMIN

    def test_infer_expected_role_moderator(self, builder):
        """Test inferring moderator role from endpoint."""
        assert builder._infer_expected_role('/api/moderator/posts') == Role.MODERATOR
        assert builder._infer_expected_role('/api/mod/reports') == Role.MODERATOR

    def test_infer_expected_role_premium(self, builder):
        """Test inferring premium role from endpoint."""
        assert builder._infer_expected_role('/api/premium/features') == Role.PREMIUM
        assert builder._infer_expected_role('/api/pro/analytics') == Role.PREMIUM

    def test_infer_expected_role_user(self, builder):
        """Test inferring user role from endpoint."""
        assert builder._infer_expected_role('/api/user/profile') == Role.USER
        assert builder._infer_expected_role('/api/users/settings') == Role.USER

    def test_infer_expected_role_guest(self, builder):
        """Test inferring guest role from generic endpoint."""
        assert builder._infer_expected_role('/api/public/info') == Role.GUEST
        assert builder._infer_expected_role('/api/data') == Role.GUEST

    # ========== Role Hierarchy Tests ==========

    def test_is_lower_role_true(self, builder):
        """Test lower role detection - positive cases."""
        assert builder._is_lower_role(Role.USER, Role.ADMIN) is True
        assert builder._is_lower_role(Role.GUEST, Role.USER) is True
        assert builder._is_lower_role(Role.ANONYMOUS, Role.OWNER) is True
        assert builder._is_lower_role(Role.MODERATOR, Role.SUPERADMIN) is True

    def test_is_lower_role_false(self, builder):
        """Test lower role detection - negative cases."""
        assert builder._is_lower_role(Role.ADMIN, Role.USER) is False
        assert builder._is_lower_role(Role.PREMIUM, Role.GUEST) is False
        assert builder._is_lower_role(Role.USER, Role.USER) is False

    # ========== Endpoint Discovery Tests ==========

    @pytest.mark.asyncio
    async def test_discover_endpoints_success(self, builder):
        """Test successful endpoint discovery."""
        with patch.object(builder.session, 'get') as mock_get, \
             patch.object(builder.session, 'post') as mock_post:

            # Mock successful responses
            mock_get.return_value.status_code = 200
            mock_post.return_value.status_code = 401

            await builder._discover_endpoints()

            assert len(builder.endpoints) > 0
            # Check that GET endpoints were discovered
            get_endpoints = [e for e in builder.endpoints if e['method'] == 'GET']
            assert len(get_endpoints) > 0

    @pytest.mark.asyncio
    async def test_discover_endpoints_404_filtered(self, builder):
        """Test that 404 endpoints are filtered out."""
        with patch.object(builder.session, 'get') as mock_get, \
             patch.object(builder.session, 'post') as mock_post, \
             patch.object(builder.session, 'put') as mock_put, \
             patch.object(builder.session, 'delete') as mock_delete:

            # All return 404
            mock_get.return_value.status_code = 404
            mock_post.return_value.status_code = 404
            mock_put.return_value.status_code = 404
            mock_delete.return_value.status_code = 404

            await builder._discover_endpoints()

            assert len(builder.endpoints) == 0

    @pytest.mark.asyncio
    async def test_discover_endpoints_network_error(self, builder):
        """Test endpoint discovery with network errors."""
        with patch.object(builder.session, 'get', side_effect=Exception("Network error")), \
             patch.object(builder.session, 'post', side_effect=Exception("Network error")), \
             patch.object(builder.session, 'put', side_effect=Exception("Network error")), \
             patch.object(builder.session, 'delete', side_effect=Exception("Network error")):

            await builder._discover_endpoints()

            # Should handle errors gracefully
            assert len(builder.endpoints) == 0

    # ========== Endpoint Access Tests ==========

    @pytest.mark.asyncio
    async def test_test_endpoint_access_get_success(self, builder):
        """Test GET endpoint access."""
        with patch.object(builder.session, 'get') as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.text = '{"data": "test"}'

            result = await builder._test_endpoint_access('/api/user', 'GET', 'token123')

            assert result['accessible'] is True
            assert result['status_code'] == 200
            assert 'data' in result['response']

    @pytest.mark.asyncio
    async def test_test_endpoint_access_post_success(self, builder):
        """Test POST endpoint access."""
        with patch.object(builder.session, 'post') as mock_post:
            mock_post.return_value.status_code = 201
            mock_post.return_value.text = '{"created": true}'

            result = await builder._test_endpoint_access('/api/user', 'POST', 'token123')

            assert result['accessible'] is True
            assert result['status_code'] == 201

    @pytest.mark.asyncio
    async def test_test_endpoint_access_unauthorized(self, builder):
        """Test endpoint access with 401 response."""
        with patch.object(builder.session, 'get') as mock_get:
            mock_get.return_value.status_code = 401

            result = await builder._test_endpoint_access('/api/admin', 'GET', 'token123')

            assert result['accessible'] is False
            assert result['status_code'] == 401

    @pytest.mark.asyncio
    async def test_test_endpoint_access_forbidden(self, builder):
        """Test endpoint access with 403 response."""
        with patch.object(builder.session, 'get') as mock_get:
            mock_get.return_value.status_code = 403

            result = await builder._test_endpoint_access('/api/admin', 'GET', 'token123')

            assert result['accessible'] is False
            assert result['status_code'] == 403

    @pytest.mark.asyncio
    async def test_test_endpoint_access_error(self, builder):
        """Test endpoint access with network error."""
        with patch.object(builder.session, 'get', side_effect=Exception("Timeout")):
            result = await builder._test_endpoint_access('/api/user', 'GET', 'token123')

            assert result['accessible'] is False
            assert 'error' in result

    # ========== IDOR Discovery Tests ==========

    @pytest.mark.asyncio
    async def test_discover_idors_found(self, builder):
        """Test IDOR discovery - vulnerability found."""
        builder.api_tokens[Role.USER] = 'user_token'

        # Create a generator that returns the mocked responses
        async def mock_access_gen(*args, **kwargs):
            # Cycle through responses for each call
            responses = [
                {'accessible': True, 'status_code': 200, 'response': '{}'},
                {'accessible': True, 'status_code': 200, 'response': '{}'}
            ]
            return responses[mock_access_gen.call_count % 2]

        mock_access_gen.call_count = 0

        original_test = builder._test_endpoint_access

        async def mock_access_side_effect(*args, **kwargs):
            result_idx = mock_access_gen.call_count % 2
            mock_access_gen.call_count += 1
            responses = [
                {'accessible': True, 'status_code': 200, 'response': '{}'},
                {'accessible': True, 'status_code': 200, 'response': '{}'}
            ]
            return responses[result_idx]

        with patch.object(builder, '_test_endpoint_access', side_effect=mock_access_side_effect):
            await builder._discover_idors()

            assert len(builder.idors) > 0
            idor = builder.idors[0]
            assert idor['vulnerable'] is True
            assert idor['can_modify'] is True
            assert idor['severity'] == 'high'

    @pytest.mark.asyncio
    async def test_discover_idors_readonly(self, builder):
        """Test IDOR discovery - read-only vulnerability."""
        builder.api_tokens[Role.USER] = 'user_token'

        call_count = [0]

        async def mock_access_side_effect(*args, **kwargs):
            result_idx = call_count[0] % 2
            call_count[0] += 1
            responses = [
                {'accessible': True, 'status_code': 200, 'response': '{}'},
                {'accessible': False, 'status_code': 403}
            ]
            return responses[result_idx]

        with patch.object(builder, '_test_endpoint_access', side_effect=mock_access_side_effect):
            await builder._discover_idors()

            if builder.idors:
                idor = builder.idors[0]
                assert idor['can_modify'] is False
                assert idor['severity'] == 'medium'

    @pytest.mark.asyncio
    async def test_discover_idors_no_user_token(self, builder):
        """Test IDOR discovery without user token."""
        builder.api_tokens.pop(Role.USER, None)

        await builder._discover_idors()

        # Should handle gracefully
        assert len(builder.idors) == 0

    # ========== Admin User Detection Tests ==========

    @pytest.mark.asyncio
    async def test_check_if_admin_user_true(self, builder):
        """Test admin user detection - positive case."""
        builder.api_tokens[Role.USER] = 'user_token'

        with patch.object(builder, '_test_endpoint_access') as mock_access:
            mock_access.return_value = {
                'accessible': True,
                'response': '{"role": "admin", "username": "admin_user"}'
            }

            result = await builder._check_if_admin_user('/api/user/1')

            assert result is True

    @pytest.mark.asyncio
    async def test_check_if_admin_user_false(self, builder):
        """Test admin user detection - negative case."""
        builder.api_tokens[Role.USER] = 'user_token'

        with patch.object(builder, '_test_endpoint_access') as mock_access:
            mock_access.return_value = {
                'accessible': True,
                'response': '{"role": "user", "username": "regular_user"}'
            }

            result = await builder._check_if_admin_user('/api/user/2')

            assert result is False

    @pytest.mark.asyncio
    async def test_check_if_admin_user_not_accessible(self, builder):
        """Test admin user detection when endpoint not accessible."""
        builder.api_tokens[Role.USER] = 'user_token'

        with patch.object(builder, '_test_endpoint_access') as mock_access:
            mock_access.return_value = {'accessible': False}

            result = await builder._check_if_admin_user('/api/user/1')

            assert result is False

    # ========== Chain Building Tests ==========

    @pytest.mark.asyncio
    async def test_build_idor_to_admin_chains(self, builder):
        """Test IDOR to admin chain building."""
        # Setup IDOR vulnerability
        builder.idors = [{
            'endpoint': '/api/user/1',
            'user_id': 1,
            'can_modify': True,
            'severity': 'high'
        }]

        with patch.object(builder, '_check_if_admin_user', return_value=True), \
             patch('engine.core.db_hooks.DatabaseHooks.check_duplicate') as mock_dup:

            mock_dup.return_value = {'is_duplicate': False}

            await builder._build_idor_to_admin_chains()

            assert len(builder.chains) > 0
            chain = builder.chains[0]
            assert chain.start_role == Role.USER
            assert chain.end_role == Role.ADMIN
            assert chain.total_severity == 'critical'
            assert len(chain.steps) == 3

    @pytest.mark.asyncio
    async def test_build_idor_to_admin_chains_duplicate_skip(self, builder):
        """Test IDOR chain building skips duplicates."""
        builder.idors = [{
            'endpoint': '/api/user/1',
            'user_id': 1,
            'can_modify': True,
            'severity': 'high'
        }]

        with patch.object(builder, '_check_if_admin_user', return_value=True), \
             patch('engine.core.db_hooks.DatabaseHooks.check_duplicate') as mock_dup:

            mock_dup.return_value = {'is_duplicate': True}

            await builder._build_idor_to_admin_chains()

            assert len(builder.chains) == 0

    @pytest.mark.asyncio
    async def test_build_role_modification_chains(self, builder):
        """Test role modification chain building."""
        builder.endpoints = [
            {'path': '/api/users', 'method': 'POST'},
            {'path': '/api/roles', 'method': 'PUT'}
        ]

        with patch('engine.core.db_hooks.DatabaseHooks.check_duplicate') as mock_dup:
            mock_dup.return_value = {'is_duplicate': False}

            await builder._build_role_modification_chains()

            assert len(builder.chains) > 0
            chain = builder.chains[0]
            assert chain.total_severity == 'critical'
            assert chain.cvss_score == 9.8
            assert len(chain.steps) == 3

    @pytest.mark.asyncio
    async def test_build_permission_inheritance_chains(self, builder):
        """Test permission inheritance chain building."""
        builder.endpoints = [
            {'path': '/api/groups/admin', 'method': 'POST'}
        ]

        with patch('engine.core.db_hooks.DatabaseHooks.check_duplicate') as mock_dup:
            mock_dup.return_value = {'is_duplicate': False}

            await builder._build_permission_inheritance_chains()

            assert len(builder.chains) > 0
            chain = builder.chains[0]
            assert chain.total_severity == 'critical'
            assert chain.cvss_score == 8.5

    @pytest.mark.asyncio
    async def test_build_multi_idor_chains(self, builder):
        """Test multi-IDOR chain building."""
        builder.idors = [
            {'endpoint': '/api/user/1', 'vulnerable': True},
            {'endpoint': '/api/profile/2', 'vulnerable': True}
        ]

        with patch('engine.core.db_hooks.DatabaseHooks.check_duplicate') as mock_dup:
            mock_dup.return_value = {'is_duplicate': False}

            await builder._build_multi_idor_chains()

            assert len(builder.chains) > 0
            chain = builder.chains[0]
            assert chain.cvss_score == 9.5

    @pytest.mark.asyncio
    async def test_build_graphql_chains(self, builder):
        """Test GraphQL mutation chain building."""
        builder.endpoints = [
            {'path': '/graphql', 'method': 'POST'}
        ]

        with patch('engine.core.db_hooks.DatabaseHooks.check_duplicate') as mock_dup:
            mock_dup.return_value = {'is_duplicate': False}

            await builder._build_graphql_chains()

            assert len(builder.chains) > 0
            chain = builder.chains[0]
            assert chain.total_severity == 'critical'
            assert chain.cvss_score == 9.3

    # ========== Chain Validation Tests ==========

    @pytest.mark.asyncio
    async def test_validate_chains_success(self, builder):
        """Test chain validation - successful validation."""
        builder.chains = [
            EscalationChain(
                chain_id="test_chain",
                start_role=Role.USER,
                end_role=Role.ADMIN,
                steps=[
                    EscalationStep(1, "desc", "/api/test", "GET", {}, "result", "IDOR", "high")
                ],
                total_severity="critical",
                combined_impact="test",
                proof_of_concept="poc",
                bounty_estimate="$5,000",
                cvss_score=9.0
            )
        ]

        await builder._validate_chains()

        assert builder.chains[0].validated is True

    @pytest.mark.asyncio
    async def test_validate_chains_failure(self, builder):
        """Test chain validation - validation failure."""
        builder.chains = [
            EscalationChain(
                chain_id="test_chain",
                start_role=Role.USER,
                end_role=Role.ADMIN,
                steps=[
                    EscalationStep(1, "desc", "", "GET", {}, "result", "IDOR", "high")  # Empty endpoint
                ],
                total_severity="critical",
                combined_impact="test",
                proof_of_concept="poc",
                bounty_estimate="$5,000",
                cvss_score=9.0
            )
        ]

        await builder._validate_chains()

        assert builder.chains[0].validated is False

    @pytest.mark.asyncio
    async def test_execute_chain_valid(self, builder):
        """Test chain execution validation - valid chain."""
        chain = EscalationChain(
            chain_id="test",
            start_role=Role.USER,
            end_role=Role.ADMIN,
            steps=[
                EscalationStep(1, "desc", "/api/test", "GET", {}, "result", "IDOR", "high"),
                EscalationStep(2, "desc", "/api/admin", "POST", {'data': 'test'}, "result", "Escalation", "critical")
            ],
            total_severity="critical",
            combined_impact="test",
            proof_of_concept="poc",
            bounty_estimate="$10,000",
            cvss_score=9.5
        )

        result = await builder._execute_chain(chain)

        assert result is True

    @pytest.mark.asyncio
    async def test_execute_chain_invalid(self, builder):
        """Test chain execution validation - invalid chain."""
        chain = EscalationChain(
            chain_id="test",
            start_role=Role.USER,
            end_role=Role.ADMIN,
            steps=[
                EscalationStep(1, "desc", "", "GET", {}, "result", "IDOR", "high")  # Missing endpoint
            ],
            total_severity="critical",
            combined_impact="test",
            proof_of_concept="poc",
            bounty_estimate="$5,000",
            cvss_score=9.0
        )

        result = await builder._execute_chain(chain)

        assert result is False

    # ========== Report Generation Tests ==========

    def test_generate_report(self, builder):
        """Test report generation."""
        builder.chains = [
            EscalationChain(
                chain_id="chain1",
                start_role=Role.USER,
                end_role=Role.ADMIN,
                steps=[],
                total_severity="critical",
                combined_impact="test",
                proof_of_concept="poc",
                bounty_estimate="$10,000 - $20,000",
                cvss_score=9.5,
                validated=True
            ),
            EscalationChain(
                chain_id="chain2",
                start_role=Role.GUEST,
                end_role=Role.PREMIUM,
                steps=[],
                total_severity="high",
                combined_impact="test",
                proof_of_concept="poc",
                bounty_estimate="$5,000 - $10,000",
                cvss_score=7.5,
                validated=False
            )
        ]

        report = builder.generate_report()

        assert 'summary' in report
        assert 'chains' in report
        assert 'estimated_total_bounty' in report
        assert report['summary']['total_chains'] == 2
        assert report['summary']['validated_chains'] == 1
        assert report['summary']['average_cvss'] == 8.5

    def test_calculate_severity_breakdown(self, builder):
        """Test severity distribution calculation."""
        builder.chains = [
            EscalationChain("1", Role.USER, Role.ADMIN, [], "critical", "", "", "$10K", 9.5),
            EscalationChain("2", Role.USER, Role.ADMIN, [], "critical", "", "", "$10K", 9.0),
            EscalationChain("3", Role.USER, Role.MODERATOR, [], "high", "", "", "$5K", 7.5)
        ]

        breakdown = builder._calculate_severity_breakdown()

        assert breakdown['critical'] == 2
        assert breakdown['high'] == 1
        assert breakdown['medium'] == 0
        assert breakdown['low'] == 0

    def test_calculate_average_cvss(self, builder):
        """Test average CVSS calculation."""
        builder.chains = [
            EscalationChain("1", Role.USER, Role.ADMIN, [], "critical", "", "", "$10K", 9.0),
            EscalationChain("2", Role.USER, Role.ADMIN, [], "critical", "", "", "$10K", 8.0),
            EscalationChain("3", Role.USER, Role.ADMIN, [], "high", "", "", "$5K", 7.0)
        ]

        avg_cvss = builder._calculate_average_cvss()

        assert avg_cvss == 8.0

    def test_calculate_average_cvss_empty(self, builder):
        """Test average CVSS with no chains."""
        builder.chains = []

        avg_cvss = builder._calculate_average_cvss()

        assert avg_cvss == 0.0

    def test_calculate_total_bounty(self, builder):
        """Test total bounty calculation."""
        builder.chains = [
            EscalationChain("1", Role.USER, Role.ADMIN, [], "critical", "", "", "$10,000 - $20,000", 9.5),
            EscalationChain("2", Role.USER, Role.ADMIN, [], "high", "", "", "$5,000 - $10,000", 7.5)
        ]

        total = builder._calculate_total_bounty()

        assert total == "$15,000 - $30,000"

    # ========== PoC Generation Tests ==========

    def test_generate_idor_admin_poc(self, builder):
        """Test IDOR to admin PoC generation."""
        poc = builder._generate_idor_admin_poc('/api/user/1', '/api/user/100')

        assert '/api/user/1' in poc
        assert '/api/user/100' in poc
        assert 'Privilege Escalation' in poc
        assert 'IDOR' in poc

    def test_generate_role_mod_poc(self, builder):
        """Test role modification PoC generation."""
        poc = builder._generate_role_mod_poc('/api/users', '/api/roles')

        assert '/api/users' in poc
        assert '/api/roles' in poc
        assert 'admin' in poc

    def test_generate_inheritance_poc(self, builder):
        """Test permission inheritance PoC generation."""
        poc = builder._generate_inheritance_poc()

        assert 'Permission Inheritance' in poc
        assert 'group' in poc.lower()

    def test_generate_multi_idor_poc(self, builder):
        """Test multi-IDOR PoC generation."""
        poc = builder._generate_multi_idor_poc()

        assert 'Chained IDORs' in poc
        assert 'API key' in poc

    def test_generate_graphql_poc(self, builder):
        """Test GraphQL PoC generation."""
        poc = builder._generate_graphql_poc()

        assert 'GraphQL' in poc
        assert 'mutation' in poc
        assert '/graphql' in poc

    # ========== Database Integration Tests ==========

    @pytest.mark.asyncio
    async def test_database_integration_skip_recent(self, builder):
        """Test database integration skips recently tested targets."""
        with patch('engine.core.db_hooks.DatabaseHooks.before_test') as mock_before:
            mock_before.return_value = {
                'should_skip': True,
                'reason': 'Tested 2 days ago',
                'previous_findings': [],
                'recommendations': []
            }

            chains = await builder.discover_and_exploit()

            assert len(chains) == 0
            mock_before.assert_called_once()

    @pytest.mark.asyncio
    async def test_database_integration_proceed(self, builder):
        """Test database integration proceeds when safe."""
        with patch('engine.core.db_hooks.DatabaseHooks.before_test') as mock_before, \
             patch.object(builder, '_discover_endpoints'), \
             patch.object(builder, '_map_permissions'), \
             patch.object(builder, '_test_permission_boundaries'), \
             patch.object(builder, '_discover_idors'), \
             patch.object(builder, '_build_escalation_chains'), \
             patch.object(builder, '_validate_chains'), \
             patch.object(builder.db, 'record_tool_run'):

            mock_before.return_value = {
                'should_skip': False,
                'reason': 'Last tested 45 days ago',
                'previous_findings': [],
                'recommendations': ['Full test recommended']
            }

            await builder.discover_and_exploit()

            mock_before.assert_called_once()

    @pytest.mark.asyncio
    async def test_database_recording(self, builder):
        """Test database recording after testing."""
        with patch('engine.core.db_hooks.DatabaseHooks.before_test') as mock_before, \
             patch.object(builder, '_discover_endpoints'), \
             patch.object(builder, '_map_permissions'), \
             patch.object(builder, '_test_permission_boundaries'), \
             patch.object(builder, '_discover_idors'), \
             patch.object(builder, '_build_escalation_chains'), \
             patch.object(builder, '_validate_chains'), \
             patch.object(builder.db, 'record_tool_run') as mock_record:

            mock_before.return_value = {
                'should_skip': False,
                'reason': 'Safe to test',
                'previous_findings': [],
                'recommendations': []
            }

            builder.chains = [
                EscalationChain("1", Role.USER, Role.ADMIN, [], "critical", "", "", "$10K", 9.0, validated=True)
            ]

            await builder.discover_and_exploit()

            mock_record.assert_called_once_with(
                domain='example.com',
                tool_name='privilege_escalation_chain_builder',
                findings_count=1,
                success=True
            )


# ========== Integration Test ==========

@pytest.mark.asyncio
async def test_full_integration():
    """Full integration test of the entire workflow."""
    api_tokens = {
        Role.USER: 'user_token',
        Role.ADMIN: 'admin_token'
    }

    builder = PrivilegeEscalationChainBuilder(
        target_url="https://test.example.com",
        api_tokens=api_tokens,
        domain="test.example.com"
    )

    # Mock all external dependencies
    with patch('engine.core.db_hooks.DatabaseHooks.before_test') as mock_before, \
         patch.object(builder.session, 'get') as mock_get, \
         patch.object(builder.session, 'post') as mock_post, \
         patch.object(builder.session, 'put') as mock_put, \
         patch.object(builder.session, 'delete') as mock_delete, \
         patch.object(builder.db, 'record_tool_run'):

        mock_before.return_value = {
            'should_skip': False,
            'reason': 'Safe to test',
            'previous_findings': [],
            'recommendations': []
        }

        # Mock successful endpoint discovery
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = '{"role": "admin"}'
        mock_post.return_value.status_code = 201
        mock_put.return_value.status_code = 200
        mock_delete.return_value.status_code = 204

        chains = await builder.discover_and_exploit()

        # Verify execution
        assert builder.endpoints is not None
        report = builder.generate_report()
        assert 'summary' in report
        assert 'chains' in report
