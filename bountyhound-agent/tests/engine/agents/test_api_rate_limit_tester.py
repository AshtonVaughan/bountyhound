"""
Tests for API Rate Limit Tester Agent

Comprehensive test suite with 30+ tests targeting 95%+ coverage.
"""

import pytest
import asyncio
import aiohttp
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import date

from engine.agents.api_rate_limit_tester import (
    ApiRateLimitTester,
    RateLimitProfile,
    RateLimitVulnerability,
    RateLimitSeverity,
    RateLimitVulnType
)


@pytest.fixture
def mock_db_hooks():
    """Mock DatabaseHooks to prevent actual database access."""
    with patch('engine.agents.api_rate_limit_tester.DatabaseHooks') as mock:
        mock.before_test.return_value = {
            'should_skip': False,
            'reason': 'Test mode',
            'previous_findings': [],
            'recommendations': ['Test'],
            'last_tested_days': None
        }
        yield mock


@pytest.fixture
def mock_payload_hooks():
    """Mock PayloadHooks."""
    with patch('engine.agents.api_rate_limit_tester.PayloadHooks') as mock:
        yield mock


@pytest.fixture
def tester():
    """Create a tester instance."""
    return ApiRateLimitTester("example.com", api_key="test_key")


@pytest.fixture
def sample_profile():
    """Create a sample rate limit profile."""
    return RateLimitProfile(
        endpoint="/api/test",
        threshold=10,
        window_seconds=60,
        reset_behavior="fixed",
        headers_present=True,
        bypass_vectors=[],
        rate_limit_headers={"X-RateLimit-Limit": "10"}
    )


class TestInitialization:
    """Test agent initialization."""

    def test_init_with_defaults(self):
        """Test initialization with default parameters."""
        tester = ApiRateLimitTester("example.com")

        assert tester.target_domain == "example.com"
        assert tester.base_url == "https://example.com"
        assert tester.api_key is None
        assert tester.timeout == 30
        assert tester.verify_ssl is True
        assert tester.session is None
        assert len(tester.findings) == 0
        assert len(tester.profiles) == 0

    def test_init_with_custom_params(self):
        """Test initialization with custom parameters."""
        tester = ApiRateLimitTester(
            "test.com",
            api_key="secret",
            timeout=60,
            verify_ssl=False
        )

        assert tester.target_domain == "test.com"
        assert tester.api_key == "secret"
        assert tester.timeout == 60
        assert tester.verify_ssl is False

    def test_constants(self):
        """Test class constants are defined."""
        assert len(ApiRateLimitTester.SPOOFING_HEADERS) >= 8
        assert len(ApiRateLimitTester.USER_AGENTS) >= 7
        assert "X-Forwarded-For" in ApiRateLimitTester.SPOOFING_HEADERS
        assert "curl/7.68.0" in ApiRateLimitTester.USER_AGENTS


class TestContextManager:
    """Test async context manager."""

    @pytest.mark.asyncio
    async def test_async_context_manager_enter(self):
        """Test __aenter__ creates session."""
        tester = ApiRateLimitTester("example.com")

        async with tester:
            assert tester.session is not None
            assert isinstance(tester.session, aiohttp.ClientSession)

    @pytest.mark.asyncio
    async def test_async_context_manager_exit(self):
        """Test __aexit__ closes session."""
        tester = ApiRateLimitTester("example.com")

        async with tester:
            session = tester.session

        # Session should be closed after exiting context
        assert session.closed


class TestDataClasses:
    """Test data classes."""

    def test_rate_limit_profile_creation(self):
        """Test RateLimitProfile creation."""
        profile = RateLimitProfile(
            endpoint="/api/test",
            threshold=100,
            window_seconds=60,
            reset_behavior="sliding",
            headers_present=True
        )

        assert profile.endpoint == "/api/test"
        assert profile.threshold == 100
        assert profile.window_seconds == 60
        assert profile.reset_behavior == "sliding"
        assert profile.headers_present is True
        assert len(profile.bypass_vectors) == 0

    def test_rate_limit_vulnerability_creation(self):
        """Test RateLimitVulnerability creation."""
        vuln = RateLimitVulnerability(
            endpoint="/api/login",
            vuln_type=RateLimitVulnType.MISSING_RATE_LIMIT,
            severity=RateLimitSeverity.HIGH,
            description="No rate limit",
            poc="curl test",
            remediation="Add rate limit",
            bounty_estimate="$1000-$5000",
            exploit_complexity="Low"
        )

        assert vuln.endpoint == "/api/login"
        assert vuln.vuln_type == RateLimitVulnType.MISSING_RATE_LIMIT
        assert vuln.severity == RateLimitSeverity.HIGH
        assert vuln.discovered_date == date.today().isoformat()

    def test_vulnerability_to_dict(self):
        """Test vulnerability serialization."""
        vuln = RateLimitVulnerability(
            endpoint="/api/test",
            vuln_type=RateLimitVulnType.IP_SPOOFING_BYPASS,
            severity=RateLimitSeverity.CRITICAL,
            description="Test",
            poc="Test",
            remediation="Test",
            bounty_estimate="$1000",
            exploit_complexity="Low",
            evidence={"key": "value"}
        )

        data = vuln.to_dict()

        assert isinstance(data, dict)
        assert data['severity'] == 'CRITICAL'
        assert data['vuln_type'] == 'IP_SPOOFING_BYPASS'
        assert data['evidence'] == {"key": "value"}


class TestProfileRateLimit:
    """Test rate limit profiling."""

    @pytest.mark.asyncio
    async def test_profile_no_rate_limit(self, mock_db_hooks, mock_payload_hooks):
        """Test profiling endpoint with no rate limit."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - all 200 OK
        mock_responses = [
            AsyncMock(status=200, headers={}) for _ in range(50)
        ]

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                profile = await tester.profile_rate_limit("/api/test")

                # Should return None and create a finding
                assert profile is None
                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.MISSING_RATE_LIMIT
                assert tester.findings[0].severity == RateLimitSeverity.HIGH

    @pytest.mark.asyncio
    async def test_profile_with_rate_limit(self, mock_db_hooks):
        """Test profiling endpoint with rate limit."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - 10 OK, then 429s
        mock_responses = []
        for i in range(50):
            if i < 10:
                mock_responses.append(AsyncMock(status=200, headers={}))
            else:
                mock_responses.append(AsyncMock(
                    status=429,
                    headers={"X-RateLimit-Limit": "10", "Retry-After": "60"}
                ))

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                profile = await tester.profile_rate_limit("/api/test")

                # Should return profile
                assert profile is not None
                assert profile.endpoint == "/api/test"
                assert profile.threshold == 10
                assert profile.headers_present is True
                assert profile.reset_behavior == "fixed"
                assert "X-RateLimit-Limit" in profile.rate_limit_headers

    @pytest.mark.asyncio
    async def test_profile_sliding_window(self, mock_db_hooks):
        """Test profiling sliding window rate limit."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - intermittent 429s (sliding window)
        mock_responses = []
        for i in range(50):
            if i % 5 == 0:
                mock_responses.append(AsyncMock(status=429, headers={}))
            else:
                mock_responses.append(AsyncMock(status=200, headers={}))

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                profile = await tester.profile_rate_limit("/api/test")

                assert profile is not None
                assert profile.reset_behavior == "sliding"

    @pytest.mark.asyncio
    async def test_profile_error_handling(self, mock_db_hooks):
        """Test profiling handles errors gracefully."""
        tester = ApiRateLimitTester("example.com")

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = Exception("Network error")

                profile = await tester.profile_rate_limit("/api/test")

                # Should handle error and return None
                assert profile is None


class TestIPSpoofingBypass:
    """Test IP spoofing bypass detection."""

    @pytest.mark.asyncio
    async def test_ip_spoofing_bypass_found(self, sample_profile, mock_db_hooks):
        """Test detection of IP spoofing bypass."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - all succeed (bypass works)
        mock_responses = [
            AsyncMock(status=200, headers={}) for _ in range(30)
        ]

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                await tester.test_ip_spoofing_bypass("/api/test", sample_profile)

                # Should find bypass
                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.IP_SPOOFING_BYPASS
                assert tester.findings[0].severity == RateLimitSeverity.HIGH

    @pytest.mark.asyncio
    async def test_ip_spoofing_no_bypass(self, sample_profile, mock_db_hooks):
        """Test when IP spoofing doesn't work."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - many 429s (bypass doesn't work)
        mock_responses = []
        for i in range(30):
            if i < 10:
                mock_responses.append(AsyncMock(status=200, headers={}))
            else:
                mock_responses.append(AsyncMock(status=429, headers={}))

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                await tester.test_ip_spoofing_bypass("/api/test", sample_profile)

                # Should not find bypass
                assert len(tester.findings) == 0


class TestHeaderManipulation:
    """Test header manipulation bypass detection."""

    @pytest.mark.asyncio
    async def test_user_agent_bypass(self, sample_profile, mock_db_hooks):
        """Test User-Agent rotation bypass."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - all succeed
        mock_responses = [
            AsyncMock(status=200, headers={}) for _ in range(30)
        ]

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                await tester._test_user_agent_bypass("/api/test", sample_profile)

                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.USER_AGENT_BYPASS
                assert tester.findings[0].severity == RateLimitSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_origin_bypass(self, sample_profile, mock_db_hooks):
        """Test Origin header bypass."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - all succeed
        mock_responses = [
            AsyncMock(status=200, headers={}) for _ in range(30)
        ]

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                await tester._test_origin_bypass("/api/test", sample_profile)

                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.ORIGIN_BYPASS

    @pytest.mark.asyncio
    async def test_header_manipulation_no_bypass(self, sample_profile, mock_db_hooks):
        """Test when header manipulation doesn't work."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - rate limited
        mock_responses = [AsyncMock(status=429, headers={}) for _ in range(30)]

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                await tester.test_header_manipulation("/api/test", sample_profile)

                assert len(tester.findings) == 0


class TestEndpointVariations:
    """Test endpoint variation bypass detection."""

    @pytest.mark.asyncio
    async def test_endpoint_variation_bypass(self, sample_profile, mock_db_hooks):
        """Test endpoint variation bypass."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - all succeed
        mock_responses = [
            AsyncMock(status=200, headers={}) for _ in range(100)
        ]

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                await tester.test_endpoint_variations("/api/v1/test", sample_profile)

                # Should find at least one variation bypass
                variations = [f for f in tester.findings if f.vuln_type == RateLimitVulnType.ENDPOINT_VARIATION_BYPASS]
                assert len(variations) >= 1

    @pytest.mark.asyncio
    async def test_endpoint_variation_404(self, sample_profile, mock_db_hooks):
        """Test endpoint variations that return 404."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - all 404
        mock_responses = [AsyncMock(status=404, headers={}) for _ in range(100)]

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                await tester.test_endpoint_variations("/api/v1/test", sample_profile)

                assert len(tester.findings) == 0


class TestSessionBypass:
    """Test session-based bypass detection."""

    @pytest.mark.asyncio
    async def test_session_bypass(self, sample_profile, mock_db_hooks):
        """Test session multiplication bypass."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - all succeed
        mock_responses = [
            AsyncMock(status=200, headers={}) for _ in range(100)
        ]

        # Mock session creation
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_sessions = []
            for _ in range(5):
                mock_session = AsyncMock()
                mock_session.get = AsyncMock(side_effect=mock_responses)
                mock_session.close = AsyncMock()
                mock_sessions.append(mock_session)

            mock_session_class.side_effect = mock_sessions

            async with tester:
                await tester.test_session_bypass("/api/test", sample_profile)

                # Should find bypass
                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.SESSION_BYPASS


class TestGraphQLBypass:
    """Test GraphQL-specific bypass detection."""

    @pytest.mark.asyncio
    async def test_graphql_batch_bypass(self, sample_profile, mock_db_hooks):
        """Test GraphQL batch query bypass."""
        tester = ApiRateLimitTester("example.com")

        # Mock batch success, single query rate limited
        mock_batch_response = AsyncMock(
            status=200,
            text=AsyncMock(return_value='{"data": [{"__typename": "Query"}]}')
        )
        mock_single_response = AsyncMock(status=429)

        async with tester:
            with patch.object(tester.session, 'post') as mock_post:
                # First call is batch (succeeds), subsequent are single (rate limited)
                mock_post.side_effect = [mock_batch_response] + [mock_single_response] * 20

                await tester.test_graphql_batching("/graphql", sample_profile)

                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.GRAPHQL_BATCH_BYPASS

    @pytest.mark.asyncio
    async def test_graphql_alias_bypass(self, sample_profile, mock_db_hooks):
        """Test GraphQL alias multiplication."""
        tester = ApiRateLimitTester("example.com")

        # Mock response with all aliases
        response_body = '{"data": {' + ', '.join([f'"alias{i}": "Query"' for i in range(20)]) + '}}'
        mock_response = AsyncMock(
            status=200,
            text=AsyncMock(return_value=response_body)
        )

        async with tester:
            with patch.object(tester.session, 'post') as mock_post:
                mock_post.return_value.__aenter__.return_value = mock_response

                await tester._test_graphql_aliases("/graphql", sample_profile)

                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.GRAPHQL_ALIAS_BYPASS


class TestBruteForce:
    """Test brute force feasibility detection."""

    @pytest.mark.asyncio
    async def test_login_brute_force_feasible(self, mock_db_hooks):
        """Test login brute force detection."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - all succeed (no rate limit)
        mock_responses = [
            AsyncMock(status=200, headers={}) for _ in range(50)
        ]

        async with tester:
            with patch.object(tester.session, 'post') as mock_post:
                mock_post.side_effect = mock_responses

                await tester._test_login_brute_force("/api/login")

                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.CREDENTIAL_BRUTE_FORCE
                assert tester.findings[0].severity in [RateLimitSeverity.CRITICAL, RateLimitSeverity.HIGH]

    @pytest.mark.asyncio
    async def test_otp_brute_force_critical(self, mock_db_hooks):
        """Test OTP brute force (critical)."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - all succeed
        mock_responses = [
            AsyncMock(status=200, headers={}) for _ in range(100)
        ]

        async with tester:
            with patch.object(tester.session, 'post') as mock_post:
                mock_post.side_effect = mock_responses

                await tester._test_otp_brute_force("/api/otp/verify")

                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.OTP_BRUTE_FORCE
                assert tester.findings[0].severity == RateLimitSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_otp_brute_force_with_ip_rotation(self, mock_db_hooks):
        """Test OTP brute force with IP rotation."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - 30% succeed (need IP rotation)
        mock_responses = []
        for i in range(100):
            if i % 3 == 0:
                mock_responses.append(AsyncMock(status=200, headers={}))
            else:
                mock_responses.append(AsyncMock(status=429, headers={}))

        async with tester:
            with patch.object(tester.session, 'post') as mock_post:
                mock_post.side_effect = mock_responses

                await tester._test_otp_brute_force("/api/otp/verify")

                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.OTP_BRUTE_FORCE_IP_ROTATION
                assert tester.findings[0].severity == RateLimitSeverity.HIGH


class TestRaceConditions:
    """Test race condition detection."""

    @pytest.mark.asyncio
    async def test_race_condition_found(self, sample_profile, mock_db_hooks):
        """Test race condition detection."""
        tester = ApiRateLimitTester("example.com")

        # Mock responses - many succeed (race condition)
        mock_responses = [
            AsyncMock(status=200, headers={}, read=AsyncMock()) for _ in range(20)
        ]

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                # Return mock response objects
                async def mock_get_func(*args, **kwargs):
                    resp = mock_responses.pop(0) if mock_responses else AsyncMock(status=429)
                    return resp

                mock_get.side_effect = mock_get_func

                # Re-populate for the test
                mock_responses = [
                    AsyncMock(status=200, headers={}, read=AsyncMock()) for _ in range(20)
                ]

                await tester.test_race_conditions("/api/test", sample_profile)

                assert len(tester.findings) == 1
                assert tester.findings[0].vuln_type == RateLimitVulnType.RACE_CONDITION


class TestFullScan:
    """Test full scan workflow."""

    @pytest.mark.asyncio
    async def test_run_full_scan_skip_target(self, mock_db_hooks):
        """Test full scan skips target based on database."""
        mock_db_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested recently',
            'previous_findings': [],
            'recommendations': ['Skip this target'],
            'last_tested_days': 3
        }

        tester = ApiRateLimitTester("example.com")

        async with tester:
            findings = await tester.run_full_scan(["/api/test"])

            # Should return empty list
            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_run_full_scan_integration(self, mock_db_hooks, mock_payload_hooks):
        """Test full scan integration."""
        tester = ApiRateLimitTester("example.com")

        # Mock profiling to return no rate limit
        mock_responses = [
            AsyncMock(status=200, headers={}) for _ in range(100)
        ]

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = mock_responses

                findings = await tester.run_full_scan(["/api/login"])

                # Should find at least missing rate limit
                assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_run_full_scan_auth_endpoints(self, mock_db_hooks, mock_payload_hooks):
        """Test full scan prioritizes auth endpoints."""
        tester = ApiRateLimitTester("example.com")

        mock_responses = [
            AsyncMock(status=200, headers={}) for _ in range(200)
        ]

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                with patch.object(tester.session, 'post') as mock_post:
                    mock_get.side_effect = mock_responses
                    mock_post.side_effect = mock_responses.copy()

                    findings = await tester.run_full_scan([
                        "/api/login",
                        "/api/otp/verify",
                        "/api/users"
                    ])

                    # Should test auth endpoints
                    assert len(findings) >= 1


class TestSummary:
    """Test summary generation."""

    def test_get_summary_empty(self):
        """Test summary with no findings."""
        tester = ApiRateLimitTester("example.com")

        summary = tester.get_summary()

        assert summary['target'] == "example.com"
        assert summary['total_findings'] == 0
        assert summary['vulnerable'] is False
        assert summary['critical_count'] == 0

    def test_get_summary_with_findings(self, sample_profile):
        """Test summary with findings."""
        tester = ApiRateLimitTester("example.com")

        # Add some findings
        tester.findings.append(RateLimitVulnerability(
            endpoint="/api/test",
            vuln_type=RateLimitVulnType.MISSING_RATE_LIMIT,
            severity=RateLimitSeverity.CRITICAL,
            description="Test",
            poc="Test",
            remediation="Test",
            bounty_estimate="$1000",
            exploit_complexity="Low"
        ))

        tester.findings.append(RateLimitVulnerability(
            endpoint="/api/test2",
            vuln_type=RateLimitVulnType.IP_SPOOFING_BYPASS,
            severity=RateLimitSeverity.HIGH,
            description="Test",
            poc="Test",
            remediation="Test",
            bounty_estimate="$1000",
            exploit_complexity="Low"
        ))

        tester.profiles["/api/test"] = sample_profile

        summary = tester.get_summary()

        assert summary['total_findings'] == 2
        assert summary['vulnerable'] is True
        assert summary['critical_count'] == 1
        assert summary['severity_breakdown']['CRITICAL'] == 1
        assert summary['severity_breakdown']['HIGH'] == 1
        assert len(summary['endpoints_tested']) == 1


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_empty_endpoint_list(self, mock_db_hooks):
        """Test scan with empty endpoint list."""
        tester = ApiRateLimitTester("example.com")

        async with tester:
            findings = await tester.run_full_scan([])

            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_network_error_handling(self, mock_db_hooks):
        """Test handling of network errors."""
        tester = ApiRateLimitTester("example.com")

        async with tester:
            with patch.object(tester.session, 'get') as mock_get:
                mock_get.side_effect = aiohttp.ClientError("Network error")

                # Should not crash
                profile = await tester.profile_rate_limit("/api/test")
                assert profile is None

    @pytest.mark.asyncio
    async def test_graphql_non_graphql_endpoint(self, sample_profile, mock_db_hooks):
        """Test GraphQL tests on non-GraphQL endpoint."""
        tester = ApiRateLimitTester("example.com")

        async with tester:
            with patch.object(tester.session, 'post') as mock_post:
                mock_post.side_effect = Exception("Not GraphQL")

                # Should handle gracefully
                await tester.test_graphql_batching("/api/rest", sample_profile)

    def test_enums_defined(self):
        """Test all enums are properly defined."""
        # Test severity enum
        assert RateLimitSeverity.CRITICAL.value == "CRITICAL"
        assert RateLimitSeverity.HIGH.value == "HIGH"

        # Test vuln type enum
        assert RateLimitVulnType.MISSING_RATE_LIMIT.value == "MISSING_RATE_LIMIT"
        assert RateLimitVulnType.IP_SPOOFING_BYPASS.value == "IP_SPOOFING_BYPASS"


class TestPayloadLearning:
    """Test payload learning integration."""

    @pytest.mark.asyncio
    async def test_payload_recording(self, mock_db_hooks, mock_payload_hooks):
        """Test successful payloads are recorded."""
        tester = ApiRateLimitTester("example.com")

        # Add a finding
        tester.findings.append(RateLimitVulnerability(
            endpoint="/api/test",
            vuln_type=RateLimitVulnType.IP_SPOOFING_BYPASS,
            severity=RateLimitSeverity.CRITICAL,
            description="Test",
            poc="Test",
            remediation="Test",
            bounty_estimate="$1000",
            exploit_complexity="Low",
            evidence={'bypass_pattern': 'X-Forwarded-For: 1.2.3.4'}
        ))

        async with tester:
            await tester.run_full_scan([])

            # Should record payload
            assert mock_payload_hooks.record_payload_success.called


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=engine.agents.api_rate_limit_tester", "--cov-report=term-missing"])
