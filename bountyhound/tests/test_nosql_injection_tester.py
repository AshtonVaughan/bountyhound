"""
Test suite for NoSQL Injection Tester Agent

Tests all major functionality:
- MongoDB operator injection
- Redis command injection
- Elasticsearch query injection
- CouchDB Mango query injection
- Authentication bypass
- Blind injection detection
- JavaScript injection
- Database fingerprinting
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from engine.agents.nosql_injection_tester import (
    NoSQLInjectionTester,
    NoSQLType,
    InjectionType,
    NoSQLFinding
)


class TestNoSQLInjectionTester:
    """Test suite for NoSQL Injection Tester."""

    @pytest.fixture
    def tester(self):
        """Create tester instance."""
        return NoSQLInjectionTester(
            target_url="https://api.example.com/login",
            target="example.com"
        )

    @pytest.mark.asyncio
    async def test_mongodb_detection(self, tester):
        """Test MongoDB fingerprinting."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value="MongoError: Invalid query")
        mock_session.post = AsyncMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))

        result = await tester._detect_mongodb(mock_session)
        assert result is True

    @pytest.mark.asyncio
    async def test_redis_detection(self, tester):
        """Test Redis fingerprinting."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value="-ERR unknown command")
        mock_session.post = AsyncMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))

        result = await tester._detect_redis(mock_session)
        assert result is True

    @pytest.mark.asyncio
    async def test_elasticsearch_detection(self, tester):
        """Test Elasticsearch fingerprinting."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"cluster_name": "test-cluster"})
        mock_session.get = AsyncMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))

        result = await tester._detect_elasticsearch(mock_session)
        assert result is True

    @pytest.mark.asyncio
    async def test_couchdb_detection(self, tester):
        """Test CouchDB fingerprinting."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"couchdb": "Welcome", "version": "3.0.0"})
        mock_session.get = AsyncMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))

        result = await tester._detect_couchdb(mock_session)
        assert result is True

    @pytest.mark.asyncio
    async def test_mongodb_auth_bypass_detection(self, tester):
        """Test MongoDB authentication bypass detection."""
        # Mock successful auth bypass
        mock_response = MagicMock()
        mock_response.status = 200
        mock_text = '{"token": "jwt_token_here", "user": "admin"}'

        with patch.object(tester, '_make_request', return_value=(mock_response, mock_text)):
            await tester._test_mongo_auth_bypass({"password": {"$ne": None}})

        assert len(tester.findings) == 1
        assert tester.findings[0].severity == "CRITICAL"
        assert tester.findings[0].injection_type == InjectionType.AUTH_BYPASS

    @pytest.mark.asyncio
    async def test_mongodb_operator_injection(self, tester):
        """Test MongoDB operator injection detection."""
        # Mock data leak response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_text = '[{"_id": "123", "email": "user@example.com", "password": "hash"}]'

        with patch.object(tester, '_make_request', return_value=(mock_response, mock_text)):
            with patch.object(tester, '_has_data_leak', return_value=True):
                await tester._test_mongo_operator_injection({"username": {"$gt": ""}})

        assert len(tester.findings) == 1
        assert tester.findings[0].severity == "HIGH"
        assert tester.findings[0].db_type == NoSQLType.MONGODB

    @pytest.mark.asyncio
    async def test_redis_crlf_injection(self, tester):
        """Test Redis CRLF injection detection."""
        # Mock Redis response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_text = "+OK\r\n$4\r\ntest\r\n"

        with patch.object(tester, '_make_request', return_value=(mock_response, mock_text)):
            await tester._test_redis_crlf("\r\nKEYS *\r\n")

        assert len(tester.findings) == 1
        assert tester.findings[0].severity in ["CRITICAL", "HIGH"]
        assert tester.findings[0].db_type == NoSQLType.REDIS

    @pytest.mark.asyncio
    async def test_timing_based_injection(self, tester):
        """Test blind timing-based injection detection."""
        # Mock slow response (5+ seconds)
        import time

        async def slow_request(*args, **kwargs):
            await asyncio.sleep(0.1)  # Simulate in test
            mock_response = MagicMock()
            mock_response.status = 200
            return (mock_response, "")

        with patch.object(tester, '_make_request', side_effect=slow_request):
            with patch('time.time', side_effect=[0, 5.5]):  # Mock 5.5s elapsed
                await tester._test_timing_injection({"password": {"$where": "sleep(5000)"}})

        assert len(tester.findings) == 1
        assert tester.findings[0].injection_type == InjectionType.TIMING_INJECTION

    @pytest.mark.asyncio
    async def test_javascript_injection(self, tester):
        """Test JavaScript injection detection."""
        # Mock successful JS execution
        mock_response = MagicMock()
        mock_response.status = 200
        mock_text = '[{"username": "admin", "data": "leaked"}]'

        with patch.object(tester, '_make_request', return_value=(mock_response, mock_text)):
            with patch.object(tester, '_has_data_leak', return_value=True):
                await tester._test_mongo_js_injection({"username": {"$where": "function(){return true}"}})

        assert len(tester.findings) == 1
        assert tester.findings[0].injection_type == InjectionType.JAVASCRIPT_INJECTION

    @pytest.mark.asyncio
    async def test_elasticsearch_query_injection(self, tester):
        """Test Elasticsearch query injection detection."""
        tester.db_types.add(NoSQLType.ELASTICSEARCH)

        # Mock Elasticsearch response with hits
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "hits": {
                    "hits": [
                        {"_source": {"email": "user@example.com", "password": "hash"}}
                    ]
                }
            })
            mock_session.post.return_value.__aenter__.return_value = mock_response
            mock_session_class.return_value.__aenter__.return_value = mock_session

            await tester._test_es_injection({"query": {"match_all": {}}})

        assert len(tester.findings) == 1
        assert tester.findings[0].db_type == NoSQLType.ELASTICSEARCH

    @pytest.mark.asyncio
    async def test_couchdb_mango_injection(self, tester):
        """Test CouchDB Mango query injection detection."""
        tester.db_types.add(NoSQLType.COUCHDB)

        # Mock CouchDB response with documents
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "docs": [
                    {"_id": "doc1", "email": "user@example.com"}
                ]
            })
            mock_session.post.return_value.__aenter__.return_value = mock_response
            mock_session_class.return_value.__aenter__.return_value = mock_session

            await tester._test_couchdb_mango({"selector": {"$gt": None}})

        assert len(tester.findings) == 1
        assert tester.findings[0].db_type == NoSQLType.COUCHDB

    def test_data_leak_detection(self, tester):
        """Test data leak indicator detection."""
        # Positive cases
        assert tester._has_data_leak('[{"_id": "123", "email": "test@example.com"}]')
        assert tester._has_data_leak('{"users": [{"password": "hash"}]}')
        assert tester._has_data_leak('{"data": [{"email": "test@example.com"}]}')

        # Negative cases
        assert not tester._has_data_leak('{"status": "ok"}')
        assert not tester._has_data_leak('error')
        assert not tester._has_data_leak('')
        assert not tester._has_data_leak('[]')

    def test_get_findings_by_severity(self, tester):
        """Test filtering findings by severity."""
        # Add mock findings
        tester.findings = [
            NoSQLFinding(
                finding_id="1",
                severity="CRITICAL",
                title="Test Critical",
                description="Test",
                db_type=NoSQLType.MONGODB,
                injection_type=InjectionType.AUTH_BYPASS,
                endpoint="test",
                parameter="test",
                payload="test",
                evidence={},
                impact="test",
                remediation="test",
                bounty_estimate="$1000"
            ),
            NoSQLFinding(
                finding_id="2",
                severity="HIGH",
                title="Test High",
                description="Test",
                db_type=NoSQLType.REDIS,
                injection_type=InjectionType.COMMAND_INJECTION,
                endpoint="test",
                parameter="test",
                payload="test",
                evidence={},
                impact="test",
                remediation="test",
                bounty_estimate="$500"
            )
        ]

        critical = tester.get_findings_by_severity("CRITICAL")
        assert len(critical) == 1
        assert critical[0].severity == "CRITICAL"

        high = tester.get_findings_by_severity("HIGH")
        assert len(high) == 1
        assert high[0].severity == "HIGH"

    def test_get_findings_by_db_type(self, tester):
        """Test filtering findings by database type."""
        # Add mock findings
        tester.findings = [
            NoSQLFinding(
                finding_id="1",
                severity="HIGH",
                title="MongoDB Test",
                description="Test",
                db_type=NoSQLType.MONGODB,
                injection_type=InjectionType.OPERATOR_INJECTION,
                endpoint="test",
                parameter="test",
                payload="test",
                evidence={},
                impact="test",
                remediation="test",
                bounty_estimate="$1000"
            ),
            NoSQLFinding(
                finding_id="2",
                severity="HIGH",
                title="Redis Test",
                description="Test",
                db_type=NoSQLType.REDIS,
                injection_type=InjectionType.COMMAND_INJECTION,
                endpoint="test",
                parameter="test",
                payload="test",
                evidence={},
                impact="test",
                remediation="test",
                bounty_estimate="$1000"
            )
        ]

        mongo_findings = tester.get_findings_by_db_type(NoSQLType.MONGODB)
        assert len(mongo_findings) == 1
        assert mongo_findings[0].db_type == NoSQLType.MONGODB

        redis_findings = tester.get_findings_by_db_type(NoSQLType.REDIS)
        assert len(redis_findings) == 1
        assert redis_findings[0].db_type == NoSQLType.REDIS

    def test_get_summary(self, tester):
        """Test summary generation."""
        tester.db_types.add(NoSQLType.MONGODB)
        tester.tests_run = 50

        # Add mock findings
        tester.findings = [
            NoSQLFinding(
                finding_id="1",
                severity="CRITICAL",
                title="Test",
                description="Test",
                db_type=NoSQLType.MONGODB,
                injection_type=InjectionType.AUTH_BYPASS,
                endpoint="test",
                parameter="test",
                payload="test",
                evidence={},
                impact="test",
                remediation="test",
                bounty_estimate="$1000"
            )
        ]

        summary = tester.get_summary()

        assert summary['target'] == tester.target_url
        assert summary['total_tests'] == 50
        assert summary['total_findings'] == 1
        assert summary['severity_breakdown']['CRITICAL'] == 1
        assert summary['vulnerable'] is True
        assert 'mongodb' in summary['database_types_detected']

    @pytest.mark.asyncio
    async def test_database_integration(self, tester):
        """Test database hooks integration."""
        with patch('engine.core.db_hooks.DatabaseHooks.before_test') as mock_before_test:
            mock_before_test.return_value = {
                'should_skip': False,
                'reason': 'Never tested before',
                'previous_findings': [],
                'recommendations': ['Full test recommended'],
                'last_tested_days': None
            }

            with patch('engine.core.database.BountyHoundDB'):
                with patch('engine.core.payload_hooks.PayloadHooks.get_payloads_by_type', return_value=[]):
                    with patch.object(tester, '_establish_timing_baseline'):
                        with patch.object(tester, '_fingerprint_database'):
                            findings = await tester.test_all()

            mock_before_test.assert_called_once_with('example.com', 'nosql_injection_tester')

    def test_finding_to_dict(self, tester):
        """Test finding serialization."""
        finding = NoSQLFinding(
            finding_id="TEST-1",
            severity="HIGH",
            title="Test Finding",
            description="Test description",
            db_type=NoSQLType.MONGODB,
            injection_type=InjectionType.OPERATOR_INJECTION,
            endpoint="https://api.example.com/test",
            parameter="username",
            payload='{"username": {"$gt": ""}}',
            evidence={"test": "data"},
            impact="Test impact",
            remediation="Test remediation",
            bounty_estimate="$2000-$5000"
        )

        finding_dict = finding.to_dict()

        assert finding_dict['finding_id'] == "TEST-1"
        assert finding_dict['severity'] == "HIGH"
        assert finding_dict['db_type'] == "mongodb"
        assert finding_dict['injection_type'] == "operator_injection"
        assert finding_dict['cwe_id'] == "CWE-943"


@pytest.mark.asyncio
async def test_full_test_run():
    """Integration test for full test run."""
    tester = NoSQLInjectionTester(
        target_url="https://api.example.com/login",
        target="example.com"
    )

    # Mock all external dependencies
    with patch('engine.core.db_hooks.DatabaseHooks.before_test') as mock_before_test:
        mock_before_test.return_value = {
            'should_skip': False,
            'reason': 'Testing allowed',
            'previous_findings': [],
            'recommendations': [],
            'last_tested_days': None
        }

        with patch('engine.core.database.BountyHoundDB'):
            with patch('engine.core.payload_hooks.PayloadHooks.get_payloads_by_type', return_value=[]):
                with patch.object(tester, '_make_request', return_value=None):
                    findings = await tester.test_all()

    # Should complete without errors
    assert isinstance(findings, list)
    assert tester.tests_run > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
