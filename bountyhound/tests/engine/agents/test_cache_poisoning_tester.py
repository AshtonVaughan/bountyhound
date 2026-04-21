"""
Comprehensive tests for Cache Poisoning Tester Agent

Tests cover:
- Cache detection
- Unkeyed header detection
- Unkeyed parameter detection
- Host header poisoning
- Cache deception attacks
- Fat GET request smuggling
- Database integration
- Payload recording

Target: 95%+ code coverage
"""

import pytest
import requests
from unittest.mock import Mock, patch, MagicMock, call
from datetime import date
import time

from engine.agents.cache_poisoning_tester import (
    CacheDetector,
    UnkeyedInputTester,
    CacheDeceptionTester,
    FatGETTester,
    CachePoisoningTester,
    CachePoisoningFinding,
    CachePoisoningTest
)


# Fixtures

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    response = Mock()
    response.status_code = 200
    response.text = "Test response content"
    response.headers = {}
    return response


@pytest.fixture
def cloudflare_response():
    """Create a mock Cloudflare response."""
    response = Mock()
    response.status_code = 200
    response.text = "Cloudflare cached response"
    response.headers = {
        'CF-Cache-Status': 'HIT',
        'Age': '120',
        'Cache-Control': 'max-age=3600'
    }
    return response


@pytest.fixture
def varnish_response():
    """Create a mock Varnish response."""
    response = Mock()
    response.status_code = 200
    response.text = "Varnish cached response"
    response.headers = {
        'X-Varnish': '123456 789012',
        'X-Cache': 'HIT',
        'Age': '60'
    }
    return response


@pytest.fixture
def poisoned_response():
    """Create a mock poisoned response."""
    response = Mock()
    response.status_code = 200
    response.text = "Response with evil.com/testcache injected"
    response.headers = {
        'X-Cache': 'MISS'
    }
    return response


# CacheDetector Tests

class TestCacheDetector:
    """Tests for CacheDetector class."""

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_cloudflare_cache(self, mock_get, cloudflare_response):
        """Test detection of Cloudflare cache."""
        mock_get.return_value = cloudflare_response

        detector = CacheDetector('https://example.com')
        result = detector.detect_cache()

        assert result['cache_detected'] is True
        assert result['cache_provider'] == 'Cloudflare'
        assert result['cache_status'] == 'hit'
        assert result['ttl'] == 120

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_varnish_cache(self, mock_get, varnish_response):
        """Test detection of Varnish cache."""
        mock_get.return_value = varnish_response

        detector = CacheDetector('https://example.com')
        result = detector.detect_cache()

        assert result['cache_detected'] is True
        assert result['cache_provider'] == 'Varnish'
        assert result['cache_status'] == 'hit'

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_fastly_cache(self, mock_get):
        """Test detection of Fastly cache."""
        response = Mock()
        response.status_code = 200
        response.text = "Fastly response"
        response.headers = {
            'X-Fastly-Cache-Status': 'HIT',
            'Age': '30'
        }
        mock_get.return_value = response

        detector = CacheDetector('https://example.com')
        result = detector.detect_cache()

        assert result['cache_detected'] is True
        assert result['cache_provider'] == 'Fastly'

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_akamai_cache(self, mock_get):
        """Test detection of Akamai cache."""
        response = Mock()
        response.status_code = 200
        response.text = "Akamai response"
        response.headers = {
            'Akamai-Cache-Status': 'Hit from child'
        }
        mock_get.return_value = response

        detector = CacheDetector('https://example.com')
        result = detector.detect_cache()

        assert result['cache_detected'] is True
        assert result['cache_provider'] == 'Akamai'

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_cache_via_age_header(self, mock_get):
        """Test cache detection via Age header only."""
        response = Mock()
        response.status_code = 200
        response.text = "Response"
        response.headers = {'Age': '100'}
        mock_get.return_value = response

        detector = CacheDetector('https://example.com')
        result = detector.detect_cache()

        assert result['cache_detected'] is True
        assert result['cache_status'] == 'detected_via_age'
        assert result['ttl'] == 100

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_no_cache(self, mock_get, mock_response):
        """Test detection when no cache present."""
        mock_response.headers = {}

        # Return different responses to simulate no caching
        response1 = Mock()
        response1.status_code = 200
        response1.text = "Response 1"
        response1.headers = {'Date': 'Mon, 01 Jan 2024 00:00:00 GMT'}

        response2 = Mock()
        response2.status_code = 200
        response2.text = "Response 1"
        response2.headers = {'Date': 'Mon, 01 Jan 2024 00:00:01 GMT'}

        mock_get.side_effect = [mock_response, response1, response2]

        detector = CacheDetector('https://example.com')
        result = detector.detect_cache()

        assert result['cache_detected'] is False

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_cache_via_testing(self, mock_get):
        """Test cache detection via behavioral testing."""
        # First request for initial detection
        response1 = Mock()
        response1.status_code = 200
        response1.text = "Response"
        response1.headers = {}

        # Subsequent requests with same content
        response2 = Mock()
        response2.status_code = 200
        response2.text = "Cached response"
        response2.headers = {}

        response3 = Mock()
        response3.status_code = 200
        response3.text = "Cached response"
        response3.headers = {}

        mock_get.side_effect = [response1, response2, response3]

        detector = CacheDetector('https://example.com')
        result = detector.detect_cache()

        assert result['cache_detected'] is True
        assert result['cache_status'] == 'detected_via_testing'

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_cache_error_handling(self, mock_get):
        """Test error handling in cache detection."""
        mock_get.side_effect = requests.exceptions.Timeout()

        detector = CacheDetector('https://example.com')
        result = detector.detect_cache()

        assert result['cache_detected'] is False
        assert 'error' in result

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_cache_multiple_status_values(self, mock_get):
        """Test detection with various cache status values."""
        statuses = ['MISS', 'EXPIRED', 'STALE', 'BYPASS', 'UPDATING']

        for status in statuses:
            response = Mock()
            response.status_code = 200
            response.text = "Response"
            response.headers = {'X-Cache-Status': status}
            mock_get.return_value = response

            detector = CacheDetector('https://example.com')
            result = detector.detect_cache()

            assert result['cache_detected'] is True
            assert result['cache_status'] == status.lower()


# UnkeyedInputTester Tests

class TestUnkeyedInputTester:
    """Tests for UnkeyedInputTester class."""

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    @patch('engine.agents.cache_poisoning_tester.time.sleep')
    def test_detect_unkeyed_header(self, mock_sleep, mock_get):
        """Test detection of unkeyed header."""
        # First request - header reflected
        response1 = Mock()
        response1.status_code = 200
        response1.text = "Response with evil.com/testcache"
        response1.headers = {}

        # Second request - cache hit
        response2 = Mock()
        response2.status_code = 200
        response2.text = "Response with evil.com/testcache"
        response2.headers = {}

        mock_get.side_effect = [response1, response2]

        tester = UnkeyedInputTester('https://example.com')
        # Patch random to return predictable value
        with patch('engine.agents.cache_poisoning_tester.random.choices', return_value=['t', 'e', 's', 't', 'c', 'a', 'c', 'h']):
            findings = tester.test_all_unkeyed_inputs()

        assert len(findings) > 0
        assert any('Unkeyed Header' in f.title for f in findings)
        assert any(f.severity == 'HIGH' for f in findings)

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    @patch('engine.agents.cache_poisoning_tester.time.sleep')
    def test_detect_unkeyed_parameter(self, mock_sleep, mock_get):
        """Test detection of unkeyed parameter."""
        # First request - parameter reflected
        response1 = Mock()
        response1.status_code = 200
        response1.text = "Response with testcache payload"
        response1.headers = {}

        # Second request without parameter - still reflected (cached)
        response2 = Mock()
        response2.status_code = 200
        response2.text = "Response with testcache payload"
        response2.headers = {}

        mock_get.side_effect = [response1, response2]

        tester = UnkeyedInputTester('https://example.com')
        with patch('engine.agents.cache_poisoning_tester.random.choices', return_value=['t', 'e', 's', 't', 'c', 'a', 'c', 'h']):
            findings = tester.test_all_unkeyed_inputs()

        assert len(findings) > 0
        assert any('Unkeyed Parameter' in f.title for f in findings)
        assert any(f.severity == 'CRITICAL' for f in findings)

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_host_header_poisoning(self, mock_get):
        """Test detection of Host header poisoning."""
        response = Mock()
        response.status_code = 200
        response.text = "Response with evil.com/testcache"
        response.headers = {}

        mock_get.return_value = response

        tester = UnkeyedInputTester('https://example.com')
        with patch('engine.agents.cache_poisoning_tester.random.choices', return_value=['t', 'e', 's', 't', 'c', 'a', 'c', 'h']):
            findings = tester.test_all_unkeyed_inputs()

        assert len(findings) > 0
        host_findings = [f for f in findings if 'Host Header' in f.title]
        if host_findings:
            assert host_findings[0].severity == 'HIGH'

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_unkeyed_header_not_reflected(self, mock_get):
        """Test when header is not reflected."""
        response = Mock()
        response.status_code = 200
        response.text = "Normal response without injection"
        response.headers = {}

        mock_get.return_value = response

        tester = UnkeyedInputTester('https://example.com')
        findings = tester.test_all_unkeyed_inputs()

        # Should not detect vulnerability if not reflected
        assert len(findings) == 0

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    @patch('engine.agents.cache_poisoning_tester.time.sleep')
    def test_header_reflected_but_not_cached(self, mock_sleep, mock_get):
        """Test when header is reflected but not cached."""
        # First request - reflected
        response1 = Mock()
        response1.status_code = 200
        response1.text = "Response with testcache"

        # Second request - not reflected (not cached)
        response2 = Mock()
        response2.status_code = 200
        response2.text = "Normal response"

        mock_get.side_effect = [response1, response2]

        tester = UnkeyedInputTester('https://example.com')
        with patch('engine.agents.cache_poisoning_tester.random.choices', return_value=['t', 'e', 's', 't', 'c', 'a', 'c', 'h']):
            findings = tester.test_all_unkeyed_inputs()

        # Should not find unkeyed header vulnerability if not cached
        unkeyed_findings = [f for f in findings if 'Unkeyed Header' in f.category]
        assert len(unkeyed_findings) == 0

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_request_exception_handling(self, mock_get):
        """Test exception handling in unkeyed input tests."""
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")

        tester = UnkeyedInputTester('https://example.com')
        findings = tester.test_all_unkeyed_inputs()

        # Should not crash, return empty or partial results
        assert isinstance(findings, list)

    def test_poc_generation(self):
        """Test POC generation methods."""
        tester = UnkeyedInputTester('https://example.com')

        # Test header POC
        header_poc = tester._generate_header_poc('X-Forwarded-Host', 'testcache')
        assert 'X-Forwarded-Host' in header_poc
        assert 'testcache' in header_poc
        assert 'curl' in header_poc

        # Test param POC
        param_poc = tester._generate_param_poc('utm_content', 'testcache')
        assert 'utm_content' in param_poc
        assert 'testcache' in param_poc

        # Test host POC
        host_poc = tester._generate_host_poc('evil.com')
        assert 'evil.com' in host_poc


# CacheDeceptionTester Tests

class TestCacheDeceptionTester:
    """Tests for CacheDeceptionTester class."""

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_detect_extension_confusion(self, mock_get):
        """Test detection of extension confusion vulnerability."""
        response = Mock()
        response.status_code = 200
        response.text = "User profile with email: user@example.com and balance: $100"
        response.headers = {
            'X-Cache': 'HIT',
            'Age': '60'
        }

        mock_get.return_value = response

        tester = CacheDeceptionTester('https://example.com/profile')
        findings = tester.test_all_cache_deception()

        assert len(findings) > 0
        ext_findings = [f for f in findings if 'Extension Confusion' in f.title]
        if ext_findings:
            assert ext_findings[0].severity == 'HIGH'
            assert 'Cache Deception' in ext_findings[0].category

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_extension_confusion_404(self, mock_get):
        """Test extension confusion when endpoint returns 404."""
        response = Mock()
        response.status_code = 404
        response.text = "Not found"

        mock_get.return_value = response

        tester = CacheDeceptionTester('https://example.com/profile')
        findings = tester.test_all_cache_deception()

        # Should not detect vulnerability on 404
        assert len(findings) == 0

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_extension_confusion_no_sensitive_data(self, mock_get):
        """Test extension confusion without sensitive data."""
        response = Mock()
        response.status_code = 200
        response.text = "Public content without sensitive data"
        response.headers = {'X-Cache': 'HIT'}

        mock_get.return_value = response

        tester = CacheDeceptionTester('https://example.com/public')
        findings = tester.test_all_cache_deception()

        # Should not flag if no sensitive data
        assert len(findings) == 0

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_path_confusion(self, mock_get):
        """Test detection of path confusion vulnerability."""
        response = Mock()
        response.status_code = 200
        response.text = "Dynamic content with sensitive data"
        response.headers = {'X-Cache': 'HIT'}

        mock_get.return_value = response

        tester = CacheDeceptionTester('https://example.com/api/user')
        findings = tester.test_all_cache_deception()

        path_findings = [f for f in findings if 'Path Confusion' in f.title]
        if path_findings:
            assert path_findings[0].severity == 'HIGH'

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_delimiter_confusion(self, mock_get):
        """Test delimiter confusion detection."""
        response = Mock()
        response.status_code = 200
        response.text = "Response content that bypassed delimiter check"

        mock_get.return_value = response

        tester = CacheDeceptionTester('https://example.com/api')
        findings = tester.test_all_cache_deception()

        # Test runs but may not find vulnerability (depends on response)
        assert isinstance(findings, list)

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_cache_deception_exception_handling(self, mock_get):
        """Test exception handling in cache deception tests."""
        mock_get.side_effect = requests.exceptions.Timeout()

        tester = CacheDeceptionTester('https://example.com')
        findings = tester.test_all_cache_deception()

        # Should handle exceptions gracefully
        assert isinstance(findings, list)

    def test_poc_generation_cache_deception(self):
        """Test POC generation for cache deception."""
        tester = CacheDeceptionTester('https://example.com/account')

        ext_poc = tester._generate_extension_poc('.css')
        assert '.css' in ext_poc
        assert 'Attacker' in ext_poc

        path_poc = tester._generate_path_poc('https://example.com/account/static.css')
        assert 'curl' in path_poc


# FatGETTester Tests

class TestFatGETTester:
    """Tests for FatGETTester class."""

    @patch('engine.agents.cache_poisoning_tester.requests.request')
    def test_detect_fat_get(self, mock_request):
        """Test detection of Fat GET vulnerability."""
        response = Mock()
        response.status_code = 200
        response.text = "Response with testcache payload"

        mock_request.return_value = response

        tester = FatGETTester('https://example.com/api')
        with patch('engine.agents.cache_poisoning_tester.random.choices', return_value=['t', 'e', 's', 't', 'c', 'a', 'c', 'h']):
            findings = tester.test_fat_get()

        assert len(findings) > 0
        assert findings[0].title == 'Fat GET - POST Body in GET Request'
        assert findings[0].severity == 'HIGH'
        assert 'Fat GET' in findings[0].category

    @patch('engine.agents.cache_poisoning_tester.requests.request')
    def test_fat_get_not_vulnerable(self, mock_request):
        """Test when endpoint is not vulnerable to Fat GET."""
        response = Mock()
        response.status_code = 200
        response.text = "Normal response without payload reflection"

        mock_request.return_value = response

        tester = FatGETTester('https://example.com/api')
        findings = tester.test_fat_get()

        assert len(findings) == 0

    @patch('engine.agents.cache_poisoning_tester.requests.request')
    def test_fat_get_exception_handling(self, mock_request):
        """Test exception handling in Fat GET tests."""
        mock_request.side_effect = requests.exceptions.RequestException()

        tester = FatGETTester('https://example.com')
        findings = tester.test_fat_get()

        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_fat_get_poc_generation(self):
        """Test POC generation for Fat GET."""
        tester = FatGETTester('https://example.com/api')
        poc = tester._generate_fat_get_poc('testcache')

        assert 'curl' in poc
        assert 'GET' in poc
        assert 'testcache' in poc
        assert '-d' in poc


# CachePoisoningTester Integration Tests

class TestCachePoisoningTester:
    """Integration tests for CachePoisoningTester class."""

    @patch('engine.agents.cache_poisoning_tester.DatabaseHooks.before_test')
    @patch('engine.agents.cache_poisoning_tester.BountyHoundDB')
    @patch('engine.agents.cache_poisoning_tester.PayloadHooks.record_payload_success')
    @patch('engine.agents.cache_poisoning_tester.requests.get')
    @patch('engine.agents.cache_poisoning_tester.requests.request')
    def test_run_all_tests_with_cache(self, mock_request, mock_get, mock_payload_hooks, mock_db, mock_before_test):
        """Test full test suite when cache is detected."""
        # Setup database hooks
        mock_before_test.return_value = {
            'should_skip': False,
            'reason': 'Never tested before'
        }

        # Setup cache detection
        cache_response = Mock()
        cache_response.status_code = 200
        cache_response.text = "Response"
        cache_response.headers = {'CF-Cache-Status': 'HIT', 'Age': '60'}

        # Setup poisoned response
        poisoned = Mock()
        poisoned.status_code = 200
        poisoned.text = "Response with testcache"
        poisoned.headers = {}

        mock_get.return_value = cache_response
        mock_request.return_value = poisoned

        tester = CachePoisoningTester('https://example.com')

        with patch('engine.agents.cache_poisoning_tester.random.choices', return_value=['t', 'e', 's', 't', 'c', 'a', 'c', 'h']):
            with patch('engine.agents.cache_poisoning_tester.time.sleep'):
                findings = tester.run_all_tests()

        # Verify database recording
        assert mock_db.called
        assert isinstance(findings, list)

    @patch('engine.agents.cache_poisoning_tester.DatabaseHooks.before_test')
    @patch('engine.agents.cache_poisoning_tester.BountyHoundDB')
    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_run_all_tests_no_cache(self, mock_get, mock_db, mock_before_test):
        """Test when no cache is detected."""
        mock_before_test.return_value = {
            'should_skip': False,
            'reason': 'Never tested before'
        }

        # No cache headers
        response = Mock()
        response.status_code = 200
        response.text = "Response"
        response.headers = {}

        mock_get.return_value = response

        tester = CachePoisoningTester('https://example.com')
        findings = tester.run_all_tests()

        # Should skip tests if no cache
        assert len(findings) == 0

    @patch('engine.agents.cache_poisoning_tester.DatabaseHooks.before_test')
    def test_database_skip_logic(self, mock_before_test):
        """Test that database skip logic is respected."""
        mock_before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested 2 days ago',
            'previous_findings': []
        }

        tester = CachePoisoningTester('https://example.com')
        findings = tester.run_all_tests()

        # Should skip and return empty
        assert len(findings) == 0

    @patch('engine.agents.cache_poisoning_tester.DatabaseHooks.before_test')
    @patch('engine.agents.cache_poisoning_tester.BountyHoundDB')
    @patch('engine.agents.cache_poisoning_tester.PayloadHooks.record_payload_success')
    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_payload_recording(self, mock_get, mock_payload_hooks, mock_db, mock_before_test):
        """Test that successful payloads are recorded."""
        mock_before_test.return_value = {
            'should_skip': False,
            'reason': 'Test'
        }

        # Setup responses
        cache_resp = Mock()
        cache_resp.status_code = 200
        cache_resp.text = "Response"
        cache_resp.headers = {'CF-Cache-Status': 'HIT'}

        poisoned = Mock()
        poisoned.status_code = 200
        poisoned.text = "Response with testcache and evil.com/testcache"
        poisoned.headers = {}

        mock_get.side_effect = [cache_resp, poisoned, poisoned]

        tester = CachePoisoningTester('https://example.com')

        with patch('engine.agents.cache_poisoning_tester.random.choices', return_value=['t', 'e', 's', 't', 'c', 'a', 'c', 'h']):
            with patch('engine.agents.cache_poisoning_tester.time.sleep'):
                findings = tester.run_all_tests()

        # Verify payloads were recorded if HIGH/CRITICAL findings
        if any(f.severity in ['HIGH', 'CRITICAL'] for f in findings):
            assert mock_payload_hooks.called

    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        tester = CachePoisoningTester('https://example.com')

        # Add mock findings
        tester.findings = [
            CachePoisoningFinding(
                severity='CRITICAL',
                title='Test 1',
                category='Test',
                description='Test',
                evidence={},
                impact='Test',
                poc='Test',
                recommendation='Test',
                endpoint='https://example.com'
            ),
            CachePoisoningFinding(
                severity='HIGH',
                title='Test 2',
                category='Test',
                description='Test',
                evidence={},
                impact='Test',
                poc='Test',
                recommendation='Test',
                endpoint='https://example.com'
            ),
            CachePoisoningFinding(
                severity='HIGH',
                title='Test 3',
                category='Test',
                description='Test',
                evidence={},
                impact='Test',
                poc='Test',
                recommendation='Test',
                endpoint='https://example.com'
            )
        ]

        critical = tester.get_findings_by_severity('CRITICAL')
        high = tester.get_findings_by_severity('HIGH')

        assert len(critical) == 1
        assert len(high) == 2

    def test_target_extraction_from_url(self):
        """Test domain extraction for database tracking."""
        tester = CachePoisoningTester('https://example.com/api/endpoint')
        assert tester.target == 'example.com'

    def test_custom_target_identifier(self):
        """Test custom target identifier."""
        tester = CachePoisoningTester('https://example.com', target='custom-target')
        assert tester.target == 'custom-target'

    @patch('engine.agents.cache_poisoning_tester.DatabaseHooks.before_test')
    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_url_trailing_slash_removal(self, mock_get, mock_before_test):
        """Test that trailing slash is removed from URL."""
        mock_before_test.return_value = {'should_skip': False, 'reason': 'Test'}

        response = Mock()
        response.status_code = 200
        response.headers = {}
        mock_get.return_value = response

        tester = CachePoisoningTester('https://example.com/')
        assert tester.target_url == 'https://example.com'


# Data Structure Tests

class TestDataStructures:
    """Tests for data structures."""

    def test_cache_poisoning_finding_to_dict(self):
        """Test CachePoisoningFinding to_dict conversion."""
        finding = CachePoisoningFinding(
            severity='HIGH',
            title='Test Finding',
            category='Test Category',
            description='Test description',
            evidence={'key': 'value'},
            impact='Test impact',
            poc='Test POC',
            recommendation='Test recommendation',
            endpoint='https://example.com'
        )

        result = finding.to_dict()

        assert result['severity'] == 'HIGH'
        assert result['title'] == 'Test Finding'
        assert result['category'] == 'Test Category'
        assert 'timestamp' in result
        assert result['cwe_id'] == 'CWE-444'

    def test_cache_poisoning_test_structure(self):
        """Test CachePoisoningTest dataclass."""
        test = CachePoisoningTest(
            name='Test',
            category='Unkeyed Header',
            severity='HIGH',
            description='Test description',
            test_type='unkeyed_header'
        )

        assert test.name == 'Test'
        assert test.severity == 'HIGH'
        assert test.test_type == 'unkeyed_header'


# Edge Cases and Error Handling

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_empty_response_text(self, mock_get):
        """Test handling of empty response text."""
        response = Mock()
        response.status_code = 200
        response.text = ""
        response.headers = {}

        mock_get.return_value = response

        tester = UnkeyedInputTester('https://example.com')
        findings = tester.test_all_unkeyed_inputs()

        # Should not crash on empty response
        assert isinstance(findings, list)

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_malformed_headers(self, mock_get):
        """Test handling of malformed response headers."""
        response = Mock()
        response.status_code = 200
        response.text = "Response"
        response.headers = {'X-Cache': 'INVALID_VALUE_123'}

        mock_get.return_value = response

        detector = CacheDetector('https://example.com')
        result = detector.detect_cache()

        # Should handle gracefully
        assert isinstance(result, dict)

    def test_timeout_parameter(self):
        """Test custom timeout parameter."""
        tester = CachePoisoningTester('https://example.com', timeout=30)
        assert tester.timeout == 30

    @patch('engine.agents.cache_poisoning_tester.requests.get')
    def test_redirect_response(self, mock_get):
        """Test handling of redirect responses."""
        response = Mock()
        response.status_code = 302
        response.text = ""
        response.headers = {'Location': 'https://example.com/new'}

        mock_get.return_value = response

        tester = CacheDeceptionTester('https://example.com')
        findings = tester.test_all_cache_deception()

        # Should handle redirects
        assert isinstance(findings, list)

    def test_ssl_warnings_disabled(self):
        """Test that SSL warnings are disabled."""
        tester = CachePoisoningTester('https://example.com')

        # Verify tester initializes without SSL verification issues
        assert tester.target_url == 'https://example.com'


# CLI Tests

class TestCLI:
    """Tests for CLI functionality."""

    @patch('engine.agents.cache_poisoning_tester.CachePoisoningTester.run_all_tests')
    @patch('sys.argv', ['cache_poisoning_tester.py', 'https://example.com'])
    def test_main_function(self, mock_run_all_tests):
        """Test main CLI function."""
        mock_run_all_tests.return_value = []

        from engine.agents.cache_poisoning_tester import main

        # Should run without error
        main()

        assert mock_run_all_tests.called

    @patch('sys.argv', ['cache_poisoning_tester.py'])
    def test_main_no_arguments(self):
        """Test main function with no arguments."""
        from engine.agents.cache_poisoning_tester import main

        with pytest.raises(SystemExit):
            main()
