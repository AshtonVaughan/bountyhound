"""
Tests for HTTP Request Smuggling integration in PhasedHunter
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from engine.agents.phased_hunter import PhasedHunter, Finding


@pytest.fixture
def hunter():
    """Create a PhasedHunter instance with mocked database"""
    with patch('engine.agents.phased_hunter.BountyHoundDB'):
        hunter = PhasedHunter(target='example.com')
        return hunter


def test_test_request_smuggling(hunter):
    """Test that _test_request_smuggling method exists and works"""
    with patch('engine.agents.phased_hunter.SmugglingTester') as MockTester:
        mock_tester = MockTester.return_value

        # Mock finding from CL.TE test
        mock_finding = Finding(
            title="HTTP Request Smuggling (CL.TE)",
            severity="CRITICAL",
            vuln_type="HTTP_Smuggling_CLTE",
            description="Server vulnerable to CL.TE request smuggling",
            poc="curl ...",
            endpoints=["https://example.com/api"],
            evidence={"type": "CL.TE"},
            status="verified"
        )

        mock_tester.test_cl_te.return_value = [mock_finding]
        mock_tester.test_te_cl.return_value = []
        mock_tester.test_te_te.return_value = []
        mock_tester.test_timing_detection.return_value = False

        endpoints = ["https://example.com/api"]
        findings = hunter._test_request_smuggling(endpoints)

        assert len(findings) == 1
        assert findings[0].vuln_type == "HTTP_Smuggling_CLTE"
        assert findings[0].severity == "CRITICAL"

        # Verify all test methods were called
        mock_tester.test_cl_te.assert_called_once()
        mock_tester.test_te_cl.assert_called_once()
        mock_tester.test_te_te.assert_called_once()
        mock_tester.test_timing_detection.assert_called_once()


def test_test_request_smuggling_timing_detection(hunter):
    """Test that timing-based detection creates a finding"""
    with patch('engine.agents.phased_hunter.SmugglingTester') as MockTester:
        mock_tester = MockTester.return_value

        # No findings from standard tests
        mock_tester.test_cl_te.return_value = []
        mock_tester.test_te_cl.return_value = []
        mock_tester.test_te_te.return_value = []

        # But timing detection is positive
        mock_tester.test_timing_detection.return_value = True

        endpoints = ["https://example.com/api"]
        findings = hunter._test_request_smuggling(endpoints)

        assert len(findings) == 1
        assert findings[0].vuln_type == "HTTP_Smuggling_Timing"
        assert findings[0].severity == "HIGH"
        assert "timing" in findings[0].evidence["detection_method"]


def test_test_request_smuggling_multiple_endpoints(hunter):
    """Test smuggling tests on multiple endpoints"""
    with patch('engine.agents.phased_hunter.SmugglingTester') as MockTester:
        mock_tester = MockTester.return_value

        # Different findings for different endpoints
        def cl_te_side_effect(endpoint):
            if "api1" in endpoint:
                return [Finding(
                    title="CL.TE",
                    severity="CRITICAL",
                    vuln_type="HTTP_Smuggling_CLTE",
                    description="CL.TE",
                    poc="curl ...",
                    endpoints=[endpoint]
                )]
            return []

        mock_tester.test_cl_te.side_effect = cl_te_side_effect
        mock_tester.test_te_cl.return_value = []
        mock_tester.test_te_te.return_value = []
        mock_tester.test_timing_detection.return_value = False

        endpoints = ["https://example.com/api1", "https://example.com/api2"]
        findings = hunter._test_request_smuggling(endpoints)

        assert len(findings) == 1
        assert "api1" in findings[0].endpoints[0]


def test_test_request_smuggling_skip_tested_endpoints(hunter):
    """Test that already tested endpoints are skipped"""
    with patch('engine.agents.phased_hunter.SmugglingTester') as MockTester:
        mock_tester = MockTester.return_value

        mock_tester.test_cl_te.return_value = []
        mock_tester.test_te_cl.return_value = []
        mock_tester.test_te_te.return_value = []
        mock_tester.test_timing_detection.return_value = False

        endpoint = "https://example.com/api"

        # Mark endpoint as already tested
        hunter.tested_endpoints.add(endpoint)

        findings = hunter._test_request_smuggling([endpoint])

        # Should not call any test methods
        assert not mock_tester.test_cl_te.called
        assert not mock_tester.test_te_cl.called
        assert not mock_tester.test_te_te.called
        assert not mock_tester.test_timing_detection.called
        assert len(findings) == 0


def test_validation_phase_includes_smuggling_tests(hunter):
    """Test that validation phase calls request smuggling tests"""
    with patch('engine.agents.phased_hunter.SmugglingTester') as MockTester, \
         patch.object(hunter, '_validate_http_endpoint'), \
         patch.object(hunter, '_test_request_smuggling') as mock_smuggling:

        mock_tester = MockTester.return_value
        mock_tester.test_cl_te.return_value = []
        mock_tester.test_te_cl.return_value = []
        mock_tester.test_te_te.return_value = []
        mock_tester.test_timing_detection.return_value = False

        mock_smuggling.return_value = []

        # Setup phase results
        hunter.phase_results['discovery'] = Mock(
            status='success',
            artifacts={'hypotheses': []}
        )
        hunter.phase_results['recon'] = Mock(
            status='success',
            artifacts={
                'endpoints': ['https://example.com/api1', 'https://example.com/api2']
            }
        )

        result = hunter._phase_validation()

        # Verify smuggling test was called
        mock_smuggling.assert_called_once()
        called_endpoints = mock_smuggling.call_args[0][0]
        assert len(called_endpoints) == 2
        assert 'https://example.com/api1' in called_endpoints


def test_all_smuggling_types_tested(hunter):
    """Test that all smuggling types (CL.TE, TE.CL, TE.TE, timing) are tested"""
    with patch('engine.agents.phased_hunter.SmugglingTester') as MockTester:
        mock_tester = MockTester.return_value

        # Return findings from each type
        mock_tester.test_cl_te.return_value = [Finding(
            title="CL.TE", severity="CRITICAL", vuln_type="HTTP_Smuggling_CLTE",
            description="CL.TE", poc="", endpoints=["https://example.com"]
        )]
        mock_tester.test_te_cl.return_value = [Finding(
            title="TE.CL", severity="CRITICAL", vuln_type="HTTP_Smuggling_TECL",
            description="TE.CL", poc="", endpoints=["https://example.com"]
        )]
        mock_tester.test_te_te.return_value = [Finding(
            title="TE.TE", severity="CRITICAL", vuln_type="HTTP_Smuggling_TETE",
            description="TE.TE", poc="", endpoints=["https://example.com"]
        )]
        mock_tester.test_timing_detection.return_value = True

        findings = hunter._test_request_smuggling(["https://example.com/api"])

        # Should have 4 findings (3 from tests + 1 from timing)
        assert len(findings) == 4

        vuln_types = [f.vuln_type for f in findings]
        assert "HTTP_Smuggling_CLTE" in vuln_types
        assert "HTTP_Smuggling_TECL" in vuln_types
        assert "HTTP_Smuggling_TETE" in vuln_types
        assert "HTTP_Smuggling_Timing" in vuln_types
