"""Tests for Deserialization Tester Agent"""

import pytest
from unittest.mock import Mock, patch
from engine.agents.deserialization_tester import DeserializationTester, DeserializationFinding


class TestDeserializationTester:
    """Test suite for DeserializationTester"""

    def test_init(self):
        """Test initialization"""
        tester = DeserializationTester(
            target_url="http://example.com/api/deserialize",
            param_name="data",
            target="example.com"
        )
        assert tester.target_url == "http://example.com/api/deserialize"
        assert tester.param_name == "data"
        assert tester.target == "example.com"
        assert tester.findings == []
        assert tester.tests_run == 0

    def test_target_extraction(self):
        """Test automatic target extraction from URL"""
        tester = DeserializationTester("http://test.example.com/api")
        assert tester.target == "test.example.com"

    @patch('engine.agents.deserialization_tester.DatabaseHooks')
    @patch('engine.agents.deserialization_tester.BountyHoundDB')
    def test_run_all_tests_skip(self, mock_db, mock_hooks):
        """Test skipping when database suggests"""
        mock_hooks.before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested 2 days ago',
            'previous_findings': []
        }

        tester = DeserializationTester("http://example.com/api")
        findings = tester.run_all_tests()

        assert findings == []
        mock_hooks.before_test.assert_called_once()

    def test_finding_to_dict(self):
        """Test DeserializationFinding to_dict conversion"""
        finding = DeserializationFinding(
            severity="CRITICAL",
            title="Test Finding",
            category="RCE",
            payload="test_payload",
            description="Test description",
            evidence={'test': 'data'},
            impact="High impact"
        )

        result = finding.to_dict()
        assert result['severity'] == "CRITICAL"
        assert result['title'] == "Test Finding"
        assert result['category'] == "RCE"

    def test_get_findings(self):
        """Test get_findings method"""
        tester = DeserializationTester("http://example.com/api")

        finding = DeserializationFinding(
            severity="HIGH",
            title="Test",
            category="Detection",
            payload="test",
            description="desc",
            evidence={},
            impact="impact"
        )
        tester.findings.append(finding)

        findings = tester.get_findings()
        assert len(findings) == 1
        assert findings[0].title == "Test"


if __name__ == "__main__":
    pytest.main([__file__, '-v'])
