"""
Tests for Mythril Symbolic Execution Runner
Comprehensive testing of Mythril integration
"""

import pytest
import subprocess
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from engine.blockchain.solidity.mythril_runner import MythrilRunner


class TestMythrilRunnerInit:
    """Test MythrilRunner initialization"""

    def test_init_with_valid_file(self, tmp_path):
        """Should initialize with valid contract file"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = MythrilRunner(str(contract_file))

        assert runner.contract_path == contract_file
        assert runner.target == "test"
        assert runner.findings == []

    def test_init_with_custom_target(self, tmp_path):
        """Should use custom target name"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = MythrilRunner(str(contract_file), target="custom-target")

        assert runner.target == "custom-target"

    def test_init_with_nonexistent_file(self):
        """Should raise FileNotFoundError for missing file"""
        with pytest.raises(FileNotFoundError, match="Contract not found"):
            MythrilRunner("/nonexistent/contract.sol")


class TestMythrilExecution:
    """Test Mythril execution"""

    @patch('subprocess.run')
    def test_run_mythril_success(self, mock_run, tmp_path):
        """Should run Mythril successfully"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_result = Mock()
        mock_result.stdout = """
==== Integer Overflow ====
SWC ID: 101
Severity: High
Contract: TestContract
Function name: add(uint256)
PC address: 245
Estimated Gas Usage: 1234
        """
        mock_run.return_value = mock_result

        runner = MythrilRunner(str(contract_file))

        with patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.mythril_runner.BountyHoundDB'):
                findings = runner.run()

        assert len(findings) > 0
        assert any(f['severity'] in ['CRITICAL', 'HIGH'] for f in findings)

    @patch('subprocess.run')
    def test_run_mythril_json_output(self, mock_run, tmp_path):
        """Should parse JSON output from Mythril"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mythril_output = {
            "success": True,
            "error": None,
            "issues": [
                {
                    "swc-id": "101",
                    "severity": "High",
                    "title": "Integer Overflow",
                    "description": "The binary addition can result in an integer overflow."
                }
            ]
        }

        mock_result = Mock()
        mock_result.stdout = json.dumps(mythril_output)
        mock_run.return_value = mock_result

        runner = MythrilRunner(str(contract_file))

        with patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.mythril_runner.BountyHoundDB'):
                findings = runner.run(output_format='json')

        assert len(findings) > 0

    @patch('subprocess.run')
    def test_run_mythril_timeout(self, mock_run, tmp_path, capsys):
        """Should handle Mythril timeout"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_run.side_effect = subprocess.TimeoutExpired('myth', 120)

        runner = MythrilRunner(str(contract_file))

        with patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            findings = runner.run()

        assert findings == []
        captured = capsys.readouterr()
        assert "timeout" in captured.out.lower()

    @patch('subprocess.run')
    def test_run_mythril_not_installed(self, mock_run, tmp_path, capsys):
        """Should handle Mythril not being installed"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_run.side_effect = FileNotFoundError()

        runner = MythrilRunner(str(contract_file))

        with patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            findings = runner.run()

        assert findings == []
        captured = capsys.readouterr()
        # Check for "not" AND ("installed" OR "found") to handle both message variants
        assert ("not" in captured.out.lower() and
                ("installed" in captured.out.lower() or "found" in captured.out.lower()))


class TestVulnerabilityParsing:
    """Test parsing of Mythril vulnerability output"""

    @patch('subprocess.run')
    def test_parse_swc_101_integer_overflow(self, mock_run, tmp_path):
        """Should parse SWC-101 Integer Overflow"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_result = Mock()
        mock_result.stdout = "SWC ID: 101\nSeverity: High\nInteger Overflow detected"
        mock_run.return_value = mock_result

        runner = MythrilRunner(str(contract_file))

        with patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.mythril_runner.BountyHoundDB'):
                findings = runner.run()

        assert any('101' in str(f) or 'overflow' in str(f).lower() for f in findings)

    @patch('subprocess.run')
    def test_parse_swc_107_reentrancy(self, mock_run, tmp_path):
        """Should parse SWC-107 Reentrancy"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_result = Mock()
        mock_result.stdout = "SWC ID: 107\nSeverity: High\nReentrancy vulnerability"
        mock_run.return_value = mock_result

        runner = MythrilRunner(str(contract_file))

        with patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.mythril_runner.BountyHoundDB'):
                findings = runner.run()

        assert any('107' in str(f) or 'reentrancy' in str(f).lower() for f in findings)

    @patch('subprocess.run')
    def test_parse_swc_105_unprotected_ether(self, mock_run, tmp_path):
        """Should parse SWC-105 Unprotected Ether Withdrawal"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_result = Mock()
        mock_result.stdout = "SWC ID: 105\nSeverity: High\nUnprotected Ether Withdrawal"
        mock_run.return_value = mock_result

        runner = MythrilRunner(str(contract_file))

        with patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.mythril_runner.BountyHoundDB'):
                findings = runner.run()

        assert any('105' in str(f) or 'ether' in str(f).lower() for f in findings)


class TestDatabaseIntegration:
    """Test database hooks integration"""

    @patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test')
    def test_database_skip_when_recent(self, mock_before_test, tmp_path):
        """Should skip analysis when tested recently"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested 2 days ago',
            'previous_findings': []
        }

        runner = MythrilRunner(str(contract_file))
        findings = runner.run()

        assert findings == []

    @patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test')
    @patch('engine.blockchain.solidity.mythril_runner.BountyHoundDB')
    @patch('subprocess.run')
    def test_database_record_on_success(self, mock_run, mock_db_class, mock_before_test, tmp_path):
        """Should record tool run on success"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_before_test.return_value = {
            'should_skip': False,
            'reason': 'Never tested'
        }

        mock_result = Mock()
        mock_result.stdout = "SWC ID: 101\nVulnerability found"
        mock_run.return_value = mock_result

        mock_db = Mock()
        mock_db_class.return_value = mock_db

        runner = MythrilRunner(str(contract_file))
        runner.run()

        mock_db.record_tool_run.assert_called_once()


class TestOutputOptions:
    """Test different output options"""

    @patch('subprocess.run')
    def test_run_with_custom_timeout(self, mock_run, tmp_path):
        """Should use custom timeout"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_result = Mock()
        mock_result.stdout = "Analysis complete"
        mock_run.return_value = mock_result

        runner = MythrilRunner(str(contract_file))

        with patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.mythril_runner.BountyHoundDB'):
                runner.run(execution_timeout=30)

        # Verify timeout was passed to subprocess
        call_args = mock_run.call_args
        assert '--execution-timeout' in call_args[0][0]
        assert '30' in call_args[0][0]

    @patch('subprocess.run')
    def test_run_with_max_depth(self, mock_run, tmp_path):
        """Should use custom max depth"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_result = Mock()
        mock_result.stdout = "Analysis complete"
        mock_run.return_value = mock_result

        runner = MythrilRunner(str(contract_file))

        with patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.mythril_runner.BountyHoundDB'):
                runner.run(max_depth=50)

        call_args = mock_run.call_args
        assert '--max-depth' in call_args[0][0]


class TestFindingSeverityMapping:
    """Test severity mapping from Mythril output"""

    def test_map_high_severity(self, tmp_path):
        """Should map High severity to CRITICAL"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = MythrilRunner(str(contract_file))
        severity = runner.map_severity("High")

        assert severity == "CRITICAL"

    def test_map_medium_severity(self, tmp_path):
        """Should map Medium severity to HIGH"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = MythrilRunner(str(contract_file))
        severity = runner.map_severity("Medium")

        assert severity == "HIGH"

    def test_map_low_severity(self, tmp_path):
        """Should map Low severity to MEDIUM"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = MythrilRunner(str(contract_file))
        severity = runner.map_severity("Low")

        assert severity == "MEDIUM"


class TestSummaryOutput:
    """Test summary and reporting"""

    @patch('subprocess.run')
    def test_print_summary(self, mock_run, tmp_path, capsys):
        """Should print summary of findings"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_result = Mock()
        mock_result.stdout = "SWC ID: 101\nSeverity: High\nVulnerability"
        mock_run.return_value = mock_result

        runner = MythrilRunner(str(contract_file))

        with patch('engine.blockchain.solidity.mythril_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.mythril_runner.BountyHoundDB'):
                runner.run()

        captured = capsys.readouterr()
        assert "Mythril" in captured.out or "findings" in captured.out.lower()

    def test_get_critical_findings(self, tmp_path):
        """Should filter critical findings"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = MythrilRunner(str(contract_file))
        runner.findings = [
            {"severity": "CRITICAL", "title": "Bad Vuln"},
            {"severity": "HIGH", "title": "Medium Vuln"},
            {"severity": "CRITICAL", "title": "Another Bad"}
        ]

        critical = runner.get_critical_findings()

        assert len(critical) == 2
        assert all(f['severity'] == 'CRITICAL' for f in critical)
