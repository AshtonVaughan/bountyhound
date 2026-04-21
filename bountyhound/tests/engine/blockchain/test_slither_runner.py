"""
Tests for Slither Static Analyzer Runner
Comprehensive testing of Slither integration
"""

import pytest
import subprocess
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from engine.blockchain.solidity.slither_runner import SlitherRunner


class TestSlitherRunnerInit:
    """Test SlitherRunner initialization"""

    def test_init_with_valid_file(self, tmp_path):
        """Should initialize with valid contract file"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = SlitherRunner(str(contract_file))

        assert runner.contract_path == contract_file
        assert runner.target == "test"
        assert runner.findings == []

    def test_init_with_custom_target(self, tmp_path):
        """Should use custom target name"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = SlitherRunner(str(contract_file), target="custom-target")

        assert runner.target == "custom-target"


class TestSlitherExecution:
    """Test Slither execution"""

    @patch('subprocess.run')
    def test_run_slither_success(self, mock_run, tmp_path):
        """Should run Slither successfully"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        slither_output = {
            "results": {
                "detectors": [
                    {
                        "impact": "High",
                        "check": "reentrancy-eth",
                        "description": "Reentrancy in withdraw() function",
                        "confidence": "High",
                        "elements": []
                    }
                ]
            }
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(slither_output)
        mock_run.return_value = mock_result

        runner = SlitherRunner(str(contract_file))

        with patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.slither_runner.BountyHoundDB'):
                findings = runner.run()

        assert len(findings) == 1
        assert findings[0]['severity'] == 'CRITICAL'
        assert findings[0]['title'] == 'reentrancy-eth'

    @patch('subprocess.run')
    def test_run_slither_timeout(self, mock_run, tmp_path, capsys):
        """Should handle Slither timeout"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_run.side_effect = subprocess.TimeoutExpired('slither', 60)

        runner = SlitherRunner(str(contract_file))

        with patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            findings = runner.run()

        assert findings == []
        captured = capsys.readouterr()
        assert "timeout" in captured.out.lower()

    @patch('subprocess.run')
    def test_run_slither_not_installed(self, mock_run, tmp_path, capsys):
        """Should handle Slither not being installed"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_run.side_effect = FileNotFoundError()

        runner = SlitherRunner(str(contract_file))

        with patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            findings = runner.run()

        assert findings == []
        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestFindingProcessing:
    """Test processing of Slither findings"""

    def test_process_findings_severity_mapping(self, tmp_path):
        """Should map Slither severity to standard severity"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = SlitherRunner(str(contract_file))

        detectors = [
            {"impact": "High", "check": "test1", "description": "desc1", "confidence": "High"},
            {"impact": "Medium", "check": "test2", "description": "desc2", "confidence": "Medium"},
            {"impact": "Low", "check": "test3", "description": "desc3", "confidence": "Low"},
            {"impact": "Informational", "check": "test4", "description": "desc4", "confidence": "High"}
        ]

        findings = runner.process_findings(detectors)

        assert findings[0]['severity'] == 'CRITICAL'  # High -> CRITICAL
        assert findings[1]['severity'] == 'HIGH'      # Medium -> HIGH
        assert findings[2]['severity'] == 'MEDIUM'    # Low -> MEDIUM
        assert findings[3]['severity'] == 'INFO'      # Informational -> INFO

    def test_process_findings_extract_locations(self, tmp_path):
        """Should extract code locations from findings"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = SlitherRunner(str(contract_file))

        detectors = [
            {
                "impact": "High",
                "check": "reentrancy-eth",
                "description": "Reentrancy",
                "confidence": "High",
                "elements": [
                    {
                        "source_mapping": {
                            "filename_short": "contract.sol",
                            "lines": [10, 11, 12]
                        }
                    }
                ]
            }
        ]

        findings = runner.process_findings(detectors)

        assert len(findings[0]['locations']) == 1
        assert findings[0]['locations'][0]['file'] == 'contract.sol'
        assert findings[0]['locations'][0]['lines'] == [10, 11, 12]

    def test_process_empty_findings(self, tmp_path):
        """Should handle empty findings"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = SlitherRunner(str(contract_file))
        findings = runner.process_findings([])

        assert findings == []


class TestDatabaseIntegration:
    """Test database hooks integration"""

    @patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test')
    def test_database_skip_when_recent(self, mock_before_test, tmp_path):
        """Should skip analysis when tested recently"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested 2 days ago',
            'previous_findings': []
        }

        runner = SlitherRunner(str(contract_file))
        findings = runner.run()

        assert findings == []

    @patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test')
    @patch('engine.blockchain.solidity.slither_runner.BountyHoundDB')
    @patch('subprocess.run')
    def test_database_record_on_success(self, mock_run, mock_db_class, mock_before_test, tmp_path):
        """Should record tool run on success"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_before_test.return_value = {
            'should_skip': False,
            'reason': 'Never tested'
        }

        slither_output = {"results": {"detectors": []}}
        mock_result = Mock()
        mock_result.stdout = json.dumps(slither_output)
        mock_run.return_value = mock_result

        mock_db = Mock()
        mock_db_class.return_value = mock_db

        runner = SlitherRunner(str(contract_file))
        runner.run()

        mock_db.record_tool_run.assert_called_once()


class TestOutputSummary:
    """Test output and summary reporting"""

    @patch('subprocess.run')
    def test_print_summary(self, mock_run, tmp_path, capsys):
        """Should print summary of findings"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        slither_output = {
            "results": {
                "detectors": [
                    {"impact": "High", "check": "test1", "description": "desc", "confidence": "High"},
                    {"impact": "Medium", "check": "test2", "description": "desc", "confidence": "Medium"}
                ]
            }
        }

        mock_result = Mock()
        mock_result.stdout = json.dumps(slither_output)
        mock_run.return_value = mock_result

        runner = SlitherRunner(str(contract_file))

        with patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.slither_runner.BountyHoundDB'):
                runner.run()

        captured = capsys.readouterr()
        assert "Found 2 issues" in captured.out or "Severity breakdown" in captured.out

    def test_get_critical_findings(self, tmp_path):
        """Should filter critical findings"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        runner = SlitherRunner(str(contract_file))
        runner.findings = [
            {"severity": "CRITICAL", "title": "Bad Vuln"},
            {"severity": "HIGH", "title": "Medium Vuln"},
            {"severity": "CRITICAL", "title": "Another Bad"}
        ]

        critical = runner.get_critical_findings()

        assert len(critical) == 2
        assert all(f['severity'] == 'CRITICAL' for f in critical)


class TestVulnerabilityDetection:
    """Test detection of specific vulnerabilities"""

    @patch('subprocess.run')
    def test_detect_reentrancy(self, mock_run, tmp_path):
        """Should detect reentrancy vulnerabilities"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        slither_output = {
            "results": {
                "detectors": [
                    {
                        "impact": "High",
                        "check": "reentrancy-eth",
                        "description": "Reentrancy vulnerability",
                        "confidence": "High",
                        "elements": []
                    }
                ]
            }
        }

        mock_result = Mock()
        mock_result.stdout = json.dumps(slither_output)
        mock_run.return_value = mock_result

        runner = SlitherRunner(str(contract_file))

        with patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.slither_runner.BountyHoundDB'):
                findings = runner.run()

        assert any('reentrancy' in f['title'].lower() for f in findings)

    @patch('subprocess.run')
    def test_detect_unchecked_calls(self, mock_run, tmp_path):
        """Should detect unchecked low-level calls"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        slither_output = {
            "results": {
                "detectors": [
                    {
                        "impact": "Medium",
                        "check": "unchecked-lowlevel",
                        "description": "Unchecked low-level call",
                        "confidence": "Medium",
                        "elements": []
                    }
                ]
            }
        }

        mock_result = Mock()
        mock_result.stdout = json.dumps(slither_output)
        mock_run.return_value = mock_result

        runner = SlitherRunner(str(contract_file))

        with patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.slither_runner.BountyHoundDB'):
                findings = runner.run()

        assert any('unchecked' in f['title'].lower() for f in findings)

    @patch('subprocess.run')
    def test_detect_tx_origin(self, mock_run, tmp_path):
        """Should detect tx.origin usage"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        slither_output = {
            "results": {
                "detectors": [
                    {
                        "impact": "Medium",
                        "check": "tx-origin",
                        "description": "Dangerous use of tx.origin",
                        "confidence": "Medium",
                        "elements": []
                    }
                ]
            }
        }

        mock_result = Mock()
        mock_result.stdout = json.dumps(slither_output)
        mock_run.return_value = mock_result

        runner = SlitherRunner(str(contract_file))

        with patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.slither_runner.BountyHoundDB'):
                findings = runner.run()

        assert any('tx-origin' in f['title'].lower() or 'origin' in f['title'].lower() for f in findings)


class TestCommandLineOptions:
    """Test different CLI options"""

    @patch('subprocess.run')
    def test_exclude_dependencies_flag(self, mock_run, tmp_path):
        """Should use --exclude-dependencies flag"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_result = Mock()
        mock_result.stdout = json.dumps({"results": {"detectors": []}})
        mock_run.return_value = mock_result

        runner = SlitherRunner(str(contract_file))

        with patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.slither_runner.BountyHoundDB'):
                runner.run()

        # Verify --exclude-dependencies was in command
        call_args = mock_run.call_args
        assert '--exclude-dependencies' in call_args[0][0]

    @patch('subprocess.run')
    def test_json_output_flag(self, mock_run, tmp_path):
        """Should use JSON output format"""
        contract_file = tmp_path / "test.sol"
        contract_file.write_text("pragma solidity ^0.8.0;")

        mock_result = Mock()
        mock_result.stdout = json.dumps({"results": {"detectors": []}})
        mock_run.return_value = mock_result

        runner = SlitherRunner(str(contract_file))

        with patch('engine.blockchain.solidity.slither_runner.DatabaseHooks.before_test',
                   return_value={'should_skip': False, 'reason': 'Test'}):
            with patch('engine.blockchain.solidity.slither_runner.BountyHoundDB'):
                runner.run()

        # Verify JSON output flags
        call_args = mock_run.call_args
        assert '--json' in call_args[0][0]
        assert '-' in call_args[0][0]  # stdout
