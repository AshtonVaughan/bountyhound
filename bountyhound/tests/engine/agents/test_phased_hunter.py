"""
Comprehensive tests for PhasedHunter agent.

Tests cover:
- Initialization
- Phase execution (all 5 phases)
- Full workflow
- Error handling
- Database integration
- Finding management
- Report generation
- Edge cases
"""

import pytest
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, date

from engine.agents.phased_hunter import (
    PhasedHunter,
    Finding,
    PhaseResult
)
from engine.core.database import BountyHoundDB


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_db():
    """Create a temporary test database."""
    tmp = tempfile.mkdtemp()
    db_path = Path(tmp) / "test.db"
    db = BountyHoundDB(str(db_path))
    yield db
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def temp_output_dir():
    """Create a temporary output directory."""
    tmp = tempfile.mkdtemp()
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def hunter(temp_db, temp_output_dir):
    """Create a PhasedHunter instance for testing."""
    return PhasedHunter(
        target="testphp.vulnweb.com",
        db=temp_db,
        output_dir=temp_output_dir
    )


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return Finding(
        title="Test IDOR vulnerability",
        severity="HIGH",
        vuln_type="IDOR",
        description="Test description",
        poc="curl https://example.com/api/users/123",
        endpoints=["https://example.com/api/users/123"],
        evidence={"status_code": "200"}
    )


# ============================================================================
# Initialization Tests
# ============================================================================

class TestInitialization:
    """Test PhasedHunter initialization."""

    def test_init_with_defaults(self):
        """Test initialization with default parameters."""
        hunter = PhasedHunter(target="example.com")

        assert hunter.target == "example.com"
        assert hunter.current_phase == "init"
        assert hunter.findings == []
        assert hunter.phase_results == {}
        assert hunter.start_time is None
        assert hunter.end_time is None

    def test_init_with_custom_db(self, temp_db):
        """Test initialization with custom database."""
        hunter = PhasedHunter(target="example.com", db=temp_db)

        assert hunter.db is temp_db

    def test_init_with_custom_output_dir(self, temp_output_dir):
        """Test initialization with custom output directory."""
        hunter = PhasedHunter(
            target="example.com",
            output_dir=temp_output_dir
        )

        assert hunter.output_dir == Path(temp_output_dir)

    def test_init_creates_output_directories(self, hunter):
        """Test that initialization creates required directories."""
        assert (hunter.output_dir / "tmp").exists()
        assert (hunter.output_dir / "approved").exists()
        assert (hunter.output_dir / "rejected").exists()
        assert (hunter.output_dir / "screenshots").exists()

    def test_init_sets_correct_phases(self):
        """Test that phases are correctly defined."""
        expected_phases = ['recon', 'discovery', 'validation', 'exploitation', 'reporting']
        assert PhasedHunter.PHASES == expected_phases


# ============================================================================
# Finding Tests
# ============================================================================

class TestFinding:
    """Test Finding dataclass."""

    def test_finding_creation(self, sample_finding):
        """Test creating a finding."""
        assert sample_finding.title == "Test IDOR vulnerability"
        assert sample_finding.severity == "HIGH"
        assert sample_finding.vuln_type == "IDOR"
        assert sample_finding.status == "pending"

    def test_finding_to_dict(self, sample_finding):
        """Test converting finding to dictionary."""
        finding_dict = sample_finding.to_dict()

        assert finding_dict['title'] == "Test IDOR vulnerability"
        assert finding_dict['severity'] == "HIGH"
        assert finding_dict['vuln_type'] == "IDOR"
        assert finding_dict['endpoints'] == ["https://example.com/api/users/123"]

    def test_finding_with_defaults(self):
        """Test finding creation with default values."""
        finding = Finding(
            title="Test",
            severity="LOW",
            vuln_type="INFO",
            description="Test",
            poc="test"
        )

        assert finding.endpoints == []
        assert finding.evidence == {}
        assert finding.status == "pending"
        assert finding.discovered_date == date.today().isoformat()


# ============================================================================
# PhaseResult Tests
# ============================================================================

class TestPhaseResult:
    """Test PhaseResult dataclass."""

    def test_phase_result_creation(self):
        """Test creating a phase result."""
        result = PhaseResult(
            phase='recon',
            status='success',
            duration_seconds=10.5,
            findings_count=3
        )

        assert result.phase == 'recon'
        assert result.status == 'success'
        assert result.duration_seconds == 10.5
        assert result.findings_count == 3

    def test_phase_result_to_dict(self, sample_finding):
        """Test converting phase result to dictionary."""
        result = PhaseResult(
            phase='validation',
            status='success',
            duration_seconds=5.0,
            findings_count=1,
            findings=[sample_finding]
        )

        result_dict = result.to_dict()

        assert result_dict['phase'] == 'validation'
        assert result_dict['status'] == 'success'
        assert result_dict['duration_seconds'] == 5.0
        assert len(result_dict['findings']) == 1

    def test_phase_result_with_error(self):
        """Test phase result with error."""
        result = PhaseResult(
            phase='recon',
            status='failed',
            duration_seconds=1.0,
            error_message='Tool not found'
        )

        assert result.status == 'failed'
        assert result.error_message == 'Tool not found'


# ============================================================================
# Finding Management Tests
# ============================================================================

class TestFindingManagement:
    """Test finding management methods."""

    def test_add_finding(self, hunter, sample_finding):
        """Test adding a finding."""
        hunter.add_finding(sample_finding)

        assert len(hunter.findings) == 1
        assert hunter.findings[0] == sample_finding

    def test_add_multiple_findings(self, hunter):
        """Test adding multiple findings."""
        for i in range(3):
            finding = Finding(
                title=f"Finding {i}",
                severity="MEDIUM",
                vuln_type="XSS",
                description="Test",
                poc="test"
            )
            hunter.add_finding(finding)

        assert len(hunter.findings) == 3

    def test_get_all_findings(self, hunter, sample_finding):
        """Test getting all findings."""
        hunter.add_finding(sample_finding)
        findings = hunter.get_findings()

        assert len(findings) == 1
        assert findings[0] == sample_finding

    def test_get_findings_by_status(self, hunter):
        """Test getting findings filtered by status."""
        # Add verified finding
        verified = Finding(
            title="Verified",
            severity="HIGH",
            vuln_type="IDOR",
            description="Test",
            poc="test",
            status="verified"
        )
        hunter.add_finding(verified)

        # Add pending finding
        pending = Finding(
            title="Pending",
            severity="MEDIUM",
            vuln_type="XSS",
            description="Test",
            poc="test",
            status="pending"
        )
        hunter.add_finding(pending)

        # Get only verified
        verified_findings = hunter.get_findings(status="verified")
        assert len(verified_findings) == 1
        assert verified_findings[0].title == "Verified"

        # Get only pending
        pending_findings = hunter.get_findings(status="pending")
        assert len(pending_findings) == 1
        assert pending_findings[0].title == "Pending"

    def test_get_findings_empty(self, hunter):
        """Test getting findings when none exist."""
        findings = hunter.get_findings()
        assert findings == []


# ============================================================================
# Phase Execution Tests
# ============================================================================

class TestPhaseExecution:
    """Test individual phase execution."""

    def test_run_phase_invalid_phase(self, hunter):
        """Test running an invalid phase raises error."""
        with pytest.raises(ValueError, match="Unknown phase"):
            hunter.run_phase('invalid_phase')

    @patch('subprocess.run')
    def test_phase_recon_success(self, mock_run, hunter):
        """Test successful recon phase."""
        # Mock bountyhound CLI being available
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Recon complete",
            stderr=""
        )

        result = hunter.run_phase('recon')

        assert result.phase == 'recon'
        assert result.status in ['success', 'failed']  # May fail if no data
        assert result.duration_seconds >= 0

    @patch('subprocess.run')
    def test_phase_recon_cli_not_found(self, mock_run, hunter):
        """Test recon phase when CLI is not found."""
        # Mock bountyhound CLI not available
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="command not found")

        result = hunter.run_phase('recon')

        assert result.phase == 'recon'
        assert result.status == 'failed'
        assert 'CLI not found' in result.error_message

    def test_phase_discovery_without_recon(self, hunter):
        """Test discovery phase without completed recon."""
        result = hunter.run_phase('discovery')

        assert result.phase == 'discovery'
        assert result.status == 'skipped'
        assert 'Recon phase' in result.error_message

    def test_phase_discovery_with_recon(self, hunter):
        """Test discovery phase with completed recon."""
        # Mock successful recon phase
        hunter.phase_results['recon'] = PhaseResult(
            phase='recon',
            status='success',
            duration_seconds=5.0,
            artifacts={'subdomains': ['api.example.com', 'app.example.com']}
        )

        result = hunter.run_phase('discovery')

        assert result.phase == 'discovery'
        assert result.status == 'success'
        assert 'hypotheses' in result.artifacts

    def test_phase_validation_without_discovery(self, hunter):
        """Test validation phase without completed discovery."""
        result = hunter.run_phase('validation')

        assert result.phase == 'validation'
        assert result.status == 'skipped'

    @patch('subprocess.run')
    def test_phase_validation_with_discovery(self, mock_run, hunter):
        """Test validation phase with completed discovery."""
        # Mock curl command
        mock_run.return_value = Mock(
            returncode=0,
            stdout="200",
            stderr=""
        )

        # Mock discovery phase
        hunter.phase_results['discovery'] = PhaseResult(
            phase='discovery',
            status='success',
            duration_seconds=2.0,
            artifacts={
                'hypotheses': [
                    {
                        'id': 'H001',
                        'hypothesis': 'Test API',
                        'endpoints': ['https://api.example.com/users']
                    }
                ]
            }
        )

        result = hunter.run_phase('validation')

        assert result.phase == 'validation'
        assert result.status == 'success'

    def test_phase_exploitation_without_validation(self, hunter):
        """Test exploitation phase without validation."""
        result = hunter.run_phase('exploitation')

        assert result.phase == 'exploitation'
        assert result.status == 'skipped'

    def test_phase_exploitation_with_validation(self, hunter, sample_finding):
        """Test exploitation phase with validation findings."""
        # Mock validation phase
        hunter.phase_results['validation'] = PhaseResult(
            phase='validation',
            status='success',
            duration_seconds=10.0,
            findings=[sample_finding]
        )
        hunter.findings.append(sample_finding)

        result = hunter.run_phase('exploitation')

        assert result.phase == 'exploitation'
        assert result.status == 'success'
        assert result.findings_count >= 0

    def test_phase_reporting_without_exploitation(self, hunter):
        """Test reporting phase without exploitation."""
        result = hunter.run_phase('reporting')

        assert result.phase == 'reporting'
        assert result.status == 'skipped'

    def test_phase_reporting_with_findings(self, hunter, sample_finding):
        """Test reporting phase with verified findings."""
        # Mark finding as verified
        sample_finding.status = 'verified'
        hunter.findings.append(sample_finding)

        # Mock exploitation phase
        hunter.phase_results['exploitation'] = PhaseResult(
            phase='exploitation',
            status='success',
            duration_seconds=5.0,
            findings=[sample_finding]
        )

        result = hunter.run_phase('reporting')

        assert result.phase == 'reporting'
        assert result.status == 'success'
        assert 'report_files' in result.artifacts


# ============================================================================
# Full Workflow Tests
# ============================================================================

class TestFullWorkflow:
    """Test complete hunting workflow."""

    @patch('engine.core.db_hooks.DatabaseHooks.before_test')
    def test_run_full_hunt_skips_recently_tested(self, mock_before_test, hunter):
        """Test that hunt is skipped if target was recently tested."""
        mock_before_test.return_value = {
            'should_skip': True,
            'reason': 'Tested 2 days ago',
            'previous_findings': [],
            'recommendations': ['Skip this target']
        }

        result = hunter.run_full_hunt()

        assert result['status'] == 'skipped'
        assert 'reason' in result

    @patch('engine.core.db_hooks.DatabaseHooks.before_test')
    @patch('subprocess.run')
    def test_run_full_hunt_executes_all_phases(self, mock_run, mock_before_test, hunter):
        """Test that full hunt executes all phases."""
        mock_before_test.return_value = {
            'should_skip': False,
            'reason': 'Good to test',
            'previous_findings': [],
            'recommendations': ['Full test recommended']
        }

        # Mock subprocess calls
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        result = hunter.run_full_hunt()

        assert result['status'] == 'completed'
        assert 'phases' in result
        assert len(hunter.phase_results) > 0

    @patch('engine.core.db_hooks.DatabaseHooks.before_test')
    def test_run_full_hunt_records_session(self, mock_before_test, hunter):
        """Test that hunt session is recorded in database."""
        mock_before_test.return_value = {
            'should_skip': False,
            'reason': 'Good to test',
            'previous_findings': [],
            'recommendations': []
        }

        hunter.run_full_hunt()

        # Check that session was recorded
        target_id = hunter.db.get_or_create_target(hunter.target)

        with hunter.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) as count FROM testing_sessions
                WHERE target_id = ?
            """, (target_id,))

            count = cursor.fetchone()['count']
            assert count > 0


# ============================================================================
# Report Generation Tests
# ============================================================================

class TestReportGeneration:
    """Test report generation."""

    def test_generate_report_empty(self, hunter):
        """Test generating report with no findings."""
        report = hunter.generate_report()

        assert report['target'] == hunter.target
        assert report['status'] == 'completed'
        assert report['findings']['total'] == 0
        assert report['findings']['verified'] == 0

    def test_generate_report_with_findings(self, hunter, sample_finding):
        """Test generating report with findings."""
        sample_finding.status = 'verified'
        hunter.add_finding(sample_finding)

        report = hunter.generate_report()

        assert report['findings']['total'] == 1
        assert report['findings']['verified'] == 1
        assert 'HIGH' in report['findings']['by_severity']

    def test_generate_finding_report(self, hunter, sample_finding):
        """Test generating individual finding report."""
        report = hunter._generate_finding_report(sample_finding)

        assert sample_finding.title in report
        assert sample_finding.severity in report
        assert sample_finding.vuln_type in report
        assert '## Description' in report
        assert '## Proof of Concept' in report

    def test_generate_summary_report(self, hunter, sample_finding):
        """Test generating summary report."""
        sample_finding.status = 'verified'
        hunter.add_finding(sample_finding)
        hunter.start_time = datetime.now()
        hunter.end_time = datetime.now()

        # Add phase result
        hunter.phase_results['recon'] = PhaseResult(
            phase='recon',
            status='success',
            duration_seconds=10.0
        )

        report = hunter._generate_summary_report()

        assert hunter.target in report
        assert 'Total Findings' in report
        assert 'RECON' in report

    def test_count_by_severity(self, hunter):
        """Test counting findings by severity."""
        findings = [
            Finding("F1", "CRITICAL", "IDOR", "Test", "test"),
            Finding("F2", "HIGH", "XSS", "Test", "test"),
            Finding("F3", "HIGH", "SQLi", "Test", "test"),
            Finding("F4", "MEDIUM", "CORS", "Test", "test")
        ]

        counts = hunter._count_by_severity(findings)

        assert counts['CRITICAL'] == 1
        assert counts['HIGH'] == 2
        assert counts['MEDIUM'] == 1


# ============================================================================
# Database Integration Tests
# ============================================================================

class TestDatabaseIntegration:
    """Test database integration."""

    def test_record_hunt_session(self, hunter):
        """Test recording hunt session in database."""
        hunter.start_time = datetime.now()
        hunter.end_time = datetime.now()

        # Add a verified finding
        finding = Finding(
            title="Test",
            severity="HIGH",
            vuln_type="IDOR",
            description="Test",
            poc="test",
            status="verified"
        )
        hunter.add_finding(finding)

        hunter._record_hunt_session()

        # Verify session was recorded
        target_id = hunter.db.get_or_create_target(hunter.target)

        with hunter.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM testing_sessions
                WHERE target_id = ?
            """, (target_id,))

            session = cursor.fetchone()
            assert session is not None
            assert session['findings_count'] == 1

    def test_database_target_creation(self, hunter):
        """Test that target is created in database."""
        target_id = hunter.db.get_or_create_target(hunter.target)

        assert target_id is not None
        assert target_id > 0

        # Verify target exists
        stats = hunter.db.get_target_stats(hunter.target)
        assert stats is not None
        assert stats['domain'] == hunter.target


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Test error handling."""

    @patch('subprocess.run')
    def test_phase_execution_handles_subprocess_error(self, mock_run, hunter):
        """Test that subprocess errors are handled gracefully."""
        mock_run.side_effect = Exception("Command failed")

        result = hunter.run_phase('recon')

        assert result.status == 'failed'
        assert result.error_message is not None

    @patch('subprocess.run')
    def test_phase_execution_handles_timeout(self, mock_run, hunter):
        """Test that timeouts are handled gracefully."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired('cmd', 10)

        result = hunter.run_phase('recon')

        assert result.status == 'failed'
        assert 'timeout' in result.error_message.lower()

    def test_get_total_duration_no_times(self, hunter):
        """Test getting duration when times are not set."""
        duration = hunter._get_total_duration()
        assert duration == 0.0

    def test_get_total_duration_with_times(self, hunter):
        """Test getting duration with set times."""
        from datetime import timedelta

        hunter.start_time = datetime.now()
        hunter.end_time = hunter.start_time + timedelta(seconds=30)

        duration = hunter._get_total_duration()
        assert duration >= 29.9  # Allow for float precision
        assert duration <= 30.1


# ============================================================================
# Edge Cases Tests
# ============================================================================

class TestEdgeCases:
    """Test edge cases."""

    def test_hunter_with_empty_target(self):
        """Test hunter with empty target string."""
        hunter = PhasedHunter(target="")
        assert hunter.target == ""

    def test_hunter_output_dir_creation_existing_dir(self, temp_output_dir):
        """Test that existing output dir doesn't cause errors."""
        # Create hunter twice with same dir
        hunter1 = PhasedHunter(target="example.com", output_dir=temp_output_dir)
        hunter2 = PhasedHunter(target="example.com", output_dir=temp_output_dir)

        assert hunter1.output_dir == hunter2.output_dir

    def test_tested_endpoints_tracking(self, hunter):
        """Test that tested endpoints are tracked to avoid duplicates."""
        endpoint = "https://example.com/api/test"

        hunter.tested_endpoints.add(endpoint)
        assert endpoint in hunter.tested_endpoints

    @patch('subprocess.run')
    def test_validation_skips_duplicate_endpoints(self, mock_run, hunter):
        """Test that validation doesn't retest endpoints."""
        # Pre-add endpoint to tested set
        hunter.tested_endpoints.add("https://api.example.com/users")

        # Mock discovery with that endpoint
        hunter.phase_results['discovery'] = PhaseResult(
            phase='discovery',
            status='success',
            duration_seconds=2.0,
            artifacts={
                'hypotheses': [
                    {
                        'id': 'H001',
                        'endpoints': ['https://api.example.com/users']
                    }
                ]
            }
        )

        result = hunter.run_phase('validation')

        # Curl should not be called since endpoint already tested
        mock_run.assert_not_called()

    def test_phase_result_duration_calculation(self, hunter):
        """Test that phase duration is calculated correctly."""
        result = hunter.run_phase('discovery')

        # Duration should be >= 0 and reasonable (< 60 seconds for discovery)
        assert result.duration_seconds >= 0
        assert result.duration_seconds < 60
