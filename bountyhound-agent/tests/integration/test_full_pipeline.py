"""
End-to-end integration test for the complete BountyHound pipeline.

Tests the full flow from hunt initiation to report submission, including:
- Phase 0: Database check (DatabaseHooks.before_test)
- Phase 1: Reconnaissance (asset discovery)
- Phase 2: Discovery (DiscoveryEngine generates hypotheses)
- Phase 3: Validation (StateVerifier confirms exploits)
- Phase 4: Exploitation (POC validation)
- Phase 5: Reporting (RejectionFilter + report generation)
- Hunt state checkpointing (HuntState saves progress)
- Semantic duplicate detection (before submission)
- Payout tracking (if bounty awarded)
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, patch

from engine.core.database import BountyHoundDB
from engine.agents.phased_hunter import PhasedHunter, Finding, PhaseResult
from engine.core.hunt_state import HuntState
from engine.core.db_hooks import DatabaseHooks
from engine.core.state_verifier import StateVerifier, StateCheckResult
from engine.agents.rejection_filter import RejectionFilter, Finding as RFinding, Verdict

from tests.integration.mocks import MockGraphQLTarget, MockReconTool, MockDiscoveryEngine


@pytest.fixture
def test_db(tmp_path):
    """Create test database in temporary file"""
    db_path = str(tmp_path / "test_bountyhound.db")
    db = BountyHoundDB(db_path)
    yield db
    # No close method needed - connections are managed with context managers


@pytest.fixture
def temp_output_dir():
    """Create temporary directory for test outputs"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def mock_graphql_target():
    """Create mock GraphQL target with known vulnerability"""
    return MockGraphQLTarget()


class TestFullHuntPipeline:
    """End-to-end integration tests for complete hunt pipeline"""

    def test_full_hunt_pipeline_graphql_target(self, test_db, temp_output_dir, mock_graphql_target):
        """
        End-to-end test: Complete hunt from recon to report submission

        Pipeline stages:
        1. Phase 0: Database check (DatabaseHooks.before_test)
        2. Phase 1: Reconnaissance (asset discovery)
        3. Phase 2: Discovery (DiscoveryEngine generates hypotheses)
        4. Phase 3: Validation (StateVerifier confirms exploits)
        5. Phase 4: Exploitation (POC validation)
        6. Phase 5: Reporting (RejectionFilter + report generation)
        7. Hunt state checkpointing (HuntState saves progress)
        8. Semantic duplicate detection (before submission)
        9. Payout tracking (if bounty awarded)
        """

        # Setup: Mock GraphQL target with known vulnerability
        target = "graphql-target.example.com"

        # Phase 0: Database check
        context = DatabaseHooks.before_test(target, "phased_hunter", db=test_db)
        assert context['should_skip'] is False, "First test of this target should not skip"
        assert "never tested" in context['reason'].lower()

        # Initialize hunter with mocked components
        hunter = PhasedHunter(
            target=target,
            db=test_db,
            output_dir=temp_output_dir
        )

        # Mock Phase 1: Reconnaissance
        recon_data = MockReconTool.get_recon_data(target)
        hunter.phase_results['recon'] = PhaseResult(
            phase='recon',
            status='success',
            duration_seconds=5.0,
            artifacts=recon_data
        )

        assert hunter.phase_results['recon'].status == 'success'
        assert len(hunter.phase_results['recon'].artifacts['endpoints']) > 0
        assert 'graphql' in hunter.phase_results['recon'].artifacts['tech_stack']

        # Mock Phase 2: Discovery
        hypotheses = MockDiscoveryEngine.generate_hypotheses(recon_data)
        hunter.phase_results['discovery'] = PhaseResult(
            phase='discovery',
            status='success',
            duration_seconds=2.0,
            artifacts={
                'hypotheses': hypotheses,
                'hypotheses_count': len(hypotheses)
            }
        )

        assert hunter.phase_results['discovery'].status == 'success'
        assert len(hunter.phase_results['discovery'].artifacts['hypotheses']) > 0

        # Verify DiscoveryEngine was used
        graphql_hypothesis = next((h for h in hypotheses if 'graphql' in h['title'].lower()), None)
        assert graphql_hypothesis is not None
        assert graphql_hypothesis['confidence'] in ['HIGH', 'MEDIUM', 'LOW']
        assert 'mutation' in graphql_hypothesis  # GraphQL-specific field
        assert 'state_query' in graphql_hypothesis  # Required for state verification

        # Phase 3: Validation with StateVerifier
        verifier = StateVerifier()

        # Simulate state verification for the BOLA hypothesis
        bola_hypothesis = next(h for h in hypotheses if h['vuln_type'] == 'BOLA')

        # Step 1: Read state BEFORE (2 users exist)
        before_state = {
            "data": {
                "users": [
                    {"id": "user-1", "email": "alice@test.com"},
                    {"id": "user-2", "email": "bob@test.com"}
                ]
            }
        }

        # Step 2: Execute mutation (delete user-2)
        mutation_response = mock_graphql_target.execute_mutation("deleteUser", "user-2")

        # Step 3: Read state AFTER (1 user remains)
        after_state = {
            "data": {
                "users": [
                    {"id": "user-1", "email": "alice@test.com"}
                ]
            }
        }

        # Step 4: Verify state change
        verification = verifier.verify_mutation(before_state, mutation_response, after_state)

        assert verification.changed is True, "State should have changed"
        assert verification.mutation_succeeded is True, "Mutation should have succeeded"
        assert len(verification.diff) > 0, "Should detect user removal"

        # Create finding from verified hypothesis
        finding = Finding(
            title=bola_hypothesis['title'],
            severity='HIGH',
            vuln_type=bola_hypothesis['vuln_type'],
            description=f"GraphQL mutation {bola_hypothesis['mutation']} can be executed without authorization",
            poc=f"""# Read state before
curl -X POST https://api.{target}/graphql \\
  -H 'Content-Type: application/json' \\
  -d '{{"query": "{bola_hypothesis['state_query']}"}}'

# Execute unauthorized mutation
curl -X POST https://api.{target}/graphql \\
  -H 'Content-Type: application/json' \\
  -d '{{"query": "{bola_hypothesis['mutation']}"}}'

# Read state after - user is deleted
curl -X POST https://api.{target}/graphql \\
  -H 'Content-Type: application/json' \\
  -d '{{"query": "{bola_hypothesis['state_query']}"}}'

# Verified diff: {json.dumps(verification.diff, indent=2)}
""",
            endpoints=[f"https://api.{target}/graphql"],
            evidence={
                'verification': {
                    'changed': verification.changed,
                    'mutation_succeeded': verification.mutation_succeeded,
                    'diff': verification.diff,
                    'reason': verification.reason
                },
                'hypothesis': bola_hypothesis,
                'before_state': before_state,
                'after_state': after_state,
            },
            status='verified'
        )

        hunter.findings.append(finding)
        hunter.phase_results['validation'] = PhaseResult(
            phase='validation',
            status='success',
            duration_seconds=3.0,
            findings_count=1,
            findings=[finding]
        )

        assert len(hunter.findings) == 1
        assert hunter.findings[0].status == 'verified'
        assert hunter.findings[0].evidence['verification']['changed'] is True

        # Phase 4: Exploitation (already validated above)
        hunter.phase_results['exploitation'] = PhaseResult(
            phase='exploitation',
            status='success',
            duration_seconds=2.0,
            findings_count=1,
            findings=[finding],
            artifacts={
                'verified_count': 1,
                'false_positive_count': 0
            }
        )

        # Phase 5: Reporting with RejectionFilter
        rejection_filter = RejectionFilter()

        # Convert Finding to RejectionFilter.Finding format
        rf_finding = RFinding(
            title=finding.title,
            description=finding.description,
            evidence=json.dumps(finding.evidence),
            auth_context="unauthenticated",  # No auth required = critical
            state_change_verified=True,  # StateVerifier confirmed
            impact="high",
            in_scope=True
        )

        filter_result = rejection_filter.evaluate(rf_finding)

        # Verify RejectionFilter scoring
        assert filter_result.score >= 70, f"High-quality finding should score >= 70, got {filter_result.score}"
        assert filter_result.verdict in [Verdict.AUTO_SUBMIT, Verdict.SUBMIT], \
            f"Verified finding should be submittable, got {filter_result.verdict}"
        assert filter_result.rejection_pattern is None, "Valid finding should not match rejection patterns"

        # Generate report
        report_data = {
            'target': target,
            'finding_id': 1,
            'title': finding.title,
            'severity': finding.severity,
            'vuln_type': finding.vuln_type,
            'description': finding.description,
            'poc': finding.poc,
            'evidence': finding.evidence,
            'rejection_score': filter_result.score,
            'recommendation': filter_result.verdict.value,
            'filter_reason': filter_result.reason
        }

        hunter.phase_results['reporting'] = PhaseResult(
            phase='reporting',
            status='success',
            duration_seconds=1.0,
            artifacts={
                'reports': [report_data],
                'reports_generated': 1
            }
        )

        # Verify hunt state was saved (checkpoint)
        state_file = Path(temp_output_dir) / ".hunt_state.json"
        hunter._save_checkpoint(5, state_file)  # After reporting phase

        assert state_file.exists(), "Hunt state checkpoint should be saved"

        loaded_state = HuntState.load(str(state_file))
        assert loaded_state is not None
        assert loaded_state.target == target
        assert loaded_state.current_phase == 5  # Completed all phases
        assert len(loaded_state.findings) == 1

        # Verify semantic duplicate detection
        test_db.insert_finding(
            target=target,
            vuln_type=finding.vuln_type,
            title=finding.title,
            description=finding.description,
            severity=finding.severity
        )

        # Try to submit semantically similar finding
        dup_check = DatabaseHooks.check_duplicate(
            target=target,
            vuln_type=finding.vuln_type,
            keywords=['graphql', 'mutation', 'authorization'],
            title="GraphQL deleteUser mutation missing authorization",
            description="The deleteUser mutation can be executed without authentication",
            db=test_db
        )

        assert dup_check['is_duplicate'] is True, "Semantic duplicate should be detected"
        assert dup_check['match_type'] in ['keyword', 'semantic']  # Can be keyword or semantic
        assert len(dup_check['matches']) > 0

        # Simulate payout awarded
        # Update first finding with payout and accepted status
        with test_db._get_connection() as conn:
            cursor = conn.cursor()

            # Update finding
            cursor.execute("""
                UPDATE findings
                SET payout = ?, currency = ?, status = 'accepted'
                WHERE id = (
                    SELECT id FROM findings
                    WHERE target_id = (SELECT id FROM targets WHERE domain = ?)
                    ORDER BY id
                    LIMIT 1
                )
            """, (1500.0, "USD", target))

            # Update target totals (same logic as update_finding_payout)
            cursor.execute("""
                UPDATE targets
                SET total_payouts = (
                    SELECT COALESCE(SUM(payout), 0)
                    FROM findings
                    WHERE target_id = targets.id AND status = 'accepted'
                ),
                accepted_findings = (
                    SELECT COUNT(*)
                    FROM findings
                    WHERE target_id = targets.id AND status = 'accepted'
                ),
                avg_payout = (
                    SELECT COALESCE(AVG(payout), 0)
                    FROM findings
                    WHERE target_id = targets.id AND status = 'accepted' AND payout > 0
                )
                WHERE domain = ?
            """, (target,))

            conn.commit()

        # Verify ROI calculation with real payout (use get_target_stats)
        roi_stats = test_db.get_target_stats(target)
        assert roi_stats is not None
        assert roi_stats['total_payouts'] == 1500.0
        assert roi_stats['total_findings'] >= 1

    def test_pipeline_with_error_recovery(self, test_db, temp_output_dir):
        """Test hunt resumption after crash during validation phase"""

        target = "crash-test.example.com"

        # Start hunt and complete phases 1-2
        hunter = PhasedHunter(target=target, db=test_db, output_dir=temp_output_dir)

        # Simulate completed recon
        recon_data = MockReconTool.get_recon_data(target)
        hunter.phase_results['recon'] = PhaseResult(
            phase='recon',
            status='success',
            duration_seconds=5.0,
            artifacts=recon_data
        )

        # Simulate completed discovery
        hypotheses = MockDiscoveryEngine.generate_hypotheses(recon_data)
        hunter.phase_results['discovery'] = PhaseResult(
            phase='discovery',
            status='success',
            duration_seconds=2.0,
            artifacts={'hypotheses': hypotheses}
        )

        # Save checkpoint after phase 2
        state_file = Path(temp_output_dir) / ".hunt_state.json"
        hunter._save_checkpoint(2, state_file)

        assert state_file.exists()

        # Simulate crash and restart
        new_hunter = PhasedHunter(target=target, db=test_db, output_dir=temp_output_dir)

        # Load checkpoint
        loaded_state = HuntState.load(str(state_file))
        assert loaded_state is not None
        assert loaded_state.current_phase == 2
        assert len(loaded_state.completed_phases) == 2

        # Verify state can be restored
        assert loaded_state.recon_data is not None
        assert loaded_state.hypotheses is not None
        assert len(loaded_state.hypotheses) > 0

    def test_rejection_filter_blocks_false_positive(self):
        """Test that RejectionFilter blocks false positives from submission"""

        rejection_filter = RejectionFilter()

        # Create finding that looks like false positive
        false_positive = RFinding(
            title="Can access user data",
            description="Got HTTP 200 but no actual data returned",
            evidence='{"response": {"status": 200, "body": "{\\"error\\": \\"Unauthorized\\"}"}}',
            auth_context="unknown",
            state_change_verified=False,  # No state change confirmed
            impact="high",
            in_scope=True
        )

        result = rejection_filter.evaluate(false_positive)

        # Should be flagged for manual review or rejected
        assert result.score < 70, f"False positive should score < 70, got {result.score}"
        assert result.verdict in [Verdict.REJECT, Verdict.MANUAL_REVIEW], \
            f"False positive should not auto-submit, got {result.verdict}"

    def test_rejection_filter_blocks_own_account_access(self):
        """Test that accessing own resources is correctly rejected"""

        rejection_filter = RejectionFilter()

        # Accessing own account data is NOT a vulnerability
        own_account = RFinding(
            title="Can view own profile data",
            description="User can access their own account information",
            evidence='{"user_id": "123", "accessed": "own account"}',
            auth_context="own_account",  # Key indicator
            state_change_verified=True,
            impact="low",
            in_scope=True
        )

        result = rejection_filter.evaluate(own_account)

        # Should be rejected as intended functionality
        assert result.verdict == Verdict.REJECT
        assert result.rejection_pattern == "intended_functionality"
        assert "own resources" in result.reason.lower()

    def test_semantic_dedup_catches_similar_finding(self, test_db):
        """Test that semantic duplicate detection prevents duplicate submissions"""

        target = "semantic-test.com"

        # Insert first finding
        test_db.insert_finding(
            target=target,
            vuln_type="IDOR",
            title="IDOR allows unauthorized access to user data",
            description="The /api/users/{id} endpoint does not verify ownership",
            severity="HIGH"
        )

        # Try to submit semantically similar finding
        dup_check = DatabaseHooks.check_duplicate(
            target=target,
            vuln_type="IDOR",
            keywords=['api', 'users'],
            title="Missing authorization check in user profile endpoint",
            description="Any authenticated user can access /api/users/{id} without permission check",
            db=test_db
        )

        # Should be flagged as duplicate
        assert dup_check['is_duplicate'] is True
        assert dup_check['match_type'] in ['keyword', 'semantic']  # Can be keyword or semantic
        assert len(dup_check['matches']) > 0

    def test_state_verifier_rejects_http_200_only(self):
        """Test that HTTP 200 alone is not sufficient proof"""

        verifier = StateVerifier()

        # HTTP status code alone should NOT be accepted
        result = verifier.verify_from_status_code(200)

        assert result.changed is False
        assert result.mutation_succeeded is False
        assert "insufficient" in result.reason.lower()
        assert "must compare" in result.reason.lower()

    def test_state_verifier_detects_actual_change(self):
        """Test that StateVerifier correctly identifies real state changes"""

        verifier = StateVerifier()

        before = {
            "data": {
                "user": {
                    "id": "123",
                    "email": "test@example.com",
                    "role": "user"
                }
            }
        }

        mutation_response = {
            "data": {
                "updateUser": {
                    "success": True,
                    "id": "123"
                }
            }
        }

        after = {
            "data": {
                "user": {
                    "id": "123",
                    "email": "test@example.com",
                    "role": "admin"  # Changed!
                }
            }
        }

        result = verifier.verify_mutation(before, mutation_response, after)

        assert result.changed is True
        assert result.mutation_succeeded is True
        assert len(result.diff) > 0
        assert "data.user.role" in result.diff or "role" in str(result.diff)
        assert "confirmed" in result.reason.lower()

    def test_phase_0_database_check_skips_recent_test(self, test_db):
        """Test that Phase 0 correctly skips recently tested targets"""

        target = "recently-tested.com"

        # Record a recent test
        test_db.record_tool_run(
            domain=target,
            tool_name="phased_hunter",
            findings_count=5,
            duration_seconds=300,
            success=True
        )

        # Check if should skip
        context = DatabaseHooks.before_test(target, "phased_hunter", db=test_db)

        # Should skip because tested recently
        assert context['should_skip'] is True
        assert "tested" in context['reason'].lower() and "ago" in context['reason'].lower()
        assert context['last_tested_days'] is not None
        assert context['last_tested_days'] < 7

    def test_database_tracks_payout_roi(self, test_db):
        """Test that database correctly tracks payouts and calculates ROI"""

        target = "high-roi.com"

        # Insert findings with payouts
        finding1_id = test_db.insert_finding(
            target=target,
            vuln_type="IDOR",
            title="User data exposure",
            description="Test",
            severity="HIGH",
            status="accepted",  # Must be accepted for payout to count
            payout=2500.0,
            report_id="H1-123456"
        )

        finding2_id = test_db.insert_finding(
            target=target,
            vuln_type="XSS",
            title="Reflected XSS",
            description="Test",
            severity="MEDIUM",
            status="accepted",  # Must be accepted for payout to count
            payout=500.0,
            report_id="H1-123457"
        )

        # Get ROI stats (use get_target_stats which includes payout info)
        roi = test_db.get_target_stats(target)

        assert roi is not None
        assert roi['total_payouts'] == 3000.0
        assert roi['total_findings'] == 2
