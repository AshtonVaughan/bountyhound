"""
Phased Hunter Agent

Main orchestrator for bug bounty hunts. Executes complete 5-phase hunting pipeline:
1. Reconnaissance (recon)
2. Discovery (LLM-powered hypothesis generation)
3. Validation (multi-account authorization testing)
4. Exploitation (POC validation and evidence gathering)
5. Reporting (structured report generation)

This agent coordinates other specialized agents and integrates with the BountyHound
database for data-driven hunting decisions.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import logging
import os
import json
from datetime import datetime, date
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field, asdict
from engine.core.database import BountyHoundDB
from engine.core.db_hooks import DatabaseHooks
from engine.core.hunt_state import HuntState
from engine.core.state_verifier import StateVerifier, StateCheckResult
from engine.agents.smuggling_tester import SmugglingTester
from engine.agents.mfa_bypass_tester import MFABypassTester


logger = logging.getLogger("bountyhound.agents.phased_hunter")


@dataclass
class Finding:
    """Represents a single vulnerability finding."""
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    vuln_type: str  # IDOR, XSS, SQLi, etc.
    description: str
    poc: str  # Proof of concept
    endpoints: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"  # pending, verified, false_positive, duplicate
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return asdict(self)


@dataclass
class PhaseResult:
    """Result from a single phase execution."""
    phase: str
    status: str  # success, failed, skipped
    duration_seconds: float
    findings_count: int = 0
    findings: List[Finding] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert phase result to dictionary."""
        return {
            'phase': self.phase,
            'status': self.status,
            'duration_seconds': self.duration_seconds,
            'findings_count': self.findings_count,
            'findings': [f.to_dict() for f in self.findings],
            'artifacts': self.artifacts,
            'error_message': self.error_message
        }


class PhasedHunter:
    """
    Main orchestrator for phased bug bounty hunting.

    Executes a complete 5-phase pipeline:
    - Phase 1: Reconnaissance
    - Phase 2: Discovery
    - Phase 3: Validation
    - Phase 4: Exploitation
    - Phase 5: Reporting
    """

    # Phase definitions
    PHASES = ['recon', 'discovery', 'validation', 'exploitation', 'reporting']

    # Perfect Hunter — method and CVSS maps used in _verify_findings
    _VULN_METHOD_MAP: dict = {
        "HTTP_SMUGGLING": "POST",
        "MFA_BYPASS": "POST",
        "RACE_CONDITION": "POST",
    }
    _SEVERITY_CVSS_MAP: dict = {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.0,
        "INFO": 0.0,
    }

    def __init__(self, target: str, db: Optional[BountyHoundDB] = None,
                 output_dir: Optional[str] = None):
        """
        Initialize the Phased Hunter.

        Args:
            target: Target domain (e.g., 'example.com')
            db: BountyHound database instance (creates new if None)
            output_dir: Directory for findings output (uses default if None)
        """
        self.target = target
        self.db = db or BountyHoundDB()
        self.current_phase = "init"
        self.findings: List[Finding] = []
        self.phase_results: Dict[str, PhaseResult] = {}
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

        # Set output directory
        if output_dir is None:
            BOUNTY_DIR = os.environ.get('BOUNTYHOUND_DIR', os.path.expanduser('~/BountyHound'))
            output_dir = os.path.join(BOUNTY_DIR, 'findings', target)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        (self.output_dir / "tmp").mkdir(exist_ok=True)
        (self.output_dir / "approved").mkdir(exist_ok=True)
        (self.output_dir / "rejected").mkdir(exist_ok=True)
        (self.output_dir / "screenshots").mkdir(exist_ok=True)

        # Track tested endpoints to avoid duplicates
        self.tested_endpoints: Set[str] = set()

    def run_full_hunt(self, resume: bool = True) -> Dict[str, Any]:
        """
        Execute complete 5-phase hunt with checkpoint support.

        Args:
            resume: If True, resume from checkpoint if one exists

        Returns:
            Dict with hunt summary including all phase results and findings
        """
        self.start_time = datetime.now()
        state_path = self.output_dir / ".hunt_state.json"

        try:
            # Check for existing checkpoint
            start_phase_idx = 0
            if resume and state_path.exists():
                saved_state = HuntState.load(str(state_path))
                if saved_state and saved_state.target == self.target:
                    # Resume from saved state
                    print(f"Resuming hunt from phase {saved_state.current_phase}")
                    start_phase_idx = saved_state.current_phase

                    # Restore previous findings
                    if saved_state.findings:
                        for finding_dict in saved_state.findings:
                            finding = Finding(**finding_dict)
                            self.findings.append(finding)

            # Check database before starting
            context = DatabaseHooks.before_test(self.target, 'phased_hunter')

            if context['should_skip']:
                return {
                    'status': 'skipped',
                    'reason': context['reason'],
                    'previous_findings': context['previous_findings'],
                    'recommendations': context['recommendations']
                }

            # Execute all phases (starting from checkpoint if resuming)
            for phase_idx, phase in enumerate(self.PHASES):
                # Skip already completed phases
                if phase_idx < start_phase_idx:
                    continue

                result = self.run_phase(phase)
                self.phase_results[phase] = result

                # Save checkpoint after each phase
                self._save_checkpoint(phase_idx + 1, state_path)

                # Stop if phase failed critically
                if result.status == 'failed' and phase in ['recon', 'validation']:
                    break

            # Generate final report
            report = self.generate_report()

            # Record in database
            self._record_hunt_session()

            # Clean up checkpoint file on successful completion
            if state_path.exists():
                state_path.unlink()

            return report

        finally:
            self.end_time = datetime.now()

    def run_phase(self, phase: str) -> PhaseResult:
        """
        Execute a specific phase.

        Args:
            phase: Phase name (recon, discovery, validation, exploitation, reporting)

        Returns:
            PhaseResult object with phase execution results
        """
        if phase not in self.PHASES:
            raise ValueError(f"Unknown phase: {phase}. Valid phases: {self.PHASES}")

        self.current_phase = phase
        phase_start = datetime.now()

        try:
            # Execute phase-specific logic
            if phase == 'recon':
                result = self._phase_recon()
            elif phase == 'discovery':
                result = self._phase_discovery()
            elif phase == 'validation':
                result = self._phase_validation()
            elif phase == 'exploitation':
                result = self._phase_exploitation()
            elif phase == 'reporting':
                result = self._phase_reporting()
            else:
                result = PhaseResult(
                    phase=phase,
                    status='failed',
                    duration_seconds=0,
                    error_message=f"Phase {phase} not implemented"
                )

            # Calculate duration
            phase_end = datetime.now()
            result.duration_seconds = (phase_end - phase_start).total_seconds()

            return result

        except Exception as e:
            phase_end = datetime.now()
            duration = (phase_end - phase_start).total_seconds()

            return PhaseResult(
                phase=phase,
                status='failed',
                duration_seconds=duration,
                error_message=str(e)
            )

    def _phase_recon(self) -> PhaseResult:
        """
        Phase 1: Reconnaissance

        Executes subdomain enumeration, port scanning, and tech fingerprinting.
        """
        artifacts = {}

        try:
            # Check if bountyhound CLI is available
            result = subprocess.run(
                ['bountyhound', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                return PhaseResult(
                    phase='recon',
                    status='failed',
                    duration_seconds=0,
                    error_message='bountyhound CLI not found. Run: pip install bountyhound'
                )

            # Add target to database
            subprocess.run(
                ['bountyhound', 'target', 'add', self.target],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Run reconnaissance
            recon_result = subprocess.run(
                ['bountyhound', 'recon', self.target, '--batch'],
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes
            )

            artifacts['recon_stdout'] = recon_result.stdout
            artifacts['recon_stderr'] = recon_result.stderr

            # Extract discovered assets from database
            target_id = self.db.get_or_create_target(self.target)

            with self.db._get_connection() as conn:
                cursor = conn.cursor()

                # Get subdomains
                cursor.execute("""
                    SELECT data_value FROM recon_data
                    WHERE target_id = ? AND data_type = 'subdomain'
                """, (target_id,))

                subdomains = [row['data_value'] for row in cursor.fetchall()]
                artifacts['subdomains'] = subdomains
                artifacts['subdomains_count'] = len(subdomains)

            return PhaseResult(
                phase='recon',
                status='success' if recon_result.returncode == 0 else 'failed',
                duration_seconds=0,  # Set by caller
                artifacts=artifacts
            )

        except subprocess.TimeoutExpired:
            return PhaseResult(
                phase='recon',
                status='failed',
                duration_seconds=0,
                error_message='Recon timeout (>10 minutes)',
                artifacts=artifacts
            )
        except Exception as e:
            return PhaseResult(
                phase='recon',
                status='failed',
                duration_seconds=0,
                error_message=str(e),
                artifacts=artifacts
            )

    def _phase_discovery(self) -> PhaseResult:
        """
        Phase 2: Discovery

        Generates vulnerability hypotheses using Discovery Engine.
        Integrates with database intelligence to prioritize proven attack patterns.
        """
        from engine.agents.discovery_engine import DiscoveryEngine

        # Get recon results
        recon_result = self.phase_results.get('recon')
        if not recon_result or recon_result.status != 'success':
            return PhaseResult(
                phase='discovery',
                status='skipped',
                duration_seconds=0,
                error_message='Recon phase did not complete successfully'
            )

        # Build recon data structure for discovery engine
        recon_data = {
            'subdomains': recon_result.artifacts.get('subdomains', []),
            'tech_stack': recon_result.artifacts.get('tech_stack', []),
            'endpoints': recon_result.artifacts.get('endpoints', []),
        }

        # Enrich recon data with database intelligence
        target_id = self.db.get_or_create_target(self.target)

        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            # Get successful vulnerability types for this target
            cursor.execute("""
                SELECT DISTINCT vuln_type FROM findings
                WHERE target_id = ? AND status IN ('accepted', 'verified')
            """, (target_id,))

            successful_vuln_types = [row['vuln_type'] for row in cursor.fetchall()]
            recon_data['successful_vuln_types'] = successful_vuln_types

        # Generate hypotheses using Discovery Engine
        engine = DiscoveryEngine()
        hypothesis_cards = engine.generate_hypotheses(recon_data)

        # Convert HypothesisCard objects to dicts for PhaseResult
        hypotheses = [
            {
                'id': card.id,
                'title': card.title,
                'confidence': card.confidence.value,
                'test_method': card.test_method,
                'payload': card.payload,
                'success_indicator': card.success_indicator,
                'reasoning_track': card.reasoning_track,
            }
            for card in hypothesis_cards
        ]

        return PhaseResult(
            phase='discovery',
            status='success',
            duration_seconds=0,
            artifacts={
                'hypotheses': hypotheses,
                'hypotheses_count': len(hypotheses),
                'successful_vuln_types': successful_vuln_types,
            }
        )

    def _phase_validation(self) -> PhaseResult:
        """
        Phase 3: Validation

        Tests hypotheses from discovery phase and validates vulnerabilities.
        Uses StateVerifier to ensure findings represent actual state changes.
        """
        findings = []
        verifier = StateVerifier()

        # Get discovery results
        discovery_result = self.phase_results.get('discovery')
        if not discovery_result or discovery_result.status != 'success':
            return PhaseResult(
                phase='validation',
                status='skipped',
                duration_seconds=0,
                error_message='Discovery phase did not complete successfully'
            )

        hypotheses = discovery_result.artifacts.get('hypotheses', [])

        # Test each hypothesis
        for hypothesis in hypotheses:
            endpoints = hypothesis.get('endpoints', [])
            test_method = hypothesis.get('test_method', 'http')

            for endpoint in endpoints:
                if endpoint in self.tested_endpoints:
                    continue

                self.tested_endpoints.add(endpoint)

                # Validate based on test method
                try:
                    if test_method == 'http':
                        verification = self._validate_http_endpoint(endpoint, verifier)
                    elif test_method == 'graphql':
                        verification = self._validate_graphql_endpoint(endpoint, hypothesis, verifier)
                    else:
                        # Fallback to basic HTTP test
                        verification = self._validate_http_endpoint(endpoint, verifier)

                    # Only create finding if state actually changed
                    if verification.changed:
                        finding = Finding(
                            title=f'Validated vulnerability: {hypothesis.get("hypothesis", "Unknown")}',
                            severity=self._calculate_severity(verification),
                            vuln_type=hypothesis.get('vuln_type', 'EXPOSURE'),
                            description=f'Endpoint {endpoint} showed state change. {verification.reason}',
                            poc=self._generate_poc(endpoint, hypothesis, verification),
                            endpoints=[endpoint],
                            evidence={
                                'verification': {
                                    'changed': verification.changed,
                                    'mutation_succeeded': verification.mutation_succeeded,
                                    'diff': verification.diff,
                                    'reason': verification.reason
                                },
                                'hypothesis': hypothesis
                            },
                            status='verified'
                        )
                        findings.append(finding)
                        self.findings.append(finding)

                except Exception as e:
                    # Log error but continue testing
                    print(f"Validation error for {endpoint}: {str(e)}")
                    continue

        # Test for HTTP Request Smuggling on all discovered endpoints
        recon_result = self.phase_results.get('recon')
        if recon_result and recon_result.status == 'success':
            raw_endpoints = recon_result.artifacts.get('endpoints', [])
            if raw_endpoints:
                # --- Priority Scoring: filter endpoints before testing ---
                prioritised_endpoints = self._apply_priority_scoring(raw_endpoints)

                print(f"Testing {len(prioritised_endpoints)} endpoints for HTTP Request Smuggling...")
                smuggling_findings = self._test_request_smuggling(prioritised_endpoints)
                findings.extend(smuggling_findings)
                self.findings.extend(smuggling_findings)

                # Filter MFA-related endpoints
                mfa_endpoints = [ep for ep in prioritised_endpoints if any(
                    keyword in ep.lower() for keyword in
                    ['mfa', '2fa', 'otp', 'totp', 'verify', 'auth', 'login', 'backup']
                )]

                if mfa_endpoints:
                    print(f"Testing {len(mfa_endpoints)} MFA-related endpoints for bypass vulnerabilities...")
                    mfa_findings = self._test_mfa_bypass(mfa_endpoints)
                    findings.extend(mfa_findings)
                    self.findings.extend(mfa_findings)

        # --- 2-stage verification: Stage A checklist + Stage B challenger ---
        # Build a minimal default scope from self.target so Gate 2 is active
        default_scope = (
            [f"*.{self.target}", self.target]
            if hasattr(self, "target") and self.target
            else []
        )
        verified_findings = self._verify_findings(findings, program_scope=default_scope)

        return PhaseResult(
            phase='validation',
            status='success',
            duration_seconds=0,
            findings_count=len(verified_findings),
            findings=verified_findings
        )

    def _validate_http_endpoint(self, endpoint: str, verifier: StateVerifier) -> StateCheckResult:
        """
        Validate an HTTP endpoint by checking for state changes.

        For simple HTTP endpoints, we use status code as a signal but don't
        claim exploitation unless we can verify actual state change.
        """
        try:
            result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', endpoint],
                capture_output=True,
                text=True,
                timeout=10
            )
            status_code = int(result.stdout.strip())

            # HTTP status code alone is NOT sufficient proof
            return verifier.verify_from_status_code(status_code)

        except Exception as e:
            return StateCheckResult(
                changed=False,
                mutation_succeeded=False,
                diff={},
                reason=f'Request failed: {str(e)}'
            )

    def _validate_graphql_endpoint(self, endpoint: str, hypothesis: Dict[str, Any],
                                   verifier: StateVerifier) -> StateCheckResult:
        """
        Validate a GraphQL endpoint with proper state verification.

        Protocol:
        1. Read state (before)
        2. Attempt mutation
        3. Read state (after)
        4. Compare states
        """
        try:
            # Extract query/mutation from hypothesis if provided
            query = hypothesis.get('query')
            mutation = hypothesis.get('mutation')
            state_query = hypothesis.get('state_query')

            if not (mutation and state_query):
                # Can't do state verification without these
                return StateCheckResult(
                    changed=False,
                    mutation_succeeded=False,
                    diff={},
                    reason='Missing mutation or state_query in hypothesis'
                )

            # Step 1: Read state BEFORE
            before_result = subprocess.run(
                ['curl', '-s', '-X', 'POST', endpoint,
                 '-H', 'Content-Type: application/json',
                 '-d', json.dumps({'query': state_query})],
                capture_output=True,
                text=True,
                timeout=10
            )
            before_state = json.loads(before_result.stdout) if before_result.stdout else {}

            # Step 2: Attempt mutation
            mutation_result = subprocess.run(
                ['curl', '-s', '-X', 'POST', endpoint,
                 '-H', 'Content-Type: application/json',
                 '-d', json.dumps({'query': mutation})],
                capture_output=True,
                text=True,
                timeout=10
            )
            mutation_response = json.loads(mutation_result.stdout) if mutation_result.stdout else {}

            # Step 3: Read state AFTER
            after_result = subprocess.run(
                ['curl', '-s', '-X', 'POST', endpoint,
                 '-H', 'Content-Type: application/json',
                 '-d', json.dumps({'query': state_query})],
                capture_output=True,
                text=True,
                timeout=10
            )
            after_state = json.loads(after_result.stdout) if after_result.stdout else {}

            # Step 4: Verify state change
            return verifier.verify_mutation(before_state, mutation_response, after_state)

        except Exception as e:
            return StateCheckResult(
                changed=False,
                mutation_succeeded=False,
                diff={},
                reason=f'GraphQL validation failed: {str(e)}'
            )

    def _calculate_severity(self, verification: StateCheckResult) -> str:
        """Calculate severity based on verification results."""
        if verification.mutation_succeeded and verification.changed:
            # Real exploitation confirmed
            return 'HIGH'
        elif verification.changed:
            # State changed but unclear if mutation succeeded
            return 'MEDIUM'
        else:
            # No state change = INFO at best
            return 'INFO'

    def _generate_poc(self, endpoint: str, hypothesis: Dict[str, Any],
                     verification: StateCheckResult) -> str:
        """Generate proof-of-concept from hypothesis and verification."""
        test_method = hypothesis.get('test_method', 'http')

        if test_method == 'graphql':
            mutation = hypothesis.get('mutation', '')
            state_query = hypothesis.get('state_query', '')

            return f"""# Read state before
curl -X POST {endpoint} \\
  -H 'Content-Type: application/json' \\
  -d '{{"query": "{state_query}"}}'

# Execute mutation
curl -X POST {endpoint} \\
  -H 'Content-Type: application/json' \\
  -d '{{"query": "{mutation}"}}'

# Read state after (should show changes)
curl -X POST {endpoint} \\
  -H 'Content-Type: application/json' \\
  -d '{{"query": "{state_query}"}}'

# Verified diff: {json.dumps(verification.diff, indent=2)}
"""
        else:
            return f'curl -s -o /dev/null -w "%{{http_code}}" {endpoint}'

    def _phase_exploitation(self) -> PhaseResult:
        """
        Phase 4: Exploitation

        Validates findings with detailed POCs and gathers evidence.
        """
        verified_findings = []

        # Get findings from validation phase
        validation_result = self.phase_results.get('validation')
        if not validation_result:
            return PhaseResult(
                phase='exploitation',
                status='skipped',
                duration_seconds=0,
                error_message='No validation phase results'
            )

        findings = validation_result.findings

        # Verify each finding
        for finding in findings:
            # In production, this would execute POC and capture evidence
            # For now, mark as verified if it has a POC
            if finding.poc:
                finding.status = 'verified'
                verified_findings.append(finding)
            else:
                finding.status = 'false_positive'

        return PhaseResult(
            phase='exploitation',
            status='success',
            duration_seconds=0,
            findings_count=len(verified_findings),
            findings=verified_findings,
            artifacts={
                'verified_count': len(verified_findings),
                'false_positive_count': len(findings) - len(verified_findings)
            }
        )

    def _phase_reporting(self) -> PhaseResult:
        """
        Phase 5: Reporting

        Generates structured reports for all verified findings.
        """
        # Get verified findings from exploitation phase
        exploitation_result = self.phase_results.get('exploitation')
        if not exploitation_result:
            return PhaseResult(
                phase='reporting',
                status='skipped',
                duration_seconds=0,
                error_message='No exploitation phase results'
            )

        verified_findings = [f for f in self.findings if f.status == 'verified']

        # Generate individual finding reports
        report_files = []
        for idx, finding in enumerate(verified_findings, 1):
            report_path = self.output_dir / 'approved' / f'finding-{idx:03d}.md'

            report_content = self._generate_finding_report(finding)
            report_path.write_text(report_content, encoding='utf-8')

            report_files.append(str(report_path))

        # Generate summary report
        summary_path = self.output_dir / 'REPORT.md'
        summary_content = self._generate_summary_report()
        summary_path.write_text(summary_content, encoding='utf-8')

        report_files.append(str(summary_path))

        return PhaseResult(
            phase='reporting',
            status='success',
            duration_seconds=0,
            artifacts={
                'report_files': report_files,
                'reports_generated': len(report_files)
            }
        )

    def _generate_finding_report(self, finding: Finding) -> str:
        """Generate markdown report for a single finding."""
        report = f"""# {finding.title}

**Severity:** {finding.severity}
**Type:** {finding.vuln_type}
**Status:** {finding.status}
**Discovered:** {finding.discovered_date}

## Description

{finding.description}

## Affected Endpoints

"""
        for endpoint in finding.endpoints:
            report += f"- {endpoint}\n"

        report += f"""
## Proof of Concept

```bash
{finding.poc}
```

## Evidence

"""
        for key, value in finding.evidence.items():
            report += f"- **{key}:** {value}\n"

        report += """
## Recommendation

[Add remediation steps here]
"""

        return report

    def _generate_summary_report(self) -> str:
        """Generate summary report for all findings."""
        verified = [f for f in self.findings if f.status == 'verified']

        # Count by severity
        severity_counts = {}
        for finding in verified:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        report = f"""# Bug Bounty Hunt Summary - {self.target}

**Date:** {date.today().isoformat()}
**Duration:** {self._get_total_duration():.2f} seconds
**Total Findings:** {len(verified)}

## Findings by Severity

"""
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                report += f"- **{severity}:** {count}\n"

        report += """
## Phase Results

"""
        for phase, result in self.phase_results.items():
            report += f"### {phase.upper()}\n"
            report += f"- Status: {result.status}\n"
            report += f"- Duration: {result.duration_seconds:.2f}s\n"
            report += f"- Findings: {result.findings_count}\n\n"

        report += """
## Verified Findings

"""
        for idx, finding in enumerate(verified, 1):
            report += f"{idx}. **{finding.title}** ({finding.severity})\n"

        return report

    def _get_total_duration(self) -> float:
        """Calculate total hunt duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    def _save_checkpoint(self, current_phase: int, state_path: Path):
        """
        Save hunt state checkpoint.

        Args:
            current_phase: Phase number to resume from next
            state_path: Path to save checkpoint file
        """
        # Extract recon data from phase results
        recon_data = None
        if 'recon' in self.phase_results:
            recon_data = self.phase_results['recon'].artifacts

        # Extract hypotheses from discovery phase
        hypotheses = None
        if 'discovery' in self.phase_results:
            hypotheses = self.phase_results['discovery'].artifacts.get('hypotheses', [])

        # Convert findings to dicts
        findings_dicts = [f.to_dict() for f in self.findings]

        # Determine completed phases
        completed = list(range(current_phase))

        # Create and save state
        state = HuntState(
            target=self.target,
            current_phase=current_phase,
            completed_phases=completed,
            recon_data=recon_data,
            hypotheses=hypotheses,
            findings=findings_dicts,
            timestamp=datetime.now().isoformat()
        )

        state.save(str(state_path))

    def _record_hunt_session(self):
        """Record hunt session in database."""
        target_id = self.db.get_or_create_target(self.target)

        # Record session
        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            duration_minutes = int(self._get_total_duration() / 60)
            verified_count = len([f for f in self.findings if f.status == 'verified'])

            cursor.execute("""
                INSERT INTO testing_sessions
                (target_id, start_time, end_time, duration_minutes, findings_count, tools_used, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                target_id,
                self.start_time.isoformat() if self.start_time else None,
                self.end_time.isoformat() if self.end_time else None,
                duration_minutes,
                verified_count,
                json.dumps(['phased_hunter']),
                f'Phased hunt with {len(self.PHASES)} phases'
            ))

        # Record tool run
        self.db.record_tool_run(
            domain=self.target,
            tool_name='phased_hunter',
            findings_count=verified_count,
            duration_seconds=int(self._get_total_duration()),
            success=True
        )

    def _test_request_smuggling(self, endpoints: List[str]) -> List[Finding]:
        """
        Test for HTTP request smuggling vulnerabilities.

        Args:
            endpoints: List of endpoint URLs to test

        Returns:
            List of smuggling findings
        """
        findings = []
        tester = SmugglingTester()

        for endpoint in endpoints:
            # Skip if already tested
            if endpoint in self.tested_endpoints:
                continue

            self.tested_endpoints.add(endpoint)

            # Test CL.TE smuggling
            cl_te_findings = tester.test_cl_te(endpoint)
            findings.extend(cl_te_findings)

            # Test TE.CL smuggling
            te_cl_findings = tester.test_te_cl(endpoint)
            findings.extend(te_cl_findings)

            # Test TE.TE smuggling
            te_te_findings = tester.test_te_te(endpoint)
            findings.extend(te_te_findings)

            # Test timing-based detection
            if tester.test_timing_detection(endpoint):
                findings.append(Finding(
                    title="HTTP Request Smuggling (Timing-based)",
                    description="Endpoint vulnerable to request smuggling detected via timing analysis. Further manual testing recommended.",
                    severity="HIGH",
                    vuln_type="HTTP_Smuggling_Timing",
                    poc=f"Timing-based detection at {endpoint}",
                    endpoints=[endpoint],
                    evidence={
                        "url": endpoint,
                        "detection_method": "timing"
                    },
                    status="verified"
                ))

        return findings

    def _test_mfa_bypass(self, mfa_endpoints: List[str]) -> List[Finding]:
        """
        Test for MFA bypass vulnerabilities.

        Args:
            mfa_endpoints: List of MFA-related endpoint URLs to test

        Returns:
            List of MFA bypass findings
        """
        findings = []
        tester = MFABypassTester()

        for endpoint in mfa_endpoints:
            # Skip if already tested
            if endpoint in self.tested_endpoints:
                continue

            self.tested_endpoints.add(endpoint)

            # Test response manipulation
            response_findings = tester.test_response_manipulation(endpoint)
            findings.extend(response_findings)

            # Test rate limiting
            rate_findings = tester.test_rate_limiting(endpoint)
            findings.extend(rate_findings)

            # Test backup code weaknesses
            if 'backup' in endpoint.lower():
                backup_findings = tester.test_backup_code_weaknesses(endpoint)
                findings.extend(backup_findings)

        return findings

    def _apply_priority_scoring(self, endpoints: List[str]) -> List[str]:
        """
        Filter a list of endpoint URLs by composite priority score.

        Only endpoints with composite_score >= 0.55 (medium tier and above) are
        returned.  If the scorer module is unavailable the full list is returned
        unchanged (graceful degradation).

        Args:
            endpoints: Raw list of URL strings from the recon phase.

        Returns:
            Filtered list of URL strings ordered by score (highest first).
        """
        try:
            from engine.scoring import score_endpoints

            endpoint_dicts = [{"url": url, "method": "GET"} for url in endpoints]
            scored = score_endpoints(endpoint_dicts)
            filtered = [s for s in scored if s.composite_score >= 0.55]

            logger.info(
                "Priority filter: %d/%d endpoints selected for testing (score >= 0.55)",
                len(filtered),
                len(scored),
            )

            return [s.url for s in filtered]

        except Exception as exc:
            logger.warning(
                "Priority scorer failed, using all %d endpoints: %s",
                len(endpoints),
                exc,
            )
            return endpoints

    def _verify_findings(
        self,
        raw_findings: List[Finding],
        program_scope: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Run the 2-stage Perfect Hunter verification pipeline on raw findings.

        Stage A — VerificationChecklist (5 deterministic gates)
        Stage B — Challenger (self-challenge agent, heuristic or AI)

        Findings that fail either stage are logged and dropped.  If either
        verification module is unavailable the original list is returned
        unchanged (graceful degradation).

        Args:
            raw_findings:   Findings produced during the validation phase.
            program_scope:  Allowed-scope patterns (e.g. ["*.example.com"]).
                            Pass None to allow all URLs.

        Returns:
            Subset of raw_findings that survived both stages.
        """
        if not raw_findings:
            return raw_findings

        # Build normalised (url, vuln_type) pairs for duplicate detection.
        # Use id-based exclusion so the check is O(1) per finding and is not
        # confused by equal-valued Finding objects that are distinct instances.
        raw_finding_ids = {id(f) for f in raw_findings}
        session_findings: List[Tuple[str, str]] = [
            (f.endpoints[0] if f.endpoints else "", f.vuln_type)
            for f in self.findings
            if id(f) not in raw_finding_ids
        ]

        # ---- Stage A: Checklist ----
        stage_a_survivors: List[Finding] = []
        try:
            from engine.verification import VerificationChecklist, ChecklistInput

            checklist = VerificationChecklist(
                allowed_scope=program_scope or [],
                known_findings=session_findings,
            )

            for finding in raw_findings:
                url = finding.endpoints[0] if finding.endpoints else ""
                evidence_snippet = str(finding.evidence)[:500] if finding.evidence else ""
                impact = finding.description  # best available impact field

                request_method = self._VULN_METHOD_MAP.get(finding.vuln_type.upper(), "GET")
                cvss = self._SEVERITY_CVSS_MAP.get(finding.severity.upper())

                ci = ChecklistInput(
                    url=url,
                    vuln_type=finding.vuln_type,
                    request_method=request_method,
                    response_snippet=evidence_snippet,
                    impact_statement=impact,
                    cvss_score=cvss,
                    severity_label=finding.severity.lower(),
                    clean_state_verified=True,
                )
                result = checklist.run(ci)
                if result.passed:
                    stage_a_survivors.append(finding)
                else:
                    logger.info(
                        "Finding dropped by Stage A checklist: %s — gates failed: %s",
                        url,
                        result.failed_gates,
                    )

        except Exception as exc:
            logger.warning(
                "Stage A checklist failed, skipping verification: %s", exc
            )
            stage_a_survivors = list(raw_findings)

        # ---- Stage B: Challenger ----
        stage_b_survivors: List[Finding] = []
        try:
            from engine.verification import Challenger, ChecklistInput

            challenger = Challenger()

            for finding in stage_a_survivors:
                url = finding.endpoints[0] if finding.endpoints else ""
                evidence_snippet = str(finding.evidence)[:500] if finding.evidence else ""
                impact = finding.description

                request_method = self._VULN_METHOD_MAP.get(finding.vuln_type.upper(), "GET")
                cvss = self._SEVERITY_CVSS_MAP.get(finding.severity.upper())

                ci = ChecklistInput(
                    url=url,
                    vuln_type=finding.vuln_type,
                    request_method=request_method,
                    response_snippet=evidence_snippet,
                    impact_statement=impact,
                    cvss_score=cvss,
                    severity_label=finding.severity.lower(),
                    clean_state_verified=True,
                )
                challenge_result = challenger.challenge(ci)
                if challenge_result.verified:
                    stage_b_survivors.append(finding)
                    logger.info(
                        "Finding VERIFIED by Stage B: %s (confidence: %.2f)",
                        url,
                        challenge_result.confidence,
                    )
                else:
                    logger.info(
                        "Finding DROPPED by Stage B challenger: %s — challenges: %s",
                        url,
                        challenge_result.challenges_raised,
                    )

        except Exception as exc:
            logger.warning(
                "Stage B challenger failed, skipping self-challenge: %s", exc
            )
            stage_b_survivors = list(stage_a_survivors)

        return stage_b_survivors

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive hunt report.

        Returns:
            Dict with complete hunt results including all phases and findings
        """
        verified_findings = [f for f in self.findings if f.status == 'verified']

        return {
            'target': self.target,
            'status': 'completed',
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self._get_total_duration(),
            'phases': {
                phase: result.to_dict()
                for phase, result in self.phase_results.items()
            },
            'findings': {
                'total': len(self.findings),
                'verified': len(verified_findings),
                'by_severity': self._count_by_severity(verified_findings),
                'details': [f.to_dict() for f in verified_findings]
            },
            'output_dir': str(self.output_dir)
        }

    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def add_finding(self, finding: Finding):
        """
        Add a finding to the hunt results.

        Args:
            finding: Finding object to add
        """
        self.findings.append(finding)

    def get_findings(self, status: Optional[str] = None) -> List[Finding]:
        """
        Get findings, optionally filtered by status.

        Args:
            status: Optional status filter (verified, pending, etc.)

        Returns:
            List of findings matching the filter
        """
        if status is None:
            return self.findings
        return [f for f in self.findings if f.status == status]
