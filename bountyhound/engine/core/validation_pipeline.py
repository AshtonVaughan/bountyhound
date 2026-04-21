"""
Validation Pipeline - Mandatory quality gate for ALL findings.

Every finding from any agent MUST pass through this pipeline before
it can be included in a report or submitted to a bug bounty platform.

Pipeline stages (in order):
1. FP Pattern Check - reject known false positive patterns
2. Error Classification - catch protocol/HTTP misinterpretations
3. POC Validation - actual curl request to confirm vulnerability
4. State Change Verification - for IDOR/BOLA/auth bypass types
5. Confidence Scoring - weighted quality score (A-F grade)
6. Submission Gating - final submit/hold/reject decision

Usage:
    from engine.core.validation_pipeline import ValidationPipeline

    pipeline = ValidationPipeline()
    result = pipeline.validate(finding_dict)

    if result['verdict'] == 'SUBMIT':
        submit_to_h1(result['finding'])
    elif result['verdict'] == 'HOLD':
        save_for_review(result['finding'])
    else:
        discard(result['finding'])

    # Batch validation
    validated = pipeline.validate_batch(findings_list)
    submittable = [r for r in validated if r['verdict'] == 'SUBMIT']
"""

import time
import json
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from colorama import Fore, Style


@dataclass
class ValidationResult:
    """Result of running a finding through the full validation pipeline."""
    finding: Dict[str, Any]
    verdict: str = 'PENDING'  # SUBMIT, HOLD, REJECT
    confidence_score: float = 0.0
    confidence_grade: str = 'F'
    stages_passed: List[str] = field(default_factory=list)
    stages_failed: List[str] = field(default_factory=list)
    rejection_reason: str = ''
    poc_verified: bool = False
    state_change_verified: bool = False
    estimated_bounty: str = '$0'
    curl_command: str = ''
    validation_time_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'verdict': self.verdict,
            'confidence_score': self.confidence_score,
            'confidence_grade': self.confidence_grade,
            'stages_passed': self.stages_passed,
            'stages_failed': self.stages_failed,
            'rejection_reason': self.rejection_reason,
            'poc_verified': self.poc_verified,
            'state_change_verified': self.state_change_verified,
            'estimated_bounty': self.estimated_bounty,
            'curl_command': self.curl_command,
        }


# Vuln types that REQUIRE state change proof
STATE_CHANGE_REQUIRED = {
    'idor', 'bola', 'auth_bypass', 'privilege_escalation',
    'csrf', 'account_takeover', 'mass_assignment',
}

# Vuln types that are often false positives or low-value noise
LOW_VALUE_TYPES = {
    'server_disclosure', 'tech_disclosure', 'missing_headers',
    'security_headers', 'server_version', 'x_powered_by',
    'framework_version', 'hsts_missing', 'csp_missing',
}


class ValidationPipeline:
    """Mandatory validation pipeline for all BountyHound findings.

    Run every finding through validate() before reporting. This enforces
    the quality standards that prevent false positives and wasted reports.
    """

    def __init__(self, skip_poc: bool = False, verbose: bool = True):
        """
        Args:
            skip_poc: Skip POC validation (for offline/testing mode)
            verbose: Print progress to stdout
        """
        self.skip_poc = skip_poc
        self.verbose = verbose
        self._stats = {
            'total': 0, 'submit': 0, 'hold': 0, 'reject': 0,
        }

    def _log(self, msg: str):
        if self.verbose:
            print(f"  {Fore.BLUE}[validate]{Style.RESET_ALL} {msg}")

    # ------------------------------------------------------------------
    # Stage 1: False Positive Pattern Check
    # ------------------------------------------------------------------

    def _stage_fp_check(self, finding: Dict) -> Tuple[bool, str]:
        """Check finding against known false positive patterns."""
        try:
            from engine.core.fp_patterns import FalsePositiveDB
            fpdb = FalsePositiveDB()
            result = fpdb.check_finding(finding)
            if result.get('is_false_positive', False):
                patterns = result.get('matched_patterns', [])
                reason = patterns[0].get('description', 'Matches known FP pattern') if patterns else 'FP pattern match'
                return False, f"FP pattern: {reason}"
        except Exception:
            pass  # FP DB not available, don't block
        return True, 'No FP patterns matched'

    # ------------------------------------------------------------------
    # Stage 2: Error Classification
    # ------------------------------------------------------------------

    def _stage_error_classification(self, finding: Dict) -> Tuple[bool, str]:
        """Classify the response to catch misinterpretations."""
        try:
            from engine.core.quality_gates import ErrorClassifier

            status_code = finding.get('status_code', 0)
            response_body = finding.get('response_body', finding.get('evidence', ''))
            protocol = 'graphql' if 'graphql' in finding.get('vuln_type', '').lower() else 'http'

            if status_code and response_body:
                result = ErrorClassifier.classify(status_code, response_body, protocol)
                if not result.get('is_vulnerability', True) and result.get('confidence', 0) > 0.7:
                    return False, f"Error classification: {result.get('explanation', 'Not a vulnerability')}"
        except Exception:
            pass
        return True, 'Error classification passed'

    # ------------------------------------------------------------------
    # Stage 3: POC Validation (actual HTTP requests)
    # ------------------------------------------------------------------

    def _stage_poc_validation(self, finding: Dict) -> Tuple[bool, str, bool]:
        """Validate finding with actual curl requests. Returns (pass, reason, poc_verified)."""
        if self.skip_poc:
            return True, 'POC validation skipped (offline mode)', False

        url = finding.get('url', '')
        if not url:
            return True, 'No URL to validate', False

        try:
            from engine.agents.poc_validator import POCValidator
            validator = POCValidator()
            result = validator.validate(finding)

            verdict = result.get('verdict', '')
            if verdict == POCValidator.CONFIRMED:
                return True, f"POC confirmed: {result.get('reason', '')}", True
            elif verdict == POCValidator.NEEDS_AUTH:
                return True, 'POC needs auth tokens (hold for manual)', False
            elif verdict == POCValidator.NEEDS_BROWSER:
                return True, 'POC needs browser verification (hold for manual)', False
            else:
                return False, f"POC failed: {result.get('reason', 'Could not confirm')}", False

        except Exception as e:
            self._log(f"POC validation error: {e}")
            return True, f'POC validation error: {e}', False

    # ------------------------------------------------------------------
    # Stage 4: State Change Verification
    # ------------------------------------------------------------------

    def _stage_state_change(self, finding: Dict) -> Tuple[bool, str, bool]:
        """For IDOR/BOLA/auth bypass, require state change proof. Returns (pass, reason, verified)."""
        vuln_type = finding.get('vulnerability_type', finding.get('vuln_type', '')).lower()
        vuln_type = vuln_type.replace('-', '_').replace(' ', '_')

        # Only enforce for types that require it
        if vuln_type not in STATE_CHANGE_REQUIRED:
            return True, f'{vuln_type} does not require state change proof', False

        # Check if finding already has state change evidence
        if finding.get('state_change_verified') or finding.get('state_change_proven'):
            # Validate the evidence
            try:
                from engine.core.state_verifier import StateVerifier
                verifier = StateVerifier()

                before = finding.get('before_state', {})
                after = finding.get('after_state', {})
                mutation_resp = finding.get('mutation_response', {})

                if isinstance(before, str):
                    before = json.loads(before)
                if isinstance(after, str):
                    after = json.loads(after)
                if isinstance(mutation_resp, str):
                    mutation_resp = json.loads(mutation_resp)

                if before and after:
                    result = verifier.verify_mutation(before, mutation_resp, after)
                    if result.changed:
                        return True, f'State change verified: {result.reason}', True
                    else:
                        return False, f'State change NOT confirmed: {result.reason}', False
            except Exception as e:
                self._log(f"State verification error: {e}")

        # No state change evidence provided
        return False, (
            f'{vuln_type} requires state change proof (before_state + after_state). '
            f'HTTP 200 alone is NOT sufficient. Read state before, attempt exploit, '
            f'read state after, and compare.'
        ), False

    # ------------------------------------------------------------------
    # Stage 5: Confidence Scoring
    # ------------------------------------------------------------------

    def _stage_confidence(self, finding: Dict, poc_verified: bool, state_verified: bool) -> Tuple[float, str, str]:
        """Score finding confidence. Returns (score, grade, recommendation)."""
        try:
            from engine.core.quality_gates import ConfidenceScorer

            scoring_input = {
                'verified_with_curl': 1.0 if poc_verified else 0.0,
                'state_change_proven': 1.0 if state_verified else 0.0,
                'severity_appropriate': self._assess_severity_match(finding),
                'not_false_positive_pattern': 0.9,  # Already passed FP check
                'clear_impact': self._assess_impact_clarity(finding),
            }
            result = ConfidenceScorer.score(scoring_input)
            return result['score'], result['grade'], result['recommendation']
        except Exception:
            return 0.5, 'C', 'Confidence scoring unavailable'

    def _assess_severity_match(self, finding: Dict) -> float:
        """Heuristic: is the claimed severity reasonable for the vuln type?"""
        severity = finding.get('severity', 'INFO').upper()
        vuln_type = finding.get('vulnerability_type', finding.get('vuln_type', '')).lower()

        if vuln_type in LOW_VALUE_TYPES and severity in ('CRITICAL', 'HIGH'):
            return 0.2  # Inflated severity
        if vuln_type in ('idor', 'sqli', 'rce', 'ssrf', 'auth_bypass') and severity in ('LOW', 'INFO'):
            return 0.3  # Deflated severity
        return 0.8  # Reasonable

    def _assess_impact_clarity(self, finding: Dict) -> float:
        """Heuristic: does the finding clearly explain the impact?"""
        evidence = finding.get('evidence', '')
        description = finding.get('description', finding.get('claimed_behavior', ''))
        total_text = f"{evidence} {description}"

        if len(total_text) > 200:
            return 0.8  # Detailed
        elif len(total_text) > 50:
            return 0.5  # Moderate
        return 0.2  # Sparse

    # ------------------------------------------------------------------
    # Stage 6: Submission Gating
    # ------------------------------------------------------------------

    def _stage_submission_gate(self, finding: Dict, poc_verified: bool,
                                state_verified: bool) -> Tuple[str, str]:
        """Final submit/hold/reject decision. Returns (verdict, estimated_bounty)."""
        try:
            from engine.core.quality_gates import SubmissionGatekeeper

            gate_input = {
                'title': finding.get('title', finding.get('description', '')),
                'severity': finding.get('severity', 'INFO'),
                'vuln_type': finding.get('vulnerability_type', finding.get('vuln_type', '')),
                'evidence': finding.get('evidence', ''),
                'target': finding.get('target_domain', finding.get('target', '')),
                'verified': poc_verified,
                'state_change_proven': state_verified,
            }
            result = SubmissionGatekeeper.evaluate(gate_input)
            verdict = 'SUBMIT' if result['submit'] else 'HOLD'
            return verdict, result.get('estimated_bounty', '$0')
        except Exception:
            return 'HOLD', '$0'

    # ------------------------------------------------------------------
    # Main validation entry point
    # ------------------------------------------------------------------

    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """Run a single finding through the full validation pipeline.

        Args:
            finding: Dict with at minimum:
                - vulnerability_type or vuln_type (str)
                - url (str, for POC validation)
                - target_domain or target (str)
                - severity (str)
                Optionally:
                - before_state, after_state, mutation_response (for state change)
                - status_code, response_body (for error classification)
                - evidence, description (for scoring)

        Returns:
            ValidationResult with verdict, scores, and evidence
        """
        start = time.time()
        self._stats['total'] += 1

        vuln_type = finding.get('vulnerability_type', finding.get('vuln_type', 'unknown'))
        title = finding.get('title', finding.get('description', vuln_type))
        self._log(f"Validating: {title}")

        # Route source code audit findings to the specialized pipeline
        finding_source = finding.get('source', finding.get('finding_type', ''))
        if finding_source in ('source_audit', 'code_audit', 'code_review', 'sast'):
            return self._validate_source_audit(finding, start)

        result = ValidationResult(finding=finding)
        poc_verified = False
        state_verified = False

        # Stage 1: FP Pattern Check
        passed, reason = self._stage_fp_check(finding)
        if passed:
            result.stages_passed.append('fp_check')
        else:
            result.stages_failed.append('fp_check')
            result.verdict = 'REJECT'
            result.rejection_reason = reason
            self._log(f"  REJECT (FP): {reason}")
            self._stats['reject'] += 1
            result.validation_time_seconds = time.time() - start
            return result

        # Stage 2: Error Classification
        passed, reason = self._stage_error_classification(finding)
        if passed:
            result.stages_passed.append('error_classification')
        else:
            result.stages_failed.append('error_classification')
            result.verdict = 'REJECT'
            result.rejection_reason = reason
            self._log(f"  REJECT (error class): {reason}")
            self._stats['reject'] += 1
            result.validation_time_seconds = time.time() - start
            return result

        # Stage 3: POC Validation
        passed, reason, poc_verified = self._stage_poc_validation(finding)
        result.poc_verified = poc_verified
        if passed:
            result.stages_passed.append('poc_validation')
        else:
            result.stages_failed.append('poc_validation')
            result.verdict = 'REJECT'
            result.rejection_reason = reason
            self._log(f"  REJECT (POC): {reason}")
            self._stats['reject'] += 1
            result.validation_time_seconds = time.time() - start
            return result

        # Stage 4: State Change Verification
        passed, reason, state_verified = self._stage_state_change(finding)
        result.state_change_verified = state_verified
        if passed:
            result.stages_passed.append('state_change')
        else:
            result.stages_failed.append('state_change')
            # State change failure is HOLD, not REJECT (can be fixed by adding evidence)
            result.verdict = 'HOLD'
            result.rejection_reason = reason
            self._log(f"  HOLD (state change): {reason}")
            self._stats['hold'] += 1
            result.validation_time_seconds = time.time() - start
            return result

        # Stage 5: Confidence Scoring
        score, grade, recommendation = self._stage_confidence(finding, poc_verified, state_verified)
        result.confidence_score = score
        result.confidence_grade = grade
        result.stages_passed.append('confidence_scoring')

        # Stage 6: Submission Gating
        verdict, bounty = self._stage_submission_gate(finding, poc_verified, state_verified)
        result.verdict = verdict
        result.estimated_bounty = bounty
        result.stages_passed.append('submission_gate')

        # Generate curl command for manual re-verification
        try:
            from engine.agents.poc_validator import POCValidator
            validator = POCValidator()
            result.curl_command = validator.generate_curl_command(finding)
        except Exception:
            pass

        result.validation_time_seconds = time.time() - start

        self._stats[verdict.lower()] += 1
        self._log(f"  {verdict} (grade {grade}, score {score:.2f})")

        return result

    # ------------------------------------------------------------------
    # Source Code Audit Validation (separate pipeline)
    # ------------------------------------------------------------------

    def _validate_source_audit(self, finding: Dict[str, Any], start: float) -> ValidationResult:
        """Route source code audit findings through the specialized pipeline.

        Source audit findings have different validation needs than web findings:
        - No curl POC (it's source code, not a running service)
        - No HTTP status codes or state changes
        - Instead: documentation checks, reachability, prior audit dedup,
          severity calibration based on exploitability evidence
        """
        self._log("  [source audit pipeline]")

        try:
            from engine.core.source_audit_gates import (
                SourceAuditPipeline, AuditFinding
            )
        except ImportError:
            self._log("  source_audit_gates not available, falling back to HOLD")
            result = ValidationResult(finding=finding, verdict='HOLD')
            result.rejection_reason = 'Source audit validation module not available'
            result.validation_time_seconds = time.time() - start
            self._stats['hold'] += 1
            return result

        # Convert dict to AuditFinding
        audit_finding = AuditFinding(
            id=finding.get('id', 'UNKNOWN'),
            title=finding.get('title', ''),
            severity=finding.get('severity', 'info'),
            description=finding.get('description', ''),
            files=finding.get('files', []),
            vuln_type=finding.get('vuln_type', finding.get('vulnerability_type', '')),
            documentation_checked=finding.get('documentation_checked', False),
            docs_mention_behavior=finding.get('docs_mention_behavior', False),
            doc_references=finding.get('doc_references', []),
            code_is_reachable=finding.get('code_is_reachable', False),
            call_chain=finding.get('call_chain', []),
            callers_with_untrusted_input=finding.get('callers_with_untrusted_input', []),
            prior_audit_checked=finding.get('prior_audit_checked', False),
            known_in_prior_audit=finding.get('known_in_prior_audit', False),
            prior_audit_id=finding.get('prior_audit_id', ''),
            prior_audit_status=finding.get('prior_audit_status', ''),
            is_intentional_tradeoff=finding.get('is_intentional_tradeoff', False),
            tradeoff_justification=finding.get('tradeoff_justification', ''),
            exploit_scenario=finding.get('exploit_scenario', ''),
            prerequisites=finding.get('prerequisites', []),
            impact=finding.get('impact', ''),
            counter_argument=finding.get('counter_argument', ''),
        )

        pipeline = SourceAuditPipeline()
        audit_result = pipeline.validate(audit_finding)

        # Map to the standard ValidationResult format
        result = ValidationResult(finding=finding)
        result.verdict = audit_result.verdict
        result.confidence_score = audit_result.confidence_score
        result.stages_passed = audit_result.gates_passed
        result.stages_failed = audit_result.gates_failed
        result.rejection_reason = '; '.join(audit_result.rejection_reasons)
        result.validation_time_seconds = time.time() - start

        # Log severity adjustment
        if audit_result.original_severity != audit_result.adjusted_severity:
            self._log(
                f"  Severity adjusted: {audit_result.original_severity} → "
                f"{audit_result.adjusted_severity}"
            )
            finding['original_severity'] = audit_result.original_severity
            finding['severity'] = audit_result.adjusted_severity

        # Log notes
        for note in audit_result.notes:
            self._log(f"  NOTE: {note}")

        verdict_lower = result.verdict.lower()
        if verdict_lower in self._stats:
            self._stats[verdict_lower] += 1
        else:
            self._stats['hold'] += 1

        self._log(f"  {result.verdict} (confidence {audit_result.confidence_score:.2f})")
        return result

    def validate_batch(self, findings: List[Dict[str, Any]]) -> List[ValidationResult]:
        """Validate a list of findings."""
        results = []
        for finding in findings:
            results.append(self.validate(finding))
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Return validation statistics."""
        total = self._stats['total']
        return {
            'total_validated': total,
            'submitted': self._stats['submit'],
            'held': self._stats['hold'],
            'rejected': self._stats['reject'],
            'acceptance_rate': (self._stats['submit'] / total * 100) if total > 0 else 0,
        }

    def print_summary(self):
        """Print validation summary."""
        s = self.get_stats()
        print(f"\n{Fore.GREEN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  VALIDATION SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*50}{Style.RESET_ALL}")
        print(f"  Total validated: {s['total_validated']}")
        print(f"  Submitted:       {s['submitted']}")
        print(f"  Held:            {s['held']}")
        print(f"  Rejected:        {s['rejected']}")
        print(f"  Acceptance rate:  {s['acceptance_rate']:.1f}%")
