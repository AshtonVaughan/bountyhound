"""
Hunt Executor - Orchestrates a complete autonomous hunt.

The main entry point for BountyHound's auto-dispatch system. Runs:
1. Phase 0: Database check (skip if recently tested)
2. Phase 0.5: Target profiling (detect capabilities)
3. Phase 1: Discovery agents
4. Phase 1.5: Hypothesis generation
5. Phase 2: Auth testing
6. Phase 3C: Non-web analysis (SAST, binary, mobile)
7. Phase 3D: Deep web testing (injections, API, cloud)
8. Phase 5: Analysis and chaining
9. Phase 6: Validation and reporting

Usage:
    executor = HuntExecutor('example.com')
    report = executor.execute()
    print(report.summary())

    # Or with options
    executor = HuntExecutor('example.com', max_workers=6, skip_phases=['3C'])
    report = executor.execute()
"""

import os
import json
import time
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from colorama import Fore, Style

from engine.core.agent_registry import AgentRegistry
from engine.core.target_profiler import TargetProfiler, TargetProfile
from engine.core.auto_dispatcher import AutoDispatcher, AgentResult


@dataclass
class HuntReport:
    """Final report from a hunt execution."""
    target: str
    started_at: str
    finished_at: str = ''
    duration_seconds: float = 0.0
    profile: Optional[TargetProfile] = None
    agent_results: List[AgentResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    agents_run: int = 0
    agents_failed: int = 0
    agents_skipped: int = 0
    phases_completed: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            f"{'='*60}",
            f"  HUNT REPORT: {self.target}",
            f"{'='*60}",
            f"  Duration:      {self.duration_seconds:.0f}s",
            f"  Agents run:    {self.agents_run}",
            f"  Agents failed: {self.agents_failed}",
            f"  Findings:      {len(self.findings)}",
            f"  Phases:        {', '.join(self.phases_completed)}",
        ]

        if self.findings:
            lines.append(f"\n  FINDINGS:")
            for i, f in enumerate(self.findings[:20], 1):
                title = f.get('title', f.get('description', f.get('vuln_type', 'Unknown')))
                severity = f.get('severity', 'INFO')
                source = f.get('_source_agent', '?')
                lines.append(f"    {i}. [{severity}] {title} (from {source})")
            if len(self.findings) > 20:
                lines.append(f"    ... and {len(self.findings) - 20} more")

        return '\n'.join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for JSON export."""
        return {
            'target': self.target,
            'started_at': self.started_at,
            'finished_at': self.finished_at,
            'duration_seconds': self.duration_seconds,
            'agents_run': self.agents_run,
            'agents_failed': self.agents_failed,
            'agents_skipped': self.agents_skipped,
            'phases_completed': self.phases_completed,
            'findings_count': len(self.findings),
            'findings': self.findings[:50],  # Cap at 50 for JSON size
            'profile_triggers': sorted(self.profile.triggers) if self.profile else [],
        }


class HuntExecutor:
    """Orchestrates a complete autonomous hunt.

    The main entry point for BountyHound's auto-dispatch system.
    Call execute() to run the full pipeline, or run individual phases.
    """

    FINDINGS_DIR = Path('C:/Users/vaugh/BountyHound/findings')

    def __init__(self, target: str, max_workers: int = 4,
                 skip_phases: Optional[List[str]] = None,
                 auth_tokens: Optional[Dict[str, str]] = None):
        """
        Args:
            target: Domain, URL, file path, or directory to hunt
            max_workers: Max parallel agents per phase
            skip_phases: Phases to skip (e.g., ['3C'] to skip SAST)
            auth_tokens: Optional {role: token} dict for auth testing
        """
        self.target = target.strip()
        self.max_workers = max_workers
        self.skip_phases = set(skip_phases or [])
        self.auth_tokens = auth_tokens or {}

        self.registry = AgentRegistry()
        self.profile: Optional[TargetProfile] = None
        self.dispatcher: Optional[AutoDispatcher] = None
        self.hunt_state = None

        self.report = HuntReport(
            target=self.target,
            started_at=datetime.now().isoformat(),
        )

    def _log(self, msg: str):
        print(f"  {Fore.MAGENTA}[executor]{Style.RESET_ALL} {msg}")

    def _banner(self):
        """Print hunt start banner."""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  BOUNTYHOUND AUTO-HUNT: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Started: {self.report.started_at}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Registry: {self.registry.summary()['total_agents']} agents available{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    # ------------------------------------------------------------------
    # Phase 0: Database check
    # ------------------------------------------------------------------

    def phase_0_db_check(self) -> bool:
        """Check database for recent test history. Returns True if should proceed."""
        self._log("Phase 0: Database check")
        try:
            from engine.core.db_hooks import DatabaseHooks
            context = DatabaseHooks.before_test(self.target, 'hunt_executor')
            if context.get('should_skip', False):
                self._log(f"  SKIP: {context.get('reason', 'tested recently')}")
                self._log(f"  Previous findings: {len(context.get('previous_findings', []))}")
                return False
            self._log(f"  OK: {context.get('reason', 'ready to test')}")
        except Exception as e:
            self._log(f"  DB check failed ({e}), proceeding anyway")
        return True

    # ------------------------------------------------------------------
    # Phase 0.5: Target profiling
    # ------------------------------------------------------------------

    def phase_05_profile(self) -> TargetProfile:
        """Profile the target to determine capabilities."""
        self._log("Phase 0.5: Target profiling")
        profiler = TargetProfiler(self.target)
        self.profile = profiler.run()
        self.report.profile = self.profile

        self._log(f"  Type: {self.profile.target_type}")
        self._log(f"  Triggers: {sorted(self.profile.triggers)}")

        return self.profile

    # ------------------------------------------------------------------
    # Run phases via dispatcher
    # ------------------------------------------------------------------

    def _run_phase(self, phase: str) -> List[AgentResult]:
        """Run a single phase through the dispatcher."""
        if phase in self.skip_phases:
            self._log(f"Phase {phase}: SKIPPED (user request)")
            return []

        results = self.dispatcher.run_phase(phase)
        self.report.phases_completed.append(phase)

        # Update profile from discovery results
        if phase in ('1', '1.5'):
            self._update_profile_from_results(results)

        return results

    def _update_profile_from_results(self, results: List[AgentResult]):
        """Update target profile based on discovery phase results.

        If discovery agents find GraphQL, JWT, etc., update the profile
        so later phases dispatch the right agents.
        """
        if not self.profile:
            return

        profiler = TargetProfiler(self.target)

        for result in results:
            if not result.success:
                continue
            for finding in result.findings:
                # Look for discovery signals in findings
                desc = str(finding.get('description', '')).lower()
                ftype = str(finding.get('type', '')).lower()

                if 'graphql' in desc or 'graphql' in ftype:
                    profiler.update_from_discovery('graphql_endpoint', True)
                if 'jwt' in desc or 'jwt' in ftype:
                    profiler.update_from_discovery('jwt_token', True)
                if 'oauth' in desc or 'oauth' in ftype:
                    profiler.update_from_discovery('oauth_flow', True)
                if 'websocket' in desc or 'ws://' in desc:
                    profiler.update_from_discovery('websocket', True)
                if 'grpc' in desc:
                    profiler.update_from_discovery('grpc_endpoint', True)
                if 'upload' in desc:
                    profiler.update_from_discovery('upload_form', True)
                if 's3' in desc or 'bucket' in ftype:
                    profiler.update_from_discovery('s3_bucket', True)

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    def _init_llm_bridge(self):
        """Initialize LLM bridge for AI-powered generation throughout the pipeline."""
        try:
            from engine.core.llm_bridge import LLMBridge
            self._llm_bridge = LLMBridge(self.target)
            if self._llm_bridge.available:
                self._log("LLM bridge initialized (AI-powered generation active)")
            else:
                self._log("LLM bridge: no API key, using template-only mode")
                self._llm_bridge = None
        except Exception:
            self._llm_bridge = None

    def _init_adaptive_engine(self):
        """Initialize the adaptive engine for mid-hunt strategy adjustment."""
        try:
            from engine.core.adaptive_engine import AdaptiveEngine
            self._adaptive = AdaptiveEngine(total_budget_seconds=1800, max_retries_per_phase=1)
            self._log("Adaptive engine initialized (30 min budget)")
        except Exception:
            self._adaptive = None

    def _init_stored_payload_tracker(self):
        """Initialize stored payload tracker for second-order vuln detection."""
        try:
            from engine.core.stored_payload_tracker import StoredPayloadTracker
            self._payload_tracker = StoredPayloadTracker(self.target)
            self._log("Stored payload tracker initialized")
        except Exception:
            self._payload_tracker = None

    def _init_browser_executor(self):
        """Browser testing handled by phased-hunter (Claude). No-op."""
        self._browser = None

    def _adaptive_evaluate(self, phase: str, results: List[AgentResult]):
        """Let the adaptive engine evaluate phase results and adjust strategy."""
        if not self._adaptive:
            return

        from engine.core.adaptive_engine import AdaptiveAction

        phase_time = sum(r.duration_seconds for r in results)
        self._adaptive.spend_budget(phase_time)

        evaluation = self._adaptive.evaluate_phase(phase, results, self.profile)

        if evaluation.action == AdaptiveAction.RETRY_DEEPER:
            self._log(f"ADAPTIVE: Retrying phase {phase} with deeper config")
            # Re-run the phase (dispatcher handles this)
            retry_results = self.dispatcher.run_phase(phase)
            self.report.phases_completed.append(f"{phase}-retry")
            self._adaptive.spend_budget(sum(r.duration_seconds for r in retry_results))

        elif evaluation.action == AdaptiveAction.EXPAND_SCOPE:
            # Expand profile triggers based on what discovery found
            new_triggers = self._adaptive.expand_profile(self.profile, results)
            if new_triggers:
                from engine.core.target_profiler import TargetProfiler
                profiler = TargetProfiler(self.target)
                for trigger in new_triggers:
                    profiler.update_from_discovery(trigger.replace('has_', ''), True)
                self._log(f"ADAPTIVE: Expanded profile with {new_triggers}")

        elif evaluation.action == AdaptiveAction.REGENERATE:
            self._log("ADAPTIVE: Regenerating hypotheses (LLM-powered)")
            failed = [r.agent_name for r in results if not r.success]
            # Pass recon data and findings so LLM can reason about what to try
            recon = {'target': self.target, 'tech_stack': [],
                     'endpoints': [], 'findings': self.dispatcher.get_findings()}
            if self.profile:
                recon['tech_stack'] = list(getattr(self.profile, 'triggers', set()))
            new_hypotheses = self._adaptive.regenerate_hypotheses(
                self.profile, failed,
                recon_data=recon,
                findings=self.dispatcher.get_findings(),
            )
            if new_hypotheses:
                self._log(f"ADAPTIVE: Generated {len(new_hypotheses)} new hypotheses")

        elif evaluation.action == AdaptiveAction.SKIP:
            self._log("ADAPTIVE: Budget exhausted, skipping remaining phases")

    def _run_exploit_chainer(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run exploit chainer to discover multi-step attack chains."""
        if len(findings) < 2:
            return findings

        try:
            from engine.core.exploit_chainer import ExploitChainer
            chainer = ExploitChainer()
            chains = chainer.find_chains(findings)

            if chains:
                self._log(f"CHAINS: Found {len(chains)} exploit chains:")
                for chain in chains:
                    self._log(f"  - {chain.name} ({chain.impact})")
                    # Generate chain report and save
                    report = chainer.generate_chain_report(chain)
                    chain.chain_report = report

                # Escalate severity on findings that participate in chains
                findings = chainer.escalate_severity(findings, chains)

                # Add chain findings as separate entries
                for chain in chains:
                    chain_finding = {
                        'title': f"Exploit Chain: {chain.name}",
                        'description': chain.description,
                        'vulnerability_type': 'exploit_chain',
                        'severity': chain.impact,
                        'evidence': chain.chain_report,
                        '_source_agent': 'exploit_chainer',
                        '_chain_steps': len(chain.steps),
                    }
                    findings.append(chain_finding)

            return findings
        except Exception as e:
            self._log(f"Exploit chainer error: {e}")
            return findings

    def _run_stored_payload_check(self) -> List[Dict[str, Any]]:
        """Check for triggered stored payloads (second-order vulns)."""
        if not self._payload_tracker:
            return []

        try:
            self._log("Checking stored payload triggers...")
            second_order = self._payload_tracker.check_triggers(timeout=10)
            if second_order:
                self._log(f"SECOND-ORDER: Found {len(second_order)} triggered payloads!")
                findings = []
                for sof in second_order:
                    findings.append({
                        'title': f"Second-Order {sof.payload.payload_type.upper()}: {sof.payload.injection_point}",
                        'description': sof.description,
                        'vulnerability_type': f'stored_{sof.payload.payload_type}',
                        'severity': sof.severity,
                        'evidence': sof.evidence,
                        'url': sof.payload.injection_point,
                        '_source_agent': 'stored_payload_tracker',
                    })
                return findings
            self._log(f"No stored payload triggers ({self._payload_tracker.get_summary()})")
            return []
        except Exception as e:
            self._log(f"Stored payload check error: {e}")
            return []

    def _cleanup_subsystems(self):
        """Clean up browser, OAST listener, etc."""
        if self._payload_tracker:
            try:
                self._payload_tracker._oast.stop_listener()
            except Exception:
                pass

    def execute(self, force: bool = False) -> HuntReport:
        """Execute the complete adaptive hunt pipeline.

        The pipeline now includes:
        - Adaptive engine: adjusts strategy when phases find nothing
        - Exploit chainer: combines findings into higher-impact chains
        - Browser executor: available for DOM/SPA testing
        - Stored payload tracker: detects second-order vulnerabilities

        Args:
            force: Skip Phase 0 DB check and run regardless

        Returns:
            HuntReport with all results
        """
        start_time = time.time()
        self._banner()

        # Initialize subsystems
        self._adaptive = None
        self._payload_tracker = None
        self._browser = None
        self._llm_bridge = None

        # Phase 0: DB check
        if not force and not self.phase_0_db_check():
            self.report.finished_at = datetime.now().isoformat()
            self.report.duration_seconds = time.time() - start_time
            return self.report

        # Phase 0.5: Profile target
        self.phase_05_profile()

        # Initialize dispatcher with profile and auth tokens
        self.dispatcher = AutoDispatcher(
            self.registry, self.profile, max_workers=self.max_workers,
            auth_tokens=self.auth_tokens,
        )

        # Initialize subsystems
        self._init_llm_bridge()
        self._init_adaptive_engine()
        self._init_stored_payload_tracker()
        self._init_browser_executor()

        # Initialize hunt state for persistence
        try:
            from engine.core.hunt_state import HuntState
            self.hunt_state = HuntState(self.target)
        except Exception:
            pass

        # Run phases in order with adaptive evaluation
        phase_order = ['1', '1.5', '2', '3C', '3D', '5', '6']

        for phase in phase_order:
            try:
                # Check adaptive budget
                if self._adaptive and self._adaptive.remaining_budget() <= 0:
                    self._log(f"Budget exhausted, skipping phase {phase}+")
                    break

                if self.hunt_state:
                    self.hunt_state.update_phase(phase, 'in_progress')

                results = self._run_phase(phase)

                # Adaptive evaluation after each phase
                self._adaptive_evaluate(phase, results)

                if self.hunt_state:
                    self.hunt_state.update_phase(phase, 'completed')

            except KeyboardInterrupt:
                self._log(f"Hunt interrupted at phase {phase}")
                break
            except Exception as e:
                self._log(f"Phase {phase} error: {e}")
                continue

        # Compile raw findings
        self.report.agent_results = self.dispatcher.results
        raw_findings = self.dispatcher.get_findings()
        self.report.agents_run = sum(1 for r in self.dispatcher.results if r.success)
        self.report.agents_failed = sum(1 for r in self.dispatcher.results if not r.success)
        self.report.agents_skipped = len(self.dispatcher._skipped)

        # CHECK STORED PAYLOADS: second-order vuln detection
        stored_findings = self._run_stored_payload_check()
        raw_findings.extend(stored_findings)

        # CHAIN: discover exploit chains across findings
        raw_findings = self._run_exploit_chainer(raw_findings)

        # DEDUP: Remove semantically duplicate findings across agents
        deduped_findings = self._dedup_findings(raw_findings)

        # MANDATORY: Run all findings through validation pipeline
        self.report.findings = self._validate_findings(deduped_findings)

        self.report.finished_at = datetime.now().isoformat()
        self.report.duration_seconds = time.time() - start_time

        # Print adaptive strategy report
        if self._adaptive:
            print(self._adaptive.get_hunt_strategy_report())

        # Print LLM usage stats
        if self._llm_bridge:
            self._llm_bridge.print_stats()

        # Save report
        self._save_report()

        # Record hunt completion so DB skip-cache activates for next 7 days
        try:
            from engine.core.database import BountyHoundDB
            _db = BountyHoundDB()
            _db.record_tool_run(
                self.target,
                'hunt_executor',
                findings_count=len(self.report.findings),
                duration_seconds=int(getattr(self.report, 'duration_seconds', 0)),
                success=True,
            )
        except Exception:
            pass

        # Print summary
        print(self.report.summary())

        # Cleanup subsystems
        self._cleanup_subsystems()

        # Generate resume file
        if self.hunt_state:
            try:
                self.hunt_state.generate_resume()
            except Exception:
                pass

        return self.report

    def _dedup_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove semantically duplicate findings across agents.

        When multiple agents find the same vulnerability, keep the one with
        the most evidence (longest description/evidence text).
        """
        if len(findings) <= 1:
            return findings

        try:
            from engine.core.semantic_dedup import SemanticDuplicateDetector
            dedup = SemanticDuplicateDetector()

            unique = []
            removed = 0

            for finding in findings:
                is_dup = False
                for existing in unique:
                    similarity = dedup.compute_similarity(finding, existing)
                    if similarity >= 0.75:
                        is_dup = True
                        # Keep the one with more evidence
                        new_text = f"{finding.get('evidence', '')} {finding.get('description', '')}"
                        old_text = f"{existing.get('evidence', '')} {existing.get('description', '')}"
                        if len(new_text) > len(old_text):
                            unique.remove(existing)
                            unique.append(finding)
                        removed += 1
                        break

                if not is_dup:
                    unique.append(finding)

            if removed > 0:
                self._log(f"Dedup: removed {removed} duplicate findings ({len(findings)} -> {len(unique)})")
            return unique

        except Exception as e:
            self._log(f"Dedup error ({e}) - skipping dedup")
            return findings

    def _validate_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run all findings through the validation pipeline.

        Only SUBMIT and HOLD findings make it to the report.
        REJECT findings are discarded with a log message.
        """
        if not raw_findings:
            return []

        self._log(f"Validating {len(raw_findings)} raw findings through quality gates...")

        try:
            from engine.core.validation_pipeline import ValidationPipeline
            pipeline = ValidationPipeline(skip_poc=False, verbose=self.max_workers > 0)
            results = pipeline.validate_batch(raw_findings)

            validated = []
            for vr in results:
                # Annotate finding with validation metadata
                finding = vr.finding.copy()
                finding['_validation'] = vr.to_dict()
                finding['_verdict'] = vr.verdict
                finding['_confidence_grade'] = vr.confidence_grade
                finding['_confidence_score'] = vr.confidence_score
                finding['_estimated_bounty'] = vr.estimated_bounty

                if vr.verdict in ('SUBMIT', 'HOLD'):
                    validated.append(finding)
                else:
                    self._log(f"  REJECTED: {finding.get('title', finding.get('description', '?'))} - {vr.rejection_reason}")

            pipeline.print_summary()
            self._log(f"Validated: {len(validated)}/{len(raw_findings)} findings passed")
            return validated

        except Exception as e:
            self._log(f"Validation pipeline error: {e} - returning raw findings")
            return raw_findings

    def _save_report(self):
        """Save hunt report to findings directory."""
        try:
            # Clean target name for directory
            safe_target = self.target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
            target_dir = self.FINDINGS_DIR / safe_target
            target_dir.mkdir(parents=True, exist_ok=True)

            # Save JSON report
            report_path = target_dir / f"auto-hunt-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            with open(report_path, 'w') as f:
                json.dump(self.report.to_dict(), f, indent=2, default=str)
            self._log(f"Report saved: {report_path}")

            # Save markdown summary
            md_path = target_dir / 'AUTO-HUNT-REPORT.md'
            with open(md_path, 'w') as f:
                f.write(f"# Auto-Hunt Report: {self.target}\n\n")
                f.write(f"**Date**: {self.report.started_at}\n")
                f.write(f"**Duration**: {self.report.duration_seconds:.0f}s\n")
                f.write(f"**Agents**: {self.report.agents_run} run, {self.report.agents_failed} failed\n")
                f.write(f"**Findings**: {len(self.report.findings)}\n\n")

                if self.profile:
                    f.write(f"## Target Profile\n\n")
                    f.write(f"- Type: {self.profile.target_type}\n")
                    f.write(f"- Triggers: {', '.join(sorted(self.profile.triggers))}\n\n")

                if self.report.findings:
                    f.write(f"## Findings\n\n")
                    for i, finding in enumerate(self.report.findings, 1):
                        title = finding.get('title', finding.get('description', 'Unknown'))
                        severity = finding.get('severity', 'INFO')
                        source = finding.get('_source_agent', '?')
                        f.write(f"{i}. **[{severity}]** {title} _(from {source})_\n")

                f.write(f"\n---\n_Generated by BountyHound Auto-Hunt_\n")

            self._log(f"Markdown report: {md_path}")

        except Exception as e:
            self._log(f"Failed to save report: {e}")

    # ------------------------------------------------------------------
    # Convenience class method
    # ------------------------------------------------------------------

    @classmethod
    def hunt(cls, target: str, **kwargs) -> HuntReport:
        """Convenience method to run a full hunt.

        Usage:
            report = HuntExecutor.hunt('example.com')
        """
        executor = cls(target, **kwargs)
        return executor.execute()
