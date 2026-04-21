"""
Adaptive Engine - Mid-hunt adaptation for the BountyHound pipeline.

Sits between phases and decides whether to retry, pivot, or dig deeper when
tests fail. The hunt executor calls evaluate_phase() after each phase, then
acts on the returned PhaseEvaluation.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from colorama import Fore, Style


class AdaptiveAction(Enum):
    CONTINUE = 'continue'
    RETRY_DEEPER = 'retry_deeper'
    REGENERATE = 'regenerate'
    EXPAND_SCOPE = 'expand_scope'
    SKIP = 'skip'


@dataclass
class PhaseEvaluation:
    phase: str
    action: AdaptiveAction
    reason: str
    findings_count: int
    agents_run: int
    agents_failed: int
    time_spent: float
    retry_config: Dict[str, Any] = field(default_factory=dict)


# Budget allocation per phase (fraction of total)
PHASE_BUDGETS = {'1': 0.15, '1.5': 0.05, '2': 0.20, '3C': 0.10,
                 '3D': 0.30, '5': 0.10, '6': 0.10}
PHASE_ORDER = ['1', '1.5', '2', '3C', '3D', '5', '6']

EMERGENCY_HYPOTHESES = [
    {'type': 'auth_bypass_4xx', 'priority': 1,
     'description': 'Test all 4xx endpoints for auth bypass via method switching and header manipulation.'},
    {'type': 'info_disclosure_errors', 'priority': 2,
     'description': 'Test error pages for info disclosure: stack traces, debug output, internal paths.'},
    {'type': 'type_confusion', 'priority': 2,
     'description': 'Test all parameters for type confusion: arrays for strings, objects for ints, null coercion.'},
    {'type': 'rate_limit_abuse', 'priority': 3,
     'description': 'Test rate limits on all state-changing endpoints: password reset, OTP, checkout, transfers.'},
    {'type': 'file_upload', 'priority': 3,
     'description': 'Test file upload endpoints: polyglot files, MIME bypass, path traversal in filename, SVG XSS.'},
]


class AdaptiveEngine:
    """Mid-hunt adaptation engine. Tracks budget, phase history, and decisions."""

    def __init__(self, total_budget_seconds: int = 1800, max_retries_per_phase: int = 1):
        self._total_budget = total_budget_seconds
        self._remaining = float(total_budget_seconds)
        self._max_retries = max_retries_per_phase
        self._retries: Dict[str, int] = {}
        self._evaluations: List[PhaseEvaluation] = []
        self._completed_phases: Set[str] = set()
        self._phase_time_spent: Dict[str, float] = {}
        self._start_time = time.time()

    def _log(self, msg: str) -> None:
        print(f"  {Fore.CYAN}[adaptive]{Style.RESET_ALL} {msg}")

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate_phase(self, phase: str, agent_results: list, profile) -> PhaseEvaluation:
        """Evaluate a phase's results and decide the next action."""
        findings_count = sum(len(getattr(r, 'findings', []) or []) for r in agent_results)
        agents_run = len(agent_results)
        agents_failed = sum(1 for r in agent_results if not getattr(r, 'success', False))
        time_spent = sum(getattr(r, 'duration', 0.0) or 0.0 for r in agent_results)

        self.spend_budget(time_spent)
        self._phase_time_spent[phase] = self._phase_time_spent.get(phase, 0.0) + time_spent
        self._completed_phases.add(phase)

        budget_pct = (self._remaining / self._total_budget) * 100.0
        retry_count = self._retries.get(phase, 0)
        triggers = getattr(profile, 'triggers', set())

        self._log(f"Phase {phase}: {findings_count} findings, {agents_failed}/{agents_run} failed, "
                  f"{budget_pct:.0f}% budget left")

        def _ev(action, reason, cfg=None):
            ev = PhaseEvaluation(phase=phase, action=action, reason=reason,
                                 findings_count=findings_count, agents_run=agents_run,
                                 agents_failed=agents_failed, time_spent=time_spent,
                                 retry_config=cfg or {})
            self._evaluations.append(ev)
            return ev

        # Budget < 10% -> SKIP
        if budget_pct < 10:
            self._log("Budget below 10% -> SKIP")
            return _ev(AdaptiveAction.SKIP, 'Budget below 10%, skipping remaining phases.')

        # Findings found -> CONTINUE
        if findings_count > 0:
            self._log(f"Found {findings_count} finding(s) -> CONTINUE")
            return _ev(AdaptiveAction.CONTINUE, f'Phase {phase} produced {findings_count} finding(s).')

        # Already retried max times -> CONTINUE
        if retry_count >= self._max_retries:
            self._log(f"Retries exhausted ({retry_count}) -> CONTINUE")
            return _ev(AdaptiveAction.CONTINUE, f'Phase {phase} retried {retry_count} time(s), moving on.')

        # Discovery with no findings -> expand scope
        if phase == '1':
            self._retries[phase] = retry_count + 1
            self._log("Discovery empty -> EXPAND_SCOPE")
            return _ev(AdaptiveAction.EXPAND_SCOPE, 'Discovery produced nothing, expanding target scope.')

        # Web testing, no findings, >50% budget -> retry deeper
        if phase == '3D' and budget_pct > 50:
            self._retries[phase] = retry_count + 1
            deeper = self.get_deeper_config(phase, agent_results)
            self._log("Web testing empty, >50% budget -> RETRY_DEEPER")
            return _ev(AdaptiveAction.RETRY_DEEPER, 'Web testing found nothing, retrying deeper.', deeper)

        # Auth testing, no findings, has auth tokens -> regenerate
        if phase == '2' and ({'has_auth', 'has_jwt', 'has_session', 'has_oauth'} & triggers):
            self._retries[phase] = retry_count + 1
            self._log("Auth empty with tokens -> REGENERATE")
            return _ev(AdaptiveAction.REGENERATE, 'Auth testing found nothing despite tokens.')

        # Default
        self._log(f"Phase {phase} empty, default -> CONTINUE")
        return _ev(AdaptiveAction.CONTINUE, f'Phase {phase} found nothing, no special conditions.')

    # ------------------------------------------------------------------
    # Deeper config
    # ------------------------------------------------------------------

    def get_deeper_config(self, phase: str, previous_results: list) -> Dict[str, Any]:
        """Return escalation config for retrying a phase."""
        configs = {
            '3D': {'payload_depth': 'deep', 'timing_delay': 2.0,
                   'param_discovery': True, 'waf_bypass': True},
            '2':  {'test_all_roles': True, 'test_mfa_bypass': True,
                   'brute_force_enabled': True},
            '1':  {'wordlist': 'extended', 'wayback_depth': 10000,
                   'js_recursive': True},
        }
        config = configs.get(phase, {'payload_depth': 'deep', 'timing_delay': 1.5})
        self._log(f"Deeper config for phase {phase}: {list(config.keys())}")
        return config

    # ------------------------------------------------------------------
    # Hypothesis regeneration
    # ------------------------------------------------------------------

    def regenerate_hypotheses(self, profile, failed_strategies: List[str],
                              recon_data: Optional[Dict] = None,
                              findings: Optional[List[Dict]] = None) -> List[Dict]:
        """Generate new hypotheses, avoiding previously failed strategies.

        Strategy chain (highest quality first):
        1. LLM-powered creative bypass generation (if API key available)
        2. DiscoveryEngine template-based generation
        3. Emergency hardcoded hypotheses (last resort)
        """
        self._log(f"Regenerating hypotheses (avoiding {len(failed_strategies)} failed)")

        # Strategy 1: LLM-powered generation (best quality)
        try:
            from engine.core.llm_bridge import LLMBridge
            target = getattr(profile, 'target', '') or ''
            bridge = LLMBridge(target)
            if bridge.available:
                llm_hypotheses = bridge.generate_creative_bypasses(
                    recon_data or {}, findings or [], failed_strategies
                )
                if llm_hypotheses:
                    self._log(f"LLM generated {len(llm_hypotheses)} creative bypasses")
                    return llm_hypotheses
        except Exception as e:
            self._log(f"LLM bypass generation failed: {e}")

        # Strategy 2: DiscoveryEngine template-based
        try:
            from engine.agents.discovery_engine import DiscoveryEngine
            de = DiscoveryEngine()
            if hasattr(de, 'set_excluded_strategies'):
                de.set_excluded_strategies(failed_strategies)
            hypotheses = (de.generate_hypotheses(recon_data or {})
                          if hasattr(de, 'generate_hypotheses') else None)
            if hypotheses:
                self._log(f"DiscoveryEngine produced {len(hypotheses)} hypotheses")
                return [{'type': h.title, 'priority': 1, 'description': h.success_indicator}
                        for h in hypotheses]
        except Exception as exc:
            self._log(f"{Fore.YELLOW}DiscoveryEngine failed ({exc}){Style.RESET_ALL}")

        # Strategy 3: Emergency hardcoded hypotheses (last resort)
        self._log(f"{Fore.YELLOW}Using emergency hypotheses{Style.RESET_ALL}")
        filtered = [h for h in EMERGENCY_HYPOTHESES if h['type'] not in failed_strategies]
        return filtered or list(EMERGENCY_HYPOTHESES)

    # ------------------------------------------------------------------
    # Profile expansion
    # ------------------------------------------------------------------

    def expand_profile(self, profile, discovery_results: list) -> Set[str]:
        """Analyze discovery results for triggers the profile missed."""
        existing = getattr(profile, 'triggers', set())
        text_blob = ''
        for r in discovery_results:
            for attr in ('output', 'raw', 'body', 'data', 'findings'):
                val = getattr(r, attr, None)
                if isinstance(val, str):
                    text_blob += val.lower() + ' '
                elif isinstance(val, (list, tuple)):
                    for item in val:
                        text_blob += (item if isinstance(item, str) else str(item)).lower() + ' '

        trigger_map = {
            'has_graphql':   ['graphql', '/graphql', 'query{', 'mutation{', '__schema'],
            'has_jwt':       ['eyj', 'jwt', 'jsonwebtoken', 'bearer eyj'],
            'has_websocket': ['wss://', 'ws://', 'websocket', 'socket.io'],
            'has_grpc':      ['grpc', 'protobuf', 'proto3'],
            'has_oauth':     ['oauth', 'authorize?', 'client_id=', '/token'],
            'has_s3':        ['s3.amazonaws', '.s3.', 'nosuchbucket', 'amz-bucket'],
            'has_api':       ['/api/', '/v1/', '/v2/', '/v3/', 'swagger'],
            'has_upload':    ['upload', 'multipart', 'file-upload', 'dropzone'],
        }
        new_triggers: Set[str] = set()
        for trigger, keywords in trigger_map.items():
            if trigger not in existing and any(kw in text_blob for kw in keywords):
                new_triggers.add(trigger)
                self._log(f"Detected new trigger: {Fore.GREEN}{trigger}{Style.RESET_ALL}")
        if not new_triggers:
            self._log("No new triggers detected from discovery results.")
        return new_triggers

    # ------------------------------------------------------------------
    # Budget management
    # ------------------------------------------------------------------

    def spend_budget(self, seconds: float) -> None:
        self._remaining = max(0.0, self._remaining - seconds)

    def remaining_budget(self) -> float:
        return self._remaining

    def phase_budget(self, phase: str) -> float:
        """Suggested budget for a phase, with surplus redistribution."""
        base = PHASE_BUDGETS.get(phase, 0.05) * self._total_budget
        surplus = 0.0
        for done in self._completed_phases:
            allocated = PHASE_BUDGETS.get(done, 0.05) * self._total_budget
            spent = self._phase_time_spent.get(done, 0.0)
            if spent < allocated:
                surplus += allocated - spent
        remaining_phases = [p for p in PHASE_ORDER if p not in self._completed_phases]
        if remaining_phases and phase in remaining_phases:
            base += surplus / len(remaining_phases)
        return min(base, self._remaining)

    # ------------------------------------------------------------------
    # Strategy report
    # ------------------------------------------------------------------

    def get_hunt_strategy_report(self) -> str:
        """Return human-readable report of all adaptive decisions."""
        elapsed = time.time() - self._start_time
        pct = (self._remaining / self._total_budget) * 100.0
        lines = [
            f"\n{Fore.CYAN}{'=' * 55}",
            f"  ADAPTIVE ENGINE STRATEGY REPORT",
            f"{'=' * 55}{Style.RESET_ALL}",
            f"  Budget: {self._remaining:.0f}s / {self._total_budget}s ({pct:.0f}%)  |  "
            f"Wall: {elapsed:.0f}s  |  Phases: {len(self._completed_phases)}",
            '',
        ]
        total_findings = 0
        colors = {AdaptiveAction.CONTINUE: Fore.GREEN, AdaptiveAction.RETRY_DEEPER: Fore.YELLOW,
                  AdaptiveAction.REGENERATE: Fore.MAGENTA, AdaptiveAction.EXPAND_SCOPE: Fore.BLUE,
                  AdaptiveAction.SKIP: Fore.RED}
        for ev in self._evaluations:
            total_findings += ev.findings_count
            c = colors.get(ev.action, '')
            lines.append(f"  Phase {ev.phase:>3s} | {c}{ev.action.value:<15s}{Style.RESET_ALL} | "
                         f"{ev.findings_count} findings | {ev.agents_run} agents "
                         f"({ev.agents_failed} failed) | {ev.time_spent:.1f}s")
            if ev.retry_config:
                lines.append(f"          cfg: {', '.join(f'{k}={v}' for k, v in ev.retry_config.items())}")

        lines.append(f"\n  Total findings: {total_findings}")
        retried = [p for p, c in self._retries.items() if c > 0]
        if retried:
            lines.append(f"  Retried: {', '.join(retried)}")
        skipped = [ev.phase for ev in self._evaluations if ev.action == AdaptiveAction.SKIP]
        if skipped:
            lines.append(f"  Skipped: {', '.join(skipped)}")
        expanded = [ev.phase for ev in self._evaluations if ev.action == AdaptiveAction.EXPAND_SCOPE]
        if expanded:
            lines.append(f"  Scope expanded after: {', '.join(expanded)}")
        lines.append('')
        return '\n'.join(lines)
