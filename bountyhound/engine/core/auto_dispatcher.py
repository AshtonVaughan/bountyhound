"""
Auto Dispatcher - Runs agents automatically based on target profile.

The dispatcher evaluates which agents should run for each phase,
dynamically imports them, instantiates them, and runs them with
ThreadPoolExecutor for parallelism within each phase.

Includes:
- Inspect-based agent factory (handles any constructor signature)
- Credential injection for auth-requiring agents
- Scope validation pre-flight checks
- Per-domain rate limiting with WAF detection

Usage:
    from engine.core.agent_registry import AgentRegistry
    from engine.core.target_profiler import TargetProfile
    from engine.core.auto_dispatcher import AutoDispatcher

    registry = AgentRegistry()
    profile = TargetProfile(target='example.com', has_web=True, has_graphql=True)

    dispatcher = AutoDispatcher(registry, profile)
    results = dispatcher.run_phase('3D')
    # Returns: [AgentResult(...), AgentResult(...), ...]
"""

import importlib
import inspect
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from colorama import Fore, Style

from engine.core.agent_registry import AgentRegistry, AgentEntry


@dataclass
class AgentResult:
    """Result from running a single agent."""
    agent_name: str
    phase: str
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ''
    duration_seconds: float = 0.0
    raw_output: Any = None


class AutoDispatcher:
    """Runs agents automatically based on target profile triggers.

    For each phase, it:
    1. Validates target against scope rules (pre-flight)
    2. Queries the registry for agents whose triggers match the profile
    3. Checks DB hooks to skip recently-run agents
    4. Dynamically imports and instantiates each agent (inspect-based factory)
    5. Injects credentials for auth-requiring agents
    6. Acquires rate limiter slot before running
    7. Runs agents in parallel using ThreadPoolExecutor
    8. Collects and returns results
    """

    # Phases in execution order
    PHASE_ORDER = ['1', '1.5', '2', '3C', '3D', '5', '6']

    def __init__(self, registry: AgentRegistry, profile, max_workers: int = 4,
                 auth_tokens: Optional[Dict[str, str]] = None):
        """
        Args:
            registry: AgentRegistry instance
            profile: TargetProfile with active triggers
            max_workers: Max parallel agents per phase
            auth_tokens: Optional {role: token} dict for auth testing
        """
        self.registry = registry
        self.profile = profile
        self.max_workers = max_workers
        self.auth_tokens = auth_tokens or {}
        self.results: List[AgentResult] = []
        self._skipped: List[str] = []
        self._failed: List[str] = []
        self._scope_checked = False
        self._in_scope = True

        # Initialize rate limiter
        self._rate_limiter = None
        try:
            from engine.core.rate_limiter import RateLimiter
            self._rate_limiter = RateLimiter(default_rps=5.0)
        except Exception:
            pass

        # Load credentials from cache if not provided
        if not self.auth_tokens:
            self._load_cached_credentials()

    def _log(self, msg: str):
        print(f"  {Fore.YELLOW}[dispatch]{Style.RESET_ALL} {msg}")

    def _log_phase(self, phase: str, count: int):
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  PHASE {phase}: {count} agents queued{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

    # ------------------------------------------------------------------
    # Credential Loading
    # ------------------------------------------------------------------

    def _load_cached_credentials(self):
        """Load credentials from CredentialCache for the target."""
        try:
            from engine.core.cred_cache import CredentialCache
            cache = CredentialCache()
            creds = cache.retrieve_all(self.profile.target)
            if creds:
                # Map cache keys to auth_tokens dict
                # Keys look like "user_a_AUTH_TOKEN", "user_b_AUTH_TOKEN"
                for cache_key, value in creds.items():
                    parts = cache_key.split('_', 2)
                    if len(parts) >= 3:
                        role = f"{parts[0]}_{parts[1]}"  # e.g. "user_a"
                        self.auth_tokens[role] = value
                if self.auth_tokens:
                    self._log(f"Loaded {len(self.auth_tokens)} credentials from cache")
        except Exception:
            pass

        # Also try loading from .env file
        if not self.auth_tokens:
            try:
                from engine.core.cred_cache import CredentialCache
                cache = CredentialCache()
                count = cache.sync_from_env(self.profile.target)
                if count > 0:
                    creds = cache.retrieve_all(self.profile.target)
                    for cache_key, value in creds.items():
                        parts = cache_key.split('_', 2)
                        if len(parts) >= 3:
                            role = f"{parts[0]}_{parts[1]}"
                            self.auth_tokens[role] = value
                    self._log(f"Synced {count} credentials from .env file")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Scope Validation
    # ------------------------------------------------------------------

    def _check_scope(self) -> bool:
        """Validate target against scope rules. Returns True if in scope."""
        if self._scope_checked:
            return self._in_scope

        self._scope_checked = True
        try:
            from engine.core.scope_validator import ScopeValidator
            validator = ScopeValidator(self.profile.target)
            if validator.scope is None:
                # No scope defined - proceed with caution
                self._log("No scope file found - proceeding (define scope for safety)")
                self._in_scope = True
                return True

            in_scope, reason = validator.is_domain_in_scope(self.profile.target)
            if not in_scope:
                self._log(f"SCOPE CHECK FAILED: {reason}")
                self._log("Aborting dispatch - target is OUT OF SCOPE")
                self._in_scope = False
                return False

            self._log(f"Scope check: {reason}")
            self._in_scope = True
            return True
        except Exception as e:
            self._log(f"Scope check error ({e}) - proceeding")
            self._in_scope = True
            return True

    # ------------------------------------------------------------------
    # Agent Selection
    # ------------------------------------------------------------------

    def get_agents_for_phase(self, phase: str) -> List[AgentEntry]:
        """Get agents that should run for a phase given current profile."""
        triggers = self.profile.triggers
        return self.registry.for_phase(phase, triggers)

    def _should_skip(self, agent: AgentEntry) -> bool:
        """Check if agent was run recently (DB hooks)."""
        try:
            from engine.core.db_hooks import DatabaseHooks
            context = DatabaseHooks.before_test(self.profile.target, agent.name)
            if context.get('should_skip', False):
                self._log(f"  SKIP {agent.name}: {context.get('reason', 'tested recently')}")
                self._skipped.append(agent.name)
                return True
        except Exception:
            pass  # DB not available, don't skip
        return False

    # ------------------------------------------------------------------
    # Inspect-Based Agent Factory
    # ------------------------------------------------------------------

    def _import_agent(self, agent: AgentEntry):
        """Dynamically import and return the agent class."""
        module = importlib.import_module(agent.module)
        cls = getattr(module, agent.class_name)
        return cls

    def _build_constructor_args(self, cls, agent: AgentEntry) -> Dict[str, Any]:
        """Inspect the constructor and map available data to parameters.

        Uses inspect.signature() to read the __init__ parameters, then
        maps known parameter names to available values from the profile,
        auth tokens, and dispatcher config.
        """
        target = self.profile.target
        base_url = getattr(self.profile, 'base_url', '') or target

        # Ensure base_url has scheme for web agents
        if agent.needs_target_url and not base_url.startswith(('http://', 'https://')):
            base_url = f"https://{base_url}"

        # Build a map of parameter name -> value
        param_pool = {
            # Target identifiers (most common first-positional params)
            'target': target,
            'target_url': base_url,
            'base_url': base_url,
            'url': base_url,
            'gateway_url': base_url,
            'hostname': target,
            'host': target,
            'target_host': target,
            'domain': target,
            'target_domain': target,
            'endpoint': base_url,
            'api_base_url': base_url,
            'upload_url': base_url,

            # Non-web targets
            'binary_path': target,
            'apk_path': target,
            'repo_path': target,

            # Common optional params
            'timeout': 30,
            'verify_ssl': True,
            'max_workers': self.max_workers,
            'threads': self.max_workers,
            'use_database': True,

            # Auth-related
            'auth_token': self.auth_tokens.get('user_a', ''),
            'api_key': self.auth_tokens.get('user_a', ''),
            'session_token': self.auth_tokens.get('user_a', ''),
        }

        # Add auth tokens if available
        if self.auth_tokens:
            param_pool['api_tokens'] = self.auth_tokens
            param_pool['tokens'] = self.auth_tokens
            param_pool['credentials'] = self.auth_tokens

        try:
            sig = inspect.signature(cls.__init__)
        except (ValueError, TypeError):
            return {}

        kwargs = {}
        params = list(sig.parameters.items())

        for i, (name, param) in enumerate(params):
            if name == 'self':
                continue

            # Check if we have a value for this parameter
            if name in param_pool:
                kwargs[name] = param_pool[name]
            elif param.default is not inspect.Parameter.empty:
                # Has a default value - skip it, let the default apply
                continue
            elif param.kind == inspect.Parameter.VAR_POSITIONAL:
                # *args - skip
                continue
            elif param.kind == inspect.Parameter.VAR_KEYWORD:
                # **kwargs - skip
                continue
            else:
                # Required param with no match - try the target as fallback
                # This handles unusual param names like 'file_param', 'app_scheme', etc.
                # Only apply target/base_url to the first unmatched required param
                if i == 1:  # First non-self param
                    kwargs[name] = base_url if agent.needs_target_url else target
                # Otherwise leave it out and let the fallback handle it

        return kwargs

    def _instantiate_agent(self, cls, agent: AgentEntry):
        """Create an instance of the agent class using inspect-based factory.

        Strategy:
        1. Inspect constructor signature and map known params
        2. Try with mapped kwargs
        3. Fall back to positional arg patterns
        4. Fall back to no-arg constructor
        """
        target = self.profile.target
        base_url = getattr(self.profile, 'base_url', '') or target
        if agent.needs_target_url and not base_url.startswith(('http://', 'https://')):
            base_url = f"https://{base_url}"

        # Strategy 1: Inspect-based kwargs
        kwargs = self._build_constructor_args(cls, agent)
        if kwargs:
            try:
                return cls(**kwargs)
            except TypeError:
                pass

        # Strategy 2: Single positional arg (most common pattern)
        for arg in [base_url, target]:
            try:
                return cls(arg)
            except TypeError:
                continue

        # Strategy 3: No-arg constructor
        try:
            return cls()
        except TypeError:
            pass

        raise TypeError(f"Cannot instantiate {agent.class_name}: no compatible constructor")

    def _inject_credentials(self, instance, agent: AgentEntry):
        """Inject credentials into an agent instance after construction.

        For agents that need auth but whose constructors don't accept tokens,
        set credentials as attributes on the instance.
        """
        if not agent.needs_auth or not self.auth_tokens:
            return

        # Common attribute names agents use for auth
        for attr_name in ['auth_token', 'token', 'api_key', 'session_token',
                          'headers', 'credentials', 'auth_tokens', 'tokens']:
            if hasattr(instance, attr_name):
                current = getattr(instance, attr_name)
                if current is None or current == '' or current == {}:
                    if attr_name == 'headers':
                        token = self.auth_tokens.get('user_a', '')
                        if token:
                            setattr(instance, attr_name, {'Authorization': token})
                    elif attr_name in ('auth_tokens', 'tokens', 'credentials'):
                        setattr(instance, attr_name, self.auth_tokens)
                    else:
                        token = self.auth_tokens.get('user_a', '')
                        if token:
                            setattr(instance, attr_name, token)

    # ------------------------------------------------------------------
    # Agent Execution
    # ------------------------------------------------------------------

    def _run_single_agent(self, agent: AgentEntry) -> AgentResult:
        """Import, instantiate, and run a single agent."""
        start = time.time()
        try:
            # Rate limit: acquire slot before running
            if self._rate_limiter:
                domain = self.profile.target
                self._rate_limiter.acquire(domain)

            # Import
            cls = self._import_agent(agent)

            # Instantiate with inspect-based factory
            instance = self._instantiate_agent(cls, agent)

            # Inject credentials if needed
            self._inject_credentials(instance, agent)

            # Get the run method
            method = getattr(instance, agent.run_method, None)
            if method is None:
                # Fallback methods
                for fallback in ['run_all_tests', 'run', 'scan', 'analyze', 'test_all']:
                    method = getattr(instance, fallback, None)
                    if method:
                        break

            if method is None:
                return AgentResult(
                    agent_name=agent.name, phase=agent.phase,
                    success=False, error=f"No callable method found (tried {agent.run_method})",
                    duration_seconds=time.time() - start,
                )

            # Run it
            self._log(f"  RUN {agent.name}.{agent.run_method}()")
            raw = method()

            # Normalize output to findings list
            findings = self._normalize_findings(raw, agent)

            duration = time.time() - start
            self._log(f"  DONE {agent.name}: {len(findings)} findings in {duration:.1f}s")

            # Record tool run in DB
            try:
                from engine.core.db_hooks import DatabaseHooks
                from engine.core.database import BountyHoundDB
                db = BountyHoundDB()
                db.record_tool_run(self.profile.target, agent.name,
                                   findings_count=len(findings),
                                   duration_seconds=int(duration))
            except Exception:
                pass

            return AgentResult(
                agent_name=agent.name, phase=agent.phase,
                success=True, findings=findings,
                duration_seconds=duration, raw_output=raw,
            )

        except Exception as e:
            duration = time.time() - start
            error_msg = f"{type(e).__name__}: {e}"
            self._log(f"  FAIL {agent.name}: {error_msg}")
            self._failed.append(agent.name)
            return AgentResult(
                agent_name=agent.name, phase=agent.phase,
                success=False, error=error_msg,
                duration_seconds=duration,
            )

    # ------------------------------------------------------------------
    # Output Normalization
    # ------------------------------------------------------------------

    def _normalize_findings(self, raw_output: Any, agent: AgentEntry) -> List[Dict[str, Any]]:
        """Convert agent output to a standard list of finding dicts."""
        if raw_output is None:
            return []

        # Already a list of dicts
        if isinstance(raw_output, list):
            findings = []
            for item in raw_output:
                if isinstance(item, dict):
                    findings.append(item)
                elif hasattr(item, '__dict__'):
                    # Dataclass or object
                    findings.append(vars(item))
                else:
                    findings.append({'description': str(item), 'source': agent.name})
            return findings

        # Single dict
        if isinstance(raw_output, dict):
            # Could be a summary dict with a 'findings' or 'vulnerabilities' key
            for key in ['findings', 'vulnerabilities', 'results', 'issues']:
                if key in raw_output and isinstance(raw_output[key], list):
                    return self._normalize_findings(raw_output[key], agent)
            return [raw_output]

        # Dataclass/object
        if hasattr(raw_output, '__dict__'):
            d = vars(raw_output)
            for key in ['findings', 'vulnerabilities', 'results', 'issues']:
                if key in d and isinstance(d[key], list):
                    return self._normalize_findings(d[key], agent)
            return [d]

        # String output
        if isinstance(raw_output, str) and raw_output.strip():
            return [{'description': raw_output, 'source': agent.name}]

        return []

    # ------------------------------------------------------------------
    # Phase Execution
    # ------------------------------------------------------------------

    def run_phase(self, phase: str) -> List[AgentResult]:
        """Run all matching agents for a single phase."""
        # Pre-flight: scope check (only on first phase)
        if not self._scope_checked:
            if not self._check_scope():
                return []

        agents = self.get_agents_for_phase(phase)
        if not agents:
            return []

        # Filter out recently-run agents
        agents_to_run = [a for a in agents if not self._should_skip(a)]
        if not agents_to_run:
            self._log(f"Phase {phase}: all agents skipped (recently tested)")
            return []

        # Warn about auth agents without credentials
        auth_agents = [a for a in agents_to_run if a.needs_auth]
        if auth_agents and not self.auth_tokens:
            self._log(f"WARNING: {len(auth_agents)} agents need auth but no credentials loaded")
            self._log("  Run /creds add <target> to set up credentials")

        self._log_phase(phase, len(agents_to_run))

        phase_results = []

        # Run agents in parallel
        workers = min(self.max_workers, len(agents_to_run))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._run_single_agent, agent): agent
                for agent in agents_to_run
            }
            for future in as_completed(futures):
                result = future.result()
                phase_results.append(result)
                self.results.append(result)

        return phase_results

    def run_all_phases(self) -> List[AgentResult]:
        """Run all phases in order, collecting results."""
        self._log(f"Starting auto-dispatch for {self.profile.target}")
        self._log(f"Active triggers: {sorted(self.profile.triggers)}")
        if self.auth_tokens:
            self._log(f"Credentials loaded: {list(self.auth_tokens.keys())}")

        for phase in self.PHASE_ORDER:
            self.run_phase(phase)

        self._print_summary()
        return self.results

    def _print_summary(self):
        """Print dispatch summary."""
        total = len(self.results)
        succeeded = sum(1 for r in self.results if r.success)
        failed = sum(1 for r in self.results if not r.success)
        total_findings = sum(len(r.findings) for r in self.results)
        total_time = sum(r.duration_seconds for r in self.results)

        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  AUTO-DISPATCH SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"  Agents run:     {succeeded}/{total}")
        print(f"  Agents failed:  {failed}")
        print(f"  Agents skipped: {len(self._skipped)}")
        print(f"  Total findings: {total_findings}")
        print(f"  Total time:     {total_time:.1f}s")

        # Rate limiter stats
        if self._rate_limiter:
            stats = self._rate_limiter.get_stats(self.profile.target)
            if stats.get('total_requests', 0) > 0:
                print(f"  Rate limited:   {stats.get('total_blocks', 0)} blocks")
                if stats.get('last_waf'):
                    print(f"  WAF detected:   {stats['last_waf']}")

        if total_findings > 0:
            print(f"\n  {Fore.RED}FINDINGS:{Style.RESET_ALL}")
            for r in self.results:
                if r.findings:
                    print(f"    {r.agent_name}: {len(r.findings)} findings")

        if self._failed:
            print(f"\n  {Fore.YELLOW}FAILED:{Style.RESET_ALL}")
            for name in self._failed:
                result = next((r for r in self.results if r.agent_name == name), None)
                if result:
                    print(f"    {name}: {result.error}")

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all findings from all completed agents."""
        all_findings = []
        for r in self.results:
            for f in r.findings:
                f['_source_agent'] = r.agent_name
                f['_phase'] = r.phase
                all_findings.append(f)
        return all_findings
