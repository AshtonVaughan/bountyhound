"""
LLM Bridge - Synchronous interface to AI-powered generation for the pipeline.

Wraps AIPoweredHunter's async methods into synchronous calls that every module
in the pipeline can use. Gracefully degrades when ANTHROPIC_API_KEY is missing.

Supported providers (configure via environment variables):
    REASONING_PROVIDER=local        # Use local finetuned Qwen 32B (free, $0 cost)
    REASONING_PROVIDER=deepseek     # Use DeepSeek R1 for heavy reasoning
    REASONING_PROVIDER=together     # Use Together.ai (DeepSeek R1 hosted)
    REASONING_PROVIDER=openrouter   # Use OpenRouter (auto-cheapest routing)
    REASONING_PROVIDER=anthropic    # Use Claude (default)

Provider API keys:
    LOCAL_LLM_API_KEY=bh-local-key  # Local vLLM server (default: bh-local-key)
    DEEPSEEK_API_KEY=sk-...         # deepseek.com API
    TOGETHER_API_KEY=...            # together.ai API
    OPENROUTER_API_KEY=sk-or-...    # openrouter.ai API
    ANTHROPIC_API_KEY=sk-ant-...    # Anthropic API (default)

Integration points:
- DiscoveryEngine: LLM-powered hypothesis generation (Track 5)
- AdaptiveEngine: LLM-powered regeneration when stuck
- ExploitChainer: LLM-powered novel chain discovery beyond templates
- HuntExecutor: LLM-powered creative bypasses when all phases fail
- WAF bypass: LLM-generated targeted bypass payloads
- Payload mutation: LLM-suggested context-aware mutations

Usage:
    from engine.core.llm_bridge import LLMBridge

    bridge = LLMBridge('example.com')
    if bridge.available:
        hypotheses = bridge.generate_hypotheses(recon_data, findings)
        chains = bridge.discover_chains(findings)
        bypasses = bridge.generate_bypasses(recon_data, findings)
        payloads = bridge.generate_payloads(context)
"""

import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional

import requests
from colorama import Fore, Style


# ---------------------------------------------------------------------------
# Provider configuration
# ---------------------------------------------------------------------------

_PROVIDERS = {
    'local': {
        'base_url': os.environ.get('LOCAL_LLM_BASE_URL',
                                   'http://localhost:8000/v1/chat/completions'),
        'reasoning_model': 'qwen32b-security',     # Same model for both tiers
        'fast_model': 'qwen32b-security',           # Finetuned Qwen 2.5 32B
        'cost_per_1k_input': 0.0,                   # Free — local inference
        'cost_per_1k_output': 0.0,
        'env_key': 'LOCAL_LLM_API_KEY',
    },
    'deepseek': {
        'base_url': 'https://api.deepseek.com/v1/chat/completions',
        'reasoning_model': 'deepseek-reasoner',   # DeepSeek R1 full
        'fast_model': 'deepseek-chat',             # DeepSeek V3 (fast + cheap)
        'cost_per_1k_input': 0.00055,
        'cost_per_1k_output': 0.00219,
        'env_key': 'DEEPSEEK_API_KEY',
    },
    'together': {
        'base_url': 'https://api.together.xyz/v1/chat/completions',
        'reasoning_model': 'deepseek-ai/DeepSeek-R1',
        'fast_model': 'meta-llama/Llama-3.3-70B-Instruct-Turbo',
        'cost_per_1k_input': 0.003,
        'cost_per_1k_output': 0.003,
        'env_key': 'TOGETHER_API_KEY',
    },
    'openrouter': {
        'base_url': 'https://openrouter.ai/api/v1/chat/completions',
        'reasoning_model': 'deepseek/deepseek-r1',
        'fast_model': 'meta-llama/llama-3.3-70b-instruct',
        'cost_per_1k_input': 0.003,
        'cost_per_1k_output': 0.003,
        'env_key': 'OPENROUTER_API_KEY',
    },
    'anthropic': {
        'base_url': None,  # Uses Anthropic SDK directly
        'reasoning_model': 'claude-opus-4-6',
        'fast_model': 'claude-sonnet-4-5-20250929',
        'cost_per_1k_input': 0.015,
        'cost_per_1k_output': 0.075,
        'env_key': 'ANTHROPIC_API_KEY',
    },
}


def _detect_provider() -> str:
    """Auto-detect which provider to use based on available API keys.

    Priority: explicit REASONING_PROVIDER env var > Local vLLM > DeepSeek >
    Together > OpenRouter > Anthropic (fallback).
    """
    explicit = os.environ.get('REASONING_PROVIDER', '').lower()
    if explicit and explicit in _PROVIDERS:
        return explicit

    # Auto-detect by key presence (local first — free, no API costs)
    for provider in ('local', 'deepseek', 'together', 'openrouter'):
        key_name = _PROVIDERS[provider]['env_key']
        if os.environ.get(key_name, '').strip():
            return provider

    return 'anthropic'


class LLMBridge:
    """Synchronous bridge to AI-powered generation.

    Supports local vLLM (finetuned Qwen 32B), DeepSeek R1, Together.ai,
    OpenRouter, and Anthropic Claude.
    Auto-selects provider based on available API keys. Falls back gracefully.
    """

    # Cost tracking (approximate per 1K tokens at 2026 pricing, USD)
    _COST_PER_1K = {'claude-opus-4-6': 0.015, 'claude-sonnet-4-5-20250929': 0.003}

    def __init__(self, target: str, api_key: Optional[str] = None):
        self.target = target

        # Detect provider
        self._provider_name = _detect_provider()
        self._provider = _PROVIDERS[self._provider_name]

        # Load API key (local provider defaults to bh-local-key)
        env_key = self._provider['env_key']
        default_key = 'bh-local-key' if self._provider_name == 'local' else ''
        self._api_key = (api_key
                         or os.environ.get(env_key, '')
                         or os.environ.get('ANTHROPIC_API_KEY', '')
                         or default_key)
        self._available = bool(self._api_key)

        self._hunter = None
        self._call_count = 0
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._total_cost = 0.0
        self._errors = 0

        if self._available:
            if self._provider_name == 'anthropic':
                try:
                    from engine.core.ai_hunter import AIPoweredHunter
                    self._hunter = AIPoweredHunter(
                        target=target, api_key=self._api_key, max_iterations=0
                    )
                except Exception as e:
                    self._log(f"Failed to init AIPoweredHunter: {e}")
                    self._available = False
            else:
                self._log(f"Provider: {self._provider_name} "
                          f"(reasoning={self._provider['reasoning_model']}, "
                          f"fast={self._provider['fast_model']})")

    @property
    def available(self) -> bool:
        return self._available

    def _log(self, msg: str):
        print(f"  {Fore.YELLOW}[llm]{Style.RESET_ALL} {msg}")

    def _run_async(self, coro):
        """Run an async coroutine synchronously."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, coro)
                    return future.result(timeout=120)
            else:
                return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    def _call_openai_compatible(self, prompt: str, model: str,
                                 max_tokens: int = 4096) -> str:
        """Call any OpenAI-compatible API (DeepSeek, Together, OpenRouter).

        Uses synchronous requests — no asyncio required. Handles DeepSeek R1's
        <think>...</think> reasoning tokens by stripping them from the output
        but logging the thinking chain length for debugging.
        """
        if not self._available:
            return ''

        base_url = self._provider['base_url']
        headers = {
            'Authorization': f'Bearer {self._api_key}',
            'Content-Type': 'application/json',
        }

        # OpenRouter requires extra headers
        if self._provider_name == 'openrouter':
            headers['HTTP-Referer'] = 'https://bountyhound.local'
            headers['X-Title'] = 'BountyHound'

        payload = {
            'model': model,
            'messages': [{'role': 'user', 'content': prompt}],
            'max_tokens': max_tokens,
            'temperature': 0.7,
        }

        try:
            self._call_count += 1
            resp = requests.post(base_url, headers=headers, json=payload, timeout=180)
            resp.raise_for_status()
            data = resp.json()

            choice = data['choices'][0]['message']
            text = choice.get('content', '') or ''

            # DeepSeek R1 returns reasoning in a separate field
            reasoning = choice.get('reasoning_content', '')
            if reasoning:
                thinking_tokens = len(reasoning.split())
                self._log(f"R1 reasoning: ~{thinking_tokens} tokens of chain-of-thought")

            # Track usage
            usage = data.get('usage', {})
            input_tokens = usage.get('prompt_tokens', 0)
            output_tokens = usage.get('completion_tokens', 0)
            self._total_input_tokens += input_tokens
            self._total_output_tokens += output_tokens
            cost = ((input_tokens / 1000) * self._provider['cost_per_1k_input'] +
                    (output_tokens / 1000) * self._provider['cost_per_1k_output'])
            self._total_cost += cost

            return text

        except requests.exceptions.Timeout:
            self._errors += 1
            self._log(f"Timeout calling {self._provider_name} ({model})")
            return ''
        except Exception as e:
            self._errors += 1
            self._log(f"{self._provider_name} call failed: {e}")
            return ''

    def _call_llm_sync(self, prompt: str, use_reasoning: bool = False,
                        max_tokens: int = 4096) -> str:
        """Unified LLM call that routes to the configured provider.

        Args:
            prompt: The prompt to send.
            use_reasoning: True for complex tasks (hypothesis gen, chain discovery).
                           Routes to DeepSeek R1 / Claude Opus.
                           False for fast tasks (WAF bypass, response analysis).
                           Routes to DeepSeek V3 / Claude Sonnet.
            max_tokens: Maximum output tokens.
        """
        if not self._available:
            return ''

        if self._provider_name == 'anthropic':
            # Use Claude via existing async path
            model = (self._provider['reasoning_model'] if use_reasoning
                     else self._provider['fast_model'])
            return self._run_async(self._call_llm_anthropic(prompt, model, max_tokens))

        # OpenAI-compatible providers
        model = (self._provider['reasoning_model'] if use_reasoning
                 else self._provider['fast_model'])
        return self._call_openai_compatible(prompt, model, max_tokens)

    async def _call_llm_anthropic(self, prompt: str, model: str,
                                   max_tokens: int = 4096) -> str:
        """Async Claude call (kept for backward compat with Anthropic provider)."""
        if not self._available:
            return ''

        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=self._api_key)

        try:
            self._call_count += 1
            response = await client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            text = response.content[0].text

            usage = getattr(response, 'usage', None)
            if usage:
                self._total_input_tokens += getattr(usage, 'input_tokens', 0)
                self._total_output_tokens += getattr(usage, 'output_tokens', 0)
                total_tokens = (getattr(usage, 'input_tokens', 0) +
                                getattr(usage, 'output_tokens', 0))
                cost = (total_tokens / 1000) * self._COST_PER_1K.get(model, 0.003)
                self._total_cost += cost

            return text

        except Exception as e:
            self._errors += 1
            self._log(f"Anthropic call failed: {e}")
            return ''

    async def _call_llm(self, prompt: str, model: str = 'claude-sonnet-4-5-20250929',
                         max_tokens: int = 4096) -> str:
        """Legacy async call — kept for any code that calls _call_llm directly."""
        return await self._call_llm_anthropic(prompt, model, max_tokens)

    def _parse_json_array(self, text: str) -> List[Dict]:
        """Extract JSON array from LLM response text."""
        try:
            start = text.find('[')
            end = text.rfind(']') + 1
            if start == -1 or end == 0:
                return []
            return json.loads(text[start:end])
        except (json.JSONDecodeError, ValueError):
            return []

    def _parse_json_object(self, text: str) -> Dict:
        """Extract JSON object from LLM response text."""
        try:
            start = text.find('{')
            end = text.rfind('}') + 1
            if start == -1 or end == 0:
                return {}
            return json.loads(text[start:end])
        except (json.JSONDecodeError, ValueError):
            return {}

    # ------------------------------------------------------------------
    # 1. Hypothesis Generation (for DiscoveryEngine)
    # ------------------------------------------------------------------

    def generate_hypotheses(self, recon_data: Dict, findings: List[Dict],
                             prior_patterns: Optional[List[Dict]] = None) -> List[Dict]:
        """Generate attack hypotheses using LLM reasoning.

        Called by DiscoveryEngine as Track 5 (LLM-powered) after the 4
        template-based tracks. Returns hypotheses that templates can't generate.
        """
        if not self._available:
            return []

        tech_stack = ', '.join(recon_data.get('tech_stack', [])) or 'unknown'
        endpoints = recon_data.get('endpoints', [])[:20]
        endpoint_list = '\n'.join(
            f"  - {e.get('path', e) if isinstance(e, dict) else e}"
            for e in endpoints
        ) or '  None discovered'

        findings_summary = self._summarize_findings(findings)
        patterns_summary = self._summarize_patterns(prior_patterns or [])

        prompt = f"""You are an elite bug bounty hunter analyzing {self.target}.

TARGET INTELLIGENCE:
- Tech Stack: {tech_stack}
- Endpoints discovered:
{endpoint_list}
- Findings so far: {len(findings)}
- Prior successful patterns: {len(prior_patterns or [])}

CURRENT FINDINGS:
{findings_summary}

SUCCESSFUL PATTERNS FROM DATABASE:
{patterns_summary}

TASK: Generate 10 SPECIFIC, NOVEL attack hypotheses that template-based scanners would MISS.

Focus on:
- Business logic flaws specific to this tech stack
- Unconventional attack vectors (HTTP/2, WebSocket upgrade, cache poisoning)
- Chaining opportunities between existing findings
- Race conditions in state-changing operations
- Serialization/deserialization attacks for the detected framework
- Auth edge cases (token rotation, session binding, scope escalation)

For each hypothesis, provide:
1. title: Clear, specific vulnerability to test
2. test: Exact curl command or test description
3. rationale: Why this is likely to work based on the intelligence
4. confidence: HIGH/MEDIUM/LOW
5. category: business_logic/race_condition/deserialization/auth_edge/cache/protocol/chain

Return ONLY a valid JSON array of objects.
"""

        text = self._call_llm_sync(prompt, use_reasoning=True)
        hypotheses = self._parse_json_array(text)

        if hypotheses:
            self._log(f"[{self._provider_name}] generated {len(hypotheses)} novel hypotheses")
        return hypotheses

    # ------------------------------------------------------------------
    # 2. Creative Bypasses (for AdaptiveEngine)
    # ------------------------------------------------------------------

    def generate_creative_bypasses(self, recon_data: Dict, findings: List[Dict],
                                     failed_strategies: List[str]) -> List[Dict]:
        """Generate creative bypass strategies when standard approaches fail.

        Called by AdaptiveEngine.regenerate_hypotheses() when templates produce
        nothing. Analyzes what failed and WHY, then suggests novel approaches.
        """
        if not self._available:
            return []

        tech_stack = ', '.join(recon_data.get('tech_stack', [])) or 'unknown'
        failed_list = '\n'.join(f"  - {s}" for s in failed_strategies[:15]) or '  None'
        findings_summary = self._summarize_findings(findings)

        prompt = f"""You are an expert bug bounty hunter who has been testing {self.target} but recent tests found NOTHING.

CURRENT STATE:
- Tech Stack: {tech_stack}
- Findings so far: {len(findings)}
- Recent findings: {findings_summary}

STRATEGIES THAT FAILED:
{failed_list}

TASK: Think creatively about what we're MISSING. The standard playbook failed. What unconventional attacks should we try?

Consider:
1. HTTP request smuggling (CL.TE, TE.CL variations)
2. Cache poisoning via unkeyed headers (X-Forwarded-Host, X-Original-URL)
3. Race conditions (TOCTOU in balance/inventory/permission checks)
4. Unicode normalization attacks (case mapping bypass)
5. CRLF injection in headers for response splitting
6. Parameter pollution (HPP with duplicate params)
7. HTTP verb tampering (PATCH/OPTIONS/TRACE)
8. Prototype pollution via __proto__ or constructor.prototype
9. GraphQL batching abuse / alias overload
10. WebSocket upgrade request hijacking
11. DNS rebinding attacks
12. Server-side template injection with framework-specific payloads
13. Deserialization attacks matching the tech stack

For each bypass, provide:
1. title: Specific attack to attempt
2. test: Exact curl command to test (use https://{self.target} as base)
3. rationale: Why this might work when standard tests failed
4. confidence: HIGH/MEDIUM/LOW
5. bypass_type: What defense this bypasses

Return ONLY a valid JSON array (max 8 hypotheses).
"""

        text = self._call_llm_sync(prompt, use_reasoning=True)
        bypasses = self._parse_json_array(text)

        if bypasses:
            self._log(f"[{self._provider_name}] generated {len(bypasses)} creative bypasses")
        return bypasses

    # ------------------------------------------------------------------
    # 3. Novel Chain Discovery (for ExploitChainer)
    # ------------------------------------------------------------------

    def discover_chains(self, findings: List[Dict]) -> List[Dict]:
        """Discover exploit chains that template matching would miss.

        Called by ExploitChainer after template matching. The LLM analyzes
        ALL findings and reasons about non-obvious combinations.
        """
        if not self._available or len(findings) < 2:
            return []

        findings_detail = []
        for i, f in enumerate(findings[:15]):
            findings_detail.append(
                f"  F{i+1}. [{f.get('severity', '?')}] {f.get('vuln_type', f.get('vulnerability_type', '?'))}: "
                f"{f.get('title', f.get('description', '?'))[:80]} "
                f"(endpoint: {f.get('url', f.get('endpoint', '?'))[:50]})"
            )
        findings_text = '\n'.join(findings_detail)

        prompt = f"""You are analyzing {len(findings)} security findings on {self.target} to discover EXPLOIT CHAINS.

FINDINGS:
{findings_text}

TASK: Identify up to 5 chains where combining findings creates HIGHER impact than individual bugs.

Think about NON-OBVIOUS chains:
- Information disclosure that reveals internal endpoints for SSRF
- Low-severity XSS that becomes account takeover when combined with weak session
- Open redirect that steals OAuth tokens
- IDOR that reveals admin secrets enabling privilege escalation
- Rate limit absence that makes brute force of leaked hash feasible
- CORS misconfiguration that enables cross-origin theft of data from another finding

For each chain:
1. title: "Finding A + Finding B -> Impact" format
2. steps: Array of step descriptions (Step 1: ..., Step 2: ..., Step 3: ...)
3. findings_used: Array like ["F1", "F3"] matching the finding IDs above
4. impact: CRITICAL/HIGH/MEDIUM
5. confidence: HIGH/MEDIUM/LOW
6. rationale: Why this chain works and why the impact is elevated

Return ONLY a valid JSON array (max 5 chains). Only include chains with CLEAR escalation path.
"""

        text = self._call_llm_sync(prompt, use_reasoning=True)
        chains = self._parse_json_array(text)

        if chains:
            self._log(f"[{self._provider_name}] discovered {len(chains)} novel chains")
        return chains[:5]

    # ------------------------------------------------------------------
    # 4. WAF Bypass Generation
    # ------------------------------------------------------------------

    def generate_waf_bypass(self, blocked_payload: str, waf_vendor: str,
                             block_response: str, injection_type: str) -> List[Dict]:
        """Generate WAF-specific bypass payloads using LLM reasoning.

        Called by the adaptive WAF bypass engine when a payload is blocked.
        Analyzes the block response to understand WHAT rule fired, then
        generates targeted mutations.
        """
        if not self._available:
            return []

        prompt = f"""A WAF ({waf_vendor}) blocked this payload on {self.target}:

BLOCKED PAYLOAD: {blocked_payload[:200]}
INJECTION TYPE: {injection_type}
BLOCK RESPONSE (first 500 chars):
{block_response[:500]}

TASK: Generate 5 bypass variants that evade this specific WAF rule.

Analyze the block response to determine:
1. WHAT rule fired (signature match? keyword? pattern?)
2. What SPECIFIC characters/patterns were detected
3. How to encode/mutate to avoid detection while preserving injection

Bypass techniques to consider:
- Double URL encoding (%2527 for ')
- Unicode alternatives (fullwidth chars, homoglyphs)
- HTML entity encoding (&#39; for ')
- Case variations with comment injection
- Chunked transfer encoding
- HTTP parameter pollution (duplicate params)
- JSON unicode escapes (\\u0027 for ')
- Null byte injection (%00)
- Newline/tab insertion within keywords
- Alternative syntax (HAVING vs WHERE, javascript: vs data:)

For each bypass:
1. payload: The complete bypass payload (ready to use)
2. technique: What encoding/mutation was applied
3. rationale: Why this should evade the detected rule
4. confidence: HIGH/MEDIUM/LOW

Return ONLY a valid JSON array.
"""

        text = self._call_llm_sync(prompt, use_reasoning=False)
        bypasses = self._parse_json_array(text)

        if bypasses:
            self._log(f"[{self._provider_name}] generated {len(bypasses)} WAF bypass variants for {waf_vendor}")
        return bypasses

    # ------------------------------------------------------------------
    # 5. Context-Aware Payload Generation
    # ------------------------------------------------------------------

    def generate_context_payloads(self, injection_context: Dict) -> List[Dict]:
        """Generate payloads tailored to a specific injection context.

        Called by the payload mutator when it detects an injection point
        and needs context-specific breakout payloads.
        """
        if not self._available:
            return []

        prompt = f"""Generate injection payloads for this specific context on {self.target}:

INJECTION CONTEXT:
- Location: {injection_context.get('location', 'unknown')} (e.g., HTML attribute, JS string, SQL WHERE, HTTP header)
- Surrounding code/markup: {injection_context.get('surrounding', 'unknown')[:300]}
- Current value reflected as: {injection_context.get('reflection', 'unknown')[:200]}
- Characters blocked/filtered: {', '.join(injection_context.get('blocked_chars', []))}
- Characters allowed: {', '.join(injection_context.get('allowed_chars', []))}
- Injection type goal: {injection_context.get('goal', 'xss')}

TASK: Generate 8 precision payloads that:
1. Break out of the current context (close the tag/string/statement)
2. Execute the injection goal
3. Avoid ALL blocked characters using alternatives
4. Are as SHORT as possible (shorter = less likely to be truncated)

For each payload:
1. payload: The complete injection string (ready to use)
2. breakout: How it escapes the current context
3. execution: How it achieves the goal
4. length: Character count
5. confidence: HIGH/MEDIUM/LOW

Return ONLY a valid JSON array, sorted by confidence.
"""

        text = self._call_llm_sync(prompt, use_reasoning=False)
        payloads = self._parse_json_array(text)

        if payloads:
            self._log(f"[{self._provider_name}] generated {len(payloads)} context-aware payloads")
        return payloads

    # ------------------------------------------------------------------
    # 6. Response Analysis
    # ------------------------------------------------------------------

    def analyze_response(self, request_info: Dict, response_info: Dict) -> Dict:
        """Analyze an HTTP response for vulnerability indicators.

        Called by the response analyzer to get LLM-powered analysis of
        ambiguous responses where rule-based analysis is inconclusive.
        """
        if not self._available:
            return {}

        prompt = f"""Analyze this HTTP response for security vulnerability indicators.

REQUEST:
- Method: {request_info.get('method', 'GET')}
- URL: {request_info.get('url', '?')}
- Payload: {str(request_info.get('payload', ''))[:200]}

RESPONSE:
- Status: {response_info.get('status_code', '?')}
- Headers: {json.dumps(dict(list(response_info.get('headers', {}).items())[:10]))}
- Body (first 1000 chars):
{response_info.get('body', '')[:1000]}

ANALYSIS RULES (BE CONSERVATIVE):
- HTTP 200 alone is NOT a vulnerability
- GraphQL always returns 200 - check data/errors fields
- Validation errors (400) are NOT missing auth
- "Access denied" means auth IS working (not vulnerable)
- Stack traces are LOW severity info disclosure, not CRITICAL

Respond with ONLY a JSON object:
{{
  "is_vulnerable": true/false,
  "vulnerability_type": "type or null",
  "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
  "confidence": "HIGH/MEDIUM/LOW",
  "evidence": "specific evidence from response",
  "false_positive_indicators": ["any reasons this might be FP"],
  "sql_dialect": "mysql/postgres/mssql/oracle/sqlite/unknown",
  "waf_detected": "vendor or null",
  "framework_detected": "framework or null"
}}
"""

        text = self._call_llm_sync(prompt, use_reasoning=False, max_tokens=1024)
        return self._parse_json_object(text)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _summarize_findings(findings: List[Dict]) -> str:
        if not findings:
            return "  None"
        lines = []
        for f in findings[-8:]:
            title = f.get('title', 'Unknown')[:60]
            severity = f.get('severity', '?')
            vtype = f.get('vuln_type', f.get('vulnerability_type', '?'))
            endpoint = f.get('endpoint', f.get('url', ''))[:40]
            lines.append(f"  - [{severity}] {vtype}: {title} ({endpoint})")
        return '\n'.join(lines)

    @staticmethod
    def _summarize_patterns(patterns: List[Dict]) -> str:
        if not patterns:
            return "  None"
        lines = []
        for p in patterns[:10]:
            name = p.get('name', 'Unknown')[:50]
            rate = p.get('success_rate', 0)
            tech = ', '.join(p.get('tech', []))[:30] if p.get('tech') else '?'
            lines.append(f"  - {name} (rate:{rate:.0%}, tech:{tech})")
        return '\n'.join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """Return LLM usage statistics."""
        return {
            'available': self._available,
            'calls': self._call_count,
            'input_tokens': self._total_input_tokens,
            'output_tokens': self._total_output_tokens,
            'total_cost': round(self._total_cost, 4),
            'errors': self._errors,
        }

    def print_stats(self):
        """Print LLM usage summary."""
        s = self.get_stats()
        if s['calls'] == 0:
            return
        self._log(
            f"LLM Stats: {s['calls']} calls, "
            f"{s['input_tokens']+s['output_tokens']} tokens, "
            f"${s['total_cost']:.4f} cost, "
            f"{s['errors']} errors"
        )
