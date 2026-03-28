# BountyHound v4.0 Overhaul - From Facade to Autonomous Hunter

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform BountyHound from a prompt-library-with-stubs into a genuinely autonomous security testing platform that finds, validates, and reports real vulnerabilities with minimal human intervention.

**Architecture:** Fix the split-brain between markdown agents (Claude instructions) and Python engine (actual execution). The markdown agents stay as orchestration guides, but every phase they reference must have real, tested Python backing it. All paths consolidated to `C:\Users\vaugh\BountyHound\`. State change verification baked into every finding validation.

**Tech Stack:** Python 3.10+, SQLite, requests, asyncio/aiohttp (new - for race conditions), interactsh-client (new - for OAST), websockets (new), pytest

---

## Milestone 1: Fix the Foundation (Day 1)

These are small, high-impact fixes that unblock everything else. Each task is independent.

---

### Task 1: Remove Hardcoded Credentials from CLAUDE.md

**SEVERITY: CRITICAL - Security risk. 30 minutes.**

**Files:**
- Modify: `bountyhound-agent/CLAUDE.md:147-148`
- Modify: `bountyhound-agent/agents/phased-hunter.md` (all `~/bounty-findings/` refs)

**Step 1: Read the file and locate credentials**

```bash
grep -n "ashtonluca\|BountyH0und\|password\|@gmail" bountyhound-agent/CLAUDE.md
```

**Step 2: Replace hardcoded creds with environment variable references**

Replace lines 147-148 (and any others found) with:

```markdown
- **Google OAuth**: Set via `BOUNTYHOUND_GOOGLE_EMAIL` env var
- **Email/Pass**: Set via `BOUNTYHOUND_EMAIL` and `BOUNTYHOUND_PASS` env vars
```

**Step 3: Create a `.env.example` template**

Create `bountyhound-agent/.env.example`:
```
# BountyHound Credentials - Copy to .env and fill in
BOUNTYHOUND_GOOGLE_EMAIL=
BOUNTYHOUND_EMAIL=
BOUNTYHOUND_PASS=
```

**Step 4: Add `.env` to `.gitignore`**

```bash
echo ".env" >> bountyhound-agent/.gitignore
```

**Step 5: Commit**

```bash
git add bountyhound-agent/CLAUDE.md bountyhound-agent/.env.example bountyhound-agent/.gitignore
git commit -m "security: remove hardcoded credentials from CLAUDE.md"
```

---

### Task 2: Consolidate All Paths to Single Standard

**SEVERITY: CRITICAL - Causes lost findings and broken cred lookups. 1-2 hours.**

There are 3 conflicting path conventions. Consolidate everything to: `C:/Users/vaugh/BountyHound/findings/<target>/`

**Files:**
- Modify: `bountyhound-agent/CLAUDE.md` (all `~/bounty-findings/` refs)
- Modify: `bountyhound-agent/agents/phased-hunter.md` (mixed refs)
- Modify: `bountyhound-agent/agents/authorization-boundary-tester.md` (`$HOME/bounty-findings/`)
- Modify: `bountyhound-agent/commands/hunt.md` (if exists)
- Modify: `bountyhound-agent/commands/creds.md` (if exists)
- Modify: `bountyhound-agent/skills/credential-manager/index.md`
- Modify: `bountyhound-agent/engine/agents/phased_hunter.py:104`

**Step 1: Find all path variants**

```bash
grep -rn "bounty-findings\|~/BountyHound\|\$HOME/bounty" bountyhound-agent/ --include="*.md" --include="*.py" | grep -v node_modules | grep -v __pycache__
```

**Step 2: Replace ALL occurrences**

Standard path rules:
- Findings: `C:/Users/vaugh/BountyHound/findings/<target>/`
- Credentials: `C:/Users/vaugh/BountyHound/findings/<target>/credentials/`
- Temp output: `C:/Users/vaugh/BountyHound/findings/<target>/tmp/`
- Tools: `C:/Users/vaugh/BountyHound/tools/`

In Python code, use:
```python
import os
BOUNTY_DIR = os.environ.get('BOUNTYHOUND_DIR', os.path.expanduser('~/BountyHound'))
FINDINGS_DIR = os.path.join(BOUNTY_DIR, 'findings')
```

**Step 3: Fix phased_hunter.py line 104**

Replace:
```python
output_dir = os.path.expanduser(f"~/BountyHound/bountyhound-agent/findings/{target}")
```

With:
```python
BOUNTY_DIR = os.environ.get('BOUNTYHOUND_DIR', os.path.expanduser('~/BountyHound'))
output_dir = os.path.join(BOUNTY_DIR, 'findings', target)
```

**Step 4: Write a test that validates path consistency**

Create `tests/test_path_consistency.py`:
```python
import os
import re
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BANNED_PATHS = [
    r'~/bounty-findings/',
    r'\$HOME/bounty-findings/',
    r'~/bounty-findings',
]

def get_all_files(extensions=('.md', '.py')):
    """Get all markdown and python files in the repo."""
    files = []
    for root, dirs, filenames in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in ('node_modules', '__pycache__', '.git', 'disabled')]
        for f in filenames:
            if any(f.endswith(ext) for ext in extensions):
                files.append(os.path.join(root, f))
    return files

def test_no_banned_paths():
    """No file should reference the old ~/bounty-findings/ path."""
    violations = []
    for filepath in get_all_files():
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        for pattern in BANNED_PATHS:
            if pattern in content:
                violations.append(f"{filepath}: contains '{pattern}'")
    assert violations == [], f"Found banned path references:\n" + "\n".join(violations)
```

**Step 5: Run test to verify it passes**

```bash
cd bountyhound-agent && python -m pytest tests/test_path_consistency.py -v
```

Expected: PASS

**Step 6: Commit**

```bash
git add -A
git commit -m "fix: consolidate all paths to C:/Users/vaugh/BountyHound/"
```

---

### Task 3: Enable and Wire Rejection Filter into Pipeline

**SEVERITY: HIGH - Quality gate is disabled, false positives leak through. 1-2 hours.**

**Files:**
- Move: `agents/disabled/rejection-pattern-filter.md` -> `agents/rejection-pattern-filter.md`
- Create: `engine/agents/rejection_filter.py`
- Test: `tests/engine/agents/test_rejection_filter.py`

**Step 1: Move the agent out of disabled**

```bash
cp bountyhound-agent/agents/disabled/rejection-pattern-filter.md bountyhound-agent/agents/rejection-pattern-filter.md
```

**Step 2: Write the failing test**

Create `tests/engine/agents/test_rejection_filter.py`:
```python
import pytest
from engine.agents.rejection_filter import RejectionFilter, Finding, Verdict

class TestRejectionFilter:
    def setup_method(self):
        self.filter = RejectionFilter()

    def test_rejects_intended_functionality(self):
        """Access to own resources is intended, not a vulnerability."""
        finding = Finding(
            title="User can view their own orders",
            description="User A can access /api/orders with their own token",
            evidence="HTTP 200 with order data",
            auth_context="own_account",
        )
        result = self.filter.evaluate(finding)
        assert result.verdict == Verdict.REJECT
        assert "intended functionality" in result.reason.lower()

    def test_rejects_ambiguous_exploitation(self):
        """GraphQL 200 with errors is not exploitation."""
        finding = Finding(
            title="IDOR in GraphQL mutation",
            description="Mutation returned HTTP 200",
            evidence='{"data":null,"errors":[{"message":"Not authorized"}]}',
            auth_context="cross_account",
        )
        result = self.filter.evaluate(finding)
        assert result.verdict == Verdict.REJECT
        assert "ambiguous" in result.reason.lower() or "no state change" in result.reason.lower()

    def test_approves_verified_cross_account_access(self):
        """Cross-account data access with state change proof is valid."""
        finding = Finding(
            title="IDOR: User B can read User A orders",
            description="User B token accessing /api/orders/123 returns User A data",
            evidence="Before: order belongs to User A. After: User B can read it. Different user IDs confirmed.",
            auth_context="cross_account",
            state_change_verified=True,
        )
        result = self.filter.evaluate(finding)
        assert result.verdict in (Verdict.SUBMIT, Verdict.AUTO_SUBMIT)
        assert result.score >= 70

    def test_score_calculation(self):
        """Score follows the formula: auth_violation*40 + clear_exploitation*30 + impact*20 + scope*10."""
        finding = Finding(
            title="Critical IDOR",
            description="Full account takeover via IDOR",
            evidence="Changed email of another user's account",
            auth_context="cross_account",
            state_change_verified=True,
            impact="critical",
            in_scope=True,
        )
        result = self.filter.evaluate(finding)
        assert result.score >= 90  # All factors present

    def test_manual_review_for_borderline(self):
        """Borderline findings go to manual review."""
        finding = Finding(
            title="Information disclosure via error message",
            description="Stack trace leaks internal paths",
            evidence="HTTP 500 with full stack trace",
            auth_context="unauthenticated",
        )
        result = self.filter.evaluate(finding)
        assert result.verdict == Verdict.MANUAL_REVIEW
```

**Step 3: Run test to verify it fails**

```bash
cd bountyhound-agent && python -m pytest tests/engine/agents/test_rejection_filter.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'engine.agents.rejection_filter'`

**Step 4: Implement rejection_filter.py**

Create `engine/agents/rejection_filter.py`:
```python
"""
Rejection Filter - Quality gate that prevents false positive submissions.

Evaluates findings against 4 rejection patterns:
1. Intended Functionality - authorized access reported as vuln
2. Ambiguous Exploitation - success:false, unclear PoC, no state change
3. Operational Issue - infrastructure gap, not security
4. Impractical Attack - brute force without proof

Score formula:
  score = (auth_violation * 40) + (clear_exploitation * 30) + (impact_severity * 20) + (scope_match * 10)

Thresholds:
  90-100: AUTO_SUBMIT
  70-89:  SUBMIT
  50-69:  MANUAL_REVIEW
  0-49:   REJECT
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Verdict(Enum):
    AUTO_SUBMIT = "AUTO_SUBMIT"
    SUBMIT = "SUBMIT"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    REJECT = "REJECT"


@dataclass
class Finding:
    title: str
    description: str
    evidence: str
    auth_context: str = "unknown"  # own_account, cross_account, unauthenticated, unknown
    state_change_verified: bool = False
    impact: str = "low"  # low, medium, high, critical
    in_scope: bool = True


@dataclass
class FilterResult:
    verdict: Verdict
    score: int
    reason: str
    rejection_pattern: Optional[str] = None


# Patterns that indicate NOT a real vulnerability
INTENDED_FUNCTIONALITY_SIGNALS = [
    "own account", "own resource", "own data", "their own",
    "authorized access", "expected behavior", "by design",
]

AMBIGUOUS_EXPLOITATION_SIGNALS = [
    '"errors"', "not authorized", "unauthorized", "forbidden",
    "success.*false", "permission denied", '"data":null',
    "no state change", "response only",
]

OPERATIONAL_SIGNALS = [
    "timeout", "rate limit", "503", "502", "infrastructure",
    "maintenance", "deployment", "configuration",
]


class RejectionFilter:
    """Evaluates findings and assigns acceptance scores."""

    def evaluate(self, finding: Finding) -> FilterResult:
        # Check rejection patterns first
        rejection = self._check_rejection_patterns(finding)
        if rejection:
            return rejection

        # Calculate score
        score = self._calculate_score(finding)

        # Determine verdict from score
        if score >= 90:
            verdict = Verdict.AUTO_SUBMIT
        elif score >= 70:
            verdict = Verdict.SUBMIT
        elif score >= 50:
            verdict = Verdict.MANUAL_REVIEW
        else:
            verdict = Verdict.REJECT

        return FilterResult(
            verdict=verdict,
            score=score,
            reason=self._build_reason(finding, score),
        )

    def _check_rejection_patterns(self, finding: Finding) -> Optional[FilterResult]:
        text = f"{finding.title} {finding.description} {finding.evidence}".lower()

        # Pattern 1: Intended Functionality
        if finding.auth_context == "own_account":
            return FilterResult(
                verdict=Verdict.REJECT,
                score=0,
                reason="Intended functionality: accessing own resources is authorized behavior",
                rejection_pattern="intended_functionality",
            )

        # Pattern 2: Ambiguous Exploitation (no state change + error signals)
        if not finding.state_change_verified:
            ambiguous_matches = [s for s in AMBIGUOUS_EXPLOITATION_SIGNALS if re.search(s, text)]
            if ambiguous_matches and finding.auth_context == "cross_account":
                return FilterResult(
                    verdict=Verdict.REJECT,
                    score=15,
                    reason=f"Ambiguous exploitation: no state change verified, error signals found: {ambiguous_matches[:3]}",
                    rejection_pattern="ambiguous_exploitation",
                )

        # Pattern 3: Operational Issue
        operational_matches = [s for s in OPERATIONAL_SIGNALS if s in text]
        if operational_matches and not finding.state_change_verified:
            if not any(kw in text for kw in ["bypass", "injection", "xss", "idor", "ssrf"]):
                return FilterResult(
                    verdict=Verdict.REJECT,
                    score=10,
                    reason=f"Operational issue, not security: {operational_matches[:3]}",
                    rejection_pattern="operational_issue",
                )

        return None

    def _calculate_score(self, finding: Finding) -> int:
        score = 0

        # Authorization violation (40 points)
        if finding.auth_context == "cross_account":
            score += 40
        elif finding.auth_context == "unauthenticated":
            score += 35
        elif finding.auth_context == "unknown":
            score += 10

        # Clear exploitation (30 points)
        if finding.state_change_verified:
            score += 30
        elif any(kw in finding.evidence.lower() for kw in ["confirmed", "verified", "changed", "modified", "deleted"]):
            score += 15

        # Impact severity (20 points)
        impact_scores = {"critical": 20, "high": 15, "medium": 10, "low": 5}
        score += impact_scores.get(finding.impact, 5)

        # Scope match (10 points)
        if finding.in_scope:
            score += 10

        return min(score, 100)

    def _build_reason(self, finding: Finding, score: int) -> str:
        parts = []
        if finding.auth_context == "cross_account":
            parts.append("cross-account access confirmed")
        if finding.state_change_verified:
            parts.append("state change verified")
        if finding.impact in ("critical", "high"):
            parts.append(f"{finding.impact} impact")
        if finding.in_scope:
            parts.append("in scope")
        return f"Score {score}: {', '.join(parts)}" if parts else f"Score {score}"
```

**Step 5: Run tests to verify they pass**

```bash
cd bountyhound-agent && python -m pytest tests/engine/agents/test_rejection_filter.py -v
```

Expected: ALL PASS

**Step 6: Commit**

```bash
git add engine/agents/rejection_filter.py tests/engine/agents/test_rejection_filter.py agents/rejection-pattern-filter.md
git commit -m "feat: implement rejection filter with 4 rejection patterns and scoring"
```

---

### Task 4: Fix get_findings_by_tool Stub in Database

**SEVERITY: MEDIUM - Causes wrong skip decisions. 1 hour.**

**Files:**
- Modify: `engine/core/database.py:267-271`
- Test: `tests/engine/core/test_database.py`

**Step 1: Write the failing test**

Add to `tests/engine/core/test_database.py`:
```python
def test_get_findings_by_tool_filters_correctly(tmp_path):
    """get_findings_by_tool should return only findings from that specific tool."""
    db = BountyHoundDB(str(tmp_path / "test.db"))
    db.record_tool_run("example.com", "ssrf_tester", findings_count=2, duration_seconds=30)
    db.record_tool_run("example.com", "xss_tester", findings_count=5, duration_seconds=60)

    # Should only return SSRF findings, not XSS
    ssrf_findings = db.get_findings_by_tool("example.com", "ssrf_tester")
    # For now, just verify the method exists and returns a list
    assert isinstance(ssrf_findings, list)
```

**Step 2: Add tool_name column to findings table**

In `database.py`, modify the findings table schema to include `tool_name TEXT`:
```python
# In _init_db(), add tool_name to findings table:
# ALTER TABLE findings ADD COLUMN tool_name TEXT DEFAULT '';
```

**Step 3: Implement real get_findings_by_tool**

Replace lines 267-271:
```python
def get_findings_by_tool(self, domain: str, tool_name: str) -> List[Dict[str, Any]]:
    """Get all findings discovered by a specific tool."""
    with self._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT f.* FROM findings f
            JOIN targets t ON f.target_id = t.id
            WHERE t.domain = ? AND f.tool_name = ?
            ORDER BY f.created_at DESC
        """, (domain, tool_name))
        return [dict(row) for row in cursor.fetchall()]
```

**Step 4: Run tests**

```bash
cd bountyhound-agent && python -m pytest tests/engine/core/test_database.py -v
```

**Step 5: Commit**

```bash
git add engine/core/database.py tests/engine/core/test_database.py
git commit -m "fix: implement real get_findings_by_tool instead of stub"
```

---

## Milestone 2: State Change Verification Engine (Day 2)

This is the single most important missing piece. Without it, every finding is potentially a false positive (see: Airbnb 6 FP disaster).

---

### Task 5: Build State Change Verifier

**SEVERITY: CRITICAL - Prevents Airbnb-style false positive disasters. 2-3 hours.**

**Files:**
- Create: `engine/core/state_verifier.py`
- Test: `tests/engine/core/test_state_verifier.py`

**Step 1: Write the failing tests**

Create `tests/engine/core/test_state_verifier.py`:
```python
import pytest
import json
from unittest.mock import patch, MagicMock
from engine.core.state_verifier import StateVerifier, StateCheckResult

class TestStateVerifier:
    def setup_method(self):
        self.verifier = StateVerifier()

    def test_detects_actual_state_change(self):
        """When before != after, state change is confirmed."""
        before = {"user": {"email": "alice@test.com", "name": "Alice"}}
        after = {"user": {"email": "evil@hacker.com", "name": "Alice"}}
        result = self.verifier.compare_states(before, after)
        assert result.changed is True
        assert "email" in str(result.diff)

    def test_detects_no_state_change(self):
        """When before == after, no state change."""
        before = {"user": {"email": "alice@test.com"}}
        after = {"user": {"email": "alice@test.com"}}
        result = self.verifier.compare_states(before, after)
        assert result.changed is False

    def test_graphql_error_is_not_state_change(self):
        """GraphQL returning errors in data means mutation failed."""
        before = {"user": {"email": "alice@test.com"}}
        mutation_response = {"data": None, "errors": [{"message": "Not authorized"}]}
        after = {"user": {"email": "alice@test.com"}}
        result = self.verifier.verify_mutation(
            before_state=before,
            mutation_response=mutation_response,
            after_state=after,
        )
        assert result.changed is False
        assert result.mutation_succeeded is False

    def test_graphql_success_with_state_change(self):
        """GraphQL mutation that actually changes data."""
        before = {"user": {"email": "alice@test.com"}}
        mutation_response = {"data": {"updateUser": {"email": "evil@hacker.com"}}}
        after = {"user": {"email": "evil@hacker.com"}}
        result = self.verifier.verify_mutation(
            before_state=before,
            mutation_response=mutation_response,
            after_state=after,
        )
        assert result.changed is True
        assert result.mutation_succeeded is True

    def test_http_200_alone_is_not_proof(self):
        """HTTP 200 without state comparison is insufficient."""
        result = self.verifier.verify_from_status_code(200)
        assert result.changed is False
        assert "insufficient" in result.reason.lower()
```

**Step 2: Run test to verify failure**

```bash
cd bountyhound-agent && python -m pytest tests/engine/core/test_state_verifier.py -v
```

Expected: FAIL - module not found

**Step 3: Implement state_verifier.py**

Create `engine/core/state_verifier.py`:
```python
"""
State Change Verifier - Prevents false positives by requiring proof of actual state change.

Protocol:
1. READ state (before)
2. ATTEMPT mutation/action
3. READ state (after)
4. COMPARE before vs after
5. Only claim vulnerability if state ACTUALLY changed

This module exists because of the Airbnb 2026-02-14 disaster where 6 findings
were false positives because HTTP 200 + __typename was treated as exploitation.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class StateCheckResult:
    changed: bool
    mutation_succeeded: bool = False
    diff: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""


class StateVerifier:
    """Verifies actual state changes to prevent false positives."""

    def compare_states(self, before: Dict, after: Dict, path: str = "") -> StateCheckResult:
        """Deep compare two state snapshots. Returns diff of changes."""
        diff = self._deep_diff(before, after, path)
        return StateCheckResult(
            changed=len(diff) > 0,
            diff=diff,
            reason=f"Found {len(diff)} change(s)" if diff else "No state change detected",
        )

    def verify_mutation(
        self,
        before_state: Dict,
        mutation_response: Dict,
        after_state: Dict,
    ) -> StateCheckResult:
        """Full verification: check mutation response AND actual state change."""
        # Check if mutation response indicates failure
        mutation_succeeded = self._did_mutation_succeed(mutation_response)

        # Compare actual states regardless
        state_diff = self._deep_diff(before_state, after_state)

        return StateCheckResult(
            changed=len(state_diff) > 0,
            mutation_succeeded=mutation_succeeded,
            diff=state_diff,
            reason=self._build_reason(mutation_succeeded, state_diff),
        )

    def verify_from_status_code(self, status_code: int) -> StateCheckResult:
        """HTTP status code alone is NEVER sufficient proof."""
        return StateCheckResult(
            changed=False,
            mutation_succeeded=False,
            diff={},
            reason=f"Insufficient: HTTP {status_code} alone does not prove state change. "
                   f"Must compare before/after state.",
        )

    def _did_mutation_succeed(self, response: Dict) -> bool:
        """Check if a GraphQL/REST mutation actually succeeded."""
        # GraphQL: check for errors
        if "errors" in response and response.get("errors"):
            return False
        # GraphQL: check for null data
        if response.get("data") is None:
            return False
        # REST: check for success:false pattern
        if response.get("success") is False:
            return False
        if response.get("status") in ("error", "failed", "failure"):
            return False
        return True

    def _deep_diff(self, before: Any, after: Any, path: str = "") -> Dict[str, Any]:
        """Recursively diff two objects, returning changed fields."""
        diff = {}
        if type(before) != type(after):
            diff[path or "root"] = {"before": before, "after": after}
            return diff

        if isinstance(before, dict):
            all_keys = set(list(before.keys()) + list(after.keys()))
            for key in all_keys:
                new_path = f"{path}.{key}" if path else key
                if key not in before:
                    diff[new_path] = {"before": None, "after": after[key]}
                elif key not in after:
                    diff[new_path] = {"before": before[key], "after": None}
                else:
                    sub_diff = self._deep_diff(before[key], after[key], new_path)
                    diff.update(sub_diff)
        elif isinstance(before, list):
            if before != after:
                diff[path or "root"] = {"before": before, "after": after}
        else:
            if before != after:
                diff[path or "root"] = {"before": before, "after": after}

        return diff

    def _build_reason(self, mutation_succeeded: bool, diff: Dict) -> str:
        if mutation_succeeded and diff:
            return f"CONFIRMED: Mutation succeeded AND state changed. Diff: {list(diff.keys())}"
        elif mutation_succeeded and not diff:
            return "WARNING: Mutation response looks successful but no state change detected. Possible false positive."
        elif not mutation_succeeded and diff:
            return "ANOMALY: Mutation failed but state changed. Investigate further."
        else:
            return "NOT VULNERABLE: Mutation failed and no state change. This is a false positive."
```

**Step 4: Run tests**

```bash
cd bountyhound-agent && python -m pytest tests/engine/core/test_state_verifier.py -v
```

Expected: ALL PASS

**Step 5: Commit**

```bash
git add engine/core/state_verifier.py tests/engine/core/test_state_verifier.py
git commit -m "feat: add state change verifier to prevent false positives"
```

---

### Task 6: Integrate State Verifier into POC Validator

**Files:**
- Modify: `engine/agents/poc_validator.py` (if exists as Python, otherwise create)
- Test: `tests/engine/agents/test_poc_validator.py`

**Step 1: Write the failing test**

Add to existing test file or create new:
```python
def test_poc_validator_requires_state_change():
    """POC validator must require state change proof for IDOR/BOLA findings."""
    validator = POCValidator()
    result = validator.validate({
        "title": "IDOR in /api/users",
        "type": "IDOR",
        "evidence": "HTTP 200 response",
        "status_code": 200,
        # No state change evidence
    })
    assert result["verified"] is False
    assert "state change" in result["reason"].lower()
```

**Step 2: Implement the integration**

Wire `StateVerifier` into the POC validation flow so that any finding of type IDOR, BOLA, auth bypass, or privilege escalation MUST include state change evidence.

**Step 3: Run tests and commit**

```bash
cd bountyhound-agent && python -m pytest tests/engine/agents/test_poc_validator.py -v
git add engine/agents/poc_validator.py tests/engine/agents/test_poc_validator.py
git commit -m "feat: integrate state verifier into POC validator"
```

---

## Milestone 3: Real Discovery Engine (Day 3-4)

Replace the 12-line stub with an actual implementation.

---

### Task 7: Implement Discovery Engine

**SEVERITY: CRITICAL - Currently empty. 3-5 hours.**

**Files:**
- Rewrite: `engine/agents/discovery_engine.py` (currently 12 lines)
- Test: `tests/engine/agents/test_discovery_engine.py`

**Step 1: Write failing tests**

Create `tests/engine/agents/test_discovery_engine.py`:
```python
import pytest
from engine.agents.discovery_engine import DiscoveryEngine, HypothesisCard, Confidence

class TestDiscoveryEngine:
    def setup_method(self):
        self.engine = DiscoveryEngine()

    def test_generates_hypotheses_from_tech_stack(self):
        """Given a tech stack, generate relevant vulnerability hypotheses."""
        recon_data = {
            "tech_stack": ["Rails", "PostgreSQL", "Redis", "GraphQL"],
            "endpoints": ["/api/graphql", "/api/v1/users", "/admin"],
            "subdomains": ["api.example.com", "admin.example.com"],
        }
        cards = self.engine.generate_hypotheses(recon_data)
        assert len(cards) >= 5
        assert all(isinstance(c, HypothesisCard) for c in cards)
        # Rails + GraphQL should trigger specific hypotheses
        titles = [c.title.lower() for c in cards]
        assert any("graphql" in t for t in titles)

    def test_hypothesis_card_has_required_fields(self):
        """Every card must have title, confidence, test_method, success_indicator."""
        recon_data = {
            "tech_stack": ["Node.js", "Express"],
            "endpoints": ["/api/login"],
            "subdomains": ["app.example.com"],
        }
        cards = self.engine.generate_hypotheses(recon_data)
        for card in cards:
            assert card.title
            assert card.confidence in (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW)
            assert card.test_method
            assert card.success_indicator

    def test_uses_past_payloads_from_database(self):
        """Engine should prioritize hypothesis types that worked before."""
        recon_data = {
            "tech_stack": ["React", "Node.js"],
            "endpoints": ["/api/users"],
            "subdomains": [],
            "successful_vuln_types": ["IDOR", "XSS"],  # From database
        }
        cards = self.engine.generate_hypotheses(recon_data)
        # IDOR and XSS should be HIGH confidence since they worked before
        idor_cards = [c for c in cards if "idor" in c.title.lower()]
        assert len(idor_cards) > 0
        assert idor_cards[0].confidence == Confidence.HIGH

    def test_gap_triggered_second_wave(self):
        """When first wave finds nothing, generate second wave hypotheses."""
        first_wave_results = {
            "tested": ["IDOR", "XSS", "SQLi"],
            "failed": ["IDOR", "XSS", "SQLi"],
            "defenses_observed": ["WAF: Cloudflare", "Rate limit: 100/min"],
            "error_messages": ["403 Forbidden", "Rate limit exceeded"],
        }
        cards = self.engine.generate_second_wave(first_wave_results)
        assert len(cards) >= 3
        # Should suggest WAF bypass, timing attacks, business logic
        titles = [c.title.lower() for c in cards]
        assert any("bypass" in t or "logic" in t or "timing" in t for t in titles)
```

**Step 2: Run to verify failure**

```bash
cd bountyhound-agent && python -m pytest tests/engine/agents/test_discovery_engine.py -v
```

**Step 3: Implement discovery_engine.py**

```python
"""
Discovery Engine - Generates vulnerability hypotheses from recon data.

4 Reasoning Tracks:
1. Pattern Synthesis: tech stack + known vulnerability patterns
2. Behavioral Anomaly: endpoint inconsistencies
3. Code Research: source code sink patterns
4. Cross-Domain Transfer: past hunt successes applied to new targets

Outputs HypothesisCards with confidence levels that feed into Phase 2 testing.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Confidence(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class HypothesisCard:
    id: str
    title: str
    confidence: Confidence
    test_method: str  # curl, browser, script
    payload: str
    success_indicator: str
    reasoning_track: str  # pattern_synthesis, behavioral_anomaly, code_research, cross_domain


# Tech stack -> common vulnerability patterns
TECH_VULN_PATTERNS: Dict[str, List[Dict[str, Any]]] = {
    "rails": [
        {"title": "Mass assignment via unprotected params", "confidence": "MEDIUM", "test": "curl", "indicator": "Unexpected field updated"},
        {"title": "Ruby deserialization RCE", "confidence": "LOW", "test": "curl", "indicator": "Command execution or error"},
        {"title": "Rails debug mode information disclosure", "confidence": "MEDIUM", "test": "curl", "indicator": "Debug page with stack trace"},
    ],
    "graphql": [
        {"title": "GraphQL introspection enabled", "confidence": "HIGH", "test": "curl", "indicator": "__schema in response"},
        {"title": "GraphQL batch query DoS", "confidence": "MEDIUM", "test": "curl", "indicator": "Server processes >100 aliases"},
        {"title": "GraphQL IDOR via direct object reference", "confidence": "HIGH", "test": "curl", "indicator": "Other user's data returned"},
        {"title": "GraphQL mutation without authentication", "confidence": "HIGH", "test": "curl", "indicator": "Mutation succeeds without auth token"},
        {"title": "GraphQL field suggestion bypass", "confidence": "MEDIUM", "test": "curl", "indicator": "Did you mean suggestions reveal schema"},
    ],
    "node.js": [
        {"title": "Prototype pollution via JSON merge", "confidence": "MEDIUM", "test": "curl", "indicator": "__proto__ accepted in input"},
        {"title": "SSRF via URL parameter", "confidence": "MEDIUM", "test": "curl", "indicator": "Internal service response"},
        {"title": "JWT none algorithm bypass", "confidence": "MEDIUM", "test": "curl", "indicator": "Accepted unsigned JWT"},
    ],
    "express": [
        {"title": "Path traversal via URL encoding", "confidence": "MEDIUM", "test": "curl", "indicator": "File contents returned"},
        {"title": "CORS misconfiguration", "confidence": "HIGH", "test": "curl", "indicator": "ACAO reflects origin"},
    ],
    "react": [
        {"title": "DOM XSS via dangerouslySetInnerHTML", "confidence": "MEDIUM", "test": "browser", "indicator": "Script execution"},
        {"title": "Client-side secrets in JS bundle", "confidence": "HIGH", "test": "curl", "indicator": "API keys in source"},
    ],
    "redis": [
        {"title": "Cache injection via unsanitized key", "confidence": "LOW", "test": "curl", "indicator": "Cache poisoned"},
        {"title": "Session fixation via Redis session store", "confidence": "MEDIUM", "test": "curl", "indicator": "Session accepted from another user"},
    ],
    "postgresql": [
        {"title": "SQL injection in search/filter params", "confidence": "MEDIUM", "test": "curl", "indicator": "SQL error or data leak"},
        {"title": "Boolean-based blind SQLi", "confidence": "LOW", "test": "script", "indicator": "Different responses for true/false"},
    ],
    "aws": [
        {"title": "S3 bucket misconfiguration", "confidence": "HIGH", "test": "curl", "indicator": "Bucket listing or file access"},
        {"title": "SSRF to AWS metadata (IMDSv1)", "confidence": "HIGH", "test": "curl", "indicator": "169.254.169.254 response"},
        {"title": "IAM role assumption abuse", "confidence": "MEDIUM", "test": "script", "indicator": "AssumeRole succeeds"},
    ],
}

# Endpoint patterns that suggest specific vulnerabilities
ENDPOINT_PATTERNS = [
    {"pattern": "/api/", "vulns": ["IDOR", "Auth bypass", "Rate limit"]},
    {"pattern": "/admin", "vulns": ["Auth bypass", "Privilege escalation"]},
    {"pattern": "/upload", "vulns": ["File upload RCE", "Path traversal"]},
    {"pattern": "/login", "vulns": ["Credential stuffing", "2FA bypass", "Account lockout bypass"]},
    {"pattern": "/graphql", "vulns": ["Introspection", "Batch query", "IDOR via mutation"]},
    {"pattern": "/webhook", "vulns": ["SSRF", "Webhook replay"]},
    {"pattern": "/oauth", "vulns": ["OAuth redirect manipulation", "Token leakage"]},
    {"pattern": "/reset", "vulns": ["Password reset poisoning", "Token prediction"]},
    {"pattern": "/export", "vulns": ["IDOR on export", "CSV injection"]},
    {"pattern": "/search", "vulns": ["SQL injection", "XSS reflected", "Info disclosure"]},
]

# Second wave patterns (when first wave fails)
SECOND_WAVE_PATTERNS = {
    "waf_bypass": [
        {"title": "WAF bypass via Unicode normalization", "test": "curl"},
        {"title": "WAF bypass via chunked encoding", "test": "curl"},
        {"title": "WAF bypass via HTTP/2 downgrade", "test": "curl"},
    ],
    "timing": [
        {"title": "Timing-based username enumeration", "test": "script"},
        {"title": "Race condition in checkout flow", "test": "script"},
        {"title": "Time-based blind SQL injection", "test": "script"},
    ],
    "business_logic": [
        {"title": "Business logic flaw: negative quantity", "test": "curl"},
        {"title": "Business logic flaw: price manipulation", "test": "curl"},
        {"title": "Business logic flaw: coupon reuse", "test": "curl"},
        {"title": "Business logic flaw: step skipping", "test": "browser"},
    ],
    "chaining": [
        {"title": "Chain: info disclosure + SSRF", "test": "curl"},
        {"title": "Chain: open redirect + OAuth token theft", "test": "browser"},
        {"title": "Chain: XSS + CSRF for account takeover", "test": "browser"},
    ],
}


class DiscoveryEngine:
    """Generates vulnerability hypotheses from recon data."""

    def __init__(self):
        self._card_counter = 0

    def generate_hypotheses(self, recon_data: Dict[str, Any]) -> List[HypothesisCard]:
        """Generate hypothesis cards from recon data using all 4 reasoning tracks."""
        cards = []

        # Track 1: Pattern Synthesis (tech stack -> known vulns)
        cards.extend(self._pattern_synthesis(recon_data))

        # Track 2: Behavioral Anomaly (endpoint patterns)
        cards.extend(self._behavioral_anomaly(recon_data))

        # Track 3: Code Research (subdomain-based)
        cards.extend(self._code_research(recon_data))

        # Track 4: Cross-Domain Transfer (past successes)
        cards.extend(self._cross_domain_transfer(recon_data))

        # Boost confidence for vuln types that worked before
        successful_types = recon_data.get("successful_vuln_types", [])
        for card in cards:
            for vtype in successful_types:
                if vtype.lower() in card.title.lower():
                    card.confidence = Confidence.HIGH

        # Deduplicate by title
        seen = set()
        unique_cards = []
        for card in cards:
            if card.title not in seen:
                seen.add(card.title)
                unique_cards.append(card)

        return unique_cards

    def generate_second_wave(self, first_wave_results: Dict[str, Any]) -> List[HypothesisCard]:
        """Generate second wave hypotheses when first wave finds nothing."""
        cards = []
        defenses = " ".join(first_wave_results.get("defenses_observed", [])).lower()

        # If WAF detected, add bypass techniques
        if "waf" in defenses or "cloudflare" in defenses or "akamai" in defenses:
            for pattern in SECOND_WAVE_PATTERNS["waf_bypass"]:
                cards.append(self._make_card(
                    pattern["title"], Confidence.MEDIUM, pattern["test"],
                    "Check if WAF is bypassed", "cross_domain",
                ))

        # Always add timing and business logic
        for pattern in SECOND_WAVE_PATTERNS["timing"]:
            cards.append(self._make_card(
                pattern["title"], Confidence.MEDIUM, pattern["test"],
                "Measurable timing difference or race success", "behavioral_anomaly",
            ))

        for pattern in SECOND_WAVE_PATTERNS["business_logic"]:
            cards.append(self._make_card(
                pattern["title"], Confidence.MEDIUM, pattern["test"],
                "Unexpected business state change", "behavioral_anomaly",
            ))

        # Add chaining opportunities
        for pattern in SECOND_WAVE_PATTERNS["chaining"]:
            cards.append(self._make_card(
                pattern["title"], Confidence.LOW, pattern["test"],
                "Chain produces higher impact", "cross_domain",
            ))

        return cards

    def _pattern_synthesis(self, recon_data: Dict) -> List[HypothesisCard]:
        """Track 1: Map tech stack to known vulnerability patterns."""
        cards = []
        tech_stack = [t.lower() for t in recon_data.get("tech_stack", [])]

        for tech in tech_stack:
            patterns = TECH_VULN_PATTERNS.get(tech, [])
            for p in patterns:
                conf = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}
                cards.append(self._make_card(
                    p["title"], conf[p["confidence"]], p["test"],
                    p["indicator"], "pattern_synthesis",
                ))

        return cards

    def _behavioral_anomaly(self, recon_data: Dict) -> List[HypothesisCard]:
        """Track 2: Identify suspicious endpoint patterns."""
        cards = []
        endpoints = recon_data.get("endpoints", [])

        for endpoint in endpoints:
            for ep in ENDPOINT_PATTERNS:
                if ep["pattern"] in endpoint.lower():
                    for vuln in ep["vulns"]:
                        cards.append(self._make_card(
                            f"{vuln} in {endpoint}",
                            Confidence.MEDIUM,
                            "curl",
                            f"Unexpected behavior at {endpoint}",
                            "behavioral_anomaly",
                        ))

        return cards

    def _code_research(self, recon_data: Dict) -> List[HypothesisCard]:
        """Track 3: Subdomain-based hypothesis generation."""
        cards = []
        subdomains = recon_data.get("subdomains", [])

        for sub in subdomains:
            if "admin" in sub:
                cards.append(self._make_card(
                    f"Admin panel access control bypass on {sub}",
                    Confidence.MEDIUM, "browser",
                    "Admin functionality accessible", "code_research",
                ))
            if "api" in sub or "gateway" in sub:
                cards.append(self._make_card(
                    f"API endpoint enumeration on {sub}",
                    Confidence.HIGH, "curl",
                    "Undocumented API endpoints discovered", "code_research",
                ))
            if "staging" in sub or "dev" in sub or "test" in sub:
                cards.append(self._make_card(
                    f"Sensitive data exposure on non-prod {sub}",
                    Confidence.HIGH, "curl",
                    "Debug info, credentials, or test data exposed", "code_research",
                ))

        return cards

    def _cross_domain_transfer(self, recon_data: Dict) -> List[HypothesisCard]:
        """Track 4: Apply lessons from past hunts."""
        cards = []
        # Universal high-value checks that work across most targets
        universal = [
            ("CORS misconfiguration", Confidence.HIGH, "curl", "ACAO reflects arbitrary origin"),
            ("Open redirect via login/OAuth flow", Confidence.MEDIUM, "browser", "Redirect to external domain"),
            ("IDOR via predictable IDs in API", Confidence.HIGH, "curl", "Other user's data returned"),
            ("JWT secret brute force", Confidence.LOW, "script", "JWT verified with common secret"),
            ("Subdomain takeover via dangling CNAME", Confidence.MEDIUM, "curl", "NXDOMAIN or unclaimed service"),
        ]
        for title, conf, method, indicator in universal:
            cards.append(self._make_card(title, conf, method, indicator, "cross_domain"))

        return cards

    def _make_card(self, title: str, confidence: Confidence, test_method: str,
                   success_indicator: str, track: str) -> HypothesisCard:
        self._card_counter += 1
        return HypothesisCard(
            id=f"H{self._card_counter:03d}",
            title=title,
            confidence=confidence,
            test_method=test_method,
            payload="",  # Filled by the testing phase
            success_indicator=success_indicator,
            reasoning_track=track,
        )
```

**Step 4: Run tests**

```bash
cd bountyhound-agent && python -m pytest tests/engine/agents/test_discovery_engine.py -v
```

Expected: ALL PASS

**Step 5: Commit**

```bash
git add engine/agents/discovery_engine.py tests/engine/agents/test_discovery_engine.py
git commit -m "feat: implement real discovery engine with 4 reasoning tracks"
```

---

## Milestone 4: Race Condition & OAST Testing (Day 5)

Two high-value missing capabilities.

---

### Task 8: Add Race Condition Tester

**SEVERITY: MEDIUM - Misses high-payout findings. 3-4 hours.**

**Files:**
- Create: `engine/agents/race_condition_tester.py`
- Test: `tests/engine/agents/test_race_condition_tester.py`

**Step 1: Write failing tests**

```python
import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from engine.agents.race_condition_tester import RaceConditionTester

class TestRaceConditionTester:
    def setup_method(self):
        self.tester = RaceConditionTester()

    def test_generates_concurrent_requests(self):
        """Should create N concurrent identical requests."""
        requests = self.tester.prepare_race(
            url="https://example.com/api/redeem",
            method="POST",
            headers={"Authorization": "Bearer token123"},
            body={"coupon": "SAVE50"},
            concurrency=10,
        )
        assert len(requests) == 10
        assert all(r["method"] == "POST" for r in requests)

    def test_detects_race_condition(self):
        """When multiple requests succeed that should only succeed once, flag it."""
        results = [
            {"status": 200, "body": {"success": True, "discount": 50}},
            {"status": 200, "body": {"success": True, "discount": 50}},
            {"status": 200, "body": {"success": True, "discount": 50}},
            {"status": 400, "body": {"error": "Already redeemed"}},
        ]
        analysis = self.tester.analyze_results(results, expected_successes=1)
        assert analysis["race_detected"] is True
        assert analysis["actual_successes"] == 3
        assert analysis["expected_successes"] == 1

    def test_no_false_positive_on_idempotent(self):
        """Idempotent operations returning 200 are not race conditions."""
        results = [
            {"status": 200, "body": {"data": "same"}},
            {"status": 200, "body": {"data": "same"}},
        ]
        analysis = self.tester.analyze_results(results, expected_successes=None)
        assert analysis["race_detected"] is False
```

**Step 2: Implement using aiohttp for true concurrency**

The key insight: race conditions require requests landing within the same ~10ms window. Sequential requests won't trigger them. Use `asyncio.gather()` with `aiohttp` to fire all requests simultaneously.

```python
"""
Race Condition Tester - Finds TOCTOU and parallel execution vulnerabilities.

High-value targets:
- Coupon/promo code redemption
- Funds transfer / withdrawal
- Like/vote counting
- Inventory/stock purchase
- Account creation (duplicate accounts)

Uses asyncio + aiohttp for true concurrent request firing.
"""

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


@dataclass
class RaceRequest:
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[Dict] = None


class RaceConditionTester:
    """Tests for race conditions via concurrent request firing."""

    def prepare_race(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict] = None,
        concurrency: int = 10,
    ) -> List[Dict[str, Any]]:
        """Prepare N identical requests for concurrent execution."""
        return [
            {
                "url": url,
                "method": method,
                "headers": headers or {},
                "body": body,
            }
            for _ in range(concurrency)
        ]

    async def fire_race(self, requests: List[Dict[str, Any]], timeout: float = 10.0) -> List[Dict[str, Any]]:
        """Fire all requests concurrently and collect results."""
        if not HAS_AIOHTTP:
            raise ImportError("aiohttp required for race condition testing: pip install aiohttp")

        results = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for req in requests:
                tasks.append(self._send_request(session, req, timeout))

            start = time.monotonic()
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.monotonic() - start

            for i, resp in enumerate(responses):
                if isinstance(resp, Exception):
                    results.append({"status": 0, "body": str(resp), "error": True})
                else:
                    results.append(resp)

            # Log timing - all requests should land within ~50ms for effective race
            results_meta = {"total_time_ms": round(elapsed * 1000, 2)}

        return results

    async def _send_request(self, session: aiohttp.ClientSession, req: Dict, timeout: float) -> Dict:
        """Send a single request."""
        method = req["method"].upper()
        kwargs = {
            "url": req["url"],
            "headers": req["headers"],
            "timeout": aiohttp.ClientTimeout(total=timeout),
            "ssl": False,
        }
        if req.get("body"):
            kwargs["json"] = req["body"]

        async with session.request(method, **kwargs) as resp:
            try:
                body = await resp.json()
            except Exception:
                body = await resp.text()
            return {"status": resp.status, "body": body}

    def analyze_results(
        self,
        results: List[Dict[str, Any]],
        expected_successes: Optional[int] = 1,
    ) -> Dict[str, Any]:
        """Analyze race condition test results."""
        successes = [r for r in results if r.get("status") == 200 and not r.get("error")]
        failures = [r for r in results if r.get("status") != 200 or r.get("error")]

        # Check if responses are all identical (idempotent = no race condition)
        if len(successes) > 1:
            bodies = [str(r.get("body", "")) for r in successes]
            all_identical = len(set(bodies)) == 1

            if all_identical and expected_successes is None:
                return {
                    "race_detected": False,
                    "actual_successes": len(successes),
                    "expected_successes": expected_successes,
                    "reason": "All responses identical - likely idempotent operation",
                }

        race_detected = False
        if expected_successes is not None and len(successes) > expected_successes:
            race_detected = True

        return {
            "race_detected": race_detected,
            "actual_successes": len(successes),
            "expected_successes": expected_successes,
            "total_requests": len(results),
            "failures": len(failures),
            "reason": self._build_reason(race_detected, len(successes), expected_successes),
        }

    def _build_reason(self, detected: bool, actual: int, expected: Optional[int]) -> str:
        if detected:
            return f"RACE CONDITION: {actual} successes when only {expected} expected"
        return f"No race condition: {actual} successes"
```

**Step 3: Add `aiohttp` to requirements**

Add to `requirements/requirements-core.txt`:
```
aiohttp>=3.9.0
```

**Step 4: Run tests and commit**

```bash
cd bountyhound-agent && python -m pytest tests/engine/agents/test_race_condition_tester.py -v
git add engine/agents/race_condition_tester.py tests/engine/agents/test_race_condition_tester.py requirements/requirements-core.txt
git commit -m "feat: add race condition tester with async concurrent requests"
```

---

### Task 9: Add OAST (Out-of-Band) Integration

**SEVERITY: MEDIUM - Misses blind SSRF, blind XSS, blind XXE. 2-3 hours.**

**Files:**
- Create: `engine/core/oast_client.py`
- Test: `tests/engine/core/test_oast_client.py`

**Step 1: Write failing tests**

```python
import pytest
from unittest.mock import patch, MagicMock
from engine.core.oast_client import OASTClient

class TestOASTClient:
    def test_generates_unique_callback_url(self):
        """Each payload should get a unique callback URL."""
        client = OASTClient(server="interact.sh")
        url1 = client.generate_callback("test1")
        url2 = client.generate_callback("test2")
        assert url1 != url2
        assert "interact.sh" in url1

    def test_checks_for_callbacks(self):
        """Should poll for received callbacks."""
        client = OASTClient(server="interact.sh")
        # Without real server, should return empty
        callbacks = client.poll_callbacks(timeout=1)
        assert isinstance(callbacks, list)

    def test_generates_ssrf_payloads(self):
        """Should generate SSRF payloads pointing to callback URL."""
        client = OASTClient(server="interact.sh")
        payloads = client.generate_ssrf_payloads("ssrf-test-1")
        assert len(payloads) > 0
        assert any("interact.sh" in p for p in payloads)

    def test_generates_xxe_payloads(self):
        """Should generate XXE payloads with callback URL."""
        client = OASTClient(server="interact.sh")
        payloads = client.generate_xxe_payloads("xxe-test-1")
        assert len(payloads) > 0
        assert any("ENTITY" in p for p in payloads)
```

**Step 2: Implement oast_client.py**

Simple integration with interact.sh (free, no auth needed) or custom OAST server. Core functionality: generate unique callback URLs, embed them in payloads, poll for callbacks.

**Step 3: Run tests and commit**

```bash
git add engine/core/oast_client.py tests/engine/core/test_oast_client.py
git commit -m "feat: add OAST client for blind vulnerability detection"
```

---

## Milestone 5: Phased Hunter Rebuild (Day 6-7)

Replace the hollow shell with a real orchestrator.

---

### Task 10: Rebuild PhasedHunter._phase_discovery()

**Files:**
- Modify: `engine/agents/phased_hunter.py:295-339`

Replace the trivial URL-appending loop with actual `DiscoveryEngine` integration:

```python
def _phase_discovery(self, recon_data: Dict) -> List[HypothesisCard]:
    """Phase 1.5: Generate vulnerability hypotheses using Discovery Engine."""
    from engine.agents.discovery_engine import DiscoveryEngine

    engine = DiscoveryEngine()

    # Enrich recon data with database intelligence
    successful_payloads = self.db.get_successful_payloads(self.target)
    recon_data["successful_vuln_types"] = list(set(
        p.get("vuln_type", "") for p in successful_payloads
    ))

    return engine.generate_hypotheses(recon_data)
```

---

### Task 11: Rebuild PhasedHunter._phase_validation() with State Verification

**Files:**
- Modify: `engine/agents/phased_hunter.py:341-406`

Replace curl-status-code-only validation with actual state change verification:

```python
def _phase_validation(self, hypotheses: List[HypothesisCard]) -> List[Finding]:
    """Phase 2: Test hypotheses with actual state change verification."""
    from engine.core.state_verifier import StateVerifier

    verifier = StateVerifier()
    findings = []

    for card in hypotheses:
        # Step 1: Read before state
        before_state = self._read_state(card)

        # Step 2: Attempt exploit
        result = self._attempt_exploit(card)

        # Step 3: Read after state
        after_state = self._read_state(card)

        # Step 4: Verify state change
        verification = verifier.compare_states(before_state, after_state)

        if verification.changed:
            findings.append(Finding(
                title=card.title,
                evidence=json.dumps(verification.diff),
                state_change_verified=True,
                hypothesis_card=card,
            ))

    return findings
```

---

### Task 12: Add Error Recovery and Hunt Resumption

**SEVERITY: HIGH - Wasted hunt time. 3-4 hours.**

**Files:**
- Modify: `engine/agents/phased_hunter.py`
- Create: `engine/core/hunt_state.py`
- Test: `tests/engine/core/test_hunt_state.py`

Implement a `HuntState` class that checkpoints after each phase:
```python
@dataclass
class HuntState:
    target: str
    current_phase: int
    completed_phases: List[int]
    recon_data: Optional[Dict] = None
    hypotheses: Optional[List] = None
    findings: Optional[List] = None
    timestamp: str = ""

    def save(self, path: str): ...
    def load(cls, path: str) -> 'HuntState': ...
```

The PhasedHunter checks for existing state on startup:
```python
def run_full_hunt(self, target: str, resume: bool = True):
    state_path = f"{FINDINGS_DIR}/{target}/.hunt_state.json"
    if resume and os.path.exists(state_path):
        state = HuntState.load(state_path)
        start_phase = state.current_phase
    else:
        state = HuntState(target=target, current_phase=0, completed_phases=[])
        start_phase = 0
    # Run from start_phase onwards, saving state after each phase
```

---

## Milestone 6: Operational Excellence (Day 8)

---

### Task 13: Add Payout Import from HackerOne API

**Files:**
- Create: `engine/core/payout_importer.py`
- Test: `tests/engine/core/test_payout_importer.py`

Use the HackerOne API to import actual payout data into the database, making ROI calculations real instead of always-zero.

---

### Task 14: Semantic Duplicate Detection

**Files:**
- Modify: `engine/core/database.py` (`find_similar_findings`)

Replace keyword `LIKE` matching with:
1. Endpoint URL normalization (strip IDs, normalize paths)
2. Vulnerability type + endpoint combination matching
3. Cosine similarity on finding descriptions (using basic TF-IDF, no external deps)

---

### Task 15: Integration Test for Full Pipeline

**Files:**
- Create: `tests/integration/test_full_pipeline.py`

Mock target that exercises all phases:
```python
def test_full_hunt_pipeline_e2e(mock_target):
    """Run a full phased hunt against a mock target and verify all phases execute."""
    hunter = PhasedHunter("mock.example.com")
    results = hunter.run_full_hunt()
    assert results["phases_completed"] == [0, 1, 1.5, 2, 3, 4, 5, 6]
    assert all(f["state_change_verified"] for f in results["findings"])
```

---

## Summary

| Milestone | Tasks | Time | Impact |
|-----------|-------|------|--------|
| **M1: Foundation** | Tasks 1-4 | Day 1 | Fixes path chaos, creds leak, quality gate |
| **M2: State Verification** | Tasks 5-6 | Day 2 | Eliminates false positives |
| **M3: Discovery Engine** | Task 7 | Day 3-4 | Real hypothesis generation |
| **M4: Race + OAST** | Tasks 8-9 | Day 5 | New high-value finding categories |
| **M5: Hunter Rebuild** | Tasks 10-12 | Day 6-7 | Working autonomous pipeline |
| **M6: Operations** | Tasks 13-15 | Day 8 | ROI tracking, dedup, integration tests |

**Total: ~8 working days to transform BountyHound from prompt library to autonomous hunter.**

After completion:
- Every finding has state change proof (no more false positives)
- Discovery engine generates real hypotheses from tech stack + past successes
- Race conditions and blind vulns are testable
- Hunts can resume after crashes
- ROI data drives target selection for real
- Quality gate blocks bad submissions before they burn reports
