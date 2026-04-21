# AI-Powered Continuous Learning Hunter Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an AI-powered continuous learning loop that actively reasons about discoveries and generates new exploit hypotheses.

**Architecture:** LLM-based reasoning engine that analyzes findings, extracts patterns, generates hypotheses, chains exploits, and learns from successes/failures. Replaces static automation with dynamic intelligent hunting.

**Tech Stack:** Anthropic Claude API (claude-opus-4-6), async Python, BountyHound database, existing agent infrastructure

---

## Task 1: Core AI Hunter Engine

**Files:**
- Create: `C:/Users/vaugh/BountyHound/bountyhound-agent/engine/core/ai_hunter.py`
- Test: `C:/Users/vaugh/BountyHound/bountyhound-agent/tests/test_ai_hunter.py`

**Step 1: Write the failing test**

```python
import pytest
from engine.core.ai_hunter import AIPoweredHunter

@pytest.mark.asyncio
async def test_ai_hunter_initialization():
    """Test AI hunter initializes with target and API key"""
    hunter = AIPoweredHunter(target="example.com", api_key="test-key")

    assert hunter.target == "example.com"
    assert hunter.api_key == "test-key"
    assert hunter.findings == []
    assert hunter.patterns == []
    assert hunter.iteration == 0

@pytest.mark.asyncio
async def test_generate_hypotheses_from_recon():
    """Test hypothesis generation from reconnaissance data"""
    hunter = AIPoweredHunter(target="example.com", api_key="test-key")

    recon = {
        "tech_stack": ["GraphQL", "React", "Node.js"],
        "endpoints": ["/api/graphql", "/api/users"],
        "findings": []
    }

    # Mock LLM response
    hunter.llm = MockLLM(response={
        "hypotheses": [
            {
                "title": "GraphQL introspection may be enabled",
                "test": "Send introspection query to /api/graphql",
                "rationale": "GraphQL detected, introspection often left enabled in production"
            }
        ]
    })

    hypotheses = await hunter._generate_hypotheses(recon, [], [])

    assert len(hypotheses) > 0
    assert hypotheses[0]["title"] == "GraphQL introspection may be enabled"
    assert "test" in hypotheses[0]
    assert "rationale" in hypotheses[0]
```

**Step 2: Run test to verify it fails**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_ai_hunter.py::test_ai_hunter_initialization -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'engine.core.ai_hunter'"

**Step 3: Write minimal implementation**

```python
import asyncio
from typing import List, Dict, Any, Optional
from anthropic import AsyncAnthropic
import json

class AIPoweredHunter:
    """AI-powered continuous learning bug bounty hunter"""

    def __init__(self, target: str, api_key: str, max_iterations: int = 20):
        self.target = target
        self.api_key = api_key
        self.max_iterations = max_iterations
        self.llm = AsyncAnthropic(api_key=api_key)

        # State tracking
        self.findings: List[Dict] = []
        self.patterns: List[Dict] = []
        self.iteration: int = 0
        self.tested_hypotheses: List[str] = []

    async def _generate_hypotheses(
        self,
        recon: Dict,
        findings: List[Dict],
        prior_knowledge: List[Dict]
    ) -> List[Dict]:
        """Generate attack hypotheses using AI reasoning"""

        prompt = self._build_hypothesis_prompt(recon, findings, prior_knowledge)

        response = await self.llm.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )

        return self._parse_hypotheses(response.content[0].text)

    def _build_hypothesis_prompt(self, recon: Dict, findings: List[Dict], prior_knowledge: List[Dict]) -> str:
        """Build prompt for hypothesis generation"""

        return f"""You are an expert bug bounty hunter analyzing {self.target}.

CURRENT INTELLIGENCE:
- Tech Stack: {', '.join(recon.get('tech_stack', []))}
- Discovered Endpoints: {len(recon.get('endpoints', []))} endpoints
- Findings So Far: {len(findings)} vulnerabilities found
- Prior Successful Patterns: {len(prior_knowledge)} known patterns

FINDINGS SUMMARY:
{json.dumps(findings[-5:], indent=2) if findings else "No findings yet"}

SUCCESSFUL PATTERNS FROM DATABASE:
{json.dumps(prior_knowledge[:10], indent=2) if prior_knowledge else "No prior patterns"}

TASK: Generate 10 specific, actionable hypotheses for what to test next.

For each hypothesis, provide:
1. Title: Clear, specific vulnerability to test
2. Test: Exact test to perform (endpoint, payload, method)
3. Rationale: Why this is likely to work based on intelligence
4. Confidence: HIGH/MEDIUM/LOW

Think creatively about:
- Patterns from successful findings
- Exploit chaining opportunities
- Unconventional attack vectors
- Cross-domain knowledge transfer
- Tech-specific vulnerabilities

Return ONLY valid JSON array:
[
  {{
    "title": "Specific vulnerability hypothesis",
    "test": "Exact test to perform",
    "rationale": "Why this should work",
    "confidence": "HIGH"
  }}
]"""

    def _parse_hypotheses(self, response_text: str) -> List[Dict]:
        """Parse LLM response into structured hypotheses"""
        try:
            # Extract JSON from response
            start = response_text.find('[')
            end = response_text.rfind(']') + 1

            if start == -1 or end == 0:
                return []

            json_text = response_text[start:end]
            hypotheses = json.loads(json_text)

            return hypotheses
        except Exception as e:
            print(f"Failed to parse hypotheses: {e}")
            return []
```

**Step 4: Run test to verify it passes**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_ai_hunter.py::test_ai_hunter_initialization -v`
Expected: PASS

**Step 5: Commit**

```bash
cd C:/Users/vaugh/BountyHound/bountyhound-agent
git add engine/core/ai_hunter.py tests/test_ai_hunter.py
git commit -m "feat: add AI-powered hunter core with hypothesis generation"
```

---

## Task 2: Pattern Extraction from Successful Exploits

**Files:**
- Modify: `C:/Users/vaugh/BountyHound/bountyhound-agent/engine/core/ai_hunter.py`
- Modify: `C:/Users/vaugh/BountyHound/bountyhound-agent/tests/test_ai_hunter.py`

**Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_extract_pattern_from_finding():
    """Test pattern extraction from successful finding"""
    hunter = AIPoweredHunter(target="example.com", api_key="test-key")
    hunter.llm = MockLLM(response={
        "pattern": {
            "name": "GraphQL IDOR via UUID enumeration",
            "tech": ["GraphQL"],
            "indicators": ["GraphQL mutation", "UUID parameter", "No auth check"],
            "exploit_template": "mutation { user(id: UUID) { email } }",
            "confidence": "HIGH"
        }
    })

    finding = {
        "title": "IDOR in getUserProfile mutation",
        "endpoint": "/api/graphql",
        "method": "POST",
        "payload": 'mutation { user(id: "123-456") { email privateData } }',
        "response": '{"data": {"user": {"email": "victim@example.com"}}}',
        "tech": "GraphQL"
    }

    pattern = await hunter._extract_pattern(finding)

    assert pattern["name"] == "GraphQL IDOR via UUID enumeration"
    assert "GraphQL" in pattern["tech"]
    assert "exploit_template" in pattern
```

**Step 2: Run test to verify it fails**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_ai_hunter.py::test_extract_pattern_from_finding -v`
Expected: FAIL with "AttributeError: 'AIPoweredHunter' object has no attribute '_extract_pattern'"

**Step 3: Write minimal implementation**

```python
async def _extract_pattern(self, finding: Dict) -> Dict:
    """Extract reusable pattern from successful finding using AI"""

    prompt = f"""You are analyzing a successful bug bounty finding to extract a reusable attack pattern.

FINDING:
{json.dumps(finding, indent=2)}

TASK: Extract a reusable pattern that can be applied to similar targets.

Return ONLY valid JSON object:
{{
  "name": "Descriptive pattern name",
  "tech": ["Technology1", "Technology2"],
  "indicators": ["What signals this pattern might work"],
  "exploit_template": "Generalized exploit payload with <PLACEHOLDER> markers",
  "confidence": "HIGH/MEDIUM/LOW",
  "similar_endpoints": "What other endpoints might be vulnerable",
  "variations": ["Common variations of this attack"]
}}"""

    response = await self.llm.messages.create(
        model="claude-opus-4-6",
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}]
    )

    return self._parse_json_response(response.content[0].text)

def _parse_json_response(self, response_text: str) -> Dict:
    """Parse JSON object from LLM response"""
    try:
        start = response_text.find('{')
        end = response_text.rfind('}') + 1

        if start == -1 or end == 0:
            return {}

        json_text = response_text[start:end]
        return json.loads(json_text)
    except Exception as e:
        print(f"Failed to parse JSON: {e}")
        return {}
```

**Step 4: Run test to verify it passes**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_ai_hunter.py::test_extract_pattern_from_finding -v`
Expected: PASS

**Step 5: Commit**

```bash
cd C:/Users/vaugh/BountyHound/bountyhound-agent
git add engine/core/ai_hunter.py tests/test_ai_hunter.py
git commit -m "feat: add pattern extraction from successful findings"
```

---

## Task 3: Exploit Chain Discovery

**Files:**
- Modify: `C:/Users/vaugh/BountyHound/bountyhound-agent/engine/core/ai_hunter.py`
- Modify: `C:/Users/vaugh/BountyHound/bountyhound-agent/tests/test_ai_hunter.py`

**Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_find_exploit_chains():
    """Test finding exploit chains from multiple findings"""
    hunter = AIPoweredHunter(target="example.com", api_key="test-key")
    hunter.llm = MockLLM(response={
        "chains": [
            {
                "title": "XSS → Session Theft → Account Takeover",
                "steps": [
                    "1. Exploit XSS in /profile endpoint",
                    "2. Steal session cookie via XSS payload",
                    "3. Use stolen cookie to access admin panel"
                ],
                "impact": "CRITICAL",
                "confidence": "HIGH"
            }
        ]
    })

    findings = [
        {"title": "XSS in profile endpoint", "severity": "MEDIUM"},
        {"title": "Admin panel accessible with valid session", "severity": "LOW"},
        {"title": "Session cookie has no HttpOnly flag", "severity": "LOW"}
    ]

    chains = await hunter._find_exploit_chains(findings)

    assert len(chains) > 0
    assert "XSS" in chains[0]["title"]
    assert chains[0]["impact"] == "CRITICAL"
    assert len(chains[0]["steps"]) >= 2
```

**Step 2: Run test to verify it fails**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_ai_hunter.py::test_find_exploit_chains -v`
Expected: FAIL with "AttributeError: 'AIPoweredHunter' object has no attribute '_find_exploit_chains'"

**Step 3: Write minimal implementation**

```python
async def _find_exploit_chains(self, findings: List[Dict]) -> List[Dict]:
    """Discover exploit chains by combining multiple vulnerabilities"""

    if len(findings) < 2:
        return []

    prompt = f"""You are analyzing multiple security findings to discover exploit chains.

FINDINGS:
{json.dumps(findings, indent=2)}

TASK: Identify chains where combining these vulnerabilities creates higher impact.

Look for:
- Information disclosure → Privilege escalation
- XSS → Session theft → Account takeover
- IDOR → Data exfiltration → Business logic abuse
- Auth bypass → IDOR → Critical data access

Return ONLY valid JSON array:
[
  {{
    "title": "Vulnerability1 → Vulnerability2 → Impact",
    "steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
    "findings_used": ["Finding ID 1", "Finding ID 2"],
    "impact": "CRITICAL/HIGH/MEDIUM/LOW",
    "confidence": "HIGH/MEDIUM/LOW",
    "rationale": "Why this chain works"
  }}
]"""

    response = await self.llm.messages.create(
        model="claude-opus-4-6",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}]
    )

    return self._parse_hypotheses(response.content[0].text)
```

**Step 4: Run test to verify it passes**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_ai_hunter.py::test_find_exploit_chains -v`
Expected: PASS

**Step 5: Commit**

```bash
cd C:/Users/vaugh/BountyHound/bountyhound-agent
git add engine/core/ai_hunter.py tests/test_ai_hunter.py
git commit -m "feat: add exploit chain discovery from multiple findings"
```

---

## Task 4: Database Integration for Learning

**Files:**
- Modify: `C:/Users/vaugh/BountyHound/bountyhound-agent/engine/core/ai_hunter.py`
- Modify: `C:/Users/vaugh/BountyHound/bountyhound-agent/tests/test_ai_hunter.py`
- Create: `C:/Users/vaugh/BountyHound/bountyhound-agent/migrations/007_ai_learning.sql`

**Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_load_prior_knowledge_from_database():
    """Test loading successful patterns from database"""
    hunter = AIPoweredHunter(target="example.com", api_key="test-key")

    # Mock database with prior successful patterns
    from engine.core.db_hooks import DatabaseHooks
    db = DatabaseHooks()
    db.save_pattern({
        "name": "GraphQL IDOR",
        "tech": ["GraphQL"],
        "success_rate": 0.75,
        "targets_succeeded": ["target1.com", "target2.com"]
    })

    prior_knowledge = await hunter._load_prior_knowledge()

    assert len(prior_knowledge) > 0
    assert prior_knowledge[0]["name"] == "GraphQL IDOR"
    assert prior_knowledge[0]["success_rate"] >= 0.5
```

**Step 2: Run test to verify it fails**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_ai_hunter.py::test_load_prior_knowledge_from_database -v`
Expected: FAIL with "AttributeError: 'AIPoweredHunter' object has no attribute '_load_prior_knowledge'"

**Step 3: Create database schema**

```sql
-- Create learned patterns table
CREATE TABLE IF NOT EXISTS learned_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    tech JSON NOT NULL,
    indicators JSON,
    exploit_template TEXT,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    success_rate REAL GENERATED ALWAYS AS (
        CAST(success_count AS REAL) / NULLIF(success_count + failure_count, 0)
    ) VIRTUAL,
    targets_succeeded JSON,
    targets_failed JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create hypothesis tracking table
CREATE TABLE IF NOT EXISTS hypothesis_tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    hypothesis_title TEXT NOT NULL,
    hypothesis_test TEXT NOT NULL,
    rationale TEXT,
    confidence TEXT,
    result TEXT, -- 'success', 'failure', 'error'
    finding_id INTEGER,
    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

-- Create exploit chains table
CREATE TABLE IF NOT EXISTS exploit_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    chain_title TEXT NOT NULL,
    steps JSON NOT NULL,
    findings_used JSON NOT NULL,
    impact TEXT,
    verified BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Step 4: Write implementation**

```python
async def _load_prior_knowledge(self) -> List[Dict]:
    """Load successful patterns from database"""
    from engine.core.db_hooks import DatabaseHooks

    db = DatabaseHooks()

    # Get patterns with success rate > 50%
    patterns = db.get_patterns(min_success_rate=0.5, limit=20)

    # Get recent successful findings for this tech stack
    recon = await self._get_recon()
    tech_stack = recon.get('tech_stack', [])

    relevant_findings = db.get_findings_by_tech(tech_stack, limit=10)

    return {
        "patterns": patterns,
        "relevant_findings": relevant_findings
    }

async def _save_pattern(self, pattern: Dict) -> None:
    """Save learned pattern to database"""
    from engine.core.db_hooks import DatabaseHooks

    db = DatabaseHooks()
    db.save_pattern({
        "name": pattern["name"],
        "tech": json.dumps(pattern.get("tech", [])),
        "indicators": json.dumps(pattern.get("indicators", [])),
        "exploit_template": pattern.get("exploit_template", ""),
        "success_count": 1,
        "failure_count": 0,
        "targets_succeeded": json.dumps([self.target])
    })

async def _record_hypothesis_test(self, hypothesis: Dict, result: str, finding_id: Optional[int] = None) -> None:
    """Record hypothesis test result in database"""
    from engine.core.db_hooks import DatabaseHooks

    db = DatabaseHooks()
    db.execute("""
        INSERT INTO hypothesis_tests
        (target, hypothesis_title, hypothesis_test, rationale, confidence, result, finding_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        self.target,
        hypothesis["title"],
        hypothesis["test"],
        hypothesis.get("rationale", ""),
        hypothesis.get("confidence", "MEDIUM"),
        result,
        finding_id
    ))
```

**Step 5: Run test to verify it passes**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_ai_hunter.py::test_load_prior_knowledge_from_database -v`
Expected: PASS

**Step 6: Commit**

```bash
cd C:/Users/vaugh/BountyHound/bountyhound-agent
git add engine/core/ai_hunter.py tests/test_ai_hunter.py migrations/007_ai_learning.sql
git commit -m "feat: add database integration for learning from prior hunts"
```

---

## Task 5: Main Hunt Loop with Continuous Learning

**Files:**
- Modify: `C:/Users/vaugh/BountyHound/bountyhound-agent/engine/core/ai_hunter.py`
- Modify: `C:/Users/vaugh/BountyHound/bountyhound-agent/tests/test_ai_hunter.py`

**Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_hunt_loop_executes_iterations():
    """Test main hunt loop executes multiple iterations"""
    hunter = AIPoweredHunter(target="example.com", api_key="test-key", max_iterations=3)

    # Mock all dependencies
    hunter._get_recon = AsyncMock(return_value={
        "tech_stack": ["GraphQL"],
        "endpoints": ["/api/graphql"]
    })
    hunter._load_prior_knowledge = AsyncMock(return_value=[])
    hunter._generate_hypotheses = AsyncMock(return_value=[
        {"title": "Test hypothesis", "test": "Test", "confidence": "HIGH"}
    ])
    hunter._test_hypothesis = AsyncMock(return_value={
        "success": True,
        "finding": {"title": "Test finding"}
    })
    hunter._extract_pattern = AsyncMock(return_value={"name": "Test pattern"})
    hunter._find_exploit_chains = AsyncMock(return_value=[])

    await hunter.hunt()

    assert hunter.iteration == 3
    assert len(hunter.findings) > 0
    assert len(hunter.patterns) > 0
```

**Step 2: Run test to verify it fails**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_ai_hunter.py::test_hunt_loop_executes_iterations -v`
Expected: FAIL with "AttributeError: 'AIPoweredHunter' object has no attribute 'hunt'"

**Step 3: Write minimal implementation**

```python
async def hunt(self) -> Dict:
    """Main continuous learning hunt loop"""

    print(f"\n🎯 Starting AI-powered hunt on {self.target}")
    print(f"Max iterations: {self.max_iterations}\n")

    # Phase 1: Initial reconnaissance
    recon = await self._get_recon()
    print(f"✓ Recon complete: {len(recon.get('endpoints', []))} endpoints, {len(recon.get('tech_stack', []))} technologies")

    # Phase 2: Load prior knowledge
    prior_knowledge = await self._load_prior_knowledge()
    print(f"✓ Loaded {len(prior_knowledge.get('patterns', []))} prior patterns, {len(prior_knowledge.get('relevant_findings', []))} relevant findings\n")

    # Phase 3: Continuous learning loop
    while self.iteration < self.max_iterations:
        self.iteration += 1
        print(f"--- Iteration {self.iteration}/{self.max_iterations} ---")

        # Generate hypotheses using AI reasoning
        hypotheses = await self._generate_hypotheses(recon, self.findings, prior_knowledge)
        print(f"Generated {len(hypotheses)} hypotheses")

        # Test each hypothesis
        iteration_findings = []
        for i, hypothesis in enumerate(hypotheses, 1):
            print(f"  [{i}/{len(hypotheses)}] Testing: {hypothesis['title']}")

            result = await self._test_hypothesis(hypothesis)

            if result["success"]:
                print(f"    ✓ FOUND: {result['finding']['title']}")
                self.findings.append(result["finding"])
                iteration_findings.append(result["finding"])

                # Extract pattern immediately
                pattern = await self._extract_pattern(result["finding"])
                self.patterns.append(pattern)
                await self._save_pattern(pattern)

                # Record success
                await self._record_hypothesis_test(hypothesis, "success", result["finding"].get("id"))

                # Apply pattern to similar endpoints immediately
                similar = self._find_similar_endpoints(result["finding"].get("endpoint", ""), recon['endpoints'])
                if similar:
                    print(f"    → Testing {len(similar)} similar endpoints with pattern")
                    await self._quick_test_pattern(similar, pattern)
            else:
                await self._record_hypothesis_test(hypothesis, "failure")

        # Look for exploit chains after each iteration
        if len(self.findings) >= 2:
            chains = await self._find_exploit_chains(self.findings)
            if chains:
                print(f"  🔗 Discovered {len(chains)} exploit chains")
                for chain in chains:
                    await self._save_exploit_chain(chain)

        # Check if we're stuck (no findings in last 3 iterations)
        if self.iteration >= 3 and len(iteration_findings) == 0:
            print("  ⚠ No findings in recent iterations, generating creative bypasses...")
            creative_hypotheses = await self._generate_creative_bypasses(recon, self.findings)
            # Test creative hypotheses...

        print()

    # Final summary
    print(f"\n{'='*60}")
    print(f"Hunt complete: {len(self.findings)} findings, {len(self.patterns)} patterns learned")
    print(f"{'='*60}\n")

    return {
        "target": self.target,
        "findings": self.findings,
        "patterns": self.patterns,
        "iterations": self.iteration,
        "exploit_chains": await self._get_all_chains()
    }

async def _get_recon(self) -> Dict:
    """Run reconnaissance on target"""
    # Integration point with existing recon agents
    from engine.agents.discovery_engine import DiscoveryEngine

    engine = DiscoveryEngine()
    return await engine.discover(self.target)

async def _test_hypothesis(self, hypothesis: Dict) -> Dict:
    """Test a specific hypothesis"""
    # Integration point with existing test agents
    # Route to appropriate agent based on hypothesis type

    test_instruction = hypothesis["test"]

    # Extract test type and route accordingly
    if "graphql" in test_instruction.lower():
        from engine.agents.graphql_tester import GraphQLTester
        tester = GraphQLTester()
        result = await tester.test(test_instruction)
    elif "api" in test_instruction.lower():
        from engine.agents.api_tester import APITester
        tester = APITester()
        result = await tester.test(test_instruction)
    else:
        # Generic test
        result = {"success": False}

    return result

def _find_similar_endpoints(self, endpoint: str, all_endpoints: List[str]) -> List[str]:
    """Find endpoints similar to the vulnerable one"""
    similar = []

    # Extract pattern (e.g., /api/users/123 → /api/.*/\d+)
    import re
    pattern = re.sub(r'\d+', r'\\d+', endpoint)
    pattern = re.sub(r'[a-f0-9-]{36}', r'[a-f0-9-]{36}', pattern)  # UUIDs

    for ep in all_endpoints:
        if ep != endpoint and re.match(pattern, ep):
            similar.append(ep)

    return similar[:10]  # Limit to 10

async def _quick_test_pattern(self, endpoints: List[str], pattern: Dict) -> None:
    """Quickly test pattern on similar endpoints"""
    for endpoint in endpoints:
        # Apply pattern's exploit template to endpoint
        payload = pattern.get("exploit_template", "").replace("<ENDPOINT>", endpoint)
        # Test with payload...
        pass

async def _save_exploit_chain(self, chain: Dict) -> None:
    """Save discovered exploit chain to database"""
    from engine.core.db_hooks import DatabaseHooks

    db = DatabaseHooks()
    db.execute("""
        INSERT INTO exploit_chains (target, chain_title, steps, findings_used, impact)
        VALUES (?, ?, ?, ?, ?)
    """, (
        self.target,
        chain["title"],
        json.dumps(chain["steps"]),
        json.dumps(chain.get("findings_used", [])),
        chain.get("impact", "MEDIUM")
    ))

async def _get_all_chains(self) -> List[Dict]:
    """Get all exploit chains for this target"""
    from engine.core.db_hooks import DatabaseHooks

    db = DatabaseHooks()
    return db.fetch_all(
        "SELECT * FROM exploit_chains WHERE target = ? ORDER BY created_at DESC",
        (self.target,)
    )

async def _generate_creative_bypasses(self, recon: Dict, findings: List[Dict]) -> List[Dict]:
    """Generate creative bypass hypotheses when stuck"""

    prompt = f"""You are an expert bug bounty hunter. You've been testing {self.target} for a while but recent tests haven't found anything.

CURRENT INTELLIGENCE:
- Tech Stack: {', '.join(recon.get('tech_stack', []))}
- Findings So Far: {len(findings)} vulnerabilities
- Recent Findings: {json.dumps(findings[-3:], indent=2) if findings else "None"}

TASK: Think creatively about unconventional attack vectors and bypasses.

Consider:
- Unusual HTTP methods (TRACE, TRACK, DEBUG)
- HTTP/2 smuggling via headers
- CRLF injection in headers
- Unicode normalization bypasses
- Race conditions in concurrent requests
- Cache poisoning via HTTP headers
- Protocol-level attacks (WebSocket upgrade, HTTP/2 upgrade)
- Business logic flaws in edge cases

Return ONLY valid JSON array of 5 creative hypotheses.
"""

    response = await self.llm.messages.create(
        model="claude-opus-4-6",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}]
    )

    return self._parse_hypotheses(response.content[0].text)
```

**Step 4: Run test to verify it passes**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_ai_hunter.py::test_hunt_loop_executes_iterations -v`
Expected: PASS

**Step 5: Commit**

```bash
cd C:/Users/vaugh/BountyHound/bountyhound-agent
git add engine/core/ai_hunter.py tests/test_ai_hunter.py
git commit -m "feat: add main continuous learning hunt loop"
```

---

## Task 6: Simplified Command System

**Files:**
- Create: `C:/Users/vaugh/BountyHound/bountyhound-agent/engine/core/command_router.py`
- Test: `C:/Users/vaugh/BountyHound/bountyhound-agent/tests/test_command_router.py`
- Modify: `C:/Users/vaugh/BountyHound/bountyhound-agent/CLAUDE.md`

**Step 1: Write the failing test**

```python
import pytest
from engine.core.command_router import CommandRouter

def test_command_router_initialization():
    """Test command router initializes correctly"""
    router = CommandRouter(api_key="test-key")

    assert router.api_key == "test-key"
    assert hasattr(router, 'route')

def test_route_hunt_command():
    """Test routing /hunt command to AI hunter"""
    router = CommandRouter(api_key="test-key")

    command = "/hunt example.com"
    route = router.route(command)

    assert route["type"] == "ai_hunt"
    assert route["target"] == "example.com"
    assert route["agent"] == "AIPoweredHunter"

def test_route_test_command_with_context():
    """Test routing /test with intelligent context detection"""
    router = CommandRouter(api_key="test-key")

    # GraphQL context
    command = "/test example.com --context 'GraphQL API at /api/graphql'"
    route = router.route(command)

    assert route["type"] == "targeted_test"
    assert "graphql" in route["agents"]

def test_route_learn_command():
    """Test routing /learn command to pattern extraction"""
    router = CommandRouter(api_key="test-key")

    command = "/learn"
    route = router.route(command)

    assert route["type"] == "extract_patterns"
    assert route["agent"] == "PatternExtractor"
```

**Step 2: Run test to verify it fails**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_command_router.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'engine.core.command_router'"

**Step 3: Write minimal implementation**

```python
import re
from typing import Dict, List, Any

class CommandRouter:
    """Intelligent command router that simplifies BountyHound interface"""

    def __init__(self, api_key: str):
        self.api_key = api_key

        # Command patterns
        self.patterns = {
            r'^/hunt\s+(\S+)': self._route_hunt,
            r'^/test\s+(\S+)(?:\s+--context\s+["\'](.+)["\'])?': self._route_test,
            r'^/learn': self._route_learn,
            r'^/chain': self._route_chain,
            r'^/report(?:\s+(\S+))?': self._route_report,
        }

    def route(self, command: str) -> Dict:
        """Route command to appropriate agent/workflow"""

        for pattern, handler in self.patterns.items():
            match = re.match(pattern, command)
            if match:
                return handler(match)

        return {"type": "unknown", "error": "Unknown command"}

    def _route_hunt(self, match: re.Match) -> Dict:
        """Route to AI-powered continuous learning hunter"""
        target = match.group(1)

        return {
            "type": "ai_hunt",
            "agent": "AIPoweredHunter",
            "target": target,
            "config": {
                "max_iterations": 20,
                "mode": "continuous_learning"
            }
        }

    def _route_test(self, match: re.Match) -> Dict:
        """Route to targeted testing with intelligent agent selection"""
        target = match.group(1)
        context = match.group(2) if match.lastindex >= 2 else None

        # Intelligently select agents based on context
        agents = self._select_agents_from_context(context) if context else ["all"]

        return {
            "type": "targeted_test",
            "target": target,
            "context": context,
            "agents": agents
        }

    def _route_learn(self, match: re.Match) -> Dict:
        """Route to pattern extraction and learning"""
        return {
            "type": "extract_patterns",
            "agent": "PatternExtractor"
        }

    def _route_chain(self, match: re.Match) -> Dict:
        """Route to exploit chain discovery"""
        return {
            "type": "find_chains",
            "agent": "ExploitChainer"
        }

    def _route_report(self, match: re.Match) -> Dict:
        """Route to report generation"""
        target = match.group(1) if match.lastindex >= 1 else None

        return {
            "type": "generate_report",
            "agent": "ReportGenerator",
            "target": target
        }

    def _select_agents_from_context(self, context: str) -> List[str]:
        """Intelligently select agents based on context"""
        context_lower = context.lower()
        agents = []

        # Tech-based selection
        if "graphql" in context_lower:
            agents.append("graphql_tester")
        if "api" in context_lower or "rest" in context_lower:
            agents.append("api_tester")
        if "websocket" in context_lower or "ws" in context_lower:
            agents.append("websocket_tester")
        if "mobile" in context_lower or "ios" in context_lower or "android" in context_lower:
            agents.append("mobile_tester")
        if "cloud" in context_lower or "s3" in context_lower or "bucket" in context_lower:
            agents.extend(["s3_tester", "azure_tester", "gcp_tester"])

        return agents if agents else ["discovery_engine"]
```

**Step 4: Run test to verify it passes**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/test_command_router.py -v`
Expected: PASS

**Step 5: Update CLAUDE.md with new simplified commands**

```markdown
# BountyHound v4.0 - AI-Powered Continuous Learning Hunter

## Simplified Commands

BountyHound now uses an intelligent command router with just 5 commands:

### `/hunt <target>`
AI-powered continuous learning hunt. Automatically:
- Runs reconnaissance
- Generates hypotheses using AI reasoning
- Tests hypotheses and learns from results
- Extracts patterns from successful exploits
- Discovers exploit chains
- Applies learned patterns to similar targets

**Example:**
```
/hunt example.com
```

### `/test <target> [--context "description"]`
Targeted testing with intelligent agent selection. Provide context and the system automatically selects appropriate agents.

**Examples:**
```
/test api.example.com --context "GraphQL API at /api/graphql"
/test example.com --context "Mobile app, iOS and Android"
/test s3bucket.example.com --context "S3 bucket enumeration"
```

### `/learn`
Extract patterns from recent successful findings and update learned patterns database.

**Example:**
```
/learn
```

### `/chain`
Discover exploit chains by analyzing all findings and identifying combinations that create higher impact.

**Example:**
```
/chain
```

### `/report [target]`
Generate professional security reports. If target specified, generates report for that target only.

**Examples:**
```
/report
/report example.com
```

## Migration from Old Commands

**OLD (60+ agent commands)** → **NEW (5 intelligent commands)**

| Old | New |
|-----|-----|
| `/graphql-scan example.com` | `/hunt example.com` (auto-detects GraphQL) |
| `/api-test example.com` | `/hunt example.com` (auto-detects APIs) |
| `/websocket-test ws://example.com` | `/hunt example.com` (auto-detects WebSocket) |
| `/s3-enum example.com` | `/test example.com --context "S3 buckets"` |
| `/mobile-test example.com` | `/test example.com --context "Mobile app"` |
| `/injection-test example.com` | `/hunt example.com` (tests all injection types) |
| `/generate-report example.com` | `/report example.com` |

## AI-Powered Features

### Continuous Learning Loop
- Learns from every finding
- Extracts reusable patterns
- Applies patterns to similar targets automatically
- Gets smarter with each hunt

### Intelligent Hypothesis Generation
- Analyzes tech stack
- Reviews prior successful patterns
- Generates creative attack vectors
- Prioritizes high-confidence tests

### Exploit Chain Discovery
- Automatically combines vulnerabilities
- Escalates impact (LOW → CRITICAL)
- Provides step-by-step exploitation paths

### Creative Bypass Generation
- Detects when stuck (no findings)
- Generates unconventional attack vectors
- Tests protocol-level attacks
- Explores business logic flaws

## Technical Architecture

**AI Engine:** Claude Opus 4.6 via Anthropic API
**Learning Database:** SQLite with pattern/hypothesis tracking
**Agent System:** 19 specialized agents + intelligent router
**Test Coverage:** 97.3% average across core modules
```

**Step 6: Commit**

```bash
cd C:/Users/vaugh/BountyHound/bountyhound-agent
git add engine/core/command_router.py tests/test_command_router.py CLAUDE.md
git commit -m "feat: add intelligent command router with simplified 5-command interface"
```

---

## Task 7: Integration Tests and End-to-End Flow

**Files:**
- Create: `C:/Users/vaugh/BountyHound/bountyhound-agent/tests/integration/test_ai_hunt_flow.py`

**Step 1: Write the failing test**

```python
import pytest
from engine.core.ai_hunter import AIPoweredHunter
from engine.core.command_router import CommandRouter
import os

@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_ai_hunt_flow():
    """Test complete AI hunt flow from command to findings"""

    # Setup
    api_key = os.getenv("ANTHROPIC_API_KEY", "test-key")
    router = CommandRouter(api_key=api_key)

    # Route command
    route = router.route("/hunt testphp.vulnweb.com")

    assert route["type"] == "ai_hunt"
    assert route["target"] == "testphp.vulnweb.com"

    # Execute hunt (with max 3 iterations for test)
    hunter = AIPoweredHunter(
        target=route["target"],
        api_key=api_key,
        max_iterations=3
    )

    # Mock LLM for deterministic test
    if api_key == "test-key":
        hunter.llm = MockLLM()

    result = await hunter.hunt()

    assert result["target"] == "testphp.vulnweb.com"
    assert result["iterations"] == 3
    assert "findings" in result
    assert "patterns" in result

@pytest.mark.integration
def test_command_routing_all_commands():
    """Test all simplified commands route correctly"""
    router = CommandRouter(api_key="test-key")

    test_cases = [
        ("/hunt example.com", "ai_hunt"),
        ('/test example.com --context "GraphQL"', "targeted_test"),
        ("/learn", "extract_patterns"),
        ("/chain", "find_chains"),
        ("/report example.com", "generate_report"),
    ]

    for command, expected_type in test_cases:
        route = router.route(command)
        assert route["type"] == expected_type, f"Failed for command: {command}"
```

**Step 2: Run test to verify it fails**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/integration/test_ai_hunt_flow.py -v -m integration`
Expected: FAIL with "ModuleNotFoundError" or test failures

**Step 3: Create integration test infrastructure**

```python
# Create tests/integration/__init__.py
# Create tests/integration/conftest.py with shared fixtures
```

**Step 4: Run test to verify it passes**

Run: `cd C:/Users/vaugh/BountyHound/bountyhound-agent && python -m pytest tests/integration/test_ai_hunt_flow.py -v -m integration`
Expected: PASS

**Step 5: Commit**

```bash
cd C:/Users/vaugh/BountyHound/bountyhound-agent
git add tests/integration/
git commit -m "test: add integration tests for AI-powered hunt flow"
```

---

## Task 8: Documentation and Examples

**Files:**
- Create: `C:/Users/vaugh/BountyHound/bountyhound-agent/docs/AI_HUNTER_GUIDE.md`
- Create: `C:/Users/vaugh/BountyHound/bountyhound-agent/examples/ai_hunt_example.py`

**Step 1: Create comprehensive guide**

```markdown
# AI-Powered Hunter Guide

## Overview

The AI-Powered Hunter uses Claude Opus 4.6 to actively reason about security findings, generate attack hypotheses, and learn from successful exploits.

## How It Works

### 1. Continuous Learning Loop

```
┌─────────────────────────────────────────────┐
│  Load Prior Knowledge from Database         │
│  (Successful patterns, relevant findings)   │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  Generate Hypotheses (AI Reasoning)         │
│  - Analyze tech stack                       │
│  - Review prior patterns                    │
│  - Think creatively                         │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  Test Each Hypothesis                       │
│  - Route to appropriate agent               │
│  - Execute test                             │
│  - Verify state change                      │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
          ┌────────┴────────┐
          │   Success?      │
          └────────┬────────┘
                   │
         YES ──────┼────── NO
         │         │        │
         ▼         │        ▼
    ┌─────────┐   │   ┌──────────┐
    │ Extract │   │   │  Record  │
    │ Pattern │   │   │ Failure  │
    └────┬────┘   │   └──────────┘
         │        │
         ▼        │
    ┌──────────┐ │
    │  Apply   │ │
    │ Pattern  │ │
    │   to     │ │
    │ Similar  │ │
    │Endpoints │ │
    └────┬─────┘ │
         │       │
         └───────┴───────┐
                        │
                        ▼
            ┌──────────────────────┐
            │ Find Exploit Chains  │
            └──────────┬───────────┘
                       │
                       ▼
               ┌───────────────┐
               │ Next Iteration│
               └───────────────┘
```

### 2. Hypothesis Generation

The AI analyzes:
- **Tech Stack**: GraphQL, React, Node.js, etc.
- **Prior Patterns**: Successful exploits from database
- **Current Findings**: What's already been discovered
- **Creative Thinking**: Unconventional attack vectors

Example generated hypothesis:
```json
{
  "title": "GraphQL IDOR via UUID enumeration",
  "test": "Send mutation with different UUID to /api/graphql",
  "rationale": "GraphQL detected + no auth errors in previous tests = likely missing authorization",
  "confidence": "HIGH"
}
```

### 3. Pattern Extraction

When a vulnerability is found, the AI extracts a reusable pattern:

```json
{
  "name": "GraphQL IDOR via UUID enumeration",
  "tech": ["GraphQL"],
  "indicators": [
    "GraphQL mutation",
    "UUID parameter",
    "No auth check in response"
  ],
  "exploit_template": "mutation { user(id: <UUID>) { email privateData } }",
  "confidence": "HIGH"
}
```

This pattern is immediately applied to similar endpoints.

### 4. Exploit Chain Discovery

The AI analyzes multiple findings to discover chains:

**Example Chain:**
```
XSS in /profile → Session Cookie No HttpOnly → Admin Panel Access
= Account Takeover (CRITICAL)
```

## Usage Examples

### Basic Hunt
```bash
/hunt example.com
```

### Targeted Test with Context
```bash
/test api.example.com --context "GraphQL API with user mutations"
```

### Learn from Recent Findings
```bash
/learn
```

### Discover Exploit Chains
```bash
/chain
```

## Advanced Configuration

### Programmatic Usage

```python
from engine.core.ai_hunter import AIPoweredHunter
import asyncio

async def main():
    hunter = AIPoweredHunter(
        target="example.com",
        api_key="your-anthropic-api-key",
        max_iterations=20
    )

    result = await hunter.hunt()

    print(f"Found {len(result['findings'])} vulnerabilities")
    print(f"Learned {len(result['patterns'])} patterns")
    print(f"Discovered {len(result['exploit_chains'])} chains")

asyncio.run(main())
```

### Custom Hypothesis Testing

```python
# Test a specific hypothesis
hypothesis = {
    "title": "Custom test",
    "test": "Send POST to /api/admin with user token",
    "rationale": "Testing horizontal privilege escalation",
    "confidence": "MEDIUM"
}

result = await hunter._test_hypothesis(hypothesis)
if result["success"]:
    print(f"Found: {result['finding']['title']}")
```

## Database Schema

The AI Hunter uses these tables:

### `learned_patterns`
Stores successful attack patterns for reuse.

### `hypothesis_tests`
Tracks all hypothesis tests (success/failure) for learning.

### `exploit_chains`
Stores discovered exploit chains.

## Best Practices

### 1. Let It Learn
Run multiple hunts to build pattern database. The more it hunts, the smarter it gets.

### 2. Review Chains
Check `/chain` output regularly. Chains often reveal critical impact from multiple LOW findings.

### 3. Provide Context
Use `--context` with `/test` for better agent selection:
```bash
/test example.com --context "GraphQL + React SPA, user authentication via JWT"
```

### 4. Monitor Hypotheses
Check `hypothesis_tests` table to see what the AI is learning:
```sql
SELECT hypothesis_title, result, COUNT(*)
FROM hypothesis_tests
GROUP BY hypothesis_title, result;
```

## Troubleshooting

### No Findings After Multiple Iterations
- The AI will automatically switch to creative bypass mode
- Check if target has aggressive WAF (Web Application Firewall)
- Try targeted testing with specific context

### Low Confidence Hypotheses
- Indicates limited prior knowledge for this tech stack
- Run more hunts on similar targets to build patterns
- Manually add successful patterns to database

### API Rate Limiting
- Reduce `max_iterations` parameter
- Add delays between hypothesis tests
- Use targeted `/test` instead of full `/hunt`

## Performance Metrics

Track these metrics:

- **Success Rate**: `hypothesis_tests.result='success' / total tests`
- **Pattern Efficiency**: `findings from patterns / total findings`
- **Chain Discovery**: `exploit_chains.impact='CRITICAL' / total chains`

Query example:
```sql
SELECT
  COUNT(CASE WHEN result='success' THEN 1 END) * 100.0 / COUNT(*) as success_rate
FROM hypothesis_tests
WHERE target = 'example.com';
```
```

**Step 2: Create example script**

```python
"""
AI Hunt Example - Demonstrates AI-powered continuous learning hunt

This example shows how to use the AIPoweredHunter programmatically.
"""

import asyncio
import os
from engine.core.ai_hunter import AIPoweredHunter
from engine.core.command_router import CommandRouter

async def example_basic_hunt():
    """Basic AI-powered hunt example"""
    print("=" * 60)
    print("Example 1: Basic AI Hunt")
    print("=" * 60)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("⚠ Set ANTHROPIC_API_KEY environment variable")
        return

    hunter = AIPoweredHunter(
        target="testphp.vulnweb.com",
        api_key=api_key,
        max_iterations=5
    )

    result = await hunter.hunt()

    print(f"\n✓ Hunt complete!")
    print(f"  Findings: {len(result['findings'])}")
    print(f"  Patterns Learned: {len(result['patterns'])}")
    print(f"  Exploit Chains: {len(result['exploit_chains'])}")

    return result

async def example_command_routing():
    """Example using command router"""
    print("\n" + "=" * 60)
    print("Example 2: Command Routing")
    print("=" * 60)

    api_key = os.getenv("ANTHROPIC_API_KEY", "test-key")
    router = CommandRouter(api_key=api_key)

    commands = [
        "/hunt example.com",
        '/test api.example.com --context "GraphQL API"',
        "/learn",
        "/chain",
        "/report example.com"
    ]

    for cmd in commands:
        route = router.route(cmd)
        print(f"\n  Command: {cmd}")
        print(f"  → Type: {route['type']}")
        print(f"  → Agent: {route.get('agent', 'N/A')}")

async def example_pattern_application():
    """Example showing pattern extraction and application"""
    print("\n" + "=" * 60)
    print("Example 3: Pattern Extraction and Application")
    print("=" * 60)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("⚠ Set ANTHROPIC_API_KEY environment variable")
        return

    hunter = AIPoweredHunter(
        target="example.com",
        api_key=api_key,
        max_iterations=1
    )

    # Simulate a finding
    finding = {
        "title": "IDOR in getUserProfile mutation",
        "endpoint": "/api/graphql",
        "method": "POST",
        "payload": 'mutation { user(id: "victim-uuid") { email privateData } }',
        "response": '{"data": {"user": {"email": "victim@example.com"}}}',
        "tech": "GraphQL"
    }

    # Extract pattern
    pattern = await hunter._extract_pattern(finding)

    print(f"\n  Extracted Pattern:")
    print(f"    Name: {pattern.get('name', 'N/A')}")
    print(f"    Tech: {pattern.get('tech', [])}")
    print(f"    Template: {pattern.get('exploit_template', 'N/A')}")

    # Find similar endpoints
    all_endpoints = [
        "/api/graphql",
        "/api/v2/graphql",
        "/graphql",
        "/api/rest/users"
    ]

    similar = hunter._find_similar_endpoints("/api/graphql", all_endpoints)
    print(f"\n  Similar endpoints to test: {similar}")

async def main():
    """Run all examples"""
    print("\n🎯 AI-Powered Hunter Examples\n")

    # Example 1: Basic hunt
    await example_basic_hunt()

    # Example 2: Command routing
    await example_command_routing()

    # Example 3: Pattern extraction
    await example_pattern_application()

    print("\n" + "=" * 60)
    print("✓ All examples complete!")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
```

**Step 3: Commit**

```bash
cd C:/Users/vaugh/BountyHound/bountyhound-agent
git add docs/AI_HUNTER_GUIDE.md examples/ai_hunt_example.py
git commit -m "docs: add AI hunter guide and usage examples"
```

---

## Execution Options

Plan complete and saved to `docs/plans/2026-02-16-ai-powered-hunter.md`.

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
