# AI-Powered Hunter Guide

## Overview

The AI-Powered Hunter is a continuous learning bug bounty system that uses Claude Opus 4.6 to actively reason about security findings, generate creative attack hypotheses, extract reusable patterns, and learn from every test. Unlike traditional static automation, the AI Hunter dynamically adapts its strategy based on what it discovers, getting smarter with each hunt.

**Key Capabilities:**
- **Intelligent Hypothesis Generation**: Analyzes tech stack, prior patterns, and findings to generate specific, actionable attack vectors
- **Continuous Learning**: Extracts patterns from successful exploits and applies them automatically to similar endpoints
- **Exploit Chain Discovery**: Combines multiple LOW/MEDIUM findings into CRITICAL impact chains
- **Creative Bypass Generation**: When stuck, generates unconventional attack vectors and protocol-level exploits
- **Database-Driven Intelligence**: Learns from all previous hunts across all targets

---

## How It Works

### Continuous Learning Loop

The AI Hunter operates in iterations, continuously learning and adapting:

```
┌─────────────────────────────────────────────┐
│  Phase 0: Load Prior Knowledge              │
│  - Successful patterns (success_rate > 50%) │
│  - Relevant findings from similar targets   │
│  - Tech-specific exploit templates          │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  Phase 1: Generate Hypotheses (AI Reasoning)│
│  - Analyze current tech stack               │
│  - Review findings so far                   │
│  - Apply learned patterns                   │
│  - Think creatively about gaps              │
│  Output: 10 specific attack hypotheses      │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  Phase 2: Test Each Hypothesis              │
│  - Route to specialized agent               │
│  - Execute test with proper auth            │
│  - Verify actual state change               │
│  - Record success/failure in database       │
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
    └────┬────┘   │   │ (Learn)  │
         │        │   └──────────┘
         ▼        │
    ┌──────────┐ │
    │  Save    │ │
    │ Pattern  │ │
    │   to     │ │
    │ Database │ │
    └────┬─────┘ │
         │       │
         ▼       │
    ┌──────────┐│
    │  Apply   ││
    │ Pattern  ││
    │   to     ││
    │ Similar  ││
    │Endpoints ││
    └────┬─────┘│
         │      │
         └──────┴───────┐
                        │
                        ▼
            ┌──────────────────────┐
            │ Phase 3: Find Chains │
            │ Combine vulnerabilities│
            │ for higher impact     │
            └──────────┬───────────┘
                       │
                       ▼
               ┌───────────────┐
               │ Next Iteration│
               │ (max 20)      │
               └───────────────┘
```

**Adaptive Behavior:**
- If no findings in 3 iterations → Switches to creative bypass mode
- If pattern found → Immediately tests similar endpoints
- If multiple findings → Searches for exploit chains
- If stuck → Generates unconventional attack vectors

---

## Hypothesis Generation

The AI generates hypotheses by reasoning about:

1. **Tech Stack**: GraphQL, React, Node.js, cloud services detected
2. **Prior Patterns**: Attack templates that worked on similar targets
3. **Current Findings**: Builds on what's already discovered
4. **Gap Analysis**: Identifies what hasn't been tested yet
5. **Creative Thinking**: Considers unconventional vectors

### Example Generated Hypothesis

```json
{
  "title": "GraphQL IDOR via UUID enumeration",
  "test": "Send getUserProfile mutation with victim UUID to /api/graphql",
  "rationale": "GraphQL detected + no UNAUTHENTICATED errors in prior tests + UUID parameters = likely missing authorization checks at gateway",
  "confidence": "HIGH"
}
```

### Hypothesis Quality Indicators

- **HIGH confidence**: Pattern previously worked on similar tech stack
- **MEDIUM confidence**: Logical inference from current intelligence
- **LOW confidence**: Creative exploration, uncommon attack vector

The AI prioritizes HIGH confidence hypotheses first but still tests MEDIUM/LOW to discover novel vulnerabilities.

---

## Pattern Extraction

When a vulnerability is found, the AI extracts a **reusable pattern**:

### Input (Successful Finding)

```json
{
  "title": "IDOR in getUserProfile mutation",
  "endpoint": "/api/graphql",
  "method": "POST",
  "payload": "mutation { user(id: \"victim-uuid\") { email privateData } }",
  "response": "{\"data\": {\"user\": {\"email\": \"victim@example.com\"}}}",
  "tech": "GraphQL",
  "verified": true
}
```

### Output (Extracted Pattern)

```json
{
  "name": "GraphQL IDOR via UUID enumeration",
  "tech": ["GraphQL"],
  "indicators": [
    "GraphQL mutation accepts UUID parameter",
    "No UNAUTHENTICATED error in response",
    "Returns data for different user ID"
  ],
  "exploit_template": "mutation { <MUTATION_NAME>(id: <UUID>) { <SENSITIVE_FIELDS> } }",
  "confidence": "HIGH",
  "similar_endpoints": "Any GraphQL mutation with id/userId/accountId parameter",
  "variations": [
    "Try with integer IDs instead of UUIDs",
    "Test read queries in addition to mutations",
    "Check subscription operations"
  ]
}
```

This pattern is:
1. **Saved to database** with success_count = 1
2. **Applied immediately** to similar endpoints on current target
3. **Reused automatically** on future targets with GraphQL

---

## Exploit Chain Discovery

The AI analyzes all findings to discover **exploit chains** that escalate impact.

### Example Chain Discovery

**Individual Findings:**
```
1. XSS in /profile endpoint (MEDIUM severity)
2. Session cookie missing HttpOnly flag (LOW severity)
3. Admin panel accessible with valid session (INFO severity)
```

**Discovered Chain:**
```json
{
  "title": "XSS → Session Theft → Admin Account Takeover",
  "steps": [
    "1. Exploit stored XSS in /profile endpoint",
    "2. Inject JavaScript to steal session cookie (HttpOnly not set)",
    "3. Use stolen cookie to access /admin panel",
    "4. Achieve full account takeover with admin privileges"
  ],
  "findings_used": ["XSS-001", "COOKIE-002", "INFO-003"],
  "impact": "CRITICAL",
  "confidence": "HIGH",
  "rationale": "XSS + accessible cookie + privileged endpoint = full account takeover"
}
```

**Impact Escalation:**
- MEDIUM + LOW + INFO → **CRITICAL**
- Typical payout: $500 + $200 + $0 → **$5,000-$15,000**

Chains are verified manually but the AI provides the complete exploitation path.

---

## Database Schema

### learned_patterns

Stores successful attack patterns for cross-target learning.

```sql
CREATE TABLE learned_patterns (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,                    -- "GraphQL IDOR via UUID enumeration"
    tech JSON NOT NULL,                    -- ["GraphQL", "Apollo"]
    indicators JSON,                       -- Signals this pattern might work
    exploit_template TEXT,                 -- Generalized payload
    success_count INTEGER DEFAULT 0,       -- Times this pattern worked
    failure_count INTEGER DEFAULT 0,       -- Times this pattern failed
    success_rate REAL VIRTUAL,             -- Calculated: success/(success+failure)
    targets_succeeded JSON,                -- ["target1.com", "target2.com"]
    targets_failed JSON,                   -- ["target3.com"]
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

**Query Example:**
```python
# Get best patterns for GraphQL
patterns = db.execute("""
    SELECT name, success_rate, success_count, exploit_template
    FROM learned_patterns
    WHERE json_extract(tech, '$[0]') = 'GraphQL'
    AND success_rate >= 0.5
    ORDER BY success_rate DESC, success_count DESC
    LIMIT 10
""")
```

### hypothesis_tests

Tracks all hypothesis tests for learning what works and what doesn't.

```sql
CREATE TABLE hypothesis_tests (
    id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    hypothesis_title TEXT NOT NULL,
    hypothesis_test TEXT NOT NULL,
    rationale TEXT,
    confidence TEXT,                       -- HIGH/MEDIUM/LOW
    result TEXT,                           -- 'success', 'failure', 'error'
    finding_id INTEGER,                    -- Links to findings table if success
    tested_at TIMESTAMP
);
```

**Query Example:**
```python
# What hypotheses work best?
stats = db.execute("""
    SELECT
        hypothesis_title,
        COUNT(*) as total_tests,
        SUM(CASE WHEN result='success' THEN 1 ELSE 0 END) as successes,
        ROUND(AVG(CASE WHEN result='success' THEN 1.0 ELSE 0.0 END), 2) as success_rate
    FROM hypothesis_tests
    GROUP BY hypothesis_title
    HAVING total_tests >= 3
    ORDER BY success_rate DESC
    LIMIT 20
""")
```

### exploit_chains

Stores discovered chains for verification and reporting.

```sql
CREATE TABLE exploit_chains (
    id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    chain_title TEXT NOT NULL,
    steps JSON NOT NULL,                   -- Step-by-step exploitation path
    findings_used JSON NOT NULL,           -- Array of finding IDs
    impact TEXT,                           -- CRITICAL/HIGH/MEDIUM/LOW
    verified BOOLEAN DEFAULT 0,            -- Manual verification status
    created_at TIMESTAMP
);
```

---

## Usage Examples

### 1. Basic AI Hunt

Run a full autonomous hunt on a target:

```python
from engine.core.ai_hunter import AIPoweredHunter
import asyncio

async def basic_hunt():
    hunter = AIPoweredHunter(
        target="example.com",
        api_key="your-anthropic-api-key",
        max_iterations=20
    )

    result = await hunter.hunt()

    print(f"Findings: {len(result['findings'])}")
    print(f"Patterns Learned: {len(result['patterns'])}")
    print(f"Exploit Chains: {len(result['exploit_chains'])}")

asyncio.run(basic_hunt())
```

### 2. Command Router

Use simplified commands (requires command_router implementation):

```bash
# Full autonomous hunt
/hunt example.com

# Targeted test with context
/test api.example.com --context "GraphQL API with JWT authentication"

# Extract patterns from recent findings
/learn

# Discover exploit chains
/chain

# Generate report
/report example.com
```

### 3. Custom Hypothesis Testing

Test a specific hypothesis manually:

```python
async def test_custom_hypothesis():
    hunter = AIPoweredHunter(
        target="example.com",
        api_key="your-api-key"
    )

    hypothesis = {
        "title": "Horizontal privilege escalation in /api/user",
        "test": "Send GET /api/user/{victim_id} with attacker token",
        "rationale": "Testing if authorization checks exist",
        "confidence": "MEDIUM"
    }

    result = await hunter._test_hypothesis(hypothesis)

    if result["success"]:
        print(f"✓ Found: {result['finding']['title']}")
        pattern = await hunter._extract_pattern(result['finding'])
        print(f"Pattern: {pattern['name']}")
```

### 4. Pattern Application

Apply a learned pattern to new endpoints:

```python
async def apply_pattern():
    hunter = AIPoweredHunter(target="newsite.com", api_key="api-key")

    # Load pattern from database
    pattern = {
        "name": "GraphQL IDOR",
        "exploit_template": "mutation { user(id: <UUID>) { email } }"
    }

    # Find similar endpoints
    endpoints = ["/api/graphql", "/graphql", "/api/v2/graphql"]

    for endpoint in endpoints:
        # Apply pattern...
        payload = pattern["exploit_template"].replace("<UUID>", "victim-uuid")
        # Test with payload
```

### 5. Monitor Learning Progress

Track how the AI is learning:

```python
from engine.core.database import BountyHoundDB

db = BountyHoundDB()

# Success rate over time
with db._get_connection() as conn:
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            DATE(tested_at) as date,
            COUNT(*) as tests,
            SUM(CASE WHEN result='success' THEN 1 ELSE 0 END) as successes
        FROM hypothesis_tests
        WHERE target = 'example.com'
        GROUP BY DATE(tested_at)
        ORDER BY date DESC
        LIMIT 30
    """)

    for row in cursor.fetchall():
        success_rate = (row[2] / row[1]) * 100 if row[1] > 0 else 0
        print(f"{row[0]}: {row[1]} tests, {success_rate:.1f}% success")
```

---

## Advanced Configuration

### Custom Iteration Limits

```python
# Quick scan (5 iterations)
hunter = AIPoweredHunter(
    target="example.com",
    api_key="api-key",
    max_iterations=5
)

# Deep hunt (50 iterations)
hunter = AIPoweredHunter(
    target="example.com",
    api_key="api-key",
    max_iterations=50
)
```

### Provide Initial Context

```python
# Pre-load reconnaissance data
recon_data = {
    "tech_stack": ["GraphQL", "React", "Node.js", "PostgreSQL"],
    "endpoints": ["/api/graphql", "/api/rest/users", "/api/admin"],
    "auth_method": "JWT",
    "findings": []
}

# Pass to hunter
hunter._get_recon = AsyncMock(return_value=recon_data)
await hunter.hunt()
```

### Custom Pattern Database

```python
# Add manual pattern to database
pattern = {
    "name": "S3 Bucket Takeover via NoSuchBucket",
    "tech": ["AWS", "S3"],
    "indicators": ["NoSuchBucket error response"],
    "exploit_template": "Register bucket: <BUCKET_NAME>.s3.amazonaws.com",
    "confidence": "HIGH"
}

await hunter._save_pattern(pattern)
```

---

## Best Practices

### 1. Let It Learn Over Time

The AI Hunter gets smarter with each hunt. Run it on multiple targets:

```bash
# First hunt: Limited patterns
/hunt target1.com  # Finds 3 vulnerabilities

# Second hunt: Learns from target1
/hunt target2.com  # Finds 5 vulnerabilities (reuses patterns)

# Third hunt: Even smarter
/hunt target3.com  # Finds 8 vulnerabilities (more patterns)
```

**ROI improves over time:**
- Hunt 1-5: ~3-5 findings per target
- Hunt 6-20: ~5-8 findings per target (pattern reuse)
- Hunt 21+: ~8-12 findings per target (compound learning)

### 2. Review Chains Regularly

Exploit chains often reveal critical impact:

```bash
/chain

# Output:
# Chain 1: XSS → Cookie Theft → Account Takeover (CRITICAL)
# Chain 2: Info Disclosure → IDOR → Data Exfiltration (HIGH)
# Chain 3: CORS + CSRF → State-Changing Attack (HIGH)
```

**Many LOW/MEDIUM findings = HIGH/CRITICAL chain**

### 3. Provide Context for Targeted Tests

When testing specific functionality:

```bash
/test payments.example.com --context "Stripe payment processing, React SPA, JWT auth"
```

Better context = better agent selection = faster results.

### 4. Monitor Hypothesis Success Rates

Identify what's working:

```sql
SELECT
    hypothesis_title,
    COUNT(*) as attempts,
    SUM(CASE WHEN result='success' THEN 1 ELSE 0 END) as successes
FROM hypothesis_tests
GROUP BY hypothesis_title
ORDER BY successes DESC
LIMIT 20;
```

Focus effort on high-success hypothesis types.

### 5. Seed the Database

Bootstrap learning with known patterns:

```python
# Add patterns from HackerOne reports
manual_patterns = [
    {
        "name": "GraphQL field suggestions bypass introspection",
        "tech": ["GraphQL", "Apollo"],
        "exploit_template": "{ __typename invalidField }",
        "success_rate": 0.65
    },
    {
        "name": "CORS misconfiguration with credentials",
        "tech": ["CORS"],
        "exploit_template": "Origin: https://attacker.com",
        "success_rate": 0.40
    }
]

for pattern in manual_patterns:
    await hunter._save_pattern(pattern)
```

---

## Troubleshooting

### No Findings After Multiple Iterations

**Symptoms:**
- 10+ iterations with 0 findings
- Only LOW confidence hypotheses generated

**Diagnosis:**
```python
# Check what's being tested
cursor.execute("""
    SELECT hypothesis_title, COUNT(*)
    FROM hypothesis_tests
    WHERE target = 'example.com'
    GROUP BY hypothesis_title
    ORDER BY COUNT(*) DESC
""")
```

**Solutions:**
1. Provide more context: `/test example.com --context "specific tech details"`
2. Check target scope (might be blocking automated testing)
3. Add manual patterns for this tech stack
4. Review reconnaissance data (might be incomplete)

### Low Confidence Hypotheses

**Symptoms:**
- All hypotheses marked "LOW" confidence
- Generic test descriptions

**Cause:** Limited prior knowledge for this tech stack

**Solutions:**
1. Run more hunts on similar targets (build pattern database)
2. Manually add successful patterns from other sources
3. Provide detailed reconnaissance data
4. Check database: `SELECT COUNT(*) FROM learned_patterns WHERE tech LIKE '%<tech>%'`

### API Rate Limiting

**Symptoms:**
- Anthropic API errors
- Slow hypothesis generation

**Solutions:**
```python
# Reduce iterations
hunter = AIPoweredHunter(target="example.com", max_iterations=10)

# Add delays between tests
import time
time.sleep(2)  # Between hypothesis tests

# Use targeted testing instead
/test example.com --context "specific area"
```

### False Positive Findings

**Symptoms:**
- Findings marked as success but can't reproduce
- HTTP 200 but no actual impact

**Critical:** Always verify state change (see MEMORY.md false-positive-prevention)

**Solution:**
```python
# Before marking as success:
# 1. Read state before
# 2. Attempt mutation
# 3. Read state after
# 4. Compare - MUST show actual change
```

---

## Performance Metrics

Track these metrics to measure AI learning effectiveness:

### 1. Hypothesis Success Rate

```sql
SELECT
    COUNT(CASE WHEN result='success' THEN 1 END) * 100.0 / COUNT(*) as success_rate,
    target
FROM hypothesis_tests
GROUP BY target
ORDER BY success_rate DESC;
```

**Benchmarks:**
- New target (no prior patterns): 15-25% success rate
- Similar tech (some patterns): 30-45% success rate
- Well-learned tech: 50-70% success rate

### 2. Pattern Reuse Efficiency

```sql
SELECT
    COUNT(CASE WHEN finding_source='pattern_reuse' THEN 1 END) * 100.0 / COUNT(*) as pattern_efficiency
FROM findings
WHERE discovered_date >= date('now', '-30 days');
```

**Benchmarks:**
- Early hunts: <10% from pattern reuse
- After 20+ hunts: 30-50% from pattern reuse
- Mature database: 50-70% from pattern reuse

### 3. Chain Discovery Rate

```sql
SELECT
    COUNT(DISTINCT ec.id) as chains,
    COUNT(DISTINCT f.id) as findings,
    COUNT(DISTINCT ec.id) * 100.0 / COUNT(DISTINCT f.id) as chain_rate
FROM exploit_chains ec
JOIN findings f ON f.target_id = ec.target;
```

**Benchmarks:**
- 1 chain per 10-15 findings = Good
- 1 chain per 5-10 findings = Excellent
- 1 chain per <5 findings = Outstanding

### 4. Time to First Finding

Track how quickly the AI finds vulnerabilities:

```sql
SELECT
    target,
    MIN(tested_at) as first_test,
    MIN(CASE WHEN result='success' THEN tested_at END) as first_finding,
    (julianday(MIN(CASE WHEN result='success' THEN tested_at END)) -
     julianday(MIN(tested_at))) * 24 * 60 as minutes_to_finding
FROM hypothesis_tests
GROUP BY target
ORDER BY minutes_to_finding ASC;
```

**Benchmarks:**
- New tech stack: 45-90 minutes to first finding
- Known tech stack: 15-30 minutes to first finding
- Well-learned patterns: 5-15 minutes to first finding

---

## Integration with Existing Agents

The AI Hunter routes hypotheses to specialized agents:

### Agent Routing

```python
async def _test_hypothesis(self, hypothesis: Dict) -> Dict:
    """Route hypothesis to appropriate agent"""

    test = hypothesis["test"].lower()

    # GraphQL testing
    if "graphql" in test:
        from engine.agents.graphql_tester import GraphQLTester
        return await GraphQLTester().test(hypothesis)

    # API testing
    elif "api" in test or "rest" in test:
        from engine.agents.api_tester import APITester
        return await APITester().test(hypothesis)

    # Cloud testing
    elif "s3" in test or "bucket" in test:
        from engine.agents.s3_tester import S3Tester
        return await S3Tester().test(hypothesis)

    # WebSocket testing
    elif "websocket" in test or "ws://" in test:
        from engine.agents.websocket_tester import WebSocketTester
        return await WebSocketTester().test(hypothesis)

    # Default: Discovery engine
    else:
        from engine.agents.discovery_engine import DiscoveryEngine
        return await DiscoveryEngine().test(hypothesis)
```

Each agent returns standardized result:

```python
{
    "success": True/False,
    "finding": {
        "title": "Vulnerability title",
        "severity": "CRITICAL/HIGH/MEDIUM/LOW",
        "endpoint": "/api/vulnerable",
        "poc": "Proof of concept",
        "verified": True/False
    }
}
```

---

## Changelog

**v1.0.0** (2026-02-16)
- Initial AI-powered hunter implementation
- Claude Opus 4.6 integration
- Hypothesis generation and testing
- Pattern extraction and learning
- Exploit chain discovery
- Database integration (learned_patterns, hypothesis_tests, exploit_chains)
- Continuous learning loop (max 20 iterations)
- Creative bypass generation when stuck

---

## Next Steps

1. **Run your first hunt**: `/hunt testphp.vulnweb.com`
2. **Review patterns learned**: Query `learned_patterns` table
3. **Check hypothesis success**: Query `hypothesis_tests` table
4. **Look for chains**: `/chain` command
5. **Run 5+ hunts**: Build up pattern database
6. **Monitor metrics**: Track success rates over time

The AI Hunter learns from every test. The more you use it, the smarter it gets.
