# BountyHound Antigravity Implementation Design

**Date**: 2026-02-16
**Status**: Approved
**Version**: 1.0

## Executive Summary

This design document describes the implementation of BountyHound as a full autonomous bug bounty hunting system running on Google Antigravity. The system executes continuous 24/7 hunting cycles with database-driven target selection, LLM-powered vulnerability discovery, parallel testing, and mandatory state verification to prevent false positives.

**Expected Performance:**
- 3-6 targets tested per day
- 2-5 verified findings per day
- $500-$2,000 daily bounties (estimated)
- Zero false positives (state verification protocol)

---

## 1. High-Level Architecture

### System Overview

The BountyHound Antigravity orchestrator is a continuous autonomous hunting system that runs 24/7, selecting high-ROI targets from historical database and executing complete hunting cycles.

### Core Components

**1. Continuous Orchestrator** (main loop)
- Runs in 10-minute cycles (configurable)
- Database-driven target selection (ROI-based)
- Sequential cycle execution with async parallelization within phases

**2. Hybrid Agent Integration**
- CLI wrapper for recon tools (subfinder, httpx, nmap, nuclei)
- Direct Python imports for testing agents (browser, API)
- Shared database for coordination

**3. Four-Phase Pipeline**
- Phase 1: Recon (CLI, 5 min, blocking)
- Phase 1.5: Discovery (Gemini 3 Pro, 2 min, async)
- Phase 2: Testing (async task queue, 15 min, parallel)
- Phase 3: Validation (state verification, 5 min, sequential)
- Phase 4: Reporting (HackerOne format, 3 min, sequential)

### Key Design Principles

- **Portable**: Works in Antigravity or standalone
- **Database-first**: All decisions driven by historical data
- **False-positive prevention**: State verification mandatory
- **Async where it matters**: I/O-bound operations parallelized
- **Fault-tolerant**: Comprehensive error handling for 24/7 operation

---

## 2. Architecture Decisions

### Decision 1: Hybrid Agent Integration

**Chosen Approach**: CLI for recon/scanning, Python imports for testing agents

**Rationale**:
- CLI tools (subfinder, httpx, nmap) are well-tested and handle errors gracefully
- Direct Python imports give full control over browser/API testing in Antigravity
- Best of both worlds: uses CLI efficiency, maintains testing flexibility

**Implementation**:
```python
# CLI for recon
subprocess.run(['bountyhound', 'recon', domain, '--output', 'json'])

# Direct import for testing
from engine.agents.browser_hunter import test_hypothesis
```

### Decision 2: Lightweight Parallelization

**Chosen Approach**: Asyncio within phases, simple main loop

**Rationale**:
- Works standalone (no Antigravity dependency)
- Simple to understand and debug
- Can be enhanced later with Antigravity Agent Manager
- Sufficient for current needs (6 concurrent tests)

**Implementation**:
```python
# Main loop stays sequential
for target in targets:
    findings = await run_hunt_cycle(target)

# Async within phases
async def _run_parallel_testing(hypotheses):
    results = await asyncio.gather(*[test(h) for h in hypotheses])
```

### Decision 3: Gemini 3 Pro via Antigravity

**Chosen Approach**: Use Antigravity's built-in Gemini 3 Pro integration

**Rationale**:
- Free during preview period
- Optimized for Antigravity environment
- No API key management needed
- Sufficient quality for hypothesis generation

**Implementation**:
```python
response = await antigravity.llm.generate(
    model="gemini-3-pro",
    prompt=context,
    temperature=0.7
)
```

### Decision 4: Async Task Queue Pattern

**Chosen Approach**: Discovery Engine creates testing jobs, orchestrator processes in parallel batches

**Rationale**:
- Clean separation of concerns
- Scalable (easy to adjust concurrency)
- Efficient resource utilization
- Natural fit for hypothesis-driven testing

**Implementation**:
```python
# Discovery creates jobs
hypotheses = await _run_discovery(recon_data)

# Orchestrator processes in parallel
browser_jobs = [h for h in hypotheses if h['test_type'] == 'browser']
api_jobs = [h for h in hypotheses if h['test_type'] == 'api']

results = await asyncio.gather(
    _run_browser_tests(browser_jobs),
    _run_api_tests(api_jobs)
)
```

### Decision 5: State Verification with Curl Fallback

**Chosen Approach**: READ→MUTATE→READ→COMPARE for stateful vulns, curl for injections

**Rationale**:
- Prevents false positives (Airbnb incident lesson)
- Matches documented protocol in MEMORY.md
- Proves actual impact, not just HTTP 200
- Different strategies for different vuln types

**Implementation**:
```python
# State verification
state_before = await read_state(endpoint)
exploit_response = await execute_exploit(finding)
state_after = await read_state(endpoint)
changed = compare_states(state_before, state_after)

# Curl fallback for injections
curl_result = subprocess.run(curl_cmd, capture_output=True)
verified = success_pattern in curl_result.stdout
```

---

## 3. Phase 1: Reconnaissance Implementation

### Overview

Uses BountyHound CLI to execute subdomain enumeration, web probing, port scanning, and technology fingerprinting. Results stored in SQLite database.

### Implementation

```python
async def _run_recon(self, domain: str) -> Dict:
    """Phase 1: CLI-based reconnaissance"""
    recon_data = {
        'domain': domain,
        'subdomains': [],
        'endpoints': [],
        'technologies': [],
        'open_ports': []
    }

    # Run CLI commands (updates database automatically)
    subprocess.run(['bountyhound', 'recon', domain, '--output', 'json'])

    # Read results from database
    with self.db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT subdomain, status_code, tech_stack, ports
            FROM recon_results
            WHERE domain = ? AND run_id = (
                SELECT MAX(id) FROM tool_runs WHERE domain = ?
            )
        """, (domain, domain))

        for row in cursor.fetchall():
            recon_data['subdomains'].append(row[0])
            recon_data['technologies'].extend(row[2].split(','))
            recon_data['open_ports'].extend(row[3].split(','))

    return recon_data
```

### Tools Used

- **subfinder**: Subdomain enumeration (passive sources)
- **httpx**: Web probing (status codes, technologies)
- **nmap**: Port scanning (top 1000 ports)
- **nuclei**: CVE scanning (background, low priority)

### Output Format

```python
{
    'domain': 'example.com',
    'subdomains': ['www.example.com', 'api.example.com', ...],
    'technologies': ['React', 'GraphQL', 'AWS', ...],
    'endpoints': ['/api/graphql', '/api/v1/users', ...],
    'open_ports': ['80', '443', '8080', ...]
}
```

### Duration

Approximately 5 minutes (blocking phase)

---

## 4. Phase 1.5: Discovery Engine (Gemini 3 Pro)

### Overview

LLM-powered hypothesis generation that analyzes recon data and generates 5-10 testable vulnerability hypotheses. Uses historical context to avoid duplicate testing.

### Implementation

```python
async def _run_discovery(self, domain: str, recon_data: Dict) -> List[Dict]:
    """Phase 1.5: LLM-powered hypothesis generation"""

    # Build context for Gemini
    context = f"""
    Target: {domain}
    Subdomains: {len(recon_data['subdomains'])} found
    Technologies: {', '.join(set(recon_data['technologies']))}
    Open ports: {', '.join(set(recon_data['open_ports']))}

    Historical context:
    {self._get_target_history(domain)}

    Generate 5-10 testable hypotheses for novel vulnerabilities.
    Focus on: GraphQL misconfigurations, IDOR, auth bypass, BOLA.
    Format each as a testing card with: endpoint, method, payload, expected_outcome.
    """

    # Call Gemini 3 Pro via Antigravity API
    response = await antigravity.llm.generate(
        model="gemini-3-pro",
        prompt=context,
        temperature=0.7  # Creative but focused
    )

    # Parse hypothesis cards
    hypotheses = self._parse_hypothesis_cards(response)

    # Prioritize by confidence + potential severity
    hypotheses.sort(key=lambda h: h['confidence'] * h['severity'], reverse=True)

    return hypotheses[:10]  # Top 10 only
```

### Hypothesis Card Structure

```python
{
    'id': 'H001',
    'endpoint': '/api/graphql',
    'vuln_type': 'BOLA',
    'method': 'POST',
    'payload': {
        'query': 'mutation { deleteUser(id: "USER_B_ID") { success } }',
        'variables': {},
        'headers': {'Authorization': 'USER_A_TOKEN'}
    },
    'test_type': 'api',  # or 'browser'
    'confidence': 0.8,
    'severity': 'high',
    'reasoning': 'GraphQL endpoint lacks authorization checks on delete mutation',
    'expected_outcome': 'User A can delete User B\'s account',
    'state_endpoint': '/api/users/USER_B_ID',  # For validation
    'expected_change': {'status': 'deleted'}
}
```

### Historical Context Integration

```python
def _get_target_history(self, domain: str) -> str:
    """Get relevant historical context"""
    with self.db._get_connection() as conn:
        cursor = conn.cursor()

        # Get previously found vuln types
        cursor.execute("""
            SELECT vuln_type, COUNT(*) as count
            FROM findings
            WHERE domain = ?
            GROUP BY vuln_type
        """, (domain,))

        found_vulns = [f"{row[0]} ({row[1]}x)" for row in cursor.fetchall()]

        # Get recent test areas
        cursor.execute("""
            SELECT DISTINCT endpoint
            FROM findings
            WHERE domain = ? AND created_at > date('now', '-30 days')
        """, (domain,))

        tested_endpoints = [row[0] for row in cursor.fetchall()]

    return f"""
    Previously found vulnerabilities: {', '.join(found_vulns) or 'None'}
    Recently tested endpoints: {', '.join(tested_endpoints) or 'None'}

    Focus on untested areas and novel attack vectors.
    """
```

### Duration

Approximately 2 minutes (async, non-blocking)

---

## 5. Phase 2: Parallel Testing (Async Task Queue)

### Overview

Processes hypothesis cards in parallel using async task queue pattern. Separates browser tests (resource-intensive) from API tests (lightweight) with different concurrency limits.

### Implementation

```python
async def _run_parallel_testing(self, domain: str, hypotheses: List[Dict]) -> Dict:
    """Phase 2: Async parallel testing"""

    # Separate hypotheses by test type
    browser_jobs = [h for h in hypotheses if h['test_type'] == 'browser']
    api_jobs = [h for h in hypotheses if h['test_type'] == 'api']

    # Run both tracks in parallel
    browser_task = self._run_browser_tests(domain, browser_jobs)
    api_task = self._run_api_tests(domain, api_jobs)

    # Gather results
    browser_results, api_results = await asyncio.gather(
        browser_task,
        api_task,
        return_exceptions=True  # Don't let one failure kill the other
    )

    return {
        'potential_findings': browser_results + api_results,
        'errors': [r for r in [browser_results, api_results] if isinstance(r, Exception)]
    }

async def _run_browser_tests(self, domain: str, jobs: List[Dict]) -> List[Dict]:
    """Run browser jobs with concurrency limit"""
    semaphore = asyncio.Semaphore(2)  # Max 2 browsers at once

    async def test_with_limit(job):
        async with semaphore:
            return await self._test_browser_hypothesis(domain, job)

    results = await asyncio.gather(*[test_with_limit(j) for j in jobs])
    return [r for r in results if r is not None]

async def _run_api_tests(self, domain: str, jobs: List[Dict]) -> List[Dict]:
    """Run API jobs with concurrency limit"""
    semaphore = asyncio.Semaphore(4)  # Max 4 API tests at once

    async def test_with_limit(job):
        async with semaphore:
            return await self._test_api_hypothesis(domain, job)

    results = await asyncio.gather(*[test_with_limit(j) for j in jobs])
    return [r for r in results if r is not None]

async def _test_browser_hypothesis(self, domain: str, hypothesis: Dict) -> Dict:
    """Test single hypothesis with Playwright"""
    # Import testing agent
    from engine.agents.browser_hunter import test_hypothesis

    finding = await test_hypothesis(
        domain=domain,
        endpoint=hypothesis['endpoint'],
        vuln_type=hypothesis['vuln_type'],
        payload=hypothesis['payload']
    )

    return finding if finding['vulnerable'] else None

async def _test_api_hypothesis(self, domain: str, hypothesis: Dict) -> Dict:
    """Test single hypothesis with HTTP client"""
    from engine.agents.api_hunter import test_hypothesis

    finding = await test_hypothesis(
        domain=domain,
        endpoint=hypothesis['endpoint'],
        vuln_type=hypothesis['vuln_type'],
        payload=hypothesis['payload']
    )

    return finding if finding['vulnerable'] else None
```

### Concurrency Control

| Test Type | Max Concurrent | Rationale |
|-----------|----------------|-----------|
| Browser | 2 | Resource-intensive (memory, CPU) |
| API | 4 | Lightweight (network I/O only) |
| **Total** | **6** | Prevents overwhelming target/local resources |

### Duration

Approximately 15 minutes (parallel execution)

---

## 6. Phase 3: Validation (State Verification)

### Overview

Critical phase that eliminates false positives by verifying actual exploitation. Uses state verification for stateful vulnerabilities (IDOR, BOLA, auth bypass) and curl validation for injection vulnerabilities.

### Implementation

```python
async def _validate_findings(self, domain: str, test_results: Dict) -> Dict:
    """Phase 3: State verification + curl fallback"""

    verified = []
    false_positives = []

    for finding in test_results['potential_findings']:
        # Choose validation strategy based on vuln type
        if finding['vuln_type'] in ['IDOR', 'BOLA', 'AUTH_BYPASS']:
            result = await self._validate_with_state_verification(finding)
        elif finding['vuln_type'] in ['XSS', 'SQLI', 'SSRF']:
            result = await self._validate_with_curl(finding)
        else:
            result = await self._validate_hybrid(finding)

        if result['verified']:
            verified.append({**finding, 'validation': result})
        else:
            false_positives.append({**finding, 'reason': result['reason']})

    return {'verified': verified, 'false_positives': false_positives}

async def _validate_with_state_verification(self, finding: Dict) -> Dict:
    """State verification: READ → MUTATE → READ → COMPARE"""

    # 1. Read initial state
    state_before = await self._read_state(finding['state_endpoint'])

    # 2. Attempt exploit
    exploit_response = await self._execute_exploit(finding)

    # 3. Read state again
    state_after = await self._read_state(finding['state_endpoint'])

    # 4. Compare states
    changed = self._compare_states(state_before, state_after, finding['expected_change'])

    return {
        'verified': changed,
        'reason': 'State changed as expected' if changed else 'No state change detected',
        'evidence': {
            'before': state_before,
            'after': state_after,
            'diff': self._state_diff(state_before, state_after)
        }
    }

async def _validate_with_curl(self, finding: Dict) -> Dict:
    """Curl validation for injection vulns"""
    curl_cmd = finding.get('curl_command')

    result = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True)

    # Check for success indicators
    verified = finding['success_pattern'] in result.stdout

    return {
        'verified': verified,
        'reason': 'Curl reproduction successful' if verified else 'Curl failed to reproduce',
        'evidence': {'curl_output': result.stdout[:1000]}
    }

def _compare_states(self, before: Dict, after: Dict, expected_change: Dict) -> bool:
    """Compare states to verify exploit impact"""

    for key, expected_value in expected_change.items():
        before_value = before.get(key)
        after_value = after.get(key)

        # Verify change occurred as expected
        if after_value != expected_value:
            return False

        # Verify state actually changed
        if before_value == after_value:
            return False

    return True
```

### State Verification Protocol

Based on MEMORY.md false positive prevention guidelines:

1. **READ** state before exploit attempt
2. **ATTEMPT** mutation/exploit
3. **READ** state after exploit
4. **COMPARE** states and verify expected change

This prevents "HTTP 200 + \_\_typename ≠ exploitation" false positives.

### Validation Strategies by Vulnerability Type

| Vulnerability Type | Strategy | Example |
|-------------------|----------|---------|
| IDOR | State verification | Read User B → Delete as User A → Verify User B deleted |
| BOLA | State verification | Read resource → Access as different user → Verify access succeeded |
| Auth Bypass | State verification | Read protected data → Access without auth → Verify data returned |
| XSS | Curl validation | Inject payload → Curl endpoint → Verify payload in response |
| SQLi | Curl validation | Inject payload → Curl endpoint → Verify error/data leakage |
| SSRF | Curl validation | Inject URL → Curl endpoint → Verify callback received |

### Duration

Approximately 5 minutes (sequential execution)

---

## 7. Phase 4: Reporting

### Overview

Generates professional HackerOne/Bugcrowd reports using Gemini 3 Pro. Reports include validation evidence, reproduction steps, impact assessment, and remediation recommendations.

### Implementation

```python
async def _generate_reports(self, domain: str, findings: List[Dict]) -> List[str]:
    """Phase 4: Generate HackerOne/Bugcrowd reports"""

    reports = []

    for finding in findings:
        # Generate report using Gemini 3 Pro
        report = await self._generate_single_report(domain, finding)

        # Save to filesystem
        report_path = self._save_report(domain, finding, report)
        reports.append(report_path)

        # Record in database
        self.db.record_finding(
            domain=domain,
            vuln_type=finding['vuln_type'],
            severity=finding['severity'],
            report_path=report_path,
            status='pending_submission'
        )

    return reports

async def _generate_single_report(self, domain: str, finding: Dict) -> str:
    """Generate professional report with Gemini"""

    prompt = f"""
    Generate a professional bug bounty report for HackerOne/Bugcrowd.

    Target: {domain}
    Vulnerability: {finding['vuln_type']}
    Severity: {finding['severity']}

    Evidence:
    {json.dumps(finding['validation']['evidence'], indent=2)}

    Format as:
    ## Summary
    [1-2 sentences describing the vulnerability and impact]

    ## Steps to Reproduce
    [Numbered steps with exact curl commands or browser actions]

    ## Impact
    [Specific impact to the business, not generic descriptions]

    ## Proof of Concept
    [Evidence from validation showing actual exploitation]

    ## Remediation
    [Specific fix recommendation with code examples if applicable]

    Use professional tone. Be concise. Focus on impact and reproducibility.
    """

    report = await antigravity.llm.generate(
        model="gemini-3-pro",
        prompt=prompt,
        temperature=0.3  # Precise, professional tone
    )

    return report

def _save_report(self, domain: str, finding: Dict, report: str) -> str:
    """Save to standardized location"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"VERIFIED-{finding['vuln_type']}-{timestamp}.md"

    path = Path(f"C:/Users/vaugh/BountyHound/findings/{domain}/{filename}")
    path.parent.mkdir(parents=True, exist_ok=True)

    # Add metadata header
    full_report = f"""---
domain: {domain}
vuln_type: {finding['vuln_type']}
severity: {finding['severity']}
discovered: {timestamp}
verified: true
status: pending_submission
---

{report}
"""

    path.write_text(full_report, encoding='utf-8')
    return str(path)
```

### Report Structure

```
C:/Users/vaugh/BountyHound/findings/{domain}/VERIFIED-{TYPE}-{TIMESTAMP}.md
```

**Example**:
```
C:/Users/vaugh/BountyHound/findings/stake.com/VERIFIED-IDOR-20260216_143022.md
```

**Content Format**:
```markdown
---
domain: stake.com
vuln_type: IDOR
severity: high
discovered: 20260216_143022
verified: true
status: pending_submission
---

## Summary
An Insecure Direct Object Reference (IDOR) vulnerability allows any authenticated user to delete other users' accounts by manipulating the user ID parameter in the delete mutation.

## Steps to Reproduce
1. Authenticate as User A (ID: user_123)
2. Obtain User B's ID (ID: user_456)
3. Execute the following request:
   ```bash
   curl 'https://stake.com/api/graphql' \
     -H 'Authorization: Bearer USER_A_TOKEN' \
     -d '{"query":"mutation { deleteUser(id: \"user_456\") { success } }"}'
   ```
4. Verify User B's account is deleted

## Impact
Any authenticated user can delete any other user's account, leading to:
- Account takeover through deletion and re-registration
- Data loss for affected users
- Denial of service
- Violation of user privacy and data integrity

## Proof of Concept
[State verification evidence showing User B deleted by User A]

Before exploit:
```json
{"id": "user_456", "email": "userb@example.com", "status": "active"}
```

After exploit:
```json
{"id": "user_456", "status": "deleted", "deletedBy": "user_123"}
```

## Remediation
Implement proper authorization checks before deleting users:

```javascript
async function deleteUser(userId, requestingUserId) {
  // Check if requesting user has permission
  if (userId !== requestingUserId && !isAdmin(requestingUserId)) {
    throw new Error('Unauthorized');
  }

  // Proceed with deletion
  await db.users.delete(userId);
}
```
```

### Duration

Approximately 3 minutes (sequential execution)

---

## 8. Data Flow & State Management

### End-to-End Data Flow

```
Database Query (ROI-based)
    ↓
Select 3 targets: [stake.com, giveaways.com.au, rainbet.com]
    ↓
For each target:
    ↓
┌─────────────────────────────────────────┐
│ Phase 1: Recon (CLI)                    │
│ ─────────────────────────────           │
│ bountyhound recon → SQLite DB           │
│ Output: recon_data Dict                 │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ Phase 1.5: Discovery (Gemini)           │
│ ──────────────────────────────          │
│ Input: recon_data                       │
│ LLM analysis → hypothesis cards         │
│ Output: List[hypothesis_card]           │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ Phase 2: Testing (Async Queue)          │
│ ───────────────────────────────         │
│ Input: hypothesis_cards                 │
│ Browser jobs (2 parallel)               │
│ API jobs (4 parallel)                   │
│ Output: potential_findings              │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ Phase 3: Validation (Sequential)        │
│ ─────────────────────────────────       │
│ For each finding:                       │
│   state_before → exploit → state_after  │
│ Output: verified_findings               │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ Phase 4: Reporting (if verified > 0)    │
│ ──────────────────────────────────      │
│ Generate reports with Gemini            │
│ Save to findings/{target}/              │
│ Record in database                      │
└─────────────────────────────────────────┘
    ↓
Update database (tool_runs, findings)
    ↓
Wait 10 minutes → Next cycle
```

### State Persistence

| Data Type | Storage | Retention |
|-----------|---------|-----------|
| Recon results | SQLite database | Permanent |
| Hypothesis cards | In-memory | Single cycle |
| Potential findings | In-memory | Until validated |
| Verified findings | Filesystem + Database | Permanent |
| Reports | Filesystem | Permanent |
| Tool runs | Database | Permanent |
| Logs | Filesystem (rotated) | 7 days |

### Memory Management

| Phase | Memory Usage | Strategy |
|-------|--------------|----------|
| Recon | < 1 MB | Keep in memory for Discovery |
| Discovery | < 100 KB | Small JSON objects |
| Testing | < 10 MB | Stream results as they complete |
| Validation | < 5 MB | Process one finding at a time |
| Reporting | < 2 MB per report | Write immediately to disk |

### Database Schema

**Relevant Tables**:

```sql
-- Target tracking
CREATE TABLE targets (
    domain TEXT PRIMARY KEY,
    last_tested DATETIME,
    total_findings INTEGER DEFAULT 0,
    total_payouts REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tool execution tracking
CREATE TABLE tool_runs (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    tool_name TEXT,
    findings_count INTEGER,
    duration_seconds INTEGER,
    status TEXT,  -- 'complete', 'partial', 'failed'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Finding tracking
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    vuln_type TEXT,
    severity TEXT,
    report_path TEXT,
    status TEXT,  -- 'pending_submission', 'submitted', 'accepted', 'rejected'
    payout REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Recon results
CREATE TABLE recon_results (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    run_id INTEGER,
    subdomain TEXT,
    status_code INTEGER,
    tech_stack TEXT,
    ports TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 9. Error Handling & Recovery

### Multi-Level Error Handling

**Level 1: Cycle-Level**
```python
while True:
    try:
        await self._run_single_cycle()
    except KeyboardInterrupt:
        logger.info("Graceful shutdown")
        await self._cleanup()
        break
    except DatabaseError:
        logger.error("Database error")
        await asyncio.sleep(60)  # Wait 1 min, retry
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        await asyncio.sleep(300)  # Wait 5 min, continue
```

**Level 2: Phase-Level**
```python
async def run_hunt_cycle(self, domain: str):
    findings = {'domain': domain, 'phase_results': {}}

    try:
        findings['recon'] = await self._safe_phase(self._run_recon, domain)
        findings['discovery'] = await self._safe_phase(self._run_discovery, domain)
        # ... etc
    except Exception as e:
        findings['error'] = str(e)
        findings['partial'] = True
    finally:
        # Always record what we got
        self.db.record_tool_run(domain, 'hunt_cycle', findings)
```

**Level 3: Task-Level**
```python
async def _safe_phase(self, phase_func, *args, timeout=600):
    try:
        return await asyncio.wait_for(phase_func(*args), timeout=timeout)
    except asyncio.TimeoutError:
        return {'error': 'timeout'}
    except Exception as e:
        return {'error': str(e)}
```

### Recovery Strategies

| Failure Type | Recovery Strategy | Retry Logic |
|--------------|-------------------|-------------|
| Phase timeout | Continue to next phase with empty results | None |
| Target failure | Skip target, continue to next in cycle | None |
| Cycle failure | Wait 5 minutes, start fresh cycle | Infinite |
| Database error | Wait 1 minute, retry | 3x exponential backoff |
| Network error | Exponential backoff (1s, 2s, 4s, 8s max) | 4x |
| LLM API error | Skip discovery, use pattern matching fallback | 1x |

### Graceful Shutdown

**Triggered by**: Ctrl+C (SIGINT)

**Shutdown Sequence**:
1. Set shutdown flag
2. Finish current phase (don't interrupt mid-test)
3. Save partial results to database
4. Close all browser instances
5. Flush logs
6. Exit with status code 0

```python
async def _cleanup(self):
    """Graceful shutdown"""
    logger.info("Cleaning up...")

    # Close browsers
    if hasattr(self, 'browser'):
        await self.browser.close()

    # Flush database
    self.db.close()

    # Final log
    logger.info(f"Orchestrator ran for {self.cycle_count} cycles")
    logger.info("Shutdown complete")
```

### Monitoring & Alerting

**Cycle Summary Logging**:
```python
logger.info(f"""
Cycle {cycle_num} complete:
  Targets: {targets_tested}
  Verified findings: {verified_count}
  False positives: {fp_count}
  Errors: {error_count}
  Duration: {duration}s
""")
```

**Alerts** (future enhancement):
- High-severity finding discovered
- Multiple consecutive cycle failures
- Database connection lost
- Unusual error rate (> 50%)

---

## 10. Implementation Roadmap

### Phase 1: Core Infrastructure (Week 1)

**Tasks**:
1. Enhance orchestrator with async support
2. Implement CLI integration for recon
3. Set up Gemini 3 Pro integration
4. Create hypothesis card parser
5. Add basic error handling

**Deliverables**:
- Working recon phase
- Discovery engine generating hypotheses
- Basic logging and monitoring

### Phase 2: Testing Implementation (Week 2)

**Tasks**:
1. Implement async task queue
2. Import browser_hunter agent
3. Import api_hunter agent
4. Add concurrency controls
5. Create finding data structures

**Deliverables**:
- Parallel browser testing (2 concurrent)
- Parallel API testing (4 concurrent)
- Potential findings collected

### Phase 3: Validation & Reporting (Week 3)

**Tasks**:
1. Implement state verification protocol
2. Add curl validation fallback
3. Create state comparison logic
4. Integrate report generation
5. Add filesystem storage

**Deliverables**:
- Zero false positives
- Professional HackerOne reports
- Complete evidence collection

### Phase 4: Production Hardening (Week 4)

**Tasks**:
1. Comprehensive error handling
2. Database optimization
3. Memory management
4. Logging improvements
5. Documentation

**Deliverables**:
- 24/7 production-ready
- Full monitoring
- Deployment guide

---

## 11. Testing Strategy

### Unit Tests

**Coverage Areas**:
- Hypothesis card parsing
- State comparison logic
- Database queries
- Error handling

**Example**:
```python
def test_state_comparison():
    before = {'id': '123', 'status': 'active'}
    after = {'id': '123', 'status': 'deleted'}
    expected = {'status': 'deleted'}

    assert compare_states(before, after, expected) == True
```

### Integration Tests

**Test Scenarios**:
1. Full cycle on test target
2. Phase failure recovery
3. Database persistence
4. Report generation

### End-to-End Tests

**Test Cases**:
1. Complete hunt cycle (mocked LLM)
2. State verification flow
3. False positive detection
4. Graceful shutdown

---

## 12. Performance Metrics

### Expected Performance

| Metric | Target | Actual (TBD) |
|--------|--------|--------------|
| Cycle duration | 30 min | - |
| Targets/day | 3-6 | - |
| Hypotheses/cycle | 5-10 | - |
| Potential findings/day | 5-15 | - |
| Verified findings/day | 2-5 | - |
| False positive rate | 0% | - |
| Memory usage | < 500 MB | - |
| CPU usage | < 50% avg | - |

### ROI Metrics

| Metric | Estimate | Basis |
|--------|----------|-------|
| Daily bounties | $500-$2,000 | Historical avg payout × verified findings |
| Monthly bounties | $15K-$60K | 30 days × daily estimate |
| Acceptance rate | 50% | Conservative estimate |
| Time saved | 8 hrs/day | vs manual hunting |

---

## 13. Security Considerations

### Credential Management

**Storage**:
- Credentials stored in `.env` files per target
- Never committed to git
- Encrypted at rest (future enhancement)

**Usage**:
```bash
# Per-target credentials
C:/Users/vaugh/BountyHound/findings/{target}/credentials/{target}-creds.env
```

### Scope Validation

**Pre-Flight Checks**:
```python
def validate_scope(domain: str, endpoint: str) -> bool:
    """Ensure endpoint is in scope"""
    # Check domain whitelist
    if not is_whitelisted(domain):
        return False

    # Check endpoint exclusions
    if is_excluded(endpoint):
        return False

    return True
```

### Rate Limiting

**Built-in Limits**:
- Browser: 2 concurrent (prevents detection)
- API: 4 concurrent (respects rate limits)
- Recon: Sequential (prevents IP blocking)

### Data Privacy

**Sensitive Data Handling**:
- No PII in logs
- Evidence sanitized before storage
- Credentials never logged
- State snapshots anonymized

---

## 14. Deployment

### Prerequisites

**System Requirements**:
- Python 3.9+
- 4 GB RAM minimum
- 10 GB disk space
- Network access to targets

**Dependencies**:
```bash
pip install -r requirements.txt
# + bountyhound CLI
# + antigravity SDK (when available)
```

### Deployment Steps

**1. Deploy to Antigravity**:
```bash
cd C:/Users/vaugh/BountyHound/deployment/antigravity
./deploy.sh
```

**2. Open Antigravity IDE**:
- Go to https://antigravityide.org/
- File → Open Folder → `~/.antigravity/projects/bountyhound`

**3. Start Orchestrator**:
```bash
# Option A: Direct
python3 continuous_orchestrator.py

# Option B: Agent Manager
# Agents → Import Workflow → config.json → Start
```

### Configuration

**Edit** `antigravity.config.json`:
```json
{
  "workflow": {
    "targetSelection": {
      "minROI": 50,
      "maxConcurrentTargets": 3
    },
    "loopSettings": {
      "waitBetweenCycles": "10m",
      "maxCyclesPerDay": 48
    }
  },
  "runtime": {
    "maxParallelAgents": 6
  }
}
```

### Monitoring

**Logs**:
```bash
tail -f C:/Users/vaugh/BountyHound/logs/orchestrator.log
```

**Database**:
```python
from engine.core.database import BountyHoundDB
db = BountyHoundDB()
stats = db.get_all_target_stats()
```

---

## 15. Success Criteria

### Must-Have (MVP)

- ✅ Continuous 24/7 operation
- ✅ Database-driven target selection
- ✅ All 4 phases functional
- ✅ State verification working
- ✅ Zero false positives
- ✅ Reports generated correctly

### Should-Have (V1.1)

- Antigravity Agent Manager integration
- Multi-model LLM support (Gemini + Claude)
- Advanced error recovery
- Performance optimization
- Comprehensive monitoring

### Nice-to-Have (V2.0)

- Auto-submission to HackerOne
- Real-time dashboard
- Machine learning for hypothesis prioritization
- Distributed execution
- Custom payload learning

---

## 16. Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| False positives | High | Low | State verification protocol |
| API rate limits | Medium | Medium | Concurrency controls, exponential backoff |
| Database corruption | High | Low | Automatic backups, transaction safety |
| Target blocking | Medium | Medium | Rate limiting, user-agent rotation |
| Memory leaks | Low | Medium | Periodic restarts, memory monitoring |
| LLM API costs | Low | Low | Using free Gemini 3 Pro in Antigravity |

---

## 17. Future Enhancements

### Short-Term (1-3 months)

1. **Antigravity Agent Manager Integration**
   - Native multi-agent coordination
   - Better parallelization
   - Automatic recovery

2. **Multi-Model LLM Support**
   - Gemini 3 Pro (primary)
   - Claude Sonnet 4.5 (fallback)
   - GPT-OSS (local option)

3. **Advanced Validation**
   - Screenshot-based evidence
   - Video recordings for complex flows
   - Automated POC generation

### Long-Term (3-6 months)

1. **Machine Learning**
   - Hypothesis success prediction
   - Payload optimization
   - Target scoring refinement

2. **Distributed Execution**
   - Multiple orchestrators
   - Shared state coordination
   - Cloud deployment

3. **Auto-Submission**
   - HackerOne API integration
   - Automated report submission
   - Status tracking

---

## 18. Appendix

### Key Files

| File | Purpose | Location |
|------|---------|----------|
| continuous_orchestrator.py | Main orchestrator | deployment/antigravity/ |
| antigravity.config.json | Configuration | deployment/antigravity/ |
| bountyhound.db | Historical data | database/ |
| CLAUDE.md | System overview | bountyhound-agent/ |
| MEMORY.md | Key techniques | ~/.claude/projects/memory/ |

### References

- Google Antigravity: https://antigravityide.org/
- BountyHound Database: C:/Users/vaugh/BountyHound/database/
- Memory Guidelines: C:/Users/vaugh/.claude/projects/C--Users-vaugh/memory/

### Change Log

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-16 | Initial design approved |

---

**Status**: Ready for Implementation
**Next Step**: Create git worktree and implementation plan
