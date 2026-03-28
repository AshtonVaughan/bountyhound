# BountyHound Optimized Hunt Design v2
## Precision + Speed + Progressive Wins

**Date**: 2026-03-04
**Version**: 2.0
**Status**: Design Complete, Ready for Implementation

---

## Executive Summary

This design refines the BountyHound hunting system to optimize for three goals simultaneously:

1. **Speed** - 29 min → 15 min (1st hunt), 7 min (2nd hunt), 5 min (3rd+ hunt) via async execution and caching
2. **Precision** - Only report findings with working PoC + evidence (screenshot proof, real damage demonstrated)
3. **Exploitability** - Validate all findings can actually be exploited before reporting; capture evidence during validation

Key innovation: **Three parallel streams** (Hunt, Validation, Report) where high-signal agents run first, findings validate immediately, and users see validated findings in real-time.

---

## Section 1: Architecture Overview

### Core Principle
Prioritize high-confidence agents, validate findings with proof-of-concept immediately, report progressively while hunting continues.

### Three Parallel Streams

**Hunt Stream** - Agent execution in priority order:
- Agents ordered by: track record + confidence + speed + stack-specificity
- High-priority agents (sqlmap, nuclei) start immediately
- Low-priority agents (generic fuzzing) queue behind
- All agents eventually run (no early termination)

**Validation Stream** - Proof-of-concept and evidence capture:
- When Hunt Stream finds a potential vulnerability, Validation Stream validates it
- Run PoC (30-60 seconds per finding) - prove the vuln actually works
- Capture evidence: before/after screenshots, request/response, command output
- Only HIGH+ severity findings reported; MEDIUM optional
- **Non-blocking**: Validation doesn't pause hunting

**Report Stream** - Real-time progressive reporting:
- When Validation completes, finding is reported immediately to user
- Create self-contained folder: `findings/example.com/{Finding_Name}/`
- Update `findings_live.json` with new finding
- User sees HIGH+ findings as they validate, not waiting until end

### ProxyEngine Integration

**During Validation Stream**:
- ProxyEngine intercepts all PoC requests/responses
- Auto-captures: exact payload, status code, response time, data extracted
- Saves raw traffic to `evidence.json` in finding folder

**Manual Testing Phase** (after hunt):
- User can load findings folder and use ProxyEngine Repeater to:
  - Test variations of proven PoCs
  - Chain findings together
  - Explore for additional impact
  - Capture supplementary evidence

---

## Section 2: Agent Priority Queue System

Each agent gets a **priority score** (0-100) calculated at hunt start based on target profile.

### Score Components

**Track Record** (0-40 points):
- Historical accuracy: how often does this agent find exploitable vulns?
- sqlmap_injection: 38 (finds real SQLi ~80% of findings)
- nuclei_scan: 35 (template-based, high accuracy)
- nmap_scanner: 32 (ports are always real)
- ffuf_fuzzer: 18 (finds endpoints, not vulnerabilities)
- generic_fuzzer: 12 (low hit rate on real vulns)

**Confidence Output** (0-30 points):
- Does the agent report confidence scores with findings?
- Agent reports 80%+ confidence: +30 points
- Agent reports 60-80% confidence: +15 points
- Agent guesses blindly with no confidence: 0 points

**Speed** (0-20 points):
- Agents finishing in <2 minutes get priority
- nmap_scanner: 18 (fast, real results)
- nuclei_scan: 16 (template-based, quick)
- ffuf_fuzzer: 8 (slower, lower priority)
- sql_deep_test: 5 (slow, runs late)

**Stack-Specificity** (0-10 points):
- Does agent match target's detected tech stack?
- Target is Django → django_auditor: +10
- Target is AWS → cloud_scanner: +10
- Generic agent on generic target: 0

### Execution Order

1. Calculate priority score for all 75 agents at hunt start
2. Sort agents by score (descending)
3. Execute in order: highest priority starts first
4. When agent completes or times out, next agent starts
5. All agents eventually run (low-priority agents queue behind)

### Example Priority Queue for Django + AWS Target

```
Priority 98: sqlmap_injection (track record 38 + stack Django 10 + confidence 30 + speed 20)
Priority 95: nuclei_scan (track record 35 + stack Django 10 + confidence 30 + speed 20)
Priority 92: nmap_scanner (track record 32 + speed 18 + confidence 30 + stack AWS 12)
Priority 88: django_auditor (track record 35 + stack Django 10 + confidence 30 + speed 13)
Priority 82: aws_security_scanner (track record 32 + stack AWS 10 + speed 18 + confidence 22)
Priority 71: ffuf_fuzzer (track record 18 + speed 8 + confidence 30 + stack 15)
...
Priority 12: generic_fuzzer (track record 12 + speed 0)
```

---

## Section 3: Immediate Validation & Evidence Capture

### Validation Pipeline (Runs in Parallel with Hunt)

When Hunt Stream reports a finding, Validation Stream immediately validates it:

**Step 1: Exploitability Check** (30-60 seconds):
- **SQLi Finding**: Run sqlmap confirmation on that endpoint
  - Payload: `' OR '1'='1`
  - Verify: Data exfiltrated, different response than normal
  - Evidence: SQL queries in output, number of rows returned

- **IDOR Finding**: Test with User B credentials, compare responses
  - Payload: Replace User A's ID with User B's ID
  - Verify: Access data you shouldn't have access to
  - Evidence: Side-by-side comparison of responses

- **XSS Finding**: Execute payload in headless browser, verify DOM changes
  - Payload: `<img src=x onerror=alert('XSS')>`
  - Verify: Alert appears, JavaScript executed
  - Evidence: Screenshot showing JavaScript alert

- **RCE Finding**: Execute harmless command, capture output
  - Payload: `; id;` or `$(whoami)`
  - Verify: Command output appears in response
  - Evidence: Screenshot showing `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

**Step 2: Evidence Capture**:
- **Before/After Screenshots**: Prove the damage
  - Before: Normal behavior (user can't access admin)
  - After: Exploited behavior (user can access admin)

- **Network Requests**: Exact HTTP request that triggers vuln
  - Request: `GET /api/admin?user_id=2&token=victim_token`
  - Response: Admin panel data (users, settings, etc)

- **PoC Output**: Raw command output showing damage
  - `SELECT * FROM users LIMIT 5;` returns 5 user records
  - `id` command output shows www-data user
  - File listing showing `/etc/passwd` contents

- **Timestamp**: Exact time exploitation succeeded
  - Proves it's a real, current vulnerability (not fixed)

**Step 3: Severity Confirmation**:
Only report if **real damage is demonstrated** (not theoretical):
- **CRITICAL**: Full account takeover, data exfiltration, RCE confirmed
  - Example: SQLi extracts all user passwords; attacker gains admin access

- **HIGH**: Partial unauthorized access, leaked sensitive data, chained vulnerability
  - Example: IDOR leaks user email/phone; XSS steals session token

- **MEDIUM**: Information disclosure, minor logic flaw
  - Example: Version number leaked; rate limit bypass (theoretical impact)

**Step 4: Report Generation**:
Auto-generate detailed report with evidence embedded:
- Vulnerability description (what is it?)
- PoC steps (how to reproduce?)
- Impact assessment (why does it matter?)
- Remediation (how to fix it?)
- All evidence files referenced

### Non-Blocking Execution

While Validation Stream validates Finding A (30-60 seconds), Hunt Stream continues:
- Agent B starts testing
- Agent C queues
- Agent D runs
- Finding A validation completes → reported
- Agent E starts
- Repeat until all agents finish

**No waiting. No bottlenecks.**

---

## Section 4: Self-Contained Findings Directory Structure

Each validated finding gets its own folder with all evidence bundled.

### Directory Structure

```
findings/example.com/
├── SQLi_Users_API_CRITICAL/
│   ├── poc.md                    # Step-by-step reproduction
│   ├── evidence.json             # Raw PoC data, requests, responses
│   ├── screenshots/
│   │   ├── 01_normal_response.png
│   │   ├── 02_injection_payload.png
│   │   ├── 03_admin_access.png
│   │   └── 04_data_dump.png
│   └── report.md                 # Detailed vulnerability report
│
├── IDOR_User_Profiles_HIGH/
│   ├── poc.md
│   ├── evidence.json
│   ├── screenshots/
│   │   ├── 01_user_a_profile.png
│   │   ├── 02_user_b_id_request.png
│   │   └── 03_user_b_data_accessed.png
│   └── report.md
│
└── XSS_Comment_Field_MEDIUM/
    ├── poc.md
    ├── evidence.json
    ├── screenshots/
    │   └── 01_xss_alert_popup.png
    └── report.md
```

### Folder Naming

Format: `{Vulnerability_Type}_{What_Affected}_{Severity}`

Examples:
- `SQLi_Users_API_CRITICAL`
- `IDOR_User_Profiles_HIGH`
- `XSS_Comment_Field_MEDIUM`
- `Auth_Bypass_Admin_Panel_CRITICAL`
- `InfoDisclosure_API_Version_LOW`

User can rename manually if desired (e.g., more descriptive names).

### File Contents

**poc.md** - Step-by-step reproduction:
```markdown
# SQL Injection in /api/users

## Steps to Reproduce

1. Log in as attacker (attacker@example.com / password123)
2. Navigate to: https://target.com/api/users
3. Modify URL parameter: ?id=1' OR '1'='1
4. Observe: Returns all users (instead of just user 1)

## Expected vs Actual

**Expected**: {"id": 1, "name": "John", "email": "john@example.com"}
**Actual**: [{"id": 1, ...}, {"id": 2, ...}, {"id": 3, ...}, ...]

## Impact

All user data (emails, hashed passwords, phone numbers) can be extracted.
```

**evidence.json** - Raw PoC data:
```json
{
  "finding_type": "SQLi",
  "endpoint": "/api/users",
  "method": "GET",
  "payload": "id=1' OR '1'='1",
  "request": {
    "url": "https://target.com/api/users?id=1' OR '1'='1",
    "headers": {
      "Authorization": "Bearer attacker_token",
      "User-Agent": "Mozilla/5.0..."
    }
  },
  "response": {
    "status_code": 200,
    "body": "[{\"id\": 1, ...}, {\"id\": 2, ...}, {\"id\": 3, ...}]",
    "response_time_ms": 245
  },
  "data_extracted": "3 user records with emails and phone numbers",
  "validation_timestamp": "2026-03-04T15:21:45Z",
  "validation_method": "sqlmap_injection agent + ProxyEngine",
  "confidence": 100
}
```

**screenshots/** - Visual proof of damage:
- Numbered sequence showing before/after
- 01_normal: User can't access admin
- 02_payload: Attacker injects SQL payload
- 03_after: User suddenly has admin access
- 04_damage: Data dump showing extracted information

**report.md** - Complete vulnerability report:
```markdown
# SQL Injection in /api/users Endpoint

## Summary
A SQL injection vulnerability allows unauthenticated attackers to extract all user data.

## Technical Details
- **Type**: Classic SQL Injection
- **Location**: `/api/users` endpoint, `id` parameter
- **Payload**: `1' OR '1'='1`
- **Impact**: Full database compromise

## Proof of Concept
[See poc.md for step-by-step reproduction]

## Evidence
- Screenshots in `screenshots/` folder
- Raw request/response in `evidence.json`

## Remediation
Use parameterized queries (prepared statements):
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);
```

## Severity
**CRITICAL** - Allows full data exfiltration without authentication
```

---

## Section 5: Progressive Real-Time Reporting

### findings_live.json - Real-Time Status

Updates continuously as findings validate. User sees findings in real-time instead of waiting until hunt end.

```json
{
  "timestamp": "2026-03-04T15:22:15Z",
  "target": "example.com",
  "hunt_in_progress": true,
  "hunt_duration_seconds": 245,

  "validated_findings": [
    {
      "id": "f_critical_001",
      "title": "SQL Injection in /api/users",
      "severity": "CRITICAL",
      "type": "SQLi",
      "affected": "Users API",
      "status": "validated_with_poc",
      "source_agent": "sqlmap_injection",
      "folder": "findings/example.com/SQLi_Users_API_CRITICAL/",
      "evidence": {
        "poc_confirmed": true,
        "data_extracted": "5 user records",
        "response_time_ms": 245,
        "screenshot_count": 4
      },
      "timestamp_validated": "2026-03-04T15:21:45Z"
    },
    {
      "id": "f_high_002",
      "title": "IDOR in User Profile Endpoint",
      "severity": "HIGH",
      "type": "IDOR",
      "affected": "User Profiles",
      "status": "validated_with_poc",
      "source_agent": "idor_tester",
      "folder": "findings/example.com/IDOR_User_Profiles_HIGH/",
      "evidence": {
        "poc_confirmed": true,
        "users_accessed": 8,
        "data_leaked": ["email", "phone", "address"],
        "screenshot_count": 3
      },
      "timestamp_validated": "2026-03-04T15:22:10Z"
    }
  ],

  "pending_validation": [
    {
      "status": "validating",
      "source_agent": "nuclei_scan",
      "finding_type": "XSS",
      "time_remaining_seconds": 45
    }
  ],

  "currently_testing": {
    "active_agents": ["ffuf_fuzzer", "nmap_scanner"],
    "next_agents": ["bloodhound_enum", "metasploit_execute"]
  },

  "summary": {
    "total_validated": 2,
    "critical": 1,
    "high": 1,
    "medium": 0,
    "agents_completed": 15,
    "agents_remaining": 60
  }
}
```

### User Experience

User opens `findings_live.json` in browser or terminal and sees:
- ✅ Validated findings (with links to evidence folders)
- 🔄 What agents are currently testing
- ⏳ Findings awaiting validation (with ETA)
- 📊 Running count of findings by severity

**Real-time updates** - File refreshes every 10 seconds with new validated findings.

---

## Section 6: Complete Hunt Flow

### Phase 0: Cache Check

Load cached data from previous hunts:
- Recon (subdomains, IPs, ports) - 30 day TTL
- Stack fingerprint (framework, auth type) - 30 day TTL
- Credentials (working logins, tokens) - 7 day TTL
- Tested methods (which agents tested what) - 7 day TTL

If cache is fresh, skip corresponding hunt phases. If stale, mark for refresh.

### Phase 0.5: Build Agent Priority Queue

Calculate priority scores for all 75 agents:
- Track record (how often does this agent find real vulns?)
- Confidence output (does it report confidence scores?)
- Speed (can it finish in <2 minutes?)
- Stack-specificity (does it match target's tech stack?)

Sort agents by score descending. High-priority agents start immediately.

### Phases 1-6: Three Parallel Streams

**Hunt Stream** (agent execution):
```
Start: sqlmap_injection (priority 98)
  └─ Calls sync_sqlmap_test() via tool_bridge
  └─ Hits http://127.0.0.1:8189/api/test
  └─ Reports findings immediately (potential vulns)
       ↓
Start: nuclei_scan (priority 95)
  └─ Calls sync_nuclei_scan() via tool_bridge
  └─ Hits http://127.0.0.1:8188/api/scan
  └─ Reports findings (template matches)
       ↓
Start: nmap_scanner (priority 92)
  └─ Calls sync_nmap_scan() via tool_bridge
  └─ Hits http://127.0.0.1:8190/api/scan
       ↓
... (continue with all 75 agents in priority order)
```

**Validation Stream** (parallel, non-blocking):
```
When Hunt finds: "Potential SQLi in /api/users"
       ↓
Validation Stream validates it (30-60 seconds):
  ├─ Run PoC: sqlmap confirmation
  ├─ Capture evidence: before/after screenshot
  ├─ ProxyEngine intercepts request/response
  ├─ Save evidence to findings/example.com/{Finding_Name}/
       ↓
If validated: Move to Report Stream
If invalid: Discard silently
```

**Report Stream** (real-time):
```
When Validation completes:
  ├─ Create findings/example.com/{Finding_Name}/ folder
  ├─ Write poc.md, evidence.json, screenshots/
  ├─ Update findings_live.json with new finding
  └─ User sees finding in real-time
```

### End of Hunt

Files generated:
- `findings/example.com/` - Multiple self-contained finding folders
- `findings_live.json` - Real-time status history
- `cache.json` - Updated cache for next hunt
- `report.json` - Machine-readable summary

Each finding folder ready for HackerOne submission:
- PoC steps documented
- Evidence captured
- Screenshots attached
- Impact explained

---

## Section 7: Timing Comparison

### 1st Hunt (Cold Cache)

**OLD**: 29 minutes (sequential phases)
**NEW**: 15 minutes (async phases + priority queue)
**Savings**: 14 minutes (48% faster)

Why:
- Async phases eliminate waiting between stages (Phase 0.5 doesn't wait for Phase 1 to finish)
- High-priority agents run first (sqlmap/nuclei validated within minutes)
- Validation runs in parallel (doesn't block hunt)

### 2nd Hunt (Same Target, Warm Cache)

**OLD**: 29 minutes (full retest)
**NEW**: 7 minutes (use cached data, only refresh stale methods)
**Savings**: 22 minutes (76% faster)

Why:
- Recon cached (30 day TTL) - skip Phase 1 entirely (saves 5 min)
- Stack cached (30 day TTL) - skip Phase 0.5 entirely (saves 2 min)
- Agent caches (7 day TTL) - many agents skip tool calls (saves 10+ min)
- Only new endpoints and stale methods tested

### 3rd+ Hunt (Warm Cache)

**OLD**: 29 minutes (full retest)
**NEW**: 5 minutes (almost all methods cached)
**Savings**: 24 minutes (83% faster)

Why:
- Most methods cached (7+ days passed, but recon/stack still fresh)
- Only truly new attack surface tested
- Validation still rigorous (PoC required)

### Thoroughness: Unchanged

✓ ALL 75 agents always run (no early termination)
✓ Complete coverage maintained
✓ Cache is for speed, not completeness
✓ Only findings that validate reported

---

## Section 8: Key Differences from v1

| Aspect | v1 | v2 |
|--------|----|----|
| **Agent Execution** | All parallel | Prioritized queue (high-signal first) |
| **Validation** | Deduplication only | Full PoC + evidence capture |
| **Reporting** | Batch at end | Progressive real-time |
| **Findings Storage** | Single findings.json | Self-contained folders per finding |
| **Evidence** | Minimal | Comprehensive (screenshots, requests, PoC output) |
| **ProxyEngine** | Not integrated | Traffic capture + manual testing |
| **Reporting Format** | JSON array | Individual folders (ready for HackerOne) |

---

## Section 9: Success Criteria

This design is successful when:

1. ✅ Agent priority queue correctly orders agents by track record + confidence + speed + stack-specificity
2. ✅ High-priority agents (sqlmap, nuclei) start and report findings within first 2 minutes
3. ✅ Validation pipeline proves exploitability (PoC runs, evidence captured) before reporting
4. ✅ findings/example.com/{Finding_Name}/ folders are self-contained with poc.md + screenshots + evidence.json
5. ✅ findings_live.json updates in real-time as findings validate
6. ✅ Hunt continues while validation runs (non-blocking parallel streams)
7. ✅ 2nd hunt on same target takes ~7 minutes (75% faster than first hunt)
8. ✅ ProxyEngine captures traffic during validation runs
9. ✅ User can load any finding folder and use ProxyEngine Repeater for manual testing
10. ✅ All findings ready for HackerOne submission (with PoC steps + evidence + impact)

---

## Next Steps

1. **Implementation Planning** - Break design into implementation tasks
2. **Cache Manager** - Build cache_manager.py (partially done)
3. **Agent Priority Queue** - Implement scoring system in hunt_executor.py
4. **Validation Pipeline** - Build validation_pipeline.py with PoC execution
5. **Findings Structure** - Implement self-contained folder creation
6. **ProxyEngine Integration** - Capture traffic during validation
7. **Real-Time Reporting** - Update findings_live.json every 10 seconds
8. **Testing** - Validate on 2-3 real targets

---

**Design Document Complete** ✅

Ready for implementation.
