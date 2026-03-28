# BountyHound Optimized Architecture
## Speed + Thoroughness + Complete Caching

---

## Design Goals
- ✓ Run ALL 75 agents (thoroughness)
- ✓ Parallelize phases instead of sequential (speed)
- ✓ Cache everything for reuse (efficiency)
- ✓ Stream results in real-time (early insights)
- ✓ No early termination (complete coverage)

**Target Time**: 29 min → 12-15 min (50% reduction)

---

## Core Changes

### 1. PERSISTENT CACHE LAYER

```
findings/target/cache/
├── recon_cache.json          # Cached: subdomains, IPs, ports, URLs
├── stack_fingerprint.json    # Cached: frameworks, CMS, libraries, auth methods
├── credentials.json          # Cached: working logins, API keys, tokens
├── previous_findings.json    # Cached: all findings ever found
├── tested_methods.json       # Cached: which agents tested what
└── method_hashes.json        # MD5 of findings (detect duplicates)
```

**On Hunt Start**:
```python
if cache exists and recent (<30 days):
    load_from_cache()
    SKIP Phase 1 recon (use cached data)
    SKIP re-testing same endpoints
    UPDATE with new findings only
else:
    run full recon
    save to cache for next hunt
```

**Benefits**:
- 2nd hunt on same target: ~7 min (skip recon, use cached data)
- New findings immediately added to cache
- Credentials/IPs/logins stored permanently

### 2. ASYNCHRONOUS PHASE EXECUTION

**OLD (Sequential)**:
```
Phase 0.5 (2 min)
  ↓ (wait)
Phase 1 (5 min)
  ↓ (wait)
Phase 1.5 (2 min)
  ↓ (wait)
Phase 2 (15 min) ← Can start earlier!
```

**NEW (Async/Streaming)**:
```
Phase 0.5 (2 min) ──┐
Phase 1 (5 min)    ├─ All start immediately, run in parallel
Phase 1.5 (2 min)  │  Discovery starts when first recon batch arrives
Phase 2 (15 min)   │  Testing starts when first hypothesis generated
Phase 3 (2 min) ───┘
Phase 4 (5 min)
Phase 5 (2 min)
Phase 6 (2 min)
────────────────────
Total: 12-15 min (down from 29 min sequential)
```

**Implementation**:
```python
# huntexecutor.py
async def execute(self):
    tasks = [
        asyncio.create_task(phase_0_5()),  # Profiling
        asyncio.create_task(phase_1()),    # Recon
        asyncio.create_task(phase_1_5()),  # Discovery (triggered when phase_1 has first batch)
        asyncio.create_task(phase_2()),    # Testing (triggered when phase_1_5 has first hypothesis)
        asyncio.create_task(phase_3()),    # Sync (triggered when phase_2 has first results)
        asyncio.create_task(phase_4()),    # Exploit
        asyncio.create_task(phase_5()),    # Chaining
        asyncio.create_task(phase_6()),    # Report
    ]
    return await asyncio.gather(*tasks)
```

### 3. REAL-TIME RESULT STREAMING

**OLD**: Results batched at phase boundaries
**NEW**: Results stream continuously

```python
# Results appear as agents complete
findings/target/findings_live.json  # Updated in real-time

{
  "timestamp": "2026-03-04T15:23:45Z",
  "findings_count": 42,
  "by_severity": {
    "CRITICAL": 3,
    "HIGH": 8,
    "MEDIUM": 31,
    "LOW": 0
  },
  "latest_findings": [
    {
      "id": "f_c3f2e1a9",
      "title": "SQL Injection in /api/login",
      "severity": "CRITICAL",
      "source_agent": "sqlmap_injection",
      "source_tool": "sqlmap-claude",
      "timestamp": "2026-03-04T15:22:15Z"
    },
    ...
  ]
}
```

**Report updates every 10 seconds** (user sees progress in real-time)

### 4. AGENT OPTIMIZATION

**OLD**: Every agent imports all 11 sync_* functions
**NEW**: Each agent only imports what it needs

```python
# ffuf_fuzzer.py - OLD
from engine.core.tool_bridge import (
    sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz,
    sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum,
    sync_bloodhound_enum, sync_metasploit_execute,
    sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
)

# ffuf_fuzzer.py - NEW
from engine.core.tool_bridge import sync_ffuf_fuzz  # Only what we use
```

**Benefit**: ~2% memory/import overhead reduction

### 5. SMART CACHING - Per Agent

```python
# Each agent checks cache before running

class FFufFuzzerAgent:
    def run(self):
        # Check cache
        cached = self.load_from_cache()
        if cached and is_recent(cached):
            return cached  # Instant return

        # Not cached or stale, run tool
        result = sync_ffuf_fuzz(...)

        # Save to cache
        self.save_to_cache(result)
        return result
```

**Cache Location**:
```
findings/target/cache/method_results/
├── ffuf_fuzzer_[url_hash].json
├── sqlmap_injection_[url_hash].json
├── nuclei_scan_[domain_hash].json
├── nmap_scan_[target_hash].json
├── amass_enum_[domain_hash].json
├── bloodhound_enum_[domain_hash].json
└── ...
```

**Time Savings**:
- 1st hunt: Full scan (29 min with optimization = 15 min)
- 2nd hunt same target: 7 min (recon cached, skip old endpoints)
- 3rd+ hunts: 5-7 min (most methods cached)

### 6. UNIFIED CACHE STRUCTURE

```
findings/target/cache.json
{
  "target": "target.com",
  "last_hunt": "2026-03-04T15:45:00Z",
  "hunt_count": 3,

  "recon": {
    "subdomains": ["api.target.com", "admin.target.com", ...],
    "ips": ["1.2.3.4", "5.6.7.8", ...],
    "ports": [80, 443, 8080, 8443, ...],
    "urls": ["https://target.com/admin", ...],
    "services": {"80": "nginx", "443": "cloudflare", ...}
  },

  "stack": {
    "framework": "Django 3.2",
    "cms": "WordPress 5.8",
    "language": "Python",
    "auth_type": "JWT + OAuth",
    "api_style": "REST",
    "dependencies": ["jQuery 3.6", "Bootstrap 5", ...]
  },

  "credentials": {
    "working_logins": [
      {"username": "admin", "password": "***", "endpoint": "/admin"},
      {"api_key": "sk-***", "scope": ["read", "write"], "expires": "2026-12-31"}
    ],
    "tokens": {
      "jwt": "eyJ...",
      "session": "SESSIONID=***",
      "oauth": "ya29.***"
    },
    "last_updated": "2026-03-04T15:00:00Z"
  },

  "findings": {
    "previous": [
      {
        "title": "SQL Injection in /api/users",
        "severity": "CRITICAL",
        "status": "open",
        "found_date": "2026-02-15T10:30:00Z",
        "finding_hash": "a3f2e1c9d7b5e3a1"
      },
      ...
    ]
  },

  "tested_methods": {
    "sqlmap_injection": {
      "last_run": "2026-03-04T15:22:00Z",
      "endpoints_tested": 12,
      "findings": 2
    },
    "nuclei_scan": {
      "last_run": "2026-03-04T15:18:00Z",
      "templates_used": 150,
      "findings": 8
    },
    ...
  }
}
```

### 7. CACHE INVALIDATION RULES

```python
# findings/target/cache.py

CACHE_TTL = {
    "recon": 30 * 86400,        # 30 days (IPs rarely change)
    "stack_fingerprint": 30 * 86400,  # 30 days
    "credentials": 7 * 86400,   # 7 days (tokens/sessions expire)
    "findings": float('inf'),   # Never expire (historical record)
    "method_results": 7 * 86400, # 7 days
}

def should_refresh_cache(method, last_run_time):
    ttl = CACHE_TTL.get(method, 7 * 86400)
    return (time.time() - last_run_time) > ttl

def refresh_stale_cache():
    # Re-run only stale methods
    for method, last_run in tested_methods.items():
        if should_refresh_cache(method, last_run):
            run_agent(method)  # Update
```

### 8. INTELLIGENT DEDUPLICATION

```python
# Don't report same finding twice

findings_cache = load_json("findings/target/cache.json")

new_finding = {
    "title": "SQL Injection in /api/login",
    "severity": "CRITICAL",
    "endpoint": "/api/login"
}

finding_hash = md5(f"{new_finding['endpoint']}_{new_finding['title']}")

if finding_hash in findings_cache["method_hashes"]:
    skip_duplicate()
else:
    save_finding()
    findings_cache["method_hashes"][finding_hash] = time.now()
```

---

## Revised Hunt Flow

```
/hunt target
    │
    ├─ Step 0: Check cache
    │  ├─ If recent: load cached recon, stack, credentials
    │  └─ If stale: mark methods for refresh
    │
    ├─ ASYNC START (all parallel):
    │  │
    │  ├─ Phase 0.5 (Profiling) ~2 min
    │  │  └─ Outputs → discovery engine immediately
    │  │
    │  ├─ Phase 1 (Recon) ~5 min
    │  │  └─ Outputs stream to discovery + testing as they arrive
    │  │     (don't wait for full recon completion)
    │  │
    │  ├─ Phase 1.5 (Discovery) - starts when first recon batch
    │  │  └─ Outputs stream to testing immediately
    │  │
    │  ├─ Phase 2 (Testing) - starts when first hypothesis
    │  │  ├─ 75 agents run in parallel
    │  │  ├─ Each agent checks cache first
    │  │  │  ├─ If cached + recent: return instantly
    │  │  │  └─ If stale: call tool_bridge + update cache
    │  │  └─ Results stream to report in real-time
    │  │
    │  ├─ Phase 3 (Sync) - continuous (not batch)
    │  │
    │  ├─ Phase 4 (Exploit) - parallel with testing
    │  │
    │  ├─ Phase 5 (Chaining) - streams as findings arrive
    │  │
    │  └─ Phase 6 (Report) - updates continuously
    │
    └─ Output: findings/target/
       ├── report.json (updated every 10s)
       ├── findings_live.json (real-time stream)
       ├── cache.json (persistent for next hunt)
       └── findings/ (historical record)
```

---

## Time Comparison

| Scenario | Old (Sequential) | New (Async + Cache) | Savings |
|----------|-----------------|-------------------|---------|
| **1st hunt (cold)** | 29 min | 15 min | 14 min (48%) |
| **2nd hunt (same target)** | 29 min | 7 min | 22 min (76%) |
| **3rd+ hunt (warm cache)** | 29 min | 5 min | 24 min (83%) |
| **New endpoints only** | 29 min | 8 min | 21 min (72%) |

---

## Implementation Checklist

- [ ] Create `engine/core/cache_manager.py` - persistent cache layer
- [ ] Update `engine/core/hunt_executor.py` - async phases instead of sequential
- [ ] Create `findings/target/cache/` - cache storage structure
- [ ] Add cache checks to each agent class (15 min per agent × 75 = ~18 hours of work, parallelizable)
- [ ] Add result streaming to report generation (10s update interval)
- [ ] Add deduplication logic (MD5 hashing of findings)
- [ ] Add cache invalidation rules (TTL per method type)
- [ ] Create `cache_stats.py` - show what's cached, what's stale

---

## Benefits

1. **Speed**: 29 min → 5-15 min (70% faster)
2. **Thoroughness**: ALL agents run always (no early termination)
3. **Reusability**: 2nd hunt on same target instant cache hit
4. **Visibility**: Real-time streaming report
5. **Efficiency**: Cache credentials/IPs across hunts
6. **Intelligence**: Smart deduplication prevents noise

---

## Critical Design Decision

**Do we:**
- A) Parallelize phases (gain speed, keep all agents) ← RECOMMENDED
- B) Add early termination (gain more speed, lose thoroughness)
- C) Add both (highest speed, but risk missing findings)

**This plan chooses A**: Async phases + caching + ALL agents = balanced optimality
