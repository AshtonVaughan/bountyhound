# Phased Parallel Pipeline Design

**Date:** 2026-02-06
**Status:** Implemented (with Discovery Engine)
**Problem:** BountyHound agent plugin (41,000 lines of markdown) doesn't actually call the bountyhound CLI

## Summary

Created a minimal wrapper agent that properly integrates the `bountyhound` CLI with browser-based testing using a 4-phase parallel pipeline.

## The Core Problem

The bountyhound-agent plugin describes procedures in markdown but only 4% of agents actually invoke the CLI. This design adds a focused agent that:
1. Actually calls `bountyhound recon` and `bountyhound scan`
2. Runs CLI scanning in parallel with browser testing
3. Merges findings and validates POCs

## Architecture

```
PHASE 1: RECON (Blocking)           ~5 min
├── bountyhound recon <domain>
├── subfinder → httpx → nmap
└── Results stored in SQLite
           ↓
PHASE 2: PARALLEL TESTING           ~15 min
├── Track A: bountyhound scan (background)
└── Track B: Browser testing (foreground)
           ↓
PHASE 3: SYNC & DEDUPE              ~2 min
├── Read CLI findings from SQLite
├── Merge with browser findings
└── Identify gaps needing POC
           ↓
PHASE 4: TARGETED EXPLOITATION      ~5 min
├── Exploit specific CVEs
├── Validate with curl
└── Capture evidence

TOTAL: ~27 min (vs 47 min sequential)
```

## Files Created

| File | Purpose | Lines |
|------|---------|-------|
| `agents/phased-hunter.md` | Main agent with 4-phase logic | ~200 |
| `commands/phunt.md` | Slash command shortcut | ~60 |

## Usage

```
/phunt example.com
```

Or invoke the agent directly:
```
Use the phased-hunter agent to hunt on example.com
```

## Key Design Decisions

1. **Minimal footprint** - 200 lines vs modifying existing 900-line files
2. **CLI-first** - Actually invokes bountyhound commands via Bash
3. **Parallel execution** - Scan runs in background while browser tests
4. **Mandatory validation** - All findings verified with curl before reporting
5. **Separate data stores** - CLI writes to SQLite, browser to markdown files

## Speed vs Accuracy Tradeoff

| Approach | Speed | Accuracy |
|----------|-------|----------|
| Sequential | 47 min | Highest |
| Full Parallel | 20 min | Gaps possible |
| **Phased Parallel** | **27 min** | **High** |

We chose phased parallel because:
- Recon completes first (full attack surface)
- Only scan + browser run in parallel (safe)
- Sync phase catches any gaps

## Dependencies

- `bountyhound` CLI installed (`pip install bountyhound`)
- Tools: subfinder, httpx, nmap, nuclei
- Playwright browser via MCP plugin

## Testing

1. Run `bountyhound doctor` to verify tools
2. Test on a small domain first
3. Check `~/bounty-findings/<domain>/` for output

---

## Discovery Engine (Implemented)

Added LLM-powered novel vulnerability discovery via `agents/discovery-engine.md`.

### The 4 Reasoning Tracks

| Track | Input | Output |
|-------|-------|--------|
| Pattern Synthesis | Tech stack + known vulns | "Rails + Redis = cache injection" |
| Behavioral Anomaly | Response inconsistencies | "JSON endpoint missing auth" |
| Code Research | Public source code | "innerHTML without sanitization" |
| Cross-Domain Transfer | MEMORY.md lessons | "GraphQL aliasing worked before" |

### Integration Points

1. **Phase 1.5 Mode** (proactive): Runs after recon, before scanning
2. **Gap-Triggered Mode** (backup): Runs if Phase 2 finds nothing

### Hypothesis Cards

```yaml
- id: H001
  hypothesis: "IDOR in /api/orders/:id"
  confidence: high
  test_method: curl
  payload: "Change order ID to another user's"
  success_indicator: "Returns other user's order data"
```

### Updated Timing

| Phase | Duration |
|-------|----------|
| Phase 1: Recon | ~5 min |
| Phase 1.5: Discovery | ~2 min |
| Phase 2: Parallel | ~15 min |
| Phase 3: Sync | ~2 min |
| Phase 4: Exploit | ~5 min |
| **Total** | **~29 min** |

*Gap-triggered second wave adds ~5 min if needed.*

---

## Phase 2: Simplify Existing Plugin (TODO)

The current plugin has massive redundancy and bloat. Once phased-hunter is validated, consolidate everything.

### Current State (Bloated)

| Component | Count | Problem |
|-----------|-------|---------|
| Commands | 8 | `/bh`, `/hunt`, `/bountyhound` all do similar things |
| Agents | 27 | Most are 500-900 lines of prose, don't call CLI |
| Skills | ~47 | Many overlap with agents |
| Engine | ~90 files | Pseudocode in markdown, never executed |
| **Total** | **~172 files** | **41,000+ lines** |

### Target State (Simplified)

| Component | Count | Purpose |
|-----------|-------|---------|
| Commands | 3 | `/hunt`, `/recon`, `/report` |
| Agents | 5 | phased-hunter, poc-validator, reporter, auth-manager, browser-tester |
| Skills | 10 | Only attack-specific skills that add value |
| Engine | 0 | Delete - CLI handles this |
| **Total** | **~18 files** | **~2,000 lines** |

### Simplification Steps

1. **Commands to keep:**
   - `/hunt` → alias to phased-hunter (primary)
   - `/recon` → just recon, no testing
   - `/report` → generate report from findings

2. **Commands to delete:**
   - `/bh` (redundant with /hunt)
   - `/bountyhound` (redundant with /hunt)
   - `/fullscan` (phased-hunter does this)
   - `/creative` (merge into phased-hunter phase 4)
   - `/limitless` (can be a flag on /hunt)
   - `/deepdive` (can be a flag on /hunt)

3. **Agents to keep:**
   - `phased-hunter.md` - main orchestrator
   - `poc-validator.md` - validates findings with curl
   - `reporter-agent.md` - generates reports
   - `auth-manager.md` - handles authentication
   - `browser-tester.md` - consolidated browser testing

4. **Agents to delete (22 files):**
   - `bounty-hunter.md` (replaced by phased-hunter)
   - `hunt-orchestrator.md` (replaced by phased-hunter)
   - `recon-agent.md` (CLI does this)
   - `scanner-agent.md` (CLI does this)
   - `injection-tester.md` (merge into browser-tester)
   - `api-tester.md` (merge into browser-tester)
   - `logic-tester.md` (merge into browser-tester)
   - All others...

5. **Engine to delete entirely:**
   - `engine/` folder - all 90 files
   - CLI + browser testing replaces all of this

6. **Skills to consolidate:**
   - Keep: xss-testing, sqli-testing, auth-bypass, idor-testing, ssrf-testing
   - Delete: everything that duplicates agent/CLI functionality

### Expected Result

```
bountyhound-agent/
├── agents/
│   ├── phased-hunter.md      # Main orchestrator (~200 lines)
│   ├── poc-validator.md      # Validates findings (~100 lines)
│   ├── reporter-agent.md     # Report generation (~150 lines)
│   ├── auth-manager.md       # Authentication (~100 lines)
│   └── browser-tester.md     # All browser tests (~300 lines)
├── commands/
│   ├── hunt.md               # Primary command (~50 lines)
│   ├── recon.md              # Recon only (~30 lines)
│   └── report.md             # Generate report (~30 lines)
├── skills/
│   └── (5-10 attack skills)  # ~500 lines total
├── CLAUDE.md                 # Simplified (~500 lines)
└── README.md                 # Updated docs
```

**From 41,000 lines → ~2,000 lines (95% reduction)**
