# BountyHound Redesign — Design Spec

**Date:** 2026-03-10
**Status:** Approved
**Goal:** Redesign BountyHound's hunt pipeline to produce confirmed, reproducible findings instead of noisy false positives — by replacing pattern-matching with implementation reasoning, browser-first testing, and a hard 4-layer validation gate.

---

## Problem Statement

The current BountyHound system fails on quality in four ranked ways:

1. **False positives** — flags things that are by design; required the user to challenge findings multiple times before the system would admit the error
2. **Bad PoC reproduction** — curl commands that don't reproduce the issue (wrong headers, missing auth, wrong params)
3. **Surface-level findings** — finds obvious CVE-matched issues, misses the interesting bugs
4. **Weak hypothesis generation** — guesses generically rather than reasoning from the specific implementation

The root cause: the system is **attack-first, understand-later**. It pattern-matches against known vulnerability signatures without genuinely understanding the target.

---

## Design Decisions

### What Gets Cut

- **138 unused agents** — only 5 core agents are used in practice; the rest add noise
- **engine/core/ (65 files)** — audited before deletion; remove anything not actively called
- **CODEXDATABASE.db + h1-programs.db** — migrated into unified `bountyhound.db`, then deleted
- **Stale documentation** — AGENT_UPDATE_REPORT.md, COMPLETION_REPORT.txt, HUNT_FLOW_DIAGRAM.txt, OPTIMIZED_HUNT_*.md, IMPLEMENTATION_SUMMARY.md, METHODOLOGY_GAPS_TODO.md

### What Gets Kept

- All 21 skill categories (recently upgraded to 0.1% depth — keep as-is)
- **5 active MCP tools: nuclei, sqlmap, nmap, ffuf, amass** — these are used in the hunt pipeline
- **6 inactive MCP tools: bloodhound, metasploit, nessus, volatility, zeek, gobuster** — kept but not wired into the new hunt loop; available for manual use, not deleted
- proxy-engine (traffic capture for curl chain extraction)
- Claude-in-Chrome browser automation
- findings/ directory structure (markdown reports)
- auth-manager.md + reporter-agent.md (core agents)
- sync.py + repatch.py (deployment workflow)
- scrape_hackerone_*.py (HackerOne scraping — updated to write to bountyhound.db)

### What Gets Rebuilt

Four new agents replace the current hunt orchestration:

1. **intelligence-loop.md** — replaces phased-hunter.md; orchestrates the full 6-step hunt loop
2. **target-researcher.md** — replaces implicit recon phase; builds the target model explicitly
3. **hypothesis-engine.md** — replaces discovery-engine.md; generates grounded novel hypotheses
4. **validator.md** — replaces poc-validator.md; implements 4-layer validation

Two new skills:

1. **skills/target-research/** — methodology for building a target model
2. **skills/validation/** — 4-layer validation protocol and challenge protocol

One new database: **bountyhound.db** — unified SQLite replacing both old databases.

---

## Architecture

### The Hunt Loop (intelligence-loop.md)

Six sequential phases. Each phase feeds the next. No phase is skipped.

```
① TARGET RESEARCH → ② BUILD TARGET MODEL → ③ HYPOTHESIS GEN
→ ④ BROWSER TEST → ⑤ 4-LAYER VALIDATE → ⑥ REPORT
```

**Phase ① — Target Research (~20 min)**
- Subdomain enum via amass
- Port scan via nmap
- Tech stack fingerprint via browser (Wappalyzer-style)
- JS bundle crawl — extract API endpoints, auth flows, feature flags, secrets
- Source code read if public GitHub exists (deps, auth, routing, config files)
- CVE pull from bountyhound.db for exact tech stack versions
- Prior disclosure pull from bountyhound.db for this program
- 5 min authenticated browser session to understand app structure

**Phase ① — Minimum acceptable output before proceeding to Phase ②:**
- At least one confirmed tech stack component (framework, language, or server) identified. If none found: proceed anyway, mark tech_stack as unknown, skip CVE matching in Phase ③.
- If amass returns no subdomains: treat the primary domain as the only target, proceed.
- If no public GitHub: skip source code step, mark source_available = false in target model.
- If authenticated browser session is not possible (no credentials): mark auth_tested = false, skip auth-surface hypotheses in Phase ③.
- Phase ① never blocks Phase ②. Incomplete data is recorded as-is; the hypothesis engine adapts.

**Phase ② — Build Target Model**
- **Source of truth:** `findings/<program>/target-model.json` is the working file. The `targets` table in bountyhound.db is a read-optimised mirror, synced after every write to the JSON file.
- **Staleness threshold:** A target model is considered stale if `last_updated` is more than 14 days old. On hunt start, if model is stale, Phase ① re-runs in full and overwrites the model. If fresh, Phase ① is skipped entirely.
- **Fields:** tech_stack, endpoints, auth_model, business_logic, attack_surface, cves_relevant, prior_disclosures, hypotheses_queue (scored pending list for current session), tested_hypotheses (list of {hypothesis_id, outcome, tested_at} — completed history), confirmed_findings (list of finding_ids), last_updated, source_available, auth_tested
- **Duplicate detection:** A hypothesis is considered duplicate if its `hypothesis_id` (sha256 of the attack surface + technique) already exists in tested_hypotheses. Duplicates are skipped silently.

**Phase ③ — Hypothesis Generation**
- Reads target model
- Runs two tracks in sequence:
  - **Track 1 (baseline):** CVE matching against exact versions; nuclei scan — fast, low expectations
  - **Track 2 (primary):** Novel hypothesis generation — see below
- **Scoring (1–10 scale, equal weights):**
  - *Novelty* — 10 if not in any prior disclosure or CVE, 5 if a known variant, 1 if a direct CVE match
  - *Exploitability* — 10 if attack surface confirmed in target model, 5 if probable, 1 if speculative
  - *Impact* — 10 if Critical/High (account takeover, data breach), 5 if Medium, 1 if Low
  - *Effort (inverted)* — 10 if testable in under 10 min, 5 if 10–30 min, 1 if over 30 min
  - Final score = average of four dimensions. Sort descending.
- Writes scored pending queue to target model `hypotheses_queue` field (distinct from `tested_hypotheses` which is the completed history); also inserts into bountyhound.db hypotheses table
- **Field clarification:** `tested_hypotheses` = completed attempts with outcomes; `hypotheses_queue` = pending scored queue for current session. Both exist in target-model.json. Phase ② field list should include both.

**Phase ④ — Browser Testing**
- Each hypothesis tested in Chrome via Claude-in-Chrome browser automation
- Proxy captures all traffic
- GIF recorded for each test attempt
- Screenshots captured for evidence

**Phase ⑤ — 4-Layer Validation**
- See full spec below — hard gate, no exceptions

**Phase ⑥ — Report**
- Uses report-psychology skill
- Writes H1-ready markdown to `findings/<program>/reports/`
- Writes finding metadata to bountyhound.db findings table
- Includes: GIF path, curl chain, impact statement, CVSS score, draft report

---

### Hypothesis Engine (Track 2 — Novel Generation)

The valuable hypotheses come from reasoning about the specific implementation, not from CVE lists. The hypothesis engine generates novel hypotheses by:

1. **Implementation reasoning** — read source code, understand developer intent, ask "where would a developer under deadline pressure skip validation in this specific app?"
2. **Business logic abuse** — understand what the app does; find ways to get something for nothing (price manipulation, role confusion, state bypass)
3. **Component interaction** — how does auth interact with caching? Does the CDN strip a security header? Does the API gateway trust an internal header?
4. **Recent change analysis** — read git commits and changelogs; what was just fixed often has an unpatched sibling nearby
5. **Variant generation** — if a CVE was patched, what is the closest variant the patch might have missed?
6. **Adversarial framing** — "If I built this feature under deadline, where would I cut corners?" Test those spots.

The hypothesis engine uses the deep skills as lenses, not checklists:
- OAuth present → load oauth-auth-deep reasoning framework
- Rails detected → load framework-idor.md Rails section
- JWT found → load JWT deduction table from reasoning-framework.md
- GraphQL present → load GraphQL introspection patterns
- Only loads skills relevant to this target's actual stack

---

### 4-Layer Validator (validator.md)

**Hard rule:** A finding that fails any layer is silently discarded. You only ever see confirmed findings.

**Layer 0 — By-Design Check (runs before any testing)**

Checks whether the observed behaviour is intentional before any attack is attempted. Sources consulted:
- Program policy page and scope rules
- Public documentation for this feature
- GitHub issues and closed PRs
- Changelog and release notes
- Prior H1 disclosed reports for this program
- CODEX CVE list in bountyhound.db
- Source code comments and RFC/spec for the protocol

PASS = confirmed not by design, with cited evidence
FAIL = silently discarded, reason logged ("by design: see [source]")

**Challenge Protocol (baked into validator.md and all hunt agents):**
- One "is this by design?" or "is this intended?" from the user = immediate re-evaluation with fresh eyes
- The system does NOT defend the finding
- The system re-checks Layer 0 sources immediately and reports honestly with cited evidence
- If any doubt exists after re-check → discard
- There is no second ask needed. Ever.

**Layer 1 — Browser Reproduction**
Execute exploit in Chrome. Record GIF. Proxy captures raw HTTP. Screenshot impact.

PASS condition varies by vulnerability class:
- *Active exploitation* (XSS, CSRF, auth bypass, IDOR): impact is directly visible in browser UI (alert fired, data displayed, session obtained)
- *Information disclosure* (CSP header leaks, JS secrets, error messages): impact is observable in DevTools Network tab or proxy capture — not necessarily visible in rendered page; this counts as Layer 1 pass
- *SSRF / blind injection*: impact is observable in proxy capture (outbound request to attacker-controlled server) or server-side response change — counts as pass
- *Missing security headers / config issues*: impact is confirmed by absence of expected header in proxy capture — counts as pass

FAIL = no observable impact in browser, DevTools, or proxy capture. Discard.

**Layer 2 — Curl Chain Generation**
Extract minimal request sequence from proxy capture. Strip non-essential headers/params. Re-run headlessly. Confirm same response/impact.
PASS = curl chain reproduces impact. FAIL = discard (browser fluke, not exploitable).

**Layer 3 — Impact Analysis**
What data/functionality is exposed or modified? How many users affected? Is it exploitable without special access? What is the business impact? Calculate CVSS.
PASS = real impact confirmed and scored. FAIL = discard (no measurable impact).

**Output of a confirmed finding:**
- GIF recording of the browser exploit
- Paste-and-run curl chain
- Impact proof (data exposed, user count, CVSS)
- H1-ready draft report

---

### Unified Database — bountyhound.db

Single SQLite database replacing CODEXDATABASE.db and h1-programs.db.

**Tables:**

| Table | Source | Purpose |
|-------|--------|---------|
| `programs` | migrated from h1-programs.db | HackerOne/Bugcrowd/Intigriti program metadata |
| `cves` | migrated from CODEXDATABASE.db | CVE + exploit data |
| `targets` | new | Target model per program |
| `endpoints` | new | Discovered endpoints per target |
| `hypotheses` | new | Generated hypotheses + outcome + tested timestamp |
| `findings` | new | Confirmed findings: severity, status, report path, payout |
| `hunt_sessions` | new | Hunt history: target, duration, hypotheses tested, findings count |
| `evidence` | new | GIF paths, screenshot paths, curl chains per finding |

**Migration:** One-time script `migrate_to_bountyhound_db.py`. Procedure:
1. Back up both source databases: `CODEXDATABASE.db.bak`, `h1-programs.db.bak`
2. Create `bountyhound.db` with full schema
3. Import CODEXDATABASE.db → `cves` table; import h1-programs.db → `programs` table
4. Verify: row count in bountyhound.db must be >= row count in each source database. If not, abort and leave source files intact.
5. Only after verification passes: delete `CODEXDATABASE.db` and `h1-programs.db` (backups remain)
6. Update scrape_hackerone_*.py to write directly to bountyhound.db programs table

**Evidence table foreign key:** `evidence.finding_id` is a foreign key to `findings.id`. One finding may have many evidence rows (multiple GIFs, multiple screenshots, one curl chain per attempt).

**Relationships:**
- `targets.program_id` → `programs.id`
- `endpoints.target_id` → `targets.id`
- `hypotheses.target_id` → `targets.id`
- `findings.hypothesis_id` → `hypotheses.id`, `findings.target_id` → `targets.id`
- `evidence.finding_id` → `findings.id`
- `hunt_sessions.target_id` → `targets.id`

---

## File Structure After Redesign

```
BountyHound/
├── bountyhound-agent/
│   ├── agents/
│   │   ├── intelligence-loop.md     # NEW: main hunt orchestrator
│   │   ├── target-researcher.md     # NEW: deep recon + model builder
│   │   ├── hypothesis-engine.md     # NEW: novel hypothesis generation
│   │   ├── validator.md             # NEW: 4-layer validation
│   │   ├── reporter-agent.md        # KEPT
│   │   └── auth-manager.md          # KEPT
│   ├── skills/
│   │   ├── target-research/         # NEW
│   │   ├── validation/              # NEW
│   │   └── [21 existing skills]     # ALL KEPT
│   ├── commands/
│   │   ├── hunt.md                  # KEPT
│   │   └── creds.md                 # KEPT
│   └── data/
│       └── bountyhound.db           # NEW: unified database
│
├── findings/
│   └── <program>/
│       ├── target-model.json        # NEW: per-target model
│       └── reports/
│
├── [tool microservices — all kept]
├── proxy-engine/                    # KEPT
├── sync.py                          # KEPT
├── repatch.py                       # KEPT
└── migrate_to_bountyhound_db.py     # NEW: one-time migration
```

---

## Success Criteria

1. Running `/hunt <target>` produces zero findings that require the user to manually verify whether they are by design
2. Every finding surfaces with a GIF, a working curl chain, and an impact statement
3. The hypothesis engine generates at least one novel hypothesis (not a direct CVE match) per hunt session
4. The target model persists and is reused on second hunt of the same target — no repeated research phase
5. The challenge protocol works: one "is this by design?" resolves honestly in one response with cited evidence
6. bountyhound.db contains all data previously in CODEXDATABASE.db and h1-programs.db

---

## Sub-Projects (implementation order)

This spec covers one full redesign implemented in four sub-projects with explicit dependencies:

1. **Database migration** *(no dependencies)* — create bountyhound.db schema, migrate data, delete old DBs, update scrapers. Testable: verify row counts match source DBs.

2. **Agent cleanup** *(no dependencies)* — audit engine/core, delete unused agents, remove stale docs. Can run in parallel with sub-project 1. Testable: verify 5 core agents + 4 new agent stubs exist, no broken imports.

3. **New skills** *(no dependencies)* — write skills/target-research/ and skills/validation/ in full before the agents reference them. Testable: manually invoke each skill and verify it loads without errors.

4. **Core agents rebuild** *(depends on 1 and 3)* — write intelligence-loop, target-researcher, hypothesis-engine, validator. These reference bountyhound.db (sub-project 1) and the new skills (sub-project 3). Do not start sub-project 4 until 1 and 3 are complete.

**Correct implementation order:** 1 and 3 in parallel → 2 in parallel with both → 4 last.
