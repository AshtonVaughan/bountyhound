# BountyHound - Claude Code Bug Bounty System

## Typography Rule

NEVER use em dashes (—) in any output, report, markdown, or code. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.

## Architecture

BountyHound runs entirely in Claude Code. There is no separate backend process.

```
bountyhound-agent/
├── agents/                     # 7 orchestration agents
│   ├── intelligence-loop.md    # Root orchestrator — invoked by /hunt
│   ├── target-researcher.md    # Phase ① — recon, 8-step model builder
│   ├── hypothesis-engine.md    # Phase ③ — scored attack hypothesis queue
│   ├── validator.md            # Phase ⑤ — 4-layer validation gate
│   ├── reporter-agent.md       # Phase ⑥ — H1-ready report generation
│   ├── auth-manager.md         # Phase ①.8 — test account creation and tokens
│   ├── source-code-auditor.md  # Source review (invoked when source_available: true)
│   └── reference/              # Full detail docs for thin agents
│       ├── auth-manager-full.md
│       └── reporter-agent-full.md
├── skills/                     # 24 Claude Code skills
│   ├── hunt/                   # Main hunt orchestration skill (/hunt command)
│   ├── validation/             # 4-layer validation protocol
│   ├── injection-attacks/      # XSS, SQLi, SSTI, XXE, OS injection
│   ├── auth-attacks/           # JWT, OAuth, session, MFA bypasses
│   ├── oauth-auth-deep/        # Deep OAuth 2.0 / OIDC / SAML methodology
│   ├── waf-bypass/             # WAF evasion techniques
│   ├── scope-parser/           # Parse HackerOne/Bugcrowd scope rules
│   ├── report-psychology/      # Effective report writing
│   ├── exploit-gate/           # Pre-report quality gate + claim protocol
│   ├── cloud/                  # AWS, GCP, Azure security testing
│   ├── mobile/                 # iOS/Android: Frida, APK analysis
│   ├── blockchain/             # Smart contract, DeFi
│   ├── hardware/               # IoT, firmware analysis
│   ├── llm-security-deep/      # LLM prompt injection, jailbreaks
│   ├── data-exfil-deep/        # Data exfiltration techniques
│   ├── sast/                   # Static analysis security testing
│   ├── omnihack/               # Advanced: kernel, anti-cheat, DLL injection
│   ├── feedback/               # Handle H1/Bugcrowd analyst responses
│   ├── creds/                  # Credential management (/creds command)
│   ├── target-research/        # Recon reference (fingerprinting, JS analysis)
│   ├── idor-harness/           # Systematic IDOR/BOLA object-swap testing
│   ├── blind-injection/        # Blind SQLi/SSRF/RCE with OOB callbacks
│   ├── nuclei-gen/             # Generate custom nuclei templates from target model
│   └── h1-submit/              # HackerOne direct API submission workflow
├── commands/                   # Slash command definitions
│   ├── hunt.md                 # /hunt <target>
│   ├── creds.md                # /creds <action>
│   ├── agents.md               # /agents (list)
│   └── feedback.md             # /feedback
├── data/                       # Databases and schema
│   ├── bountyhound.db          # Main operational DB (targets, findings, hypotheses)
│   ├── h1-programs.db          # HackerOne program scrapes (19MB)
│   ├── CODEXDATABASE.db        # CVE/vulnerability reference (42MB)
│   ├── db.py                   # Python DB interface (BountyHoundDB class)
│   ├── schema.sql              # DB schema
│   └── target-model-schema.md  # Canonical target model JSON schema
├── memory/                     # Global hunting memory
│   ├── hunting-playbook.md     # Personal methodology, priorities, skip lists
│   ├── patterns.md             # Cross-target proven techniques
│   ├── identity.md             # Email addresses for test accounts
│   └── load_memory.py          # Memory loader script
└── engine/                     # Python execution layer
    ├── core/                   # Database, AI orchestration, analytics
    │   ├── h1_submitter.py         # H1 API client (submit, fetch disclosures)
    │   ├── h1_disclosed_checker.py # Semantic duplicate detection vs H1 disclosures
    │   ├── h1_api_cli.py           # CLI wrapper — call from agent Bash blocks
    │   ├── js_differ.py            # JS bundle change detection between hunts
    │   ├── schema_importer.py      # OpenAPI/GraphQL schema → endpoint list
    │   ├── takeover_scanner.py     # Subdomain takeover detection
    │   ├── git_miner.py            # GitHub secret/endpoint mining
    │   ├── idor_harness.py         # Systematic IDOR/BOLA object-swap tester
    │   ├── scope_monitor.py        # Program scope change monitoring
    │   ├── program_advisor.py      # Program selection advisor (ROI scoring)
    │   └── nuclei_template_gen.py  # Custom nuclei template generation from CVEs
    ├── agents/                 # 11 specialist tool wrappers (sqlmap, katana, etc.)
    └── vps/                    # Vultr VPS lifecycle manager (vultr.py)
```

## Canonical Paths

```
BASE:     C:/Users/vaugh/Desktop/BountyHound
AGENT:    {BASE}/bountyhound-agent
FINDINGS: {BASE}/findings/{target}
MEMORY:   {AGENT}/memory
DB:       {AGENT}/data/bountyhound.db
TMP:      {FINDINGS}/tmp
VPS:      {AGENT}/engine/vps/vultr.py
VPS_STATE: {FINDINGS}/tmp/vps-state.json
```

**All agents and skills derive paths from these.** Never hard-code a path anywhere else.

## Commands

| Command | Description |
|---------|-------------|
| `/hunt <target>` | Full 6-phase autonomous hunt |
| `/creds <action>` | Manage saved credentials (list, show, add, refresh) |
| `/agents` | List available agents |
| `/feedback` | Handle program response to a submitted report |

## The 6-Phase Hunt Pipeline

```
/hunt <target>
      │
      ▼
① TARGET RESEARCH          (~20 min, skipped if model ≤14d old)
  target-researcher agent
  ├── Subdomain enum (amass)
  ├── Port scan (nmap)
  ├── Tech stack fingerprint (browser)
  ├── JS bundle crawl — endpoints, auth flows, secrets
  ├── Source code read (GitHub, if public)
  ├── CVE lookup (bountyhound.db CODEX)
  ├── Prior disclosures (bountyhound.db + H1 hacktivity)
  └── 5 min authenticated browse (auth-manager agent)
      │
      ▼
② BUILD TARGET MODEL       (auto, always)
  Writes findings/<program>/target-model.json
  Syncs to bountyhound.db targets table
  Schema: data/target-model-schema.md
      │
      ▼
③ HYPOTHESIS GENERATION    (~2-5 min)
  hypothesis-engine agent
  ├── Track 1: CVE baseline (20% effort)
  └── Track 2: Novel hypotheses from implementation reasoning (80%)
  Each scored 1-10 on Novelty / Exploitability / Impact / Effort
  Sorted descending. Deduped against bountyhound.db.
      │
      ▼
④ BROWSER TESTING          (~15 min)
  intelligence-loop executes directly
  Chrome browser + proxy capture + GIF recording per hypothesis
      │
      ▼
⑤ 4-LAYER VALIDATION       (per confirmed hypothesis)
  validator agent + @validation skill
  Layer 0A: Quick by-design check (policy + prior disclosures)
  Layer 1:  Browser reproduction (must observe impact)
  Layer 0B: Deep by-design check (docs, GitHub, changelog, CVE)
  Layer 2:  Curl chain / browser PoC / OOB chain
  Layer 3:  Impact analysis + CVSS 3.1
  → PROVEN/PARTIAL/CLAIMED → Phase ⑥
  → NEEDS-PROOF/WAF-BLOCKED → surfaced to user
  → Clearly false/by-design → discarded silently
      │
      ▼
⑥ REPORT                   (per validated finding)
  reporter-agent
  Writes: findings/<program>/reports/<finding-slug>.md
  Writes: bountyhound.db findings table
  Standard: first-try reproduction (triager who's never seen the target)
```

## Database Interface

**Use `data.db.BountyHoundDB` in all agents and scripts:**

```python
from data.db import BountyHoundDB
db = BountyHoundDB()

# Programs
program = db.get_program('vercel-open-source')

# CVEs
cves = db.get_cves_for_tech('next.js')

# Targets
target_id = db.upsert_target(program_id, domain, model_dict)

# Hypotheses
db.insert_hypothesis(program_id, hypothesis_dict)
db.update_hypothesis_status(hypothesis_id, 'tested')
```

The `engine/core/` layer (`engine.core.database`, `engine.core.db_hooks`) exists for the Python engine's internal use. Agents use `data.db` — it's simpler and covers everything the agents need.

## Engine Tools (Bash-Callable from Agents)

All tools below are invoked via Bash blocks in agents. Use `python {AGENT}/engine/core/<tool>.py --help` for full options.

| Tool | CLI | Purpose |
|------|-----|---------|
| `h1_api_cli.py` | `h1_api_cli.py submit <handle> <report.json> [files...]` | Submit to HackerOne API (auto-resolves weakness/scope IDs) |
| | `h1_api_cli.py lookup-weakness <handle> [vuln_type]` | List or resolve H1-internal weakness IDs for a program |
| | `h1_api_cli.py lookup-scope <handle> [url]` | List or resolve structured scope IDs for a program |
| | `h1_api_cli.py check-disclosed <handle> <report.json>` | Dedup check against publicly disclosed H1 reports |
| | `h1_api_cli.py my-reports [handle]` | List submitted reports, filtered by program |
| `js_differ.py` | `js_differ.py <findings_dir> <target> --store` | Detect JS bundle changes between hunts |
| `schema_importer.py` | `schema_importer.py <base_url> --out <file.json>` | Auto-discover OpenAPI/GraphQL/WSDL schemas → endpoint list |
| `takeover_scanner.py` | `takeover_scanner.py <subdomains_file>` | Detect dangling CNAME subdomain takeover candidates |
| `git_miner.py` | `git_miner.py <github_org_or_repo>` | Mine GitHub for secrets, endpoints, internal hostnames |
| `idor_harness.py` | `idor_harness.py <config.json>` | Run systematic object-ID swaps between two accounts |
| `scope_monitor.py` | `scope_monitor.py <handle> --check` | Detect program scope/bounty table changes since last check |
| `program_advisor.py` | `program_advisor.py --top 10 --tech <stack>` | Score programs by ROI: bounty table × tech match × competition |
| `nuclei_template_gen.py` | `nuclei_template_gen.py <target-model.json>` | Generate CVE-targeted nuclei templates from tech stack |

### H1 API Setup

Set these env vars (or in `.env`):
```
H1_API_TOKEN=your_api_token
H1_USERNAME=your_h1_username
```

Check status:
```bash
python {AGENT}/engine/core/h1_api_cli.py status
```

## Browser Automation

Claude's built-in Chrome browser is **always available** — no server, no startup, never down. It is the primary tool for all web interaction. Use it proactively throughout every hunt.

**Loading requirement:** Before calling any `mcp__claude-in-chrome__*` tool, load it via ToolSearch:
```
ToolSearch: "select:mcp__claude-in-chrome__<tool_name>"
```

**Always call `tabs_context_mcp` first** to get current tab IDs before creating or navigating. Never reuse tab IDs from a previous session.

```
mcp__claude-in-chrome__tabs_context_mcp      — get open tabs (ALWAYS call first)
mcp__claude-in-chrome__tabs_create_mcp       — open a new tab
mcp__claude-in-chrome__navigate              — navigate to URL
mcp__claude-in-chrome__read_page             — get page DOM/text (JS-rendered content)
mcp__claude-in-chrome__find                  — find elements by selector
mcp__claude-in-chrome__form_input            — fill and submit forms
mcp__claude-in-chrome__javascript_tool       — execute JS in page context (localStorage, cookies, globals)
mcp__claude-in-chrome__read_network_requests — capture full HTTP traffic (headers + bodies)
mcp__claude-in-chrome__read_console_messages — read JS console (token leaks, debug output)
mcp__claude-in-chrome__gif_creator           — record exploit sequence as animated GIF (evidence)
mcp__claude-in-chrome__computer              — screenshot current state
```

Do NOT use Playwright MCP tools. Do NOT use `WebFetch` for authenticated requests (it has no session). `WebFetch` is GET-only and unauthenticated — only use it for public, non-JS recon.

## Validation Rule

**Every finding must pass the 4-layer validator before reporting.**

Findings that don't reproduce in curl (or browser PoC for DOM-based vulns) are not reported — they're surfaced to the user as `[NEEDS-PROOF]` so the user can decide what to do.

## Authentication

Default test account credentials:
- `BOUNTYHOUND_GOOGLE_EMAIL` — Google OAuth account env var
- `BOUNTYHOUND_EMAIL` / `BOUNTYHOUND_PASS` — email/password env vars

Per-target credentials are written by auth-manager to:
```
{FINDINGS}/credentials/{target}-creds.env
```

Full credential format and account creation protocol: `agents/reference/auth-manager-full.md`

## Source Code Audits

When `source_available: true` in the target model, optionally invoke the source-code-auditor agent.

**Anti-overclaiming rules (mandatory):**

1. **Read ALL docs first** — secure-usage guides, threat models, prior audit reports
2. **Check prior audits** — bountyhound.db CODEX, GitHub Security Advisories, H1 disclosures
3. **Prove reachability** — grep for callers, trace data flow from user input to vulnerable sink
4. **Provide counter-arguments** — every finding must include "why this might NOT be a vulnerability"
5. **Use concrete language** — "attacker can X" not "could potentially X"

Source audit findings use the tag `"source": "source_audit"` in the finding record. See `agents/source-code-auditor.md` for the full methodology.

## Context Management (5 Rules)

These prevent context window crashes during long hunts:

1. **Pipe verbose output to files** — never print >50 lines of JSON/HTML inline
   ```bash
   curl ... > {TMP}/response.json
   python3 -c "import json; d=json.load(open('{TMP}/response.json')); print(len(d))"
   ```

2. **Max 2 parallel background agents** — wait for one to finish before spawning a third

3. **Compact between phases** — run `/compact` after recon, after testing, after sync

4. **Read selectively** — use `head_limit`, `head -20`, `jq`, or Python to extract only what's needed. Never dump entire files into context.

5. **Check agents one at a time** — read one background agent output, process it, then read the next.

All temporary/verbose output goes to: `{TMP}/` — create it with `mkdir -p {TMP}` at the start of each hunt.

## Memory System

| File | Purpose | Update rule |
|------|---------|------------|
| `memory/hunting-playbook.md` | Personal methodology, priorities, skip lists | Edit manually between hunts |
| `memory/patterns.md` | Cross-target proven techniques (max 50) | Haiku agent adds after each successful hunt |
| `memory/identity.md` | Test account emails and fallback rules | Edit manually |
| `findings/<t>/memory/context.md` | Per-target hunt history (rotates at 5 entries) | Haiku agent updates after hunt |
| `findings/<t>/memory/defenses.md` | WAF, rate limits, blocked patterns | Merged each hunt |
| `findings/<t>/memory/scope.md` | Parsed scope with `last_verified` date | Updated when scope is re-read |

Load memory at the start of every hunt:
```bash
python {AGENT}/memory/load_memory.py {target}
```

## Output Structure

```
findings/<program>/
├── program-map.md          # Scope, rules, bounty table
├── chain-canvas.md         # Exploit chains (persists across hunts, never reset)
├── target-model.json       # Target intelligence (Phase ② output, Phase ③ input)
├── phases/                 # Phase handoff files
│   ├── 01_recon.json
│   └── 01_recon_previous.json
├── tmp/                    # Verbose output — pipe everything here
├── reports/                # HackerOne-ready reports
│   ├── <finding-slug>.md
│   └── reproduce.py
├── evidence/               # GIFs, screenshots, OOB logs
└── memory/                 # Per-target memory files
    ├── context.md
    ├── defenses.md
    └── scope.md
```

## MCP Tools Available

When MCP tools are running (check with capability probe in hunt skill Step 0):

| Tool | Purpose |
|------|---------|
| `mcp__bounty-hound__amass_*` | Subdomain enumeration |
| `mcp__bounty-hound__nmap_*` | Port/service scanning |
| `mcp__bounty-hound__nuclei_*` | Template-based vulnerability scanning |
| `mcp__bounty-hound__sqlmap_*` | SQL injection testing |
| `mcp__bounty-hound__ffuf_*` | Web fuzzing |
| `mcp__bounty-hound__gobuster_*` | Directory enumeration |
| `mcp__bounty-hound__nessus_*` | Comprehensive vulnerability scanning |
| `mcp__bounty-hound__metasploit_*` | Exploit execution |
| `mcp__bounty-hound__bloodhound_*` | AD enumeration |
| `mcp__bounty-hound__volatility_*` | Memory forensics |
| `mcp__bounty-hound__zeek_*` | Network traffic analysis |

Full tool reference: `skills/hunt/references/tooling.md`

## Key Principles

1. **Database first** — check bountyhound.db before every test. Prevents duplicate work.
2. **Browser for logic bugs** — Chrome automation gives you real sessions, real JS, real cookies.
3. **Validate everything** — 4-layer gate, no exceptions.
4. **Capture evidence** — screenshots, GIFs, curl chains, before/after diffs.
5. **Stay in scope** — read program-map.md before every hunt. Never navigate off-target.
6. **Surface unproven findings** — `[NEEDS-PROOF]` and `[WAF-BLOCKED]` go to the user, not the trash.
