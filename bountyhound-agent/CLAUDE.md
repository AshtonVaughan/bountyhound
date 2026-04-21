# BountyHound - Claude Code Bug Bounty System

## Typography Rule

NEVER use em dashes (—) in any output, report, markdown, or code. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.

## Architecture

BountyHound runs entirely in Claude Code. There is no separate backend process.

```
bountyhound-agent/
├── agents/                     # 7 orchestration agents
│   ├── intelligence-loop.md    # Root orchestrator - invoked by /hunt (8-phase pipeline)
│   ├── target-researcher.md    # Phase ① - recon, 15-step model builder
│   ├── hypothesis-engine.md    # Phase ③ - 3-track, 8-lens scored hypothesis queue (CVE + Novel + Cross-target)
│   ├── validator.md            # Phase ⑤ — 4-layer validation gate
│   ├── reporter-agent.md       # Phase ⑥ — H1-ready report generation
│   ├── auth-manager.md         # Phase ①.8 — test account creation and tokens
│   ├── source-code-auditor.md  # Source review (invoked when source_available: true)
│   └── reference/              # Full detail docs for thin agents
│       ├── auth-manager-full.md
│       └── reporter-agent-full.md
├── skills/                     # 41 Claude Code skills
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
│   ├── blind-injection/        # Blind SQLi/SSRF/XXE/CMDi with OOB callbacks
│   ├── nuclei-gen/             # Generate custom nuclei templates from target model
│   ├── headless-mode/          # Overnight unattended API-based testing
│   ├── parallel-hunting/       # Multi-agent parallel hypothesis testing (3-5x throughput)
│   ├── vps/                    # VPS lifecycle, interactsh deployment, OOB infra
│   ├── h1-submit/              # HackerOne direct API submission workflow
│   ├── stealth-mode/           # Adaptive rate/timing evasion (4 escalation levels)
│   ├── negative-testing/       # Error path exploitation, malformed input testing
│   ├── anomaly-detection/      # Response anomaly profiling and convergent signal detection
│   ├── campaign-planner/       # Multi-session strategic hunt campaigns
│   ├── crypto-audit/           # Cryptographic implementation flaws (RNG, nonce reuse, padding oracle, KDF, downgrade)
│   ├── request-smuggling/      # HTTP request smuggling (CL.TE, TE.CL, H2.CL, browser desync, cache poisoning)
│   ├── deserialization-deep/   # Deep deserialization exploitation (Java, PHP, Python, Ruby, .NET, Node.js gadget chains)
│   ├── race-conditions-deep/   # Advanced race conditions (DB isolation, distributed locks, TOCTOU, single-packet attacks)
│   ├── side-channel/           # Side-channel attacks (timing oracles, cache inference, statistical proof methodology)
│   ├── memory-corruption/      # Memory corruption (buffer overflow, UAF, fuzzing, crash triage, source audit)
│   └── reverse-engineering/    # Systematic RE (Ghidra/Frida, protocol RE, anti-RE bypass, secret extraction)
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
| `/hunt <target>` | Full 8-phase autonomous hunt |
| `/creds <action>` | Manage saved credentials (list, show, add, refresh) |
| `/agents` | List available agents |
| `/feedback` | Handle program response to a submitted report |
| `/campaign <target>` | Multi-session strategic hunt campaign |

## The 8-Phase Hunt Pipeline

```
/hunt <target>
      │
      ▼
① TARGET RESEARCH          (~25 min, skipped if model ≤14d old)
  target-researcher agent (15 steps)
  ├── Subdomain enum (amass)
  ├── Port scan (nmap)
  ├── Platform detection (Bubble.io/Firebase/Supabase)
  ├── Tech stack fingerprint (browser)
  ├── JS bundle crawl - endpoints, auth flows, secrets
  ├── Source code read (GitHub, if public)
  ├── CVE lookup (bountyhound.db CODEX)
  ├── Prior disclosures (bountyhound.db + H1 hacktivity)
  ├── 5 min authenticated browse (auth-manager agent)
  ├── Historical endpoint discovery (Wayback Machine)
  ├── Google dorking (admin panels, config files, secrets)
  ├── Certificate transparency mining (crt.sh)
  ├── DNS record enumeration (TXT, MX, CNAME, SPF)
  ├── Mobile app API discovery
  └── Scope expansion analysis (third-party integrations)
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
  ├── Track 1: CVE baseline (15% effort)
  ├── Track 2: Novel hypotheses via 7 lenses (80% effort)
  │   └── Lens 7: Trust Assumption Mapping (NEW)
  └── Track 3: Cross-target pattern matching from memory/patterns.md (5%)
  Scored with ROI-adjusted weighting from program bounty table.
  Sorted descending. Deduped against bountyhound.db.
      │
      ▼
④ BROWSER TESTING          (~15 min)
  intelligence-loop executes directly
  Chrome browser + proxy capture + GIF recording per hypothesis
  Includes: negative testing (@negative-testing skill)
  Includes: stealth mode (@stealth-mode skill) when rate-limited
      │
      ▼
④b OBSERVATION REFRESH     (after every 5 tests or unexpected behavior)
  Feeds testing observations back to hypothesis-engine (mode: "refresh")
  Generates new hypotheses from discovered endpoints, error messages, headers
  Max 2 refresh cycles per hunt.
      │
      ▼
⑤ 4-LAYER VALIDATION       (per confirmed hypothesis)
  validator agent + @validation skill
  Layer 0A: Quick by-design check (policy + prior disclosures)
  Layer 1:  Browser reproduction (must observe impact)
  Layer 0B: Deep by-design check (docs, GitHub, changelog, CVE)
  Layer 2:  Curl chain / browser PoC / OOB chain
  Layer 3:  Impact analysis + CVSS 3.1
  → PROVEN/PARTIAL/CLAIMED → Phase ⑤b
  → NEEDS-PROOF/WAF-BLOCKED → surfaced to user
  → Clearly false/by-design → discarded silently
      │
      ▼
⑤b CHAIN DISCOVERY         (automatic after validation)
  Tests every confirmed finding against every other finding + attack surface
  Discovers A+B chains that escalate impact (e.g., info leak + IDOR = ATO)
  Writes to chain-canvas.md. Chains get combined reports in Phase ⑥.
      │
      ▼
⑥ REPORT                   (per validated finding or chain)
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
| `hunt_metrics.py` | `hunt_metrics.py start <program>` | Track per-session KPIs: hit rate, findings/hour, bounty/hour, lens effectiveness |
| | `hunt_metrics.py end <session_id> --bounty <aud>` | End session, calculate KPIs |
| | `hunt_metrics.py report [program]` | Show performance report across sessions |
| | `hunt_metrics.py lens-effectiveness [program]` | Which lenses produce the most findings? |
| | `hunt_metrics.py scoring-calibration [program]` | Predicted vs actual hypothesis outcomes |
| `cve_feed.py` | `cve_feed.py check [--program <handle>]` | Check NVD for new CVEs affecting hunted targets' tech stacks |
| | `cve_feed.py watch --interval 3600` | Continuous CVE monitoring |
| `bounty_analytics.py` | `bounty_analytics.py analyze <program>` | Analyze disclosed reports for payout patterns and hunting recommendations |
| | `bounty_analytics.py top-programs` | Find highest-ROI programs to hunt |
| | `bounty_analytics.py vuln-payouts` | Average payout by vulnerability class across all programs |
| `idor_auto.py` | `idor_auto.py generate <program>` | Auto-generate IDOR test config from target model endpoints |
| | `idor_auto.py run <program> [--quick]` | Run full IDOR test matrix between two accounts |
| | `idor_auto.py results <program>` | Show IDOR test results |

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
| `findings/<t>/memory/triager-model.json` | Per-program triager behavior model | Updated after each /feedback |
| `findings/<t>/campaign.json` | Multi-session campaign state | Updated each /campaign session |

Load memory at the start of every hunt:
```bash
python {AGENT}/memory/load_memory.py {target}
```

## Performance Tracking

BountyHound tracks hunt performance metrics to enable self-improvement:

```bash
# Start tracking at the beginning of every hunt
python {AGENT}/engine/core/hunt_metrics.py start <program>

# Record events during the hunt (called by intelligence-loop automatically)
python {AGENT}/engine/core/hunt_metrics.py record <session_id> finding_confirmed --details '{"score": 7.5}'

# End session with bounty earned
python {AGENT}/engine/core/hunt_metrics.py end <session_id> --bounty 5000

# View reports
python {AGENT}/engine/core/hunt_metrics.py report                    # All programs
python {AGENT}/engine/core/hunt_metrics.py lens-effectiveness         # Which lenses work?
python {AGENT}/engine/core/hunt_metrics.py scoring-calibration        # Is scoring accurate?
```

Metrics feed back into the system:
- Lens effectiveness data adjusts hypothesis generation effort allocation
- Scoring calibration identifies when the weighted formula needs retuning
- Bounty/hour data validates ROI-adjusted scoring accuracy

## Intelligence Tools

Live intelligence gathering between and during hunts:

```bash
# Check for new CVEs affecting your targets (run daily)
python {AGENT}/engine/core/cve_feed.py check

# Analyze program payout patterns before choosing targets
python {AGENT}/engine/core/bounty_analytics.py analyze <program>
python {AGENT}/engine/core/bounty_analytics.py top-programs

# Automated IDOR testing
python {AGENT}/engine/core/idor_auto.py run <program>
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

## ProxyEngine MCP Tools

ProxyEngine is the local interception proxy (mitmproxy-based) running at 127.0.0.1:8080 with a FastAPI backend at 127.0.0.1:8187. Start it with `proxyengine` before a hunt. All tools below are available as `mcp__proxy-engine__<name>`.

**Before using:** Call `mcp__proxy-engine__proxy_status` to verify the engine is running.

**Traffic capture** - requires browser proxied through 127.0.0.1:8080:

| Tool | Purpose |
|------|---------|
| `proxy_status` | Check engine health, flow count, active scans |
| `proxy_get_flows` | List captured HTTP flows (filter by URL/method/limit) |
| `proxy_get_flow` | Get full request + response for a single flow |
| `proxy_set_scope` | Lock deep analysis to target patterns (e.g., `*.target.com`) |
| `proxy_get_scope` | See current scope config |

**Active testing** - use these during Phase ④:

| Tool | Purpose |
|------|---------|
| `proxy_send_request` | Fire a custom HTTP request (Burp Repeater equivalent) |
| `proxy_replay_flow` | Replay a captured flow with optional header/body overrides - primary IDOR tool |
| `proxy_run_intruder` | Fuzz marked positions with payloads (Burp Intruder equivalent) |
| `proxy_run_scanner` | Run Nuclei + active vuln checks on a target URL |
| `proxy_scan_flow` | Run active checks on a single captured flow |

**Findings:**

| Tool | Purpose |
|------|---------|
| `proxy_get_findings` | All passive + active + Nuclei findings, filterable by severity/source |
| `proxy_export_nuclei` | Export a flow as a Nuclei YAML template |

**Recon:**

| Tool | Purpose |
|------|---------|
| `proxy_get_sitemap` | URL tree discovered from proxied traffic |
| `proxy_graphql_intro` | Introspect a GraphQL endpoint (full schema) |
| `proxy_graphql_query` | Execute a GraphQL query |

**OOB callbacks** - for blind SSRF/XXE/injection:

| Tool | Purpose |
|------|---------|
| `proxy_oob_generate` | Generate a unique OOB callback URL/payload |
| `proxy_oob_check` | Check for incoming DNS/HTTP/SMTP callbacks |

**ML analysis:**

| Tool | Purpose |
|------|---------|
| `proxy_ml_predict` | Run ML vuln prediction on a flow (SQLi, XSS, SSRF, IDOR probabilities) |
| `proxy_ml_anomalies` | Get anomaly-scored flows (unusual patterns worth investigating) |

**Utilities:**

| Tool | Purpose |
|------|---------|
| `proxy_decode` | Encode/decode base64, URL, JWT, hex, HTML |
| `proxy_diff` | Diff two response bodies to spot subtle differences (IDOR comparison) |

**Common patterns:**

```
# Set scope before starting a hunt
mcp__proxy-engine__proxy_set_scope(include_patterns="*.target.com,api.target.com")

# After browsing through the proxy, get all captured flows
mcp__proxy-engine__proxy_get_flows(limit=200, search="api/users")

# IDOR test: replay a flow as a different user
mcp__proxy-engine__proxy_replay_flow(
  flow_id="<id>",
  modify_headers='{"Authorization": "Bearer <user_b_token>"}'
)

# Blind SSRF/XXE: generate OOB payload, inject it, then check
mcp__proxy-engine__proxy_oob_generate()  # returns {payload, host}
# ... inject the payload URL into the target ...
mcp__proxy-engine__proxy_oob_check()     # returns {interactions: [...]}

# Quick ML triage on a suspicious flow
mcp__proxy-engine__proxy_ml_predict(flow_id="<id>")

# Fuzz a parameter
mcp__proxy-engine__proxy_run_intruder(
  request_template="GET /api/users/§PAYLOAD§ HTTP/1.1\nHost: target.com\nAuth: Bearer <token>",
  payloads="1\n2\n3\n../admin\n0\n-1",
  attack_type="sniper"
)
```

---

## MCP Tools Available

Tools run as direct subprocess calls via `tool_runner.py`. No microservices, no HTTP proxying.
The tool binary must be on PATH. Use `*_server_status()` to check availability before scanning.

| Tool | Scan Function | Status Check |
|------|--------------|--------------|
| Nuclei | `nuclei_scan(urls, templates, severity, timeout)` | `nuclei_server_status()` |
| SQLMap | `sqlmap_test(url, method, data, level, risk, timeout)` | `sqlmap_server_status()` |
| Nmap | `nmap_scan(targets, ports, scan_type, aggressive, timeout)` | `nmap_server_status()` |
| Ffuf | `ffuf_fuzz(url, wordlist, method, match_status, filter_status, timeout)` | `ffuf_server_status()` |
| Amass | `amass_enum(domain, passive, include_unresolved, timeout)` | `amass_server_status()` |
| Gobuster | `gobuster_fuzz(url, wordlist, method, timeout)` | `gobuster_server_status()` |
| BloodHound | `bloodhound_enum(domain, username, password, timeout)` | `bloodhound_server_status()` |
| Metasploit | `metasploit_exploit(module, target, lhost, lport, timeout)` | `metasploit_server_status()` |
| Nessus | `nessus_scan(targets, scan_type, timeout)` | `nessus_server_status()` |
| Volatility | `volatility_analyze(memory_file, profile, timeout)` | `volatility_server_status()` |
| Zeek | `zeek_analyze(pcap_file, rules, timeout)` | `zeek_server_status()` |

Full tool reference: `skills/hunt/references/tooling.md`

## Key Principles

1. **Database first** — check bountyhound.db before every test. Prevents duplicate work.
2. **Browser for logic bugs** — Chrome automation gives you real sessions, real JS, real cookies.
3. **Validate everything** — 4-layer gate, no exceptions.
4. **Capture evidence** — screenshots, GIFs, curl chains, before/after diffs.
5. **Stay in scope** — read program-map.md before every hunt. Never navigate off-target.
6. **Surface unproven findings** — `[NEEDS-PROOF]` and `[WAF-BLOCKED]` go to the user, not the trash.
