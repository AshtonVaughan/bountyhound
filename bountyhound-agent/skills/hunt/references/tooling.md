# BountyHound Tool Inventory

All tools available during a hunt. Consult this when choosing how to test a hypothesis — the right tool saves significant time over doing everything manually.

All paths are relative to:
- `AGENT = C:/Users/vaugh/Desktop/BountyHound/bountyhound-agent`
- `BASE  = C:/Users/vaugh/Desktop/BountyHound`

---

## Proxy-Engine MCP Tools

When the proxy-engine is running (`http://127.0.0.1:8187`), these MCP tools are available. Use them instead of raw curl for any meaningful test — they capture full request/response flows, enable replay, and feed the passive scanner automatically.

| Tool | Use For |
|------|---------|
| `repeater_send` | Send any HTTP request — replaces curl, captures full flow |
| `repeater_replay` | Replay a captured flow with modifications |
| `intruder_attack` | Fuzz parameters with built-in payloads: `@sqli`, `@xss`, `@ssti`, `@path_traversal`, `@nosqli`, `@headers_inject` |
| `intruder_status` | Check fuzzing job progress and results |
| `scanner_scan` | Active scan a URL for sqli, xss, open_redirect, ssrf |
| `passive_findings` | Get passive scanner findings: missing headers, CORS issues, info disclosure, cookie problems |
| `collaborator_generate` | Get OAST payload URL for blind SSRF / blind XSS / blind XXE detection |
| `collaborator_poll` | Check for out-of-band DNS/HTTP interactions on your OAST payload |
| `sequencer_start` | Analyze token entropy — session IDs, CSRF tokens, password reset tokens |
| `comparer_diff` | Diff two responses side-by-side — essential for IDOR (User A vs User B response) |
| `decoder_decode` | Decode JWT (header+payload), base64, URL encoding |
| `export_flow` | Export any captured flow as curl / Python / raw HTTP for reproduce.py |
| `proxy_list_flows` | Search captured traffic by host, method, status, or content |
| `proxy_get_flow` | Get full request + response for a specific flow ID |
| `proxy_annotate_flow` | Tag an interesting flow with a note for evidence |
| `target_analysis` | Tech fingerprint derived from all observed traffic for the host |
| `discovery_start` | Content discovery (directory/file fuzzing) on a URL |
| `discovery_status` | Check content discovery job results |
| `crawler_start` | Crawl a URL to depth N, maps all links and forms |
| `crawler_status` | Get crawl results |
| `scope_set` | Lock proxy to only capture target domain traffic |
| `passive_toggle` | Enable/disable passive scanner |
| `project_save` | Save current proxy session as named project |

**When proxy is down:** Fall back to raw curl + manual browser DevTools. The proxy tools are faster and more thorough, but not required.

---

## bounty-hound MCP Tools (Security Tool Suite)

These 44 MCP tools are registered via the `bounty-hound` MCP server (`{BASE}/mcp-unified-server/main.py`). Each tool follows the async job pattern: start a job → receive `job_id` → poll for results. All jobs run in the background so you can continue working while they run.

**Availability check:**
```bash
curl -s http://127.0.0.1:8188/api/status 2>/dev/null | python -c "import sys,json; print('NUCLEI:OK')" 2>/dev/null || echo "NUCLEI:DOWN"
```

### Recon & Enumeration

| Tool | Use For | Key Parameters |
|------|---------|----------------|
| `amass_enum(domain)` | Subdomain enumeration — most thorough, slowest | `passive=True` for stealth |
| `amass_status(job_id)` | Get subdomain results | — |
| `nmap_scan(targets, ports, scan_type)` | Port scanning + service detection | `scan_type="sV"` default, `aggressive=True` for OS detect |
| `nmap_status(job_id)` | Get open ports + service banners | — |
| `gobuster_fuzz(url, wordlist)` | Directory/file enumeration (fast) | Use with `@common` or `@api_endpoints` wordlists |
| `gobuster_status(job_id)` | Get discovered paths | — |
| `ffuf_fuzz(url, wordlist)` | Web fuzzing — supports `FUZZ` keyword anywhere in URL/headers/body | `filter_status="404"` default |
| `ffuf_status(job_id)` | Get fuzzing results | — |

### Vulnerability Scanning

| Tool | Use For | Key Parameters |
|------|---------|----------------|
| `nuclei_scan(urls, templates, severity)` | Template-based vuln scan — CVEs, misconfigs, exposures | `templates="http,cves"`, `severity="critical,high"` |
| `nuclei_status(job_id)` | Get nuclei findings | — |
| `sqlmap_test(url, method, data, level, risk)` | SQL injection detection + exploitation | `level=3,risk=2` for thorough; `level=1,risk=1` for safe |
| `sqlmap_status(job_id)` | Get injection findings | — |
| `nessus_scan(targets, scan_type)` | Comprehensive vuln scan (credentialed) | `scan_type="full"` for deep scan |
| `nessus_status(job_id)` | Get Nessus findings | — |

### Active Directory / Internal

| Tool | Use For |
|------|---------|
| `bloodhound_enum(domain, username, password)` | AD enumeration + attack path graph analysis |
| `bloodhound_status(job_id)` | Get AD paths and privileged accounts |
| `metasploit_exploit(module, target, lhost, lport)` | Run Metasploit exploit module |
| `metasploit_status(job_id)` | Get session/exploit status |

### Forensics & Traffic Analysis

| Tool | Use For |
|------|---------|
| `volatility_analyze(memory_file, profile)` | Memory dump analysis — extract credentials, processes, network |
| `volatility_status(job_id)` | Get memory forensics results |
| `zeek_analyze(pcap_file)` | Network traffic analysis — detect C2, exfil, anomalies |
| `zeek_status(job_id)` | Get traffic analysis results |

**Cancel any job:** `{tool}_cancel(job_id)` — e.g., `nmap_cancel(job_id)`
**Check tool health:** `{tool}_server_status()` — e.g., `nuclei_server_status()`

**Tool → hypothesis mapping:**

| Hypothesis type | Best bounty-hound MCP tool |
|-----------------|---------------------------|
| Subdomain discovery | `amass_enum` (thorough) or `gobuster_fuzz` (fast) |
| Port/service fingerprint | `nmap_scan` |
| CVE / known vuln | `nuclei_scan` with `templates="cves"` |
| SQLi confirmation | `sqlmap_test` |
| Directory discovery | `ffuf_fuzz` or `gobuster_fuzz` |
| Comprehensive scan | `nessus_scan` |

---

## Built-in Chrome Browser (Claude in Chrome)

Claude's built-in Chrome browser control — requires the Chrome extension connected (`claude --chrome`). Controls your actual Chrome browser directly, not a headless process. This means real sessions, real cookies, real JavaScript execution, and full DevTools access.

**Capabilities:**
- Navigate, click, type, fill forms — full interactive control
- Capture screenshots → save to `{FINDINGS}/tmp/`
- Record GIFs of multi-step interactions (evidence for reports)
- Read console logs — catches JS errors, token leaks in debug output
- Capture network requests — full request/response including headers and bodies
- Real browser fingerprint — no bot detection from `axios` UA

**Primary use cases during a hunt:**

| Task | How |
|------|-----|
| Program page (HackerOne/Bugcrowd) | Navigate + read all sections + screenshot |
| Tech stack fingerprint | Navigate target, read network requests, check headers |
| IDOR (two-user test) | Log in as User A → capture resource → switch to User B session → test access |
| Auth flow testing | Navigate login, intercept tokens from network requests, test bypass |
| Form-based injection | Fill form fields with payloads, observe responses |
| Business logic | Multi-step flows — add to cart, checkout, manipulate values between steps |
| Evidence capture | Screenshot + GIF every confirmed finding before and after |
| JS-heavy SPAs | Full JS execution — React/Vue/Angular apps work correctly |

**Network request capture** is particularly valuable — after browsing a feature, you get all HTTP requests with real headers, cookies, and tokens. Feed these directly into `repeater_send` or `sqlmap_test`.

**Evidence workflow:**
```
1. Screenshot the vulnerable state (before)
2. Perform the attack step in the browser
3. Screenshot the result (after)
4. Save both to {FINDINGS}/tmp/ with descriptive names
5. Record a GIF if the attack requires multiple steps
```

---

## Primary Agents (spawn via Agent tool)

These 5 agents cover the main hunt pipeline. Spawn them as subagents — read the agent file, then pass it as the skill_path to the Agent tool.

| Agent | Path | When to Use |
|-------|------|-------------|
| `phased-hunter` | `{AGENT}/agents/phased-hunter.md` | Main browser testing + triage orchestrator. Has the full proxy-engine tool reference. Spawn for Step 3 when you want to delegate a full test phase. |
| `discovery-engine` | `{AGENT}/agents/discovery-engine.md` | LLM-powered hypothesis generator using 4 reasoning tracks (pattern synthesis, behavioral anomaly, code research, cross-domain transfer). Spawn when standard scans return nothing, or for a second-opinion hypothesis pass. |
| `poc-validator` | `{AGENT}/agents/poc-validator.md` | Independent finding validator. Makes real HTTP requests, produces CONFIRMED/REJECTED verdicts with raw curl output. Spawn this to validate every finding — a finding without poc-validator confirmation is worthless. |
| `auth-manager` | `{AGENT}/agents/auth-manager.md` | Creates User A + User B accounts via browser automation, extracts tokens, writes credentials to standard .env path. Spawn at hunt start if credentials don't exist. |
| `chain-discovery-engine` | `{AGENT}/agents/chain-discovery-engine.md` | Exploit chain discovery — combines LOW+LOW into CRITICAL. XSS+CORS=ATO, IDOR+enum=mass data leak. Spawn after you have 2+ findings to check for chains. |

**How to spawn an agent:**
```
Use Agent tool:
  subagent_type: general-purpose
  skill_path: {AGENT}/agents/{agent-name}.md
  prompt: [your specific task for this agent]
  description: [short label for tracking]
```

---

## Specialized Agents (155 available)

Each specialized agent has a stub at `{AGENT}/agents/{name}.md` and full details at `{AGENT}/agents/reference/{name}-full.md`. The stub gives you the key tests; the full file gives the complete methodology.

**When to reach for a specialist:** When your hypothesis is confirmed at surface level and you need deep, systematic coverage of that attack class — the specialist knows edge cases you might not think of manually.

**Match hypothesis attack class to agent:**

| Hypothesis attack class | Specialist agent(s) |
|------------------------|---------------------|
| IDOR / object reference | `authorization-boundary-tester`, `mass-assignment-tester` |
| Auth bypass / MFA | `authentication-bypass-tester`, `multi-factor-auth-bypass-tester`, `broken-authentication-tester` |
| JWT attacks | `jwt-analyzer`, `jwt-security-comprehensive` |
| OAuth/OIDC | `oauth-flow-tester` |
| SAML | `saml-security-tester` |
| GraphQL | `graphql-advanced-tester`, `graphql-enumerator`, `graphql-security-scanner-advanced` |
| SQLi | `injection-tester-pro` |
| XSS (reflected/stored) | `injection-tester-pro`, `input-sanitization-tester` |
| SSTI | `server-side-template-injection-tester` |
| SSRF | `ssrf-tester` |
| XXE | `xxe-tester`, `xml-attacks-tester`, `xml-external-entity-advanced` |
| Command injection | `os-command-injection-tester` |
| Path traversal | `path-traversal-tester` |
| Business logic / payments | `business-logic-tester`, `payment-flow-tester`, `ecommerce-tester` |
| Race conditions | `business-logic-vulnerability-finder` |
| CORS | `cors-tester` |
| CSRF | `csrf-tester` |
| Session management | `session-analyzer`, `session-management-comprehensive` |
| Deserialization | `deserialization-tester`, `insecure-deserialization-gadget-scanner` |
| WAF bypass | `waf-bypass-engine` |
| Request smuggling | `http-request-smuggling-tester` |
| Cache poisoning | `cache-poisoning-tester`, `web-cache-behavior-analyzer` |
| Subdomain takeover | `subdomain-takeover-hunter` |
| S3 / cloud storage | `cloud-storage-scanner`, `aws-security-tester` |
| WebSocket | `websocket-tester`, `websocket-security-comprehensive` |
| API fuzzing | `api-fuzzer`, `api-fuzzing-orchestrator`, `api-endpoint-parameter-miner` |
| GraphQL | `graphql-advanced-tester`, `graphql-enumerator` |
| JWT | `jwt-analyzer`, `jwt-security-comprehensive` |
| Prototype pollution | `prototype-pollution-tester` |
| NoSQL injection | `nosql-injection-tester` |
| Rate limit bypass | `rate-limit-bypass`, `api-rate-limit-tester` |
| Info disclosure | `information-disclosure-scanner`, `sensitive-data-exposure-scanner`, `error-handling-analyzer` |
| Host header injection | `host-header-injection-tester` |
| Open redirect | `open-redirect-tester`, `redirect-chain-analyzer` |
| File upload | `file-upload-security-comprehensive` |
| Token entropy | Use `sequencer_start` proxy tool first; if anomaly, spawn `session-analyzer` |
| Exploit chaining | `chain-discovery-engine`, `account-takeover-chain-builder`, `privilege-escalation-chain-builder` |

**How to use a specialist:**
```bash
# Read the stub first for a quick overview
cat {AGENT}/agents/{name}.md

# If you need the full methodology
cat {AGENT}/agents/reference/{name}-full.md

# Then spawn via Agent tool with the stub as skill_path
```

---

## CLI Commands

```bash
bountyhound doctor     # Check tool dependencies and DB status
bountyhound db stats   # Show finding counts by status/program

# Recon and scanning are done via:
#   Agent tool → agents/target-researcher.md  (8-step recon)
#   MCP tools: amass_enum(), nmap_scan(), nuclei_scan()
#   VPS: python {AGENT}/engine/vps/vultr.py run "subfinder ..."
```

---

## Memory Tools

```bash
# Load compact memory summary (always run at hunt start)
python {AGENT}/memory/load_memory.py {target}

# Templates for new targets
{AGENT}/memory/templates/context.md
{AGENT}/memory/templates/defenses.md
{AGENT}/memory/templates/scope.md
```

---

## Proxy-Engine: Optimal Testing Workflow

For any testable hypothesis, this sequence extracts the most signal:

1. `crawler_start` the target URL → maps all reachable surfaces
2. `passive_findings` → picks up low-hanging fruit from crawl traffic
3. `repeater_send` for your specific hypothesis test → captures flow
4. `comparer_diff` if testing IDOR (User A vs User B response)
5. `collaborator_generate` if testing blind SSRF/XXE
6. `intruder_attack` on interesting parameters once surface is confirmed
7. `sequencer_start` on any token-issuing endpoint
8. `export_flow` → saves reproduce.py-ready evidence

Don't run all of these on every hypothesis — pick the ones relevant to your attack class.
