# Campaign Automation Feature - Design

## Overview

Fully autonomous bug bounty scanning from a single campaign URL. Paste a HackerOne/Bugcrowd/Intigriti/YesWeHack URL and BountyHound does everything: fetches scope, enumerates targets, AI-selects high-value hosts, scans for vulnerabilities, and generates a prioritized report.

## Command & Flow

**New CLI command:**
```
bountyhound campaign <url>
```

**Execution flow:**
1. Detect platform from URL (HackerOne, Bugcrowd, Intigriti, YesWeHack)
2. Launch headless browser, load cookies from user's logged-in session
3. Fetch campaign page, extract scope with AI
4. Run subdomain enumeration on all in-scope domains
5. AI analyzes recon results, selects top 50-100 high-value targets
6. Run vulnerability scans on selected targets
7. AI prioritizes findings by exploitability and bounty potential
8. Generate final report with executive summary

**Example:**
```bash
$ bountyhound campaign https://hackerone.com/paypal_checkout

[*] Detected platform: HackerOne
[*] Fetching campaign scope...
[*] Found 12 in-scope domains (3 wildcards)
[*] Running subdomain enumeration...
    Found 847 subdomains
[*] AI selecting high-value targets...
    Selected 67 targets for scanning
[*] Running vulnerability scans...
[*] AI prioritizing findings...
[*] Report saved: ~/.bountyhound/results/paypal_checkout_2026-02-02.md

Found 4 vulnerabilities (1 high, 2 medium, 1 low)
Estimated bounty potential: $2,500 - $8,000
```

## Architecture

**New modules:**

```
bountyhound/
├── ai/
│   ├── __init__.py
│   └── analyzer.py        # Groq LLM wrapper
├── campaign/
│   ├── __init__.py
│   ├── parser.py          # Base campaign parser
│   ├── hackerone.py       # HackerOne-specific scraper
│   ├── bugcrowd.py        # Bugcrowd-specific scraper
│   ├── intigriti.py       # Intigriti-specific scraper
│   └── yeswehack.py       # YesWeHack-specific scraper
└── browser/
    ├── __init__.py
    └── session.py         # Playwright browser session handler
```

**Key components:**

| Component | Responsibility |
|-----------|----------------|
| `CampaignParser` | Base class - detect platform, dispatch to correct scraper |
| `HackerOneParser` | Extract scope from HackerOne pages |
| `BrowserSession` | Launch Playwright, load cookies, fetch authenticated pages |
| `AIAnalyzer` | Parse scope, select targets, prioritize findings |

**New dependency:** `playwright` for browser automation

## Browser Session & Authentication

BountyHound reads cookies from user's existing browser (no need to log in again):

```
bountyhound config set browser chrome   # or firefox, edge
```

**Cookie locations by browser:**
- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*.default\cookies.sqlite`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network\Cookies`

**Flow:**
1. Read cookies from user's browser cookie store
2. Filter for bug bounty platform domains
3. Inject cookies into Playwright session
4. Fetch authenticated pages

**Fallback:** If cookie extraction fails, prompt user to paste session cookie manually or open login page.

## AI Target Selection

After subdomain enumeration, AI analyzes results to pick high-value targets.

**Selection criteria (scored by Groq):**

| Signal | Why it matters |
|--------|----------------|
| Admin/internal keywords | `admin.`, `internal.`, `staging.`, `dev.` - often less hardened |
| Interesting ports | Non-standard ports, multiple services |
| Old technologies | Legacy frameworks, outdated versions |
| API endpoints | `api.`, `gateway.`, `graphql.` - business logic bugs |
| Status codes | 403 (may bypass), 500 (errors = bugs) |
| Fewer defenses | Missing security headers, no WAF detected |

**Example AI output:**
```json
{
  "selected_targets": [
    {"host": "admin-legacy.paypal.com", "score": 95, "reason": "Admin panel, outdated Apache"},
    {"host": "api-staging.paypal.com", "score": 88, "reason": "Staging API, verbose errors"},
    {"host": "developer.paypal.com", "score": 75, "reason": "Developer portal, complex auth"}
  ],
  "skipped": 780,
  "skipped_reason": "Standard production hosts with modern stack"
}
```

**Configurable limit:** Default 50-100 targets, adjustable in config.

## Error Handling & Safety

**Platform-specific handling:**

| Scenario | Response |
|----------|----------|
| Not logged in | Prompt to log in, open browser to login page |
| Private program | Skip with warning (can't access scope) |
| Rate limited | Back off, retry with exponential delay |
| Invalid URL | Detect platform mismatch, suggest correct URL format |
| Empty scope | Warn user, exit (nothing to scan) |

**Safety guardrails:**

- **Out-of-scope check**: Before scanning any target, verify it matches in-scope patterns
- **Wildcard expansion limit**: Max 1000 subdomains per wildcard to prevent runaway scans
- **Scan timeout**: 4 hours max per campaign (configurable)
- **Resume support**: If interrupted, `bountyhound campaign --resume` continues from last checkpoint

**Logging:**
- All actions logged to `~/.bountyhound/logs/campaign_<name>_<date>.log`
- Verbose mode: `--verbose` shows real-time progress

## Configuration Additions

```yaml
# ~/.bountyhound/config.yaml additions
browser: chrome  # chrome, firefox, edge

campaign:
  max_targets: 100           # AI selection limit
  max_subdomains_per_wildcard: 1000
  scan_timeout_hours: 4

ai:
  model: llama-3.3-70b-versatile
  target_selection: true
  finding_prioritization: true
```

## Supported Platforms

| Platform | URL Pattern | Status |
|----------|-------------|--------|
| HackerOne | `hackerone.com/<program>` | Planned |
| Bugcrowd | `bugcrowd.com/<program>` | Planned |
| Intigriti | `intigriti.com/programs/<program>` | Planned |
| YesWeHack | `yeswehack.com/programs/<program>` | Planned |
