---
name: target-research
description: |
  Methodology for building a comprehensive target model for a bug bounty target.
  Use this skill whenever performing target reconnaissance, building a target profile,
  or starting a new hunt session on an unfamiliar target. Load this before running
  any recon — it defines what to look for and how to structure what you find.
model: inherit
tools: all
---

# Target Research Skill

Build a target model that makes attack hypotheses specific, grounded, and novel.
The model is the foundation of the entire hunt — a shallow model produces generic
attacks; a deep model produces findings nobody else has found.

## What You Are Building

`findings/<program>/target-model.json` — a structured JSON file with these fields:

```json
{
  "domain": "example.com",
  "program_handle": "example-program",
  "tech_stack": {
    "framework": "Next.js",
    "version": "14.1.0",
    "language": "JavaScript",
    "cdn": "Cloudflare",
    "cloud": "Vercel",
    "auth_system": "NextAuth.js",
    "database": "PostgreSQL (inferred from error messages)"
  },
  "endpoints": [
    {"url": "/api/user/{id}", "method": "GET", "auth_required": true},
    {"url": "/api/upload", "method": "POST", "auth_required": true}
  ],
  "auth_model": {
    "session_type": "JWT",
    "token_format": "HS256",
    "oauth_flows": ["authorization_code"],
    "mfa_present": false,
    "password_reset_mechanism": "email link"
  },
  "business_logic": "SaaS. Roles: free/pro/admin. Sensitive: payment, data export, team management.",
  "attack_surface": ["Auth flow", "File upload", "API endpoints", "Webhook receivers"],
  "cves_relevant": [],
  "prior_disclosures": [],
  "hypotheses_queue": [],
  "tested_hypotheses": [],
  "confirmed_findings": [],
  "source_available": false,
  "auth_tested": false,
  "last_updated": "2026-03-10T00:00:00Z"
}
```

## Staleness Rule

A target model is stale if `last_updated` is more than 14 days old. On hunt start:
- **Stale model:** Re-run Phase 1 (all 8 steps below) and overwrite the model
- **Fresh model:** Skip Phase 1 entirely — the model already exists

## Step-by-Step Research Process

See `references/tech-fingerprinting.md` for the full fingerprinting guide.
See `references/js-analysis.md` for deep JS bundle analysis techniques.

### Step 1 — Subdomain Enumeration
Run: `amass_enum(domain=target, timeout=300)`
Save results. If no subdomains found: note it, continue with primary domain only.

### Step 2 — Port Scan
Run: `nmap_scan(target=domain, flags="-sV -p 80,443,8080,8443,3000,8000,9000")`
Record any non-standard ports — they often host admin interfaces or internal APIs.

### Step 3 — Tech Stack Fingerprint
Open browser to target. Read `references/tech-fingerprinting.md` → HTTP Headers table.
Check: Server header, X-Powered-By, cookies, error pages, JS bundle names.
Record: framework + version (if detectable), CDN, cloud host, auth mechanism.

### Step 4 — JS Bundle Analysis
Read `references/js-analysis.md` for extraction commands.
Extract: API endpoint patterns, auth flow indicators, feature flags, potential secrets.
Document any internal URLs, unusual endpoints, or hardcoded configuration found.

### Step 5 — Source Code Check
Search GitHub for `github.com/<org>` or `site:github.com <target_name> security`.
If found: read `package.json` / `requirements.txt` / `Gemfile.lock` for exact versions.
Read auth-related files: middleware, route guards, session handlers.
Set `source_available: true` if found, `false` if not.

### Step 6 — CVE Pull
Query bountyhound.db for each identified framework/library:
```python
from data.db import BountyHoundDB
db = BountyHoundDB()
cves = db.get_cves_for_tech('next.js')
# Add top 10 by CVSS to model cves_relevant
```

### Step 7 — Prior Disclosures
Check hackerone.com/<handle>/hacktivity (filter: disclosed).
Note which vulnerability classes have been found — these may have unpatched siblings.
Note which areas have never had a report — these are the most valuable to explore.

### Step 8 — Authenticated Browse (if credentials available)
Use auth-manager to get credentials. Spend 5 minutes in the application:
- Map key user flows (signup → feature → export)
- Identify user roles and what each can access
- Note sensitive actions (payment, admin, data export)
- Look for unusual UI patterns that suggest complex backend logic
Set `auth_tested: true` when done.

## Minimum Viable Model Rule

If recon hits blockers (CDN blocks amass, no GitHub, no credentials):
- Record what you have
- Mark affected fields as `unknown` or `false`
- Proceed anyway — the hypothesis engine adapts to incomplete models
- Never let incomplete recon block the hunt
