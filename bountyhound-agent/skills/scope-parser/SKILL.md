---
name: scope-parser
description: "Extract and validate scope from bug bounty platforms including HackerOne, Bugcrowd, Intigriti, and others"
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# Scope Parser

## Understanding Scope

### In-Scope vs Out-of-Scope

**Always check:**
- Which domains/subdomains are included
- Which vulnerability types are accepted
- Which methods are allowed (automated scanning, social engineering)
- Testing restrictions (rate limits, production vs staging)

**Common exclusions:**
- Third-party services (Google Analytics, CDNs)
- Social engineering/phishing
- Physical attacks
- DoS/DDoS testing
- Recently fixed issues

## Platform-Specific Scope Formats

### HackerOne

```
Scope structure:
- Asset Type: Domain, API, Mobile App, Source Code, etc.
- Identifier: *.example.com, api.example.com
- Eligible for Bounty: Yes/No
- Max Severity: Critical/High/Medium/Low
```

**Extracting scope via API:**
```bash
# Get program scope (requires API token)
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://api.hackerone.com/v1/hackers/programs/PROGRAM_HANDLE"
```

**Key fields:**
- `attributes.targets` - List of in-scope assets
- `attributes.out_of_scope` - Excluded items
- `attributes.policy` - Full policy text

### Bugcrowd

```
Scope structure:
- Target: URL, IP range, mobile app
- Type: Website, API, Mobile, Hardware
- Priority: P1-P5 (P1 = highest bounty)
```

**Reading Bugcrowd scope:**
- Check "Target" section in program brief
- Note priority levels (P1 assets = higher payouts)
- Review "Out of Scope" explicitly

### Intigriti

```
Scope structure:
- Domain: *.example.com
- Type: Web, API, Mobile
- Bounty eligible: Yes/No
- Severity cap: Critical/High/Medium/Low/None
```

### YesWeHack

```
Scope definition:
- Perimeter: List of assets
- In/Out scope clearly separated
- Testing conditions specified
```

## Scope Extraction Patterns

### Wildcard Domains

```
*.example.com → All subdomains of example.com
*.*.example.com → Multi-level subdomains (rare)
api.*.example.com → Subdomains of api (unusual)
```

**Important:** Wildcard usually means:
- Subdomains discovered during recon ARE in scope
- Parent domain (example.com) may or may not be included
- Check if there are exclusions like `admin.example.com`

### IP Ranges

```
192.168.1.0/24 → 192.168.1.0 - 192.168.1.255
10.0.0.0/8 → Large internal range (verify!)
```

### Explicit URLs

```
https://api.example.com/v1/* → Only v1 endpoints
https://example.com/app/* → Only /app path
```

## Scope Validation Checklist

### Before Testing

```
[ ] Identify all in-scope assets
[ ] Note any exclusions or restrictions
[ ] Understand severity caps per asset
[ ] Check if automated scanning allowed
[ ] Verify testing hours if specified
[ ] Review safe harbor language
[ ] Note required report format
```

### During Testing

```
[ ] Verify target is in scope before reporting
[ ] Check if vulnerability type is accepted
[ ] Confirm you haven't hit out-of-scope systems
[ ] Document all tested endpoints
```

## Common Scope Scenarios

### Scenario 1: Wildcard with Exclusions

```
In Scope:
  *.example.com

Out of Scope:
  admin.example.com
  staging.example.com
  *.dev.example.com
```

**Action:** Test any subdomain EXCEPT admin, staging, and dev subdomains

### Scenario 2: Specific Endpoints Only

```
In Scope:
  https://api.example.com/v2/*
  https://app.example.com/

Out of Scope:
  https://api.example.com/v1/* (legacy)
  https://admin.example.com
```

**Action:** Only test v2 API and main app, avoid v1 and admin

### Scenario 3: Mobile App with API

```
In Scope:
  iOS App: com.example.app
  Android App: com.example.app
  API: api.example.com

Out of Scope:
  Third-party SDKs
  Backend infrastructure
```

**Action:** Test app and its API, report issues with third-party SDKs to those vendors

## Extracting Scope Programmatically

### Parse from HTML (HackerOne example)

```python
import requests
from bs4 import BeautifulSoup

def get_h1_scope(program_handle):
    url = f"https://hackerone.com/{program_handle}"
    resp = requests.get(url)
    soup = BeautifulSoup(resp.text, 'html.parser')
    # Parse scope table...
    return scope_list
```

### Parse from JSON (API response)

```python
def parse_scope(json_response):
    in_scope = []
    out_scope = []

    for target in json_response.get('targets', []):
        if target['eligible_for_bounty']:
            in_scope.append({
                'asset': target['asset_identifier'],
                'type': target['asset_type'],
                'max_severity': target.get('max_severity', 'unknown')
            })
        else:
            out_scope.append(target['asset_identifier'])

    return in_scope, out_scope
```

## Scope Edge Cases

### Third-Party Services

```
Usually OUT of scope:
- CDN providers (Cloudflare, Akamai)
- Analytics (Google Analytics, Mixpanel)
- Payment processors (Stripe, PayPal)
- Auth providers (Okta, Auth0) unless self-hosted

Exception: If target explicitly includes them
```

### Acquired Companies

```
Check if:
- Acquired domain is explicitly listed
- It shares infrastructure with main target
- Separate program exists for acquired entity
```

### Subdomains vs Subpaths

```
*.example.com → subdomains
example.com/* → all paths on main domain
example.com/api/* → only /api path

These are different! Verify what's actually in scope.
```

## Reporting Out-of-Scope Findings

If you find a critical issue on an out-of-scope asset:

1. **Don't exploit further** - Stop testing
2. **Check related programs** - Asset may be in scope elsewhere
3. **Contact program** - Some accept critical OOS findings
4. **Document carefully** - Include clear OOS acknowledgment
5. **Expect no bounty** - But may get goodwill/swag

## Quick Scope Reference Template

```markdown
## Program: [Name]
Platform: HackerOne/Bugcrowd/etc.

### In Scope
| Asset | Type | Max Severity | Notes |
|-------|------|--------------|-------|
| *.example.com | Domain | Critical | Main target |
| api.example.com | API | Critical | REST API |

### Out of Scope
- admin.example.com
- Third-party integrations
- DoS testing

### Restrictions
- No automated scanning without approval
- Production testing allowed
- Report format: [link]

### Bounty Range
- Critical: $X,000 - $XX,000
- High: $X00 - $X,000
- Medium: $X00 - $X00
- Low: $X0 - $X00
```
