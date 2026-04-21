# Target Model Schema

Canonical definition of `findings/<program>/target-model.json`.
Both `intelligence-loop.md` (Phase ②) and `target-researcher.md` reference this file.

## JSON Schema

```json
{
  "program": "<program-handle>",
  "domain": "<primary-domain>",
  "last_updated": "<ISO 8601 timestamp — use Python: datetime.utcnow().isoformat() + 'Z'>",
  "source_available": true,
  "auth_tested": true,
  "tech_stack": {
    "framework": "<e.g. Next.js 14.2.3>",
    "language": "<e.g. TypeScript>",
    "server": "<e.g. nginx 1.24>",
    "cdn": "<e.g. Cloudflare>",
    "auth": "<e.g. JWT + OAuth2 (authorization_code flow)>",
    "database": "<e.g. PostgreSQL (inferred from error messages)>",
    "platform": "<Bubble.io | Firebase | Supabase | Webflow | Retool | custom — set by Step 2.5 platform detection>",
    "payment_processor": "<Stripe | PayPal | Braintree | none — set when payment flow detected>",
    "platform_meta": {
      "bubble_app_id": "<e.g. mitch-78445 — only for Bubble.io>",
      "bubble_swagger_url": "<e.g. /api/1.1/meta/swagger.json>",
      "firebase_project_id": "<only for Firebase>",
      "supabase_ref": "<only for Supabase>",
      "data_api_enabled": "<true|false — whether platform data API returns data>"
    }
  },
  "endpoints": [
    {
      "path": "/api/users",
      "method": "GET",
      "auth_required": true,
      "source": "js_bundle | network_tab | source_code | amass | manual"
    }
  ],
  "auth_model": {
    "type": "jwt | session | oauth2 | saml | apikey",
    "login_endpoint": "/api/login",
    "token_storage": "cookie | localStorage | sessionStorage | unknown",
    "mfa": false,
    "oauth_flows": ["authorization_code"],
    "password_reset_mechanism": "email link | sms | security questions | unknown"
  },
  "business_logic": "<2-3 sentences: what does the app do, who uses it, what are the core sensitive operations>",
  "attack_surface": [
    "<specific, concrete item — e.g.: User-controlled file upload at /api/upload — no content-type validation observed in JS bundle; server may accept arbitrary MIME types>"
  ],
  "subdomains": [
    "<list of all discovered subdomains with open web ports>"
  ],
  "open_ports": {
    "<subdomain>": [80, 443, 8080]
  },
  "cves_relevant": [
    {
      "cve_id": "CVE-2024-34351",
      "component": "Next.js",
      "version_affected": "14.x before 14.1.1",
      "cvss_score": 7.5,
      "summary": "<one-sentence description of the vulnerability and its impact>"
    }
  ],
  "prior_disclosures": [
    {
      "title": "<report title>",
      "severity": "critical | high | medium | low | informative",
      "disclosed_at": "<YYYY-MM-DD>"
    }
  ],
  "hypotheses_queue": [],
  "tested_hypotheses": [],
  "confirmed_findings": []
}
```

## Field Completion Rules

- **Never omit a field.** If data is not available, use `"unknown"` for strings, `false` for booleans, `[]` for arrays, `{}` for objects.
- **Be specific.** "Next.js 14.2.3" is useful. "React app" is not.
- **attack_surface entries must be concrete.** Each entry should name a specific endpoint, parameter, or behavior — not a category like "auth flow". The hypothesis engine converts these directly into testable hypotheses.
- **business_logic must describe sensitive operations.** The hypothesis engine uses this to assess impact. "Manages financial transactions on behalf of SMBs" produces higher-severity hypotheses than "a web app".

## Duplicate Detection

Each hypothesis is identified by:

```
hypothesis_id = sha256(attack_surface_entry + '|' + technique)
```

Where `attack_surface_entry` is the specific endpoint/component being targeted and `technique` is the attack class (e.g., `SSRF`, `IDOR`, `XSS`).

Before adding any hypothesis to `hypotheses_queue` or `bountyhound.db`:
1. Compute `hypothesis_id`
2. Check both `hypotheses_queue` and `tested_hypotheses` in the target model
3. Check the `hypotheses` table in `bountyhound.db` for this program
4. If a match is found: discard silently
5. Only add hypotheses with no matching `hypothesis_id`

## Database Sync

After every write to `target-model.json`, sync to `bountyhound.db` `targets` table.
Use `data.db.BountyHoundDB.upsert_target(program_id, domain, model)`.
