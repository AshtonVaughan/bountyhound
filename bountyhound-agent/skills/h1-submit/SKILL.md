---
name: h1-submit
description: |
  HackerOne report submission workflow — convert a validated finding into an H1 report
  and submit via API or browser. Use when: a finding has passed all 4 validation layers,
  the user says "submit", "report this", "send to H1". Includes dedup check, quality
  score, and direct API submission. Trigger for: "submit", "report", "H1", "HackerOne".
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# H1 Submit Skill

## 1. Pre-Submission Checklist

Before submitting, verify ALL of the following:

- [ ] **4-layer gate passed** — validator.md confirmed PROVEN or PARTIAL with documented reason
- [ ] **Curl proof works NOW** — re-run the reproduce command right now, not from a cached result
- [ ] **In scope** — asset AND vulnerability type are both listed as in-scope per program policy
- [ ] **Not on skip list** — checked `memory/hunting-playbook.md` skip list, no match
- [ ] **Not a duplicate** — `bountyhound.db` findings table has no existing row with same target + similar title
- [ ] **Evidence captured** — at least one screenshot or GIF in `{FINDINGS}/evidence/`

If ANY item is unchecked: stop and fix it before proceeding.

---

## 2. Set H1 Credentials

```bash
export H1_API_TOKEN=<your-token>
export H1_USERNAME=<your-username>
```

**Get these from:** HackerOne → Settings → API → Create API Token
Select scope: **"Create reports"** (minimum required). Copy the token immediately — it is shown only once.

Verify credentials are working:

```bash
python {AGENT}/engine/core/h1_api_cli.py status
```

Expected output: `"authenticated": true` with your username. If `"ready": false`, set the env vars and retry.

**API Note:** BountyHound uses the **Hacker API** (`/v1/hackers/*`) — not the Customer API (`/v1/reports`). These are separate. Ensure your API token is created under a hacker account, not a program management account.

---

## 3. Dedup Check Against Disclosed Reports

Before writing the full report, confirm the finding has not already been publicly disclosed.
This queries `GET /hackers/hacktivity?queryString=team:{program} AND disclosed:true` and runs semantic similarity against returned titles.

```bash
python {AGENT}/engine/core/h1_api_cli.py check-disclosed {program_handle} \
  {FINDINGS}/tmp/finding-draft.json
```

**Interpret the result:**

| `is_duplicate` | `similarity_score` | Action |
|---|---|---|
| `true` | > 0.85 | STOP — do not submit. Show user the `matched_report_id`. |
| `false` | 0.70–0.85 | Note "similar to disclosed report #{id}", reduce confidence, proceed with caution. |
| `false` | < 0.70 | Clear — proceed to submission. |
| (skipped) | N/A | No credentials — skip check, proceed. |

---

## 4. Resolve Weakness and Scope IDs (Do This First)

H1's internal weakness IDs are program-specific integers — they are NOT the same as CWE numbers. The static `WEAKNESS_MAP` in the code is a fallback approximation. For accurate IDs, look them up before writing `finding-draft.json`:

```bash
# List all weakness IDs for this program
python {AGENT}/engine/core/h1_api_cli.py lookup-weakness {program_handle}

# Resolve a specific vuln type to its H1-internal ID
python {AGENT}/engine/core/h1_api_cli.py lookup-weakness {program_handle} sqli

# List all structured scopes
python {AGENT}/engine/core/h1_api_cli.py lookup-scope {program_handle}

# Resolve a target URL to its scope ID
python {AGENT}/engine/core/h1_api_cli.py lookup-scope {program_handle} my.example.com
```

The `submit` command calls `prepare_report()` which runs these lookups automatically — but running them first lets you verify the IDs before committing to the draft.

---

## 5. Write finding-draft.json

Write this file to `{FINDINGS}/tmp/finding-draft.json` before calling submit:

```json
{
  "title": "...",
  "vuln_type": "idor",
  "severity": "HIGH",
  "description": "...",
  "impact": "...",
  "steps_to_reproduce": "...",
  "expected_behavior": "...",
  "actual_behavior": "...",
  "poc": "curl -s ...",
  "target_url": "https://my.example.com/api/endpoint"
}
```

**Field notes:**
- `vuln_type` — used to resolve the H1-internal weakness ID dynamically via `lookup-weakness`. See section 9 for keys.
- `target_url` (optional) — used to resolve the structured scope ID. Include the exact URL or asset under test.
- `severity` must be one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- `steps_to_reproduce` should be numbered steps — the formatter uses this verbatim
- `poc` is embedded into steps if `steps_to_reproduce` is empty
- `expected_behavior` and `actual_behavior` are mandatory for the "Expected vs Actual" section

---

## 6. Submit with Confirmation Requirement

**Show the finding-draft.json to the user and ask:**

> "Ready to submit the following finding to HackerOne program `{program_handle}`:
> Title: {title}
> Severity: {severity}
> Vuln type: {vuln_type}
>
> Submit to HackerOne? (yes/no)"

**Wait for explicit "yes" before continuing.** Never auto-submit.

Once confirmed:

```bash
# Without attachments — direct submission, faster:
python {AGENT}/engine/core/h1_api_cli.py submit {program_handle} \
  {FINDINGS}/tmp/finding-draft.json

# With attachments — uses Report Intents workflow (create draft → upload → submit):
python {AGENT}/engine/core/h1_api_cli.py submit {program_handle} \
  {FINDINGS}/tmp/finding-draft.json \
  {FINDINGS}/evidence/exploit.gif \
  {FINDINGS}/reports/reproduce.py \
  {FINDINGS}/evidence/screenshot.png
```

**Always prefer the version with files** — screenshots and GIFs are uploaded as real H1 attachments, not just paths listed as text. Triagers cannot see text-only file paths.

Output on success:

```json
{
  "success": true,
  "report_id": "1234567",
  "report_url": "https://hackerone.com/reports/1234567"
}
```

---

## 7. Confirm Receipt

After submission, verify the report was received:

```bash
# List all your reports (fetches up to 100, client-side filtered by program):
python {AGENT}/engine/core/h1_api_cli.py my-reports {program_handle}

# List without program filter (all reports):
python {AGENT}/engine/core/h1_api_cli.py my-reports
```

Check that your new report ID appears in the list with `"state": "new"`. The H1 Hacker API returns all your reports paginated — BountyHound fetches the first 100 and filters client-side.

---

## 8. Record in DB

After confirmed submission:

```python
from data.db import BountyHoundDB
db = BountyHoundDB()
db.insert_finding({
    "program_id": program_id,
    "target_id": target_id,
    "title": finding["title"],
    "severity": finding["severity"],
    "vuln_type": finding["vuln_type"],
    "status": "submitted",
    "h1_report_id": report_id,
    "h1_report_url": report_url,
    "submitted_at": datetime.utcnow().isoformat(),
})
```

---

## 9. Weakness ID Table

These are static fallback values. **H1-internal IDs are program-specific** — always run `lookup-weakness {program_handle} {vuln_type}` first to get the exact integer for this program. The `submit` command does this automatically via `prepare_report()`.

Reference keys in `engine/core/h1_submitter.py → WEAKNESS_MAP`:

| vuln_type string | H1 Weakness ID | Description |
|---|---|---|
| `xss` | 60 | Cross-site Scripting — Generic |
| `reflected_xss` | 61 | Reflected XSS |
| `stored_xss` | 62 | Stored XSS |
| `sqli` | 89 | SQL Injection |
| `idor` | 639 | Insecure Direct Object Reference |
| `ssrf` | 918 | Server-Side Request Forgery |
| `cors` | 942 | CORS Misconfiguration |
| `csrf` | 352 | Cross-Site Request Forgery |
| `open_redirect` | 601 | URL Redirection to Untrusted Site |
| `info_disclosure` | 200 | Information Exposure |
| `auth_bypass` | 287 | Improper Authentication |
| `broken_auth` | 306 | Missing Authentication |
| `privilege_escalation` | 269 | Privilege Escalation |
| `rce` | 94 | Code Injection / RCE |
| `xxe` | 611 | XML External Entities |
| `ssti` | 1336 | Server Side Template Injection |
| `path_traversal` | 22 | Path Traversal |
| `command_injection` | 78 | OS Command Injection |
| `rate_limit` | 799 | Improper Control of Interaction Frequency |
| `business_logic` | 840 | Business Logic Errors |
| `subdomain_takeover` | 350 | Subdomain Takeover |
| `security_misconfiguration` | 16 | Security Misconfiguration |
| `sensitive_data` | 312 | Cleartext Storage of Sensitive Information |

If your vuln type is not in the map, set `vuln_type` to the closest match, or omit the field (weakness ID will not be set).

---

## 10. Submission Failures — Common Errors and Fixes

| Error | Cause | Fix |
|---|---|---|
| `HTTP 401` | Invalid credentials | Re-check `H1_API_TOKEN` and `H1_USERNAME`. Token must have "Create reports" scope. |
| `HTTP 403` | Program not in scope or not accepted | Confirm program is open to submissions. Check if you're banned. |
| `HTTP 404` | Wrong `program_handle` | Use the exact handle from the H1 URL: `hackerone.com/<handle>` |
| `HTTP 422` | Missing required field or invalid severity | Check `finding-draft.json` — all required fields must be non-empty |
| `HTTP 429` | Rate limited | Wait 60 seconds and retry |
| `"ready": false` in status | Missing env vars | `export H1_API_TOKEN=...` and `export H1_USERNAME=...` |
| `SETUP REQUIRED` on import | Missing dependency | Run `pip install -r requirements/requirements.txt` from `{AGENT}/` |
| Exit code 2 from check-disclosed | Duplicate detected | Do not submit — show user the `matched_report_id` from the output |
