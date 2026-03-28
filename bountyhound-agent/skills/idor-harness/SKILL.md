---
name: idor-harness
description: |
  Systematic IDOR (Insecure Direct Object Reference) testing using two test accounts.
  Use this when you have User A and User B credentials and a list of endpoints.
  Invoke for: "test IDOR", "check authorization", "can User B access User A's data",
  "object reference", "access control testing", horizontal privilege escalation.
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


## When to Invoke

Invoke this skill when ALL of the following are true:

| Condition | Required |
|-----------|----------|
| Two test accounts exist for the target | YES — hard requirement |
| The two accounts have DIFFERENT user IDs | YES — same ID = no test possible |
| At least one endpoint is `auth_required: true` | YES |
| Endpoint list available (schema_importer output or manual) | YES |

Do NOT invoke if you only have one account. Create a second account first using auth-manager.

---

## Pre-Flight Checklist (run before invoking idor_harness.py)

**1. Confirm distinct IDs — this is the most common failure mode.**

```bash
# Check User A
grep USER_A_ID {FINDINGS}/credentials/{target}-creds.env

# Check User B
grep USER_B_ID {FINDINGS}/credentials/{target}-creds-b.env
```

If both IDs are identical: stop, create a new account with auth-manager, update the .env file.

**2. Confirm endpoints file exists.**

```bash
ls {FINDINGS}/phases/api-schema.json
# If missing, run schema_importer or build manually:
# [{\"url\": \"https://target.com/api/v1/profile\", \"method\": \"GET\", \"auth_required\": true}]
```

**3. Confirm both tokens are still valid.**

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $(grep USER_A_TOKEN {FINDINGS}/credentials/{target}-creds.env | cut -d= -f2)" \
  https://{target}/api/v1/profile
# Expect 200. If 401: refresh tokens via auth-manager.
```

---

## Invocation

```bash
python {AGENT}/engine/core/idor_harness.py \
  {FINDINGS}/phases/api-schema.json \
  {FINDINGS}/credentials/{target}-creds.env \
  {FINDINGS}/credentials/{target}-creds-b.env \
  --out {FINDINGS}/phases/idor-results.json
```

Tail progress:

```bash
# idor_harness prints one line per endpoint inline — no separate log needed
# Watch for "CANDIDATE" lines
python {AGENT}/engine/core/idor_harness.py ... 2>&1 | tee {FINDINGS}/tmp/idor-run.txt
```

---

## Interpreting Results

```
{FINDINGS}/phases/idor-results.json
```

| Confidence | Meaning | Action |
|------------|---------|--------|
| `high` | Status 200, matching body, personal fields (email/phone/name) in response | Submit after manual verification |
| `medium` | Status 200, body Jaccard similarity >= 60%, no obvious personal fields | Manually confirm — check if response is generic vs user-specific |
| `low` | Flagged but low overlap | Skip — likely a false positive (shared public resource) |

**A result is only a real IDOR if:**
- User B's token was used (not User A's)
- User A's resource ID was used in the request
- User A's data appears in User B's response
- The data is user-specific (not a public/shared resource)

---

## Manual IDOR Testing (for endpoints not in the schema)

Use this 5-step method for endpoints discovered during browse/proxy capture that aren't in the automated run:

**Step 1 — Identify the object and its ID.**
Browse as User A. Find an endpoint that returns a user-specific resource. Note the resource ID (numeric or UUID) in the URL or response body.

Example: `GET /api/v1/orders/98765` returns User A's order.

**Step 2 — Capture the raw request.**
```bash
# Use the Chrome browser proxy capture or curl --verbose
curl -s -v -H "Authorization: Bearer $TOKEN_A" \
  https://target.com/api/v1/orders/98765 > {FINDINGS}/tmp/order-a.json
```

**Step 3 — Replay with User B's token, same resource ID.**
```bash
curl -s -v -H "Authorization: Bearer $TOKEN_B" \
  https://target.com/api/v1/orders/98765 > {FINDINGS}/tmp/order-b.json
```

**Step 4 — Diff the responses.**
```bash
python3 -c "
import json, sys
a = json.load(open('{FINDINGS}/tmp/order-a.json'))
b = json.load(open('{FINDINGS}/tmp/order-b.json'))
print('MATCH' if a == b else 'DIFFER')
print('Status B:', open('{FINDINGS}/tmp/order-b.json').read()[:200])
"
```

**Step 5 — Test all CRUD verbs.**
IDOR often only exists on GET but check PUT/PATCH/DELETE too — write-IDORs are Critical.

```bash
# DELETE IDOR test
curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  -H "Authorization: Bearer $TOKEN_B" \
  https://target.com/api/v1/orders/98765
# 200/204 = IDOR on delete (Critical)
```

---

## IDOR Proof Standard

Every submitted IDOR report must contain this exact chain:

> "User B's Bearer token was used. User A's resource ID (`{id}`) was used in the request.
> The response returned User A's private data including `{field}`.
> User B has no legitimate access to User A's account."

Minimum evidence:
- curl command with User B's token (redacted to first 8 chars) and User A's ID
- Raw response showing User A's data
- Screenshot or GIF of the request/response in browser DevTools

---

## Chain Potential

| Entry Point | Escalation Path | Severity |
|-------------|----------------|----------|
| IDOR on profile endpoint (email leak) | Email → password reset → ATO | Critical |
| IDOR on address/PII | GDPR violation + identity theft | High |
| IDOR on payment method | Financial data exposure | High |
| IDOR on internal admin ID | Privilege escalation | Critical |
| Write IDOR (PUT/PATCH) on profile | Modify another user's data | High-Critical |
| IDOR on password/credential endpoint | Direct ATO | Critical |

When IDOR yields an email, immediately attempt password reset on the target platform
to confirm ATO chain. Document both steps as a chained finding.

---

## Common False Positives

| Situation | Why it's not IDOR |
|-----------|------------------|
| Both users get same response for `/api/v1/config` | Shared public configuration |
| Response is a 403 or 401 for User B | Access control working correctly |
| Response body is identical but contains no personal data | Generic/public resource |
| GUID in URL is actually a public share token | Intentional public sharing |

To rule out public share tokens: check if the same URL works with NO authentication.
If `curl https://target.com/api/v1/resource/{id}` (no auth header) returns 200 → not IDOR.
