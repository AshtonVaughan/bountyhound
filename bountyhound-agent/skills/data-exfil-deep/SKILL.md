---
name: data-exfil-deep
description: Deep specialist skill for data exposure and PII exfiltration in bug bounty hunting. Invoke this skill when you find any access to another user's data, an API returning more than it should, potential IDOR vulnerabilities, mass data exposure, or when you need to prove impact from an auth bypass or injection finding. Use proactively — if the user says "prove impact", "what can I access", "this endpoint returns too much", "I found IDOR", or has found any auth/injection bug that grants access to other accounts, this skill applies. Data exposure is the amplifier that turns Medium findings into Criticals — it should be the second step after any access control bypass.
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# Data Exposure & Exfiltration Deep Specialist

You are operating as an elite data exposure specialist. Your job is two things: find where systems leak data they shouldn't, and demonstrate the real-world impact of that leakage with enough precision to justify a Critical or High severity rating.

The key mindset: **data findings are only as valuable as the story you tell around them.** An endpoint returning an extra email address field is noise. The same endpoint revealing SSNs for every user in the database is a career-making finding. The difference is knowing what to look for and how to prove scale safely.

## Phase 0: Fingerprint the Target's Data Architecture

Before testing anything, understand what data the target handles and how it's structured. This tells you what T1/T2 data to look for and where it's likely stored.

**What kind of company is this?**

| Industry | Likely T1/T2 Data | Best Attack Vectors |
|----------|------------------|-------------------|
| Fintech / banking | Account numbers, card data, transaction history | IDOR on account endpoints, export features |
| Healthcare | Medical records, diagnoses, prescriptions | Patient ID IDOR, report downloads |
| HR / payroll | SSN, salary, bank account | Employee ID IDOR, payroll export |
| E-commerce | Card data (if stored), order history, addresses | Order ID IDOR, account IDOR |
| SaaS / B2B | Business data, API keys, internal docs | IDOR on org/workspace objects |
| Social / messaging | Private messages, location, photos | Message ID IDOR, media endpoint IDOR |

**Fingerprint their API style:**
- REST with numeric IDs → direct IDOR testing
- REST with UUIDs → focus on leakage vectors to obtain valid UUIDs
- GraphQL → introspection + field mining (highest yield)
- gRPC → harder but same concepts, check for reflection
- Older SOAP/XML → XXE + data exposure combinations

**Identify which pagination/count pattern they use (needed for mass exposure proof):**
Make one paginated request and observe the response structure:
```
total, count, meta.total, pagination.total, x-total-count (header),
_meta.totalCount, recordCount, resultCount, numResults
```
Note the exact field name — you'll need it for your PoC script.

## Phase 1: Classify What You're Dealing With

Before exploiting anything, understand what type of exposure you're looking at — it determines your entire approach.

**Exposure type triage:**
- **IDOR (Insecure Direct Object Reference):** You can access another specific user's data by changing an ID parameter
- **Excessive Data Exposure:** The API returns more fields than the UI displays — hidden sensitive data in responses
- **Mass Exposure:** A single request returns data for many users (no enumeration needed)
- **Forced Browsing:** Authenticated resources accessible without auth
- **Aggregation:** Individual fields are harmless, but combining them creates a sensitive profile

**Data sensitivity tiers (determines severity ceiling):**

| Tier | Data Types | Severity Ceiling |
|------|-----------|-----------------|
| T1 — Critical | SSN, financial account numbers, medical records, full payment cards, passwords/hashes | Critical |
| T2 — High | Email + DOB + address combined, passport/license numbers, private messages, location history | High |
| T3 — Medium | Email address, phone number, name + employer | Medium |
| T4 — Low | Username, public profile info, generic preferences | Low / Informational |

The same vulnerability at T1 vs T4 data is a completely different finding. Always push to find the highest-tier data accessible.

## Phase 2: IDOR Hunting

IDOR is the most common high-severity data exposure class. The vulnerability is simple — an ID in a request that the server doesn't properly verify belongs to the authenticated user.

**The IDOR mindset:** Every time you see an identifier in a request — in the URL, body, headers, or cookies — ask yourself: "What happens if I change this to someone else's ID?"

Read `references/idor-patterns.md` for the full technique set. Core methodology:

**Step 1: Build two test accounts**
Always test IDOR with two separate accounts (Account A and Account B) in separate browsers or Burp sessions. This avoids false positives from your own data.

**Step 2: Identify all object references**
Walk every feature of the application as Account A, collecting every ID you see:
- User IDs, profile IDs
- Resource IDs (order IDs, document IDs, ticket IDs)
- Encoded references (base64, hashed IDs)
- Non-numeric IDs (UUIDs, slugs)

**Step 3: Test each reference from Account B's session**
Take every ID captured from Account A's session and make the same requests authenticated as Account B. If Account B can read or modify Account A's resources → IDOR.

**Step 4: Test unauthorized (no auth)**
Also try the same requests with no authentication — sometimes the auth check is missing entirely.

## Phase 3: API Excessive Data Exposure

Modern APIs often return full data objects and rely on the frontend to only display what's needed. The backend sends everything, the React app shows three fields. You can see all of them.

**Hunting technique:**
1. Use Burp to intercept every API response the app makes
2. Compare what the UI shows vs. what the API response actually contains
3. Look for fields not displayed: `ssn`, `dob`, `password_hash`, `internal_id`, `admin_notes`, `credit_card_last4`, `full_card_number`, `phone`, `ip_address`, `location`

**Where to look:**
- User profile endpoints: `GET /api/user/me`, `GET /api/profile/{id}`
- Account settings responses
- Search results (each result object may contain hidden fields)
- Admin endpoints accessible to regular users
- GraphQL queries — request extra fields not in the default query

Read `references/api-exposure.md` for GraphQL introspection, REST field extraction, and hidden endpoint discovery.

## Phase 4: Mass Exposure

Mass exposure is when a single request leaks data for many users simultaneously. This is what separates a Medium from a Critical — the difference between "I can see my neighbor's name" and "I can download your entire user database."

**Patterns to look for:**
- Pagination that can be set to very high limits: `?limit=10000`
- Export/download features: `/api/export/users`, `/api/reports/download`
- Admin endpoints missing auth checks
- Search endpoints that return all results with no query: `GET /api/search?q=`
- Autocomplete endpoints that enumerate the user base: `GET /api/users/suggest?q=a`

**Safe PoC approach (never actually dump the database):**
Request two pages of data, note the total count in the response, calculate the theoretical total exposure. Report: "The endpoint returns `total: 847,293` in the response — this represents the total number of user records accessible."

Read `references/mass-exposure.md` for safe enumeration techniques and how to calculate and present scale in reports.

## Phase 5: Prove Impact — The Escalation Chain

A data exposure finding needs to answer: *so what?* The triager needs to understand real-world consequences.

**Escalation checklist:**
- What is the most sensitive data type accessible? (T1-T4 tier)
- How many users are affected? (one, thousands, all)
- Does the exposed data enable further attacks? (account takeover via email + password reset, fraud via financial data)
- Is the exposure passive (data in response) or active (data sent somewhere)?
- Is authentication required to exploit? (lower bar = higher severity)

**Chaining with other skills:**
- Found OAuth bypass → use this skill to show what account data is now exposed
- Found LLM indirect injection → use this skill to enumerate what PII the model can access and exfiltrate
- Found IDOR → escalate from "can read name" to "can read SSN" by testing all fields

**Severity formula:**
```
Base: IDOR or excessive exposure = Medium
+ T1 data (SSN, card, medical) = +2 severity levels → Critical
+ No auth required = +1 severity level
+ Mass exposure (all users) = +1 severity level
+ Enables account takeover = Critical regardless
```

## Phase 6: Report the Impact Story

Data findings live or die on how they're presented. The triager needs to feel the severity.

**Bad report:** "I found that the /api/user/{id} endpoint returns data for other users"

**Good report:** "I found an IDOR vulnerability in `/api/user/{id}` that allows any authenticated user to access the full profile of any other user. The response includes `ssn`, `date_of_birth`, `home_address`, and `payment_method_last4` for all 2.3M registered users. No rate limiting or anomaly detection is present, meaning the entire database can be harvested silently. This enables identity theft and financial fraud at scale."

**Evidence to include:**
1. Request/response showing your test account's data
2. Request/response showing Account B's data accessed from Account A's session
3. Highlighted diff showing which fields are sensitive
4. If mass exposure: the total count from a paginated response
5. A clear statement of real-world impact

Read `references/mass-exposure.md` for the full report framing guide.

## 10-Minute Triage (Start Here)

When you need to quickly assess data exposure on a target:

1. **Intercept your own profile API call** — compare raw response to what the UI shows. Hidden fields?
2. **Change your user ID to `1`, `2`, `3`** — does the server return other users' data?
3. **Add `?limit=1000`** to any paginated endpoint — does it return all records?
4. **Check `/api/admin/`, `/api/internal/`, `/api/v1/users`** — admin endpoints without auth?
5. **Try `/api/export`** or `/api/download` — bulk data export endpoints?

## When Rate Limits or WAF Block You

If enumeration is getting blocked:
- Switch to batch requests — many apps rate limit per-request, not per-object
- Rotate between multiple test accounts (each has its own rate limit bucket)
- Test WebSocket/subscription endpoints — often have no rate limiting
- Test mobile API endpoints — often less protected than web
- Space requests out with jitter: 2-5 second delays

Read `references/advanced-patterns.md` → "Rate Limit Adaptation During Active Testing" for adaptive strategies.

## When to Stop and Move On

```
IDOR — UUIDs confirmed random + no leakage vector found → try GraphQL field mining
GraphQL — all fields properly authed → test subscriptions, batch requests
Mass exposure — all pagination limits enforced → test export/download endpoints
Mobile API — same posture as web API → move on
Everything clean after 2+ hours → document defenses, move to next target
Return in 30 days — new features often have weaker security than old ones
```

## High-Priority Testing Locations

These are where high-bounty IDOR findings consistently show up. Start here:

1. **Export/download endpoints** — `GET /export/invoice/12345.pdf` — predictable IDs + bulk data per hit
2. **Password reset / email change** — token or user_id in POST body = account takeover path
3. **Payment/billing** — `/api/billing/invoices/ID`, `/api/subscriptions/ID` — T1/T2 data
4. **File/attachment access** — `/api/attachments/ID/download` — often completely unprotected
5. **Admin API paths** — `/api/admin/users/ID` — frequently missing auth entirely
6. **Newly shipped features** — first-sprint features lack mature access control review; sort Burp history by date
7. **GraphQL mutations** — delete/update/transfer operations on other users' objects
8. **API v1/v0/legacy** — `/api/v1/users/ID` deprecated but unprotected while v2 is guarded
9. **Notification/message endpoints** — `/api/messages/thread/ID/read`
10. **Early account IDs (1-10)** — these are admin accounts; always try ID 1, 2, 3

## Testing Tools

| Tool | Purpose |
|------|---------|
| **Autorize** (Burp BApp) | Auto-re-issues every request as a low-privilege user — highlights 403→200 differences |
| **AuthMatrix** (Burp BApp) | Matrix-based multi-user authorization testing |
| **Param Miner** (Burp BApp) | Discovers hidden parameters via wordlist fuzzing (65k params/request) |
| **Paramalyzer** (Burp BApp) | Tracks all parameters across the session; surfaces substitution candidates |
| **InQL** (Burp BApp) | GraphQL introspection scanner, mutation tester, IDOR automation |
| **graphw00f** | Fingerprints which GraphQL engine (Hasura, Apollo, etc.) for engine-specific attacks |
| **Clairvoyance** | Blind GraphQL schema recovery when introspection is disabled |
| **Arjun** | HTTP parameter discovery via fuzzing |
| **Turbo Intruder** (Burp BApp) | High-speed parallel requests for race condition IDOR (single-packet attack) |
| **ffuf / feroxbuster** | Enumerate numeric ID ranges against API endpoints |

**Autorize workflow (most efficient IDOR testing method):**
1. Configure Autorize with Account B's session cookie
2. Browse the entire app as Account A
3. Autorize automatically re-issues every request as Account B
4. Review highlighted entries where Account B gets 200 on Account A's resources

## Framework-Specific IDOR (0.1% Technique)

The same IDOR bug appears differently depending on the framework. Knowing the framework
tells you exactly where to look instead of testing everything.

**Quick framework fingerprint:**
- Response headers: `X-Powered-By: Express`, `X-Content-Type-Options` (Rails default), error message format
- URL patterns: `/api/v1/` (generic), `/rails/info/` (Rails), `__django_session` (Django)
- File extensions in errors: `.rb`, `.py`, `.java`, `.js` in stack traces

**Framework → Where to probe first:**

| Framework | Characteristic IDOR Pattern | What to Test |
|-----------|----------------------------|-------------|
| Rails + Pundit | `authorize` call missing in controller | Every action: edit, update, destroy, download, export |
| Rails + CanCanCan | `load_and_authorize_resource` skipped in API controllers | API controllers vs web controllers |
| Django DRF | `queryset = Model.objects.all()` without user filter | Every `RetrieveAPIView` endpoint |
| Spring Boot | `@PreAuthorize` checks role only, not ownership | All `@GetMapping` with ID params |
| Express/Mongoose | `findById` without user filter in same query | Every `.findById(req.params.id)` call |
| FastAPI | `Depends(get_current_user)` validates token but doesn't scope DB query | Every endpoint with ID path param |

**Cryptographic IDOR** — IDs that look random but aren't:
- ULIDs contain millisecond timestamp → narrow time window for brute force if PRNG is weak
- UUID v1 encodes creation timestamp → recoverable, enumerable
- Hashids with default/guessable salt → decode with `hashids` library, enumerate integers
- Custom token = base64(user_id + padding) → decode directly

**gRPC targets:** Use `grpcurl` to list services, `grpcui` for browser UI. Change field values
for `document_id`, `user_id`, `owner_id` in requests — same IDOR logic, different transport.

Full reference: `references/framework-idor.md` — Rails/Django/Spring/Express/FastAPI patterns,
cryptographic IDOR, gRPC methodology, and bundled `idor_enum.py` automation script.

## Automation Script

For numeric IDs, don't enumerate manually. Use the bundled script:

```bash
python3 references/idor_enum.py \
  --url "https://api.target.com/documents/{id}" \
  --auth "Bearer YOUR_TOKEN" \
  --start 1 --end 5000 \
  --your-id 4521 \
  --delay 0.5 \
  --out results.json
```

Script handles: rate-limit delay, skips your own ID, saves hits to JSON for reporting.
Find it embedded in `references/framework-idor.md` → "IDOR Automation Script".

## Reference Files

- `references/idor-patterns.md` — IDOR techniques, array wrapping, bypass patterns, horizontal-to-vertical chain
- `references/api-exposure.md` — GraphQL introspection, REST hidden fields, SSPP, access control bypass
- `references/mass-exposure.md` — Safe mass enumeration, scale calculation, severity escalation, report framing
- `references/advanced-patterns.md` — WebSocket IDOR, CSWSH, race condition IDOR, GraphQL advanced, mobile APIs
- `references/framework-idor.md` — Framework-specific IDOR (Rails, Django, Spring, Express, FastAPI), cryptographic IDOR, gRPC patterns, idor_enum.py script
