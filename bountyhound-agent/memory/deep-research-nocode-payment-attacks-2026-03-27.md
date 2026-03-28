# No-Code Platform & Payment Flow Attack Patterns: Deep Research Intelligence Report

**Date:** 2026-03-27
**Research Method:** 4-branch parallel agent tree (Bubble.io, BaaS, Payments, IDOR), 12 Haiku search agents
**Purpose:** Fill methodology gaps identified in BountyHound post-mortem across 75 targets

---

## Bottom Line Up Front

**The #1 money-theft pattern BountyHound has been missing is not a clever exploit - it is testing for missing access controls on platforms that trust client-side enforcement.** Bubble.io apps leak data via the "list-leak bypass" (relational field references bypass privacy rules), Firebase/Supabase apps leak via missing security rules (11% of vibe-coded apps), and Stripe integrations leak money via unverified webhooks. These are not theoretical - 76% of top 100 Bubble apps were exploitable in 2023, and the AI-generated app wave has made it worse. The tool is not curl or custom exploits. The tool is the browser console calling the platform's own SDK functions.

---

## The Landscape

### Bubble.io Attack Surface
- **Platform:** No-code SPA builder, shared Elasticsearch infrastructure, ~2M+ apps
- **No paid bug bounty.** Hunt specific apps built on Bubble, not Bubble itself
- **Data API:** `/api/1.1/obj/<type>` and `/api/1.1/obj/<type>/<id>` - returns data if enabled
- **Meta endpoint:** `/api/1.1/meta/swagger.json` - ALWAYS unauthenticated, reveals all data types, fields, and workflows
- **IDs:** `<unix-ms-timestamp>x<18-digit-random>` - NOT brute-forceable, but leak in URLs/API responses
- **Encryption weakness:** AES-CBC with hardcoded IVs ("po9", "fl1"), key derived from AppName (readable from `X-Bubble-Appname` header). PoC at `demon-i386/pop_n_bubble` on GitHub

### Firebase/Supabase Attack Surface
- **Firebase:** `/.json` endpoint on Realtime Database dumps entire DB if rules allow. Firestore queried via SDK from browser console
- **Supabase:** PostgREST API with anon key (intentionally public). RLS is opt-in, not default
- **AI-generated apps:** 11% of vibe-coded apps leak Supabase credentials (January 2026 scan). CVE-2025-48757 hit 170+ Lovable-generated apps

### Stripe Integration Attack Surface
- **Webhook forgery:** HMAC verification is optional. Developers routinely skip it
- **Price manipulation:** Backend accepts client-provided `Amount` field without server-side recalculation
- **Race conditions:** Single-packet attacks (HTTP/2) on one-time bonuses/coupons remain exploitable

---

## The Gaps - What BountyHound Must Add

### Gap 1: "The List-Leak Bypass" (Bubble.io - Universal)

**What it is:** Bubble privacy rules protect a record from direct search, but NOT when that record is referenced as a field on another accessible record. Example: a `transaction` record references a `user`. If `transaction` is readable, the `user`'s protected fields (wallet_balance, payment_tokens, email) come back as nested data.

**Why BountyHound missed it:** We tested the Data API directly (`/api/1.1/obj/user`) and got 404. We never tested fetching a RELATED record type that references users.

**How to test:**
1. Hit `/api/1.1/meta/swagger.json` (always unauthenticated) to get ALL data types and fields
2. Find types that reference sensitive types (e.g., `order` has field `user`, `transaction` has field `wallet`)
3. Query the referencing type: `GET /api/1.1/obj/order` or `GET /api/1.1/obj/transaction`
4. Check if the referenced sensitive fields are returned in the response
5. Even if the Data API is disabled, check via the browser console - load any page that displays orders/transactions and inspect the Elasticsearch response for leaked user fields

**Impact:** Read wallet balances, payment tokens, emails, verification codes of ALL users

### Gap 2: "The Swagger Recon Entry Point" (Bubble.io)

**What it is:** Every Bubble app exposes `/api/1.1/meta/swagger.json` with zero authentication. This reveals every enabled data type, every field name, and every workflow endpoint.

**Why BountyHound missed it:** We never checked this endpoint. We extracted types from `window.app.user_types` in the browser console instead - which only shows type names, not field details or API enablement status.

**How to test:**
```
curl -s https://www.lootly.com.au/api/1.1/meta/swagger.json | python3 -m json.tool
```

**Impact:** Complete white-box schema map of the target in one unauthenticated request

### Gap 3: "Backend Workflow Without Auth" (Bubble.io)

**What it is:** Bubble API workflows at `/api/1.1/wf/<workflow-name>` can be configured with "No authentication required" AND "Ignore privacy rules". If both are set, any unauthenticated caller gets unrestricted database access.

**Why BountyHound missed it:** We tried `/workflow/start` (Bubble's internal workflow endpoint) but never tried the public Workflow API at `/api/1.1/wf/`. These are different endpoints.

**How to test:**
1. Get workflow names from `/api/1.1/meta/swagger.json`
2. Call each: `POST /api/1.1/wf/<name>` with empty body or guessed parameters
3. Check if it executes without auth (200 response vs 401/403)

### Gap 4: "Auto-Binding Privilege Escalation" (Bubble.io)

**What it is:** When a Bubble developer binds an input element to a database field, the client sends a direct write to the database on every keystroke. If the bound field is sensitive (role, admin, balance), any authenticated user can modify it.

**Why BountyHound missed it:** We never intercepted auto-binding API calls or tested field-level write restrictions.

**How to test:**
1. Open DevTools Network tab
2. Type in any input field on the app
3. Look for `POST /api/1.1/obj/<type>/<id>` requests with field updates
4. If found: replay with sensitive field names (`role`, `admin`, `is_admin`, `balance`, `credits`, `account_type`)
5. Check if the write succeeds (200 response)

### Gap 5: "Webhook Forgery" (Stripe Integrations)

**What it is:** Stripe webhooks use HMAC-SHA256 signing, but verification is optional. Many integrations skip it. Sending a forged `payment_intent.succeeded` payload to the webhook endpoint grants the attacker paid access without payment.

**Why BountyHound missed it:** We analyzed the Stripe checkout flow but never tested the webhook endpoint directly.

**How to test:**
1. Find the webhook endpoint: search JS bundles, GitHub repos, or common paths (`/api/webhook`, `/api/stripe/webhook`, `/webhook/stripe`)
2. Send forged payload:
```bash
curl -X POST https://target.com/api/stripe/webhook \
  -H "Content-Type: application/json" \
  -d '{"type":"checkout.session.completed","data":{"object":{"id":"cs_test_fake","payment_status":"paid","amount_total":355,"customer_email":"attacker@test.com","metadata":{"user_id":"<your_user_id>"}}}}'
```
3. Check if your account was credited without payment

### Gap 6: "Pre-Payment State Creation" (Stripe Integrations)

**What it is:** Some backends create the item/credit/subscription BEFORE Stripe payment confirms (via webhook). The workflow/start call we observed returning 200 before any payment is a signal.

**Why BountyHound missed it:** We saw `workflow/start` return 200 but never checked if our user's state changed (balance, points, opens counter).

**How to test:**
1. Note current user state (balance, points, items)
2. Click "Buy" to initiate checkout
3. DO NOT complete payment - close the Stripe modal or navigate away
4. Re-check user state - did anything change?
5. If credits/items were added before payment: that's a free purchase bug

### Gap 7: "Sell-Back Arbitrage" (Gambling/Loot Box Platforms)

**What it is:** Free/demo spin -> claim item -> sell back for credits -> use credits to open paid pack -> repeat = infinite money. Proven at $126k AUD/hr on PrizeUnbox (PRIZEUNBOX-001).

**Why BountyHound missed it on Lootly:** Demo spin creates no server state. But we never tested: (a) if Loot Points from low-value wins can be converted to real prizes in the Loot Store, (b) if the sell-back value of items exceeds the pack cost when factoring in the free pack progression (5 opens = free $15 pack).

**How to test:**
1. Open cheapest pack ($3.55)
2. Win item (likely Loot Points at ~99% rate)
3. Check: can those Loot Points buy items in the Loot Store?
4. Check: can Loot Store items be cashed out (gift cards, physical items)?
5. Check: does the "free pack progression" (5 opens = free $15 pack) create positive-EV when combined with sell-back?
6. Check: are demo/bonus credits tagged differently from paid credits?

### Gap 8: "Race Condition on One-Time Bonuses" (Financial Platforms)

**What it is:** Single-packet HTTP/2 attack on "use once" actions (coupon redeem, first-deposit bonus, referral credit). Two requests both pass the "has this been used?" check before either writes "used=true".

**Why BountyHound missed it:** We identified the pattern theoretically but never used Turbo Intruder or parallel request tooling.

**How to test:**
1. Identify one-time actions (signup bonus, referral code, coupon)
2. Use Burp Repeater "Send group in parallel" or Turbo Intruder with `Engine.BURP2`
3. Send 20-30 identical redemption requests in a single TCP packet
4. Check if credits were applied more than once

### Gap 9: "Firebase/Supabase Console Exploitation" (BaaS Platforms)

**What it is:** Call the platform's own SDK functions from the browser console to bypass client-side restrictions.

**Firebase:** `firebase.firestore().collection('users').get().then(s => s.forEach(d => console.log(d.data())))`
**Firebase role escalation:** `firebase.firestore().collection('users').doc(myUid).update({isAdmin: true, role: 'admin'})`
**Supabase:** `supabase.from('users').select('*')` (with anon key from page source)
**Supabase UUID dump:** `GET https://<ref>.supabase.co/rest/v1/<table>?id=gt.00000000-0000-0000-0000-000000000000`

### Gap 10: "Vibe-Coded App Mass Exploitation" (AI-Generated Apps)

**What it is:** AI code generators (Lovable, Bolt, Replit, v0) systematically omit security controls. 11% of scanned apps leaked Supabase credentials. CVE-2025-48757 hit 170+ apps.

**Why BountyHound missed it:** We never targeted AI-generated apps specifically. These are soft targets with high hit rates.

**How to identify:** Look for "Built with Lovable" / "Built with Bolt" footers, check Product Hunt for newly launched AI-built apps, search for `service_role` in frontend JS bundles.

---

## The Contrarian View

**"Bubble.io Elasticsearch 0-day" is overhyped.** The April 2025 disclosure (hardcoded IVs, AppName as encryption key) was partially retracted by its own authors. Bubble disputed the severity and claims it's not Elasticsearch underneath. The practical residual value is result-limit bypass on already-exposed data types - useful but not the cross-tenant apocalypse initially claimed. Privacy rules still gate what data is returned. **The list-leak bypass is more reliably exploitable.**

**Stripe itself is well-hardened.** The bugs disclosed against Stripe's own platform are edge cases. The real vulnerability is in how developers integrate Stripe - webhook forgery, client-side price acceptance, and pre-payment state creation. Target new/small integrators, not Stripe.

**Bubble IDs are NOT predictable.** Despite the timestamp prefix, the 18-digit random suffix makes brute force infeasible. The attack is ID leakage (from URLs, API responses, page source) + IDOR, not ID prediction. Stop trying to enumerate IDs - find where they're already exposed.

---

## Key Signals (The Receipts)

1. **76% of top 100 Bubble apps had exploitable vulnerabilities** - Flusk 2023 security audit, 2.3M sensitive records accessible
2. **11% of vibe-coded apps leaked Supabase credentials** - January 2026 scan of 20,000+ apps
3. **CVE-2025-48757** - 170+ Lovable-generated apps exploitable via missing RLS
4. **Hardcoded Bubble IVs: "po9" and "fl1"** - AES-CBC parameters shared across all Bubble apps, PoC at demon-i386/pop_n_bubble
5. **`/api/1.1/meta/swagger.json`** - unauthenticated schema dump on every Bubble app
6. **Firebase Storage rules bypass** - direct GCS URL access bypasses SDK-path rules (GitHub issue #5342)
7. **Stripe webhook forgery** - optional HMAC verification, documented by cablej.io and lightningsecurity.io
8. **Client-side price manipulation** - March 2026 disclosure: $329.88 reduced to $1.88 via intercepted Amount field
9. **Single-packet race condition** - PortSwigger "Smashing the State Machine" technique, YesWeHack real example: item reduced from EUR 1,337 to EUR 37.62
10. **PRIZEUNBOX-001** - Proven sell-back arbitrage at $126k AUD/hr (BountyHound's own finding)
11. **Supabase `security definer` RPC bypass** - functions with SECURITY DEFINER run as superuser, bypassing all RLS
12. **Firebase anonymous auth escalation** - `signInAnonymously()` + rules checking only `request.auth != null` = unauthenticated data access

---

## So What - Immediate Actions for BountyHound

### For the Lootly.com.au hunt (resume immediately):
1. Hit `/api/1.1/meta/swagger.json` - get the full schema with zero auth
2. Test the list-leak bypass: find data types that reference `user` (order, transaction, spin_log) and query them
3. Try `/api/1.1/wf/` workflow endpoints from the swagger output
4. Check if the `workflow/start` call that returned 200 created any state changes on the user
5. Test auto-binding by intercepting input field writes in DevTools

### For all future hunts:
1. **Add swagger.json check to Phase 1** for every Bubble app
2. **Add BaaS console exploitation** to Phase 4 for Firebase/Supabase targets
3. **Add webhook endpoint discovery + forgery test** for every Stripe integration
4. **Add pre-payment state check** to every payment flow test
5. **Target AI-generated apps** (Lovable, Bolt) as soft targets for Supabase RLS bypass
6. **Use Turbo Intruder** for race condition testing on one-time bonuses

### Priority order for next hunts:
1. **Lootly** - resume with swagger.json + list-leak + workflow API
2. **Giveaways.com.au** - submit ready IDOR findings
3. **Jemlit.com** - submit ready IDOR findings
4. **AI-generated app scan** - mass target Lovable/Bolt apps for Supabase leaks
