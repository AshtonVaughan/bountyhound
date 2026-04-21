# Cross-Target Patterns

Techniques and observations that worked across multiple targets.
Loaded at the start of every /hunt to inform testing strategy.

Max 50 entries. When full, remove the oldest entry (lowest date).

## Format
`[tech/infra] : [what worked] → [outcome] (YYYY-MM-DD)`

Include outcome so staleness is visible. Entries older than 6 months with no accepted outcome should be reviewed and removed if unconfirmed.

## Quality Gate (run during Step 4 memory update)
Before adding a new entry:
1. Check for duplicates — don't add if the same tech+technique already exists
2. Only add if the finding was VERIFIED (confirmed by cold repeat) — not just suspected
3. Accepted findings get priority — if the pattern was accepted by HackerOne, mark it `→ accepted`

## Patterns

[GitHub Pages / CNAME] : Dangling CNAME + non-existent GitHub org allows subdomain takeover (both org doesn't exist + user doesn't exist) → verified (2026-03-11)
[GitHub Orgs] : Lowercase org names (e.g., playtika vs PlaytikaOSS) not reserved when heavy CNAME usage exists → verified (2026-03-11)
[github-actions] : mutable @master action refs in release workflows with OSSRH credentials → verified finding (2026-03-11)
[maven] : com.playtika.* namespace check — only graphqlcodegen unclaimed out of 11 → dependency confusion candidate (2026-03-11)
[github-actions] : non-existent action branch (@subkey) = currently broken workflow = unmonitored pipeline → confirmed (2026-03-11)
[Next.js/Vercel] : Host header spoofing bypasses isValidHostName CDN origin check (Host: world-id-assets.com) → verified (2026-03-04)
[Next.js/OAuth] : client-supplied environment parameter bypasses staging/prod namespace isolation → verified (2026-03-06)
[PingFederate] : OIDC well-known exposes internal scopes beyond standard OIDC set → accepted (2026-03-11)
[CloudFront] : dangling CNAME SDTO via nslookup + curl 404 verification → accepted (2026-03-11)
[JS bundles] : production builds exposing internal hostnames, OAuth client IDs, API keys → accepted (2026-03-11)

# --- Seeded: statistically common across bug bounty programs, not personally confirmed ---
# These match the [seeded] label the hypothesis engine reads. Prioritize personally-confirmed
# entries above, and remove seeded entries when you have personal data on the same pattern.

[JWT anywhere] [seeded] : RS256→HS256 algorithm confusion — sign token with server's public key as HMAC secret → accepted (commonly yields critical auth bypass when verified)
[GraphQL] [seeded] : Introspection enabled in production reveals all mutations, types, and hidden admin queries → medium (enables targeted IDOR/privilege escalation)
[REST API + GUIDs] [seeded] : UUIDs in URL paths enumerable via /api/v1/users/{uuid} with predictable sequential or timestamp-seeded base → IDOR on user resources
[Multi-tenant SaaS] [seeded] : org_id / account_id / team_id in request body not validated server-side — swap to another org's ID → tenant isolation bypass (high acceptance)
[OAuth] [seeded] : redirect_uri matching too lenient — trailing slash, sub.evil.com, encoded chars, or open subdomain bypass → token theft
[React SPA / Next.js] [seeded] : /_next/data/{build_id}/*.json and /api/ routes bypassable when auth enforced only client-side → unauthenticated data access
[Any target] [seeded] : /api/v1/ endpoints lag behind /api/v2/ auth hardening — test same operations on v1 when v2 rejects → auth bypass or IDOR
[File upload] [seeded] : Content-Type not validated server-side; SVG with <script> or XXE payload accepted as image → stored XSS or SSRF
[Password reset] [seeded] : Reset tokens predictable (timestamp-based, short, numeric), not invalidated on use, or valid across accounts → account takeover
[Multi-user / teams] [seeded] : Direct object references in API responses (IDs of other users' resources) — test all IDs against User B → IDOR (high acceptance rate on HackerOne)
next.js/undici : dns.lookup() + fetch(href) are independent resolvers — DNS rebinding TOCTOU class affects all image/external URL fetching code → unconfirmed (2026-03-08)
[Bubble.io] [seeded] : /api/1.1/meta/swagger.json always unauthenticated — reveals all data types, fields, workflows. Start every Bubble hunt here → confirmed by Bubble docs (2026-03-27)
[Bubble.io] [seeded] : List-leak bypass — privacy rules don't protect records fetched via relational field references on other accessible records. Query order/transaction types to leak user fields → confirmed by Bubble docs + Flusk audit (2026-03-27)
[Bubble.io] [seeded] : /api/1.1/wf/<name> with "No auth" + "Ignore privacy rules" = unauthenticated full DB access → confirmed by Bubble forum (2026-03-27)
[Bubble.io] [seeded] : Auto-binding input fields write directly to DB — intercept in DevTools, replay with role/admin/balance fields → confirmed by Bubble docs (2026-03-27)
[Bubble.io] [seeded] : Hardcoded AES-CBC IVs ("po9","fl1") + AppName as key — decrypt/modify/replay Elasticsearch queries to bypass result limits → confirmed PoC: demon-i386/pop_n_bubble (2026-03-27)
[Firebase] [seeded] : /.json on Realtime Database dumps entire DB if rules misconfigured — single curl, zero auth → accepted (common critical finding)
[Firebase] [seeded] : isAdmin/role stored as writable Firestore field on user's own doc — self-escalate from browser console → accepted (common critical finding)
[Supabase] [seeded] : Anon key + missing RLS = full table dump via PostgREST. UUID trick: ?id=gt.00000000-... enumerates all → CVE-2025-48757, 170+ apps (2026-03-27)
[Supabase] [seeded] : service_role key in frontend JS bundle = full DB takeover bypassing all RLS → confirmed by GitGuardian tracking (2026-03-27)
[Supabase] [seeded] : SECURITY DEFINER RPC functions bypass RLS — call via supabase.rpc() as authenticated user → confirmed by Precursor Security research (2026-03-27)
[Stripe integration] [seeded] : Webhook forgery — HMAC verification optional, many devs skip it. Forged payment_intent.succeeded grants paid access → confirmed by cablej.io, lightningsecurity.io (2026-03-27)
[Stripe integration] [seeded] : Client-side price manipulation — intercept checkout, modify Amount field — Stripe charges what the session says → confirmed disclosure March 2026 (2026-03-27)
[Gambling/Lootbox] : Sell-back arbitrage — free spin → claim → sell for credits → buy paid packs → repeat = infinite money → confirmed PRIZEUNBOX-001 $126k AUD/hr (2026-03-27)
[AI-generated apps] [seeded] : Lovable/Bolt/Replit apps systematically omit Supabase RLS — 11% leak rate in January 2026 scan of 20k apps → CVE-2025-48757 (2026-03-27)
