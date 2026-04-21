# Hypothesis Engine — Deep Reasoning Patterns

Reference this when you need richer guidance on generating hypotheses from recon data. The hunt SKILL.md gives the framework; this gives the reasoning depth.

---

## Cold Start (first hunt, empty memory)

If `patterns.md` has only seeded entries or fewer than 5 personal entries, and `context.md` doesn't exist for this target, you're in cold start. This is fine — it just means you rely more heavily on your own security knowledge rather than historical signal.

**Cold start strategy:**
1. The seeded entries in `patterns.md` are a solid starting point — they represent patterns confirmed across hundreds of public HackerOne disclosures. Treat them like memory that isn't yours yet.
2. Start with the broadest, highest-ROI hypothesis per attack class: one IDOR, one auth bypass, one business logic check. Confirm or rule out before going deeper.
3. Document aggressively this hunt — even negative findings go into `defenses.md` and `context.md`. The second hunt will have much richer signal.
4. Pay attention to the tech stack — it's your strongest signal when you have no personal history with this target. The tech stack table in SKILL.md tells you what's statistically likely given what you see.

Cold start is a temporary state. After one hunt, the memory system has enough signal to start calibrating. After 3-5 hunts on the same target, the memory is genuinely compounding.

---

## Reading Recon Output for Hypothesis Seeds

When you have `01_recon.json`, extract these signals before generating hypotheses:

**High-value signals:**
- Subdomains with names like `api-`, `internal-`, `admin-`, `dev-`, `staging-`, `beta-` — these are often less hardened
- Ports beyond 80/443: 8080 (dev server), 8443 (alt HTTPS), 3000 (Node), 4000 (GraphQL), 8888 (Jupyter)
- Response headers that reveal stack depth: `X-Powered-By`, `X-Runtime`, `X-Request-Id`, `Server`, `Via`
- CORS misconfigurations in initial fingerprinting (check all subdomains, not just main)
- S3/GCS/Azure blob references in page source or JS bundles (bucket takeover potential)
- Third-party integrations referenced in JS (Stripe, Twilio, Segment) — often have their own SSRF/token vectors

**How to extract from the JSON without dumping everything:**
```bash
# Quick summary
python -c "
import json
d = json.load(open('{FINDINGS}/phases/01_recon.json'))
print('Subdomains:', len(d.get('subdomains', [])))
print('Tech stack:', d.get('technologies', []))
print('Interesting ports:', [h for h in d.get('hosts', []) if h.get('port') not in [80, 443]])
print('Headers:', d.get('interesting_headers', []))
"
```

---

## Hypothesis Generation by Attack Class

### IDOR Hypotheses (highest ROI — always generate these)

IDOR exists anywhere you see:
- Numeric or GUID identifiers in URLs, request bodies, or responses
- Multi-user features (teams, organizations, shared resources)
- Object references passed client-side (order IDs, invoice IDs, document IDs)
- Bulk operations (arrays of IDs, batch endpoints)

**Hypothesis template:**
```
Surface:    POST /api/v2/orders/{orderId}/share
Attack:     IDOR — User B accesses User A's order via orderId enumeration
Rationale:  Order IDs visible in URL; share endpoint likely doesn't check ownership
First test: Authenticated as User B, call endpoint with User A's orderId
Priority:   HIGH
```

**IDOR variants to always consider:**
- Direct object reference: access object by ID you don't own
- Function-level: call an admin function as a regular user (no ID manipulation needed)
- Indirect reference via associated object: IDOR on object A exposes object B
- Mass assignment: send unlisted fields (e.g., `{"role": "admin"}`) in update payloads

### Auth Bypass Hypotheses

Always generate these for any login/registration/reset/MFA flow:

```
Surface:    POST /api/auth/verify-mfa
Attack:     MFA bypass via response manipulation
Rationale:  MFA verification likely client-driven; intercept response and flip success field
First test: Intercept response, change {"verified": false} to {"verified": true}
Priority:   HIGH
```

```
Surface:    GET /dashboard (accessed before completing MFA)
Attack:     Auth bypass by direct endpoint access
Rationale:  Pre-MFA session token may be valid for protected endpoints
First test: After password auth (before MFA), request /dashboard directly
Priority:   HIGH
```

### Business Logic Hypotheses

These require understanding the product workflow:

```
Surface:    POST /api/checkout/apply-coupon
Attack:     Negative value / coupon stacking abuse
Rationale:  Cart arithmetic done client-side or without bounds checking
First test: Apply coupon code with amount=-100 and observe cart total
Priority:   MED
```

**Race condition pattern:**
```
Surface:    POST /api/gift-card/redeem
Attack:     Race condition — redeem same card simultaneously
Rationale:  Single-use codes often lack atomic check-and-consume
First test: Send 10 parallel requests with same code, check if multiple succeed
Priority:   MED
```

### SSRF Hypotheses

Look for any parameter that takes a URL or hostname:

```
Surface:    POST /api/integrations/webhook {"url": "..."}
Attack:     SSRF to internal services / AWS metadata
Rationale:  Webhook URLs fetched server-side; no visible validation
First test: curl {FINDINGS}/tmp/proof.json after setting url=http://169.254.169.254/latest/meta-data/
Priority:   HIGH
```

### Injection Hypotheses

Generate only when you have a concrete surface. Blind injection without a clear signal is low ROI:

```
Surface:    GET /api/search?q= (results appear server-rendered in page)
Attack:     SSTI — Jinja2/Twig template injection in search results
Rationale:  Search query reflected in rendered page; could be templated
First test: q={{7*7}} — if response shows 49, injection confirmed
Priority:   MED
```

---

## Exploit Chain Hypotheses

Chain reasoning is handled by `references/exploit-chaining.md`. Load that file as soon as any finding passes Layer 1 — it provides the full capability graph traversal, capability enables taxonomy, 3+-step chain hypothesis format, chain validation protocol, severity uplift calculation, and cross-hunt chain query.

**Trigger:** Any finding confirmed via Layer 1 → open `exploit-chaining.md` → run Steps 1-4 immediately.

**Chain canvas:** `{FINDINGS}/chain-canvas.md` — write a capability entry the moment a finding passes Layer 1. Do not wait for the end-of-hunt memory agent. The cross-hunt query (exploit-chaining.md Step 7) at the start of each repeat hunt is the highest-ROI activity on any target with prior history.

---

## Hypothesis Ranking

After generating your cards, rank by:

1. **Attack class ROI** (from playbook): IDOR > auth > business logic > SSRF > injection
2. **Evidence strength**: Do you have a concrete signal (e.g., saw order IDs in traffic) or is it speculative?
3. **New attack surface**: Recon diff showing new subdomains? Those hypotheses jump to top
4. **Cross-target pattern match**: Memory shows this technique worked on similar stack? High priority
5. **Complexity vs. likelihood**: A simple test that confirms or rules out is worth doing even for MED
6. **Dependency position**: Hypotheses that unlock other hypotheses (e.g., "need User B account first") must be sequenced before their dependents — they aren't "higher priority" but they must run first
7. **Risk-first sequencing**: Among equally-ranked hypotheses, prefer the one with highest uncertainty — eliminating unknowns early prevents cascading failures from wrong assumptions

Discard any hypothesis you can't write a concrete "First test" for — it's not ready yet, keep observing.

---

## Pre-Testing Constraint Extraction

Before testing ANY hypothesis, extract its constraints. This prevents mid-test surprises that invalidate your work.

```
Hypothesis: {name}
Hard constraints (must be true or test is invalid):
  - [ ] {e.g., "must have two separate authenticated sessions"}
  - [ ] {e.g., "endpoint must accept application/json, not form data"}
  - [ ] {e.g., "target must not have rate limiting on this endpoint"}
Resource requirements:
  - Accounts needed: {User A + User B | admin + standard | none}
  - Infrastructure needed: {OOB server | none}
  - Program permission required: {data extraction | none}
Stopping criteria (what does "confirmed" look like):
  - PASS: {specific observable — e.g., "User B's email appears in response to User A's request"}
  - FAIL: {specific observable — e.g., "401 or 403 returned consistently"}
```

If you cannot fill in the stopping criteria before testing, the hypothesis is not ready. Observe more, then generate.

---

## Dependency Modeling

Some hypotheses depend on others. Test in the right order or you'll invalidate later work.

**Dependency map format:**
```
[auth-manager] → IDOR test (needs User B account)
[auth-manager] → MFA bypass test (needs logged-in account)
[port scan] → actuator exposure check (need to know what's running on 8080)
[SSRF confirmed] → internal service mapping (SSRF needed before you can use it)
[XSS confirmed] → CSRF token theft chain (XSS is the vector for the chain)
```

Draw this map before testing starts. Any hypothesis that has an arrow pointing to it must wait for its dependency.

**Classify each hypothesis before scheduling:**
- INDEPENDENT: No dependencies, can test in any order or in parallel
- DEPENDS ON {X}: Cannot start until X is completed
- UNLOCKS {Y}: Completing this opens additional hypotheses — mark those immediately

---

## Risk-First Sequencing

After sorting by ROI and dependency order, apply risk-first within each tier:

1. Test hypotheses you're LEAST certain about first (among same ROI tier)
2. The worst outcome is spending 3 hours on a hypothesis chain that starts from a wrong assumption
3. A 5-minute disproof of the foundation saves everything built on it

**Practical rule:** When you have two HIGH hypotheses at similar ROI and no dependency between them, test the one where you'd be most surprised if it's wrong. That's the one to eliminate first.

---

## Generate-Test-Critique Cycle

After each hypothesis test (pass or fail), run this before moving to the next:

```
Result: {PASS | FAIL | INCONCLUSIVE}
Evidence: {what you actually observed}
Critique:
  - If PASS: Is this the root cause or a symptom? What deeper issue does this reveal?
  - If FAIL: Is the finding truly absent, or did my test method have a flaw? Did I actually test the right thing?
  - If INCONCLUSIVE: What additional information would resolve this?
Decision: {continue to next | retest with different method | generate follow-on hypothesis | escalate to chain}
```

**Fresh-start rule (Debugging Decay Index):** After 2 consecutive FAIL results on the SAME hypothesis with different approaches, stop. The hypothesis is most likely wrong. Do NOT generate a third approach — discard the hypothesis and generate a new one from the recon data. Continuing beyond 2 failures on the same hypothesis degrades reasoning quality.

---

## Candidate Scoring at Branch Points

Whenever you have multiple ways to proceed (e.g., 3 potential SSRF injection points, 2 IDOR surfaces), score each before committing:

```
Branch point: {what you're deciding}
Option A: {endpoint/approach/technique}
  - Rationale: {why this could work}
  - Evidence base: {what signals support this}
  - Test cost: {low = 1 curl | medium = 5-10 steps | high = needs accounts/infrastructure}
  - Score: {0-10}
Option B: {endpoint/approach/technique}
  - Rationale:
  - Evidence base:
  - Test cost:
  - Score: {0-10}
Selection: Option {X} — because {reason}
```

Never commit to a testing path without at least 30 seconds of explicit scoring. The cost of scoring is low; the cost of committing to the wrong path is a full test cycle.

---

## Skill Crystallization

When a technique works on a target, record it as a reusable procedure so it compounds across hunts.

Write to `{MEMORY}/patterns.md` immediately after a confirmed finding:

```
## Pattern: {descriptive name}
Tech context: {Rails | Next.js | Stripe integration | etc.}
Attack class: {IDOR | auth_bypass | etc.}
Trigger signal: {what to look for in recon that suggests this pattern applies}
Procedure:
  1. {step 1}
  2. {step 2}
  3. {step 3 — what confirms it}
Confirmed on: {target} — {date}
Payout: {amount if applicable, or "accepted"}
```

A pattern is worth writing when: it worked, AND it was non-obvious (you wouldn't do this automatically from first principles), AND the trigger signal is specific enough to recognize on another target.
