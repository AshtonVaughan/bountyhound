# Market-Leading Security Agent Design
*Date: 2026-02-20*

## Core Thesis

The market-leading system isn't a better scanner. It's the world's first **reasoning security agent with collective intelligence**.

| Current tools | This system |
|---|---|
| Fire payloads, match patterns | Forms hypotheses, reasons about responses |
| Single session, forget everything | Learns permanently across every hunt |
| One user's knowledge | Network of thousands of hunters' combined patterns |
| Finds individual vulns | Automatically chains low findings into criticals |
| Gives you raw output | Gives you validated, reportable findings |

The three core gaps — intelligence, speed/scale, knowledge — collapse into one thesis: **an agent that thinks like an elite hunter, scales like infrastructure, and gets smarter than any individual can**.

The unfair advantage is the flywheel: more users → more anonymized patterns → better hypothesis generation → better findings → more users trust it → more users.

---

## Target Users

Professional security researchers, bug bounty hunters, and pentesters. The distinction between "bug bounty hunter" and "pentester" is context (program vs client engagement), not capability. The same professional needs the same system.

---

## Architecture

Three layers, cleanly separated:

```
┌─────────────────────────────────────────────────────┐
│                  WEB PLATFORM (SaaS)                 │
│  Target mgmt · Findings dashboard · Team collab      │
│  Knowledge base · Analytics · Report generation      │
│  Community pattern pool (anonymized)                 │
└─────────────────────┬───────────────────────────────┘
                      │ API (REST + WebSocket)
┌─────────────────────▼───────────────────────────────┐
│              HUNTING ENGINE (Agent Core)             │
│  Runs locally OR as cloud worker                     │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐ │
│  │  Recon   │  │ Reasoning│  │   Exploit/Validate  │ │
│  │  Layer   │→ │  Brain   │→ │       Layer         │ │
│  │subfinder │  │(Claude)  │  │ curl · Playwright   │ │
│  │httpx·nmap│  │          │  │ chain discovery     │ │
│  └──────────┘  └──────────┘  └────────────────────┘ │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│                    CLI / SDK                         │
│  bountyhound hunt · scan · recon · report            │
│  Works standalone or synced to platform              │
└─────────────────────────────────────────────────────┘
```

**Key architectural decisions:**

- **Engine runs local or cloud** - security professionals who won't send target data to a SaaS can run it fully local. Cloud mode enables 24/7 autonomous hunting on a fleet of targets.
- **Claude as the reasoning brain** - not a wrapper around nuclei. Claude reads actual responses, forms hypotheses, decides what to test next. Nuclei/subfinder/httpx are tools it calls, not the system itself.
- **Platform is stateless relative to the engine** - the engine pushes findings up. The platform never needs to touch the target. This is the privacy architecture that makes enterprise/pentester adoption possible.
- **Community patterns sync down, never raw data up** - what syncs to the pool is abstracted: "JWT none-algorithm bypass worked on Express 4.x with this endpoint pattern." Not the target, not the payload verbatim.

---

## The AI Layer

Don't build one model. Build a **model orchestra** where each model does what it's best at:

```
┌─────────────────────────────────────────────────────────┐
│                    AI ORCHESTRATION LAYER                │
│                                                          │
│  ┌─────────────────┐     ┌──────────────────────────┐   │
│  │  REASONING CORE │     │   KNOWLEDGE RETRIEVAL    │   │
│  │  Claude Sonnet  │◄───►│   (Fine-tuned embeddings │   │
│  │  (hypothesis,   │     │    over community DB)    │   │
│  │   chain logic,  │     │   "What worked before    │   │
│  │   report write) │     │    on this tech stack?"  │   │
│  └────────┬────────┘     └──────────────────────────┘   │
│           │                                              │
│  ┌────────▼────────┐     ┌──────────────────────────┐   │
│  │  DEEP ANALYSIS  │     │   ROUTING/PREDICTION     │   │
│  │  DeepSeek 671B  │     │   Fine-tuned classifier  │   │
│  │  (called when   │     │   (fast, cheap, local)   │   │
│  │   Claude needs  │     │   "Given this stack,     │   │
│  │   a second      │     │    test these 10 vulns   │   │
│  │   opinion on    │     │    in this order"        │   │
│  │   novel vulns)  │     └──────────────────────────┘   │
│  └─────────────────┘                                     │
└─────────────────────────────────────────────────────────┘
```

**What each model does:**

- **Claude (Reasoning Core)** - reads raw HTTP responses, forms attack hypotheses, decides what to test next, writes final reports. The "thinking" layer.
- **Fine-tuned classifier (proprietary)** - a small model (Mistral 7B or similar) fine-tuned on community data. Its only job: given tech stack fingerprint → ranked list of vulnerability types to prioritize. Fast, cheap, runs locally. Trained on real acceptance data from thousands of hunts.
- **Fine-tuned embeddings (proprietary)** - the knowledge base retrieval layer. When Claude sees "Express 4.x API with JWT auth," this surfaces the 20 most relevant past successful findings from the community pool. Security-specific RAG, not generic embeddings.
- **DeepSeek 671B (oracle)** - called selectively when Claude hits something genuinely novel. Excellent at technical depth and reasoning about code. The "second expert opinion" at near-zero cost per call.

**Why not build one custom LLM from scratch:**

Training a security-specialized LLM from scratch requires billions of tokens of curated data, millions in compute, and months of work — to reach a baseline still worse than Claude. The orchestra approach is deployable in weeks. The fine-tuned classifier and embedding model are the actual IP — trained on data only you have.

The custom model isn't the product. **The dataset is.**

---

## The Knowledge Flywheel

```
┌─────────────────────────────────────────────────────────┐
│                    THE DATA FLYWHEEL                     │
│                                                          │
│   Hunt runs → Finding validated → User accepts/rejects  │
│        │                                    │           │
│        ▼                                    ▼           │
│   Raw pattern extracted              Outcome labeled     │
│   (anonymized, no PII,               (accepted/dup/     │
│    no target domain)                  false positive)   │
│        │                                    │           │
│        └──────────────┬─────────────────────┘           │
│                       ▼                                  │
│            COMMUNITY PATTERN POOL                        │
│  ┌────────────────────────────────────────────────────┐ │
│  │ tech_stack: "Express 4.18 + PostgreSQL + React"    │ │
│  │ endpoint_pattern: "/api/v2/users/:id"              │ │
│  │ vuln_type: "IDOR"                                  │ │
│  │ payload_class: "horizontal privilege escalation"   │ │
│  │ success_rate: 0.67                                 │ │
│  │ avg_severity: "HIGH"                               │ │
│  │ program_type: "fintech"                            │ │
│  └────────────────────────────────────────────────────┘ │
│                       │                                  │
│                       ▼                                  │
│         Fine-tuned classifier retrains weekly            │
│         Every user gets smarter immediately              │
└─────────────────────────────────────────────────────────┘
```

**What gets anonymized before pooling:**

| Raw data (never leaves user) | What enters the pool |
|---|---|
| `api.shopify.com` | `ecommerce platform, Node.js` |
| Exact JWT payload | `JWT none-algo bypass, success` |
| Response body | `Response pattern class 7` |
| User account details | Stripped entirely |

**Three flywheel mechanics:**

1. **Hypothesis quality improves with scale** - when hunting a React + Django target, the system has already seen 847 similar stacks across the community. It ranks by empirical success rate, not guesswork.
2. **False positive rate drops continuously** - every rejection is a labeled training example. After 50,000 labeled findings the validator knows real findings vs scanner noise with high precision.
3. **Zero-day pattern propagation** - when one hunter discovers a new vulnerability class, the abstract pattern propagates to all users within the weekly retrain. The community discovers it once, everyone benefits.

**The compounding effect:**

```
100 users    → decent classifier, rough pattern data
1,000 users  → solid predictions, reliable success rates
10,000 users → better than any individual expert's intuition
100,000 users → no human can compete with this system's institutional knowledge
```

---

## Product Experience (End to End)

```
DAY 1 - ONBOARDING (5 minutes)
───────────────────────────────
$ pip install bountyhound
$ bountyhound auth login          # Links to web platform
$ bountyhound doctor              # Verifies tools installed
✓ All systems ready. Community patterns: 2.3M loaded.

START A HUNT
────────────
$ bountyhound hunt shopify.com --program h1

[01] RECON          subfinder → httpx → nmap → tech fingerprint
     ✓ 847 subdomains · 312 live · Stack: Rails 7, Redis, AWS

[02] INTELLIGENCE   Querying community patterns for Rails 7 + AWS...
     ✓ 23 high-confidence hypothesis cards generated
     Top: Mass assignment (78% success rate on similar stacks)
           IDOR on /admin routes (61% success rate)
           S3 bucket misconfiguration (43% success rate)

[03] PARALLEL TEST  Claude reasoning on live targets
     Track A: nuclei scanning (background)
     Track B: Browser testing hypothesis cards
     DeepSeek consulted: unusual response on /api/internal ⚡

[04] CHAIN DISCOVERY Combining findings...
     ⚠ CHAIN FOUND: Info disclosure → IDOR → Account takeover
     Severity upgraded: LOW + LOW + MEDIUM → CRITICAL

[05] VALIDATION     Confirming with curl...
     ✓ VERIFIED: Account takeover via chained IDOR
     ✓ Evidence captured: 3 screenshots + curl transcript

[06] REPORT         Generating H1 submission...
     ✓ Draft ready: "Critical: Account Takeover via..."
```

**Web platform UI:**

```
┌──────────────────────────────────────────────────────────┐
│  BOUNTYHOUND PLATFORM                    [+ New Target]  │
├──────────────┬───────────────────────────────────────────┤
│  TARGETS     │  shopify.com                    CRITICAL  │
│  shopify.com │  ─────────────────────────────────────── │
│  github.com  │  Chain: Info disclosure → IDOR → ATO     │
│  stripe.com  │  Confidence: 94% · Validated: ✓          │
│              │  Estimated payout: $8,000-$15,000         │
│  ANALYTICS   │                                           │
│  $47K earned │  [View Full Report] [Submit to H1] [Edit] │
│  89% accept  │  ─────────────────────────────────────── │
│  rate        │  2 more findings pending review...        │
│              │                                           │
│  KNOWLEDGE   │  COMMUNITY INSIGHTS for Rails 7 + AWS    │
│  2.3M patt.  │  Mass assignment: 78% · SSRF: 34%        │
│  Weekly sync │  Top payload class: param pollution       │
└──────────────┴───────────────────────────────────────────┘
```

**Three UX differentiators:**

1. **Payout estimation** - based on community data from similar findings on similar programs, shows expected payout before submission. Hunters prioritize by ROI.
2. **Submission assistant** - knows what each program's triage team responds to. Auto-formats reports, suggests correct severity, flags missing evidence that causes rejections. Trained on real acceptance data.
3. **Hunt while you sleep** - cloud mode runs autonomous hunts 24/7. Wake up to a verified, triaged inbox — not 10,000 lines of scanner output.

---

## Go-To-Market & Defensibility

**Pricing:**

```
┌─────────────────┬───────────────┬───────────────────────┐
│  HUNTER         │  PROFESSIONAL │  TEAM                 │
│  Free           │  $99/month    │  $499/month           │
├─────────────────┼───────────────┼───────────────────────┤
│  Local CLI only │  + Cloud hunts│  + Multi-user         │
│  Basic patterns │  + Full AI    │  + Shared knowledge   │
│  5 targets      │    orchestra  │  + Custom patterns    │
│  Manual reports │  + Auto submit│  + API access         │
│                 │  + Payout est │  + Priority support   │
│  (feeds the     │  Unlimited    │  Unlimited            │
│   community DB) │  targets      │  targets              │
└─────────────────┴───────────────┴───────────────────────┘
```

Free tier exists to feed the flywheel. Free users generate community pattern data that makes paid users' results better.

**Go-to-market phases:**

- **Phase 1 (months 1-3):** Release CLI open source. Target HackerOne/Bugcrowd communities. Goal: 500 active hunters generating real pattern data.
- **Phase 2 (months 3-6):** Publish ROI case study — "our users have X% higher acceptance rate than platform average." This is the number that converts skeptics.
- **Phase 3 (months 6-12):** Land enterprise. Pentest firms with 10 operators = $5K/month and industry validation.
- **Phase 4 (12+ months):** Open an API. Let Burp Suite plugins pull community pattern data. Become infrastructure.

**Defensibility:**

```
THREAT: Synack or HackerOne builds this internally
ANSWER: Legal conflict of interest. Their hunters won't
        consent to pooling data with the platform that pays them.

THREAT: Burp Suite adds AI
ANSWER: No community data network. They have usage telemetry,
        not labeled security findings. Years of catch-up.

THREAT: Anthropic builds this directly
ANSWER: They're an AI company, not a vertical security product.
        More likely they become your infrastructure provider.

THREAT: Open source competitor emerges
ANSWER: Open source the CLI. The moat is the community pattern
        database — proprietary training data, not open sourceable.
```

**Three-layer moat:**

1. **Data moat** - community pattern database. Grows with every hunt. Competitors start at zero.
2. **Model moat** - fine-tuned classifier trained on proprietary data. More accurate every week.
3. **Network moat** - more users = better patterns = better results = more users. Classic compounding flywheel.

---

## Summary

```
THESIS:      The world's first reasoning security agent
             with collective intelligence
DELIVERY:    CLI/agent core + SaaS platform (hybrid)
AI LAYER:    Claude (reasoning) + DeepSeek 671B (oracle)
             + fine-tuned classifier + fine-tuned embeddings
MOAT:        Community pattern database (network effect)
MARKET:      Bug bounty hunters + pentest firms
PRICING:     Free → $99 → $499/month
PHASES:      OSS CLI → Prove ROI → Enterprise → Platform
```
