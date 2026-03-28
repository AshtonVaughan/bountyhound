# Perfect Hunter Methodology — Design Document

**Date:** 2026-02-20

## Goal

Define the gold-standard hunting methodology for bountyhound-agent: how it selects targets,
how it tests, and how it verifies before submitting. Modelled on the patterns observed in
top HackerOne earners (tomanthony: 97th impact percentile, nasserwashere: 6.78 signal score,
firs0v: 95th impact percentile, nnwakelam: $1M+ earner).

## Core Principle

Three sequential, gated layers. A finding can only advance by passing each gate.
No gate can be skipped, even if the finding looks compelling.

```
LAYER 1: SELECTION  → score every surface before testing anything
LAYER 2: TESTING    → hypothesis-driven, budget-capped, signal-first
LAYER 3: VERIFICATION → staged checklist then AI self-challenge
                     → REPORT only on verified survivors
```

---

## Layer 1 — Selection (Priority Scoring)

Every discovered endpoint/parameter gets scored before any test is run.

```python
def priority_score(endpoint) -> float:
    severity_potential = score_severity_potential(endpoint)  # 0.0 - 1.0
    novelty_score      = score_novelty(endpoint)             # 0.0 - 1.0
    return (severity_potential * 0.6) + (novelty_score * 0.4)
```

### Severity Potential Scoring

| Surface | Score |
|---------|-------|
| Auth endpoints (`/login`, `/oauth`, `/token`, `/reset`) | 0.9–1.0 |
| Admin / privileged endpoints | 0.85 |
| File upload / download | 0.80 |
| API endpoints with user IDs (IDOR potential) | 0.70 |
| Search / filter with parameters | 0.50 |
| Static assets, health checks | 0.10 |

### Novelty Scoring

| Condition | Score |
|-----------|-------|
| Not in Target Brief disclosed reports + not a common pattern | 1.0 |
| Similar to disclosed reports but different parameter | 0.5 |
| Exact surface pattern appears in multiple disclosed reports | 0.1 |

### Test Tiers

| Score | Tier | Budget |
|-------|------|--------|
| ≥ 0.85 | Critical priority | 30 min / 50 requests |
| 0.70–0.84 | High priority | 15 min / 25 requests |
| 0.55–0.69 | Medium priority | 5 min / 10 requests |
| < 0.55 | Skip | 1 probe only |

Only endpoints scoring ≥ 0.55 composite receive deep testing.

---

## Layer 2 — Testing (Hypothesis-Driven)

### Test Structure (per endpoint)

```
1. Form hypothesis   — "This endpoint may be vulnerable to X because Y"
                       Informed by Target Brief prior intel + endpoint type
2. Minimum viable probe — single targeted request to confirm the surface
3. Escalate only if probe shows signal — don't expand on silence
4. Document evidence as you go — request/response, impact statement
```

### Auth Endpoint Testing (highest-value surface)

- Token fixation, token reuse after logout
- OAuth state parameter manipulation
- Password reset flow race conditions
- MFA bypass via response manipulation
- Account enumeration via timing / response diff

### Stop Conditions

- Budget exhausted with no signal → skip, log, move on
- Signal found → freeze evidence immediately, enter Verification Layer
- 3 consecutive zero-signal endpoints → re-evaluate queue, may stop early

---

## Layer 3 — Verification (The Signal Engine)

Every finding that exits the Testing Layer enters this two-stage gate.
Nothing reaches a report until it exits Stage B.

### Stage A — Checklist (5 deterministic gates)

All 5 must pass. Fail any one → finding is dropped, logged as false positive.

```
□ 1. REPRODUCIBILITY  Re-exploit from clean state (fresh session, new IP if needed).
                      Result must match original finding exactly.

□ 2. SCOPE            Target URL matches program scope exactly.
                      Wildcard rules applied. No assumptions.

□ 3. IMPACT           Can articulate real-world harm in one sentence.
                      "An attacker could X" — not "this might Y"

□ 4. SEVERITY FLOOR   CVSS base score ≥ 4.0 (medium+).
                      Below this: log it, don't submit.

□ 5. DUPLICATE CHECK  Compare against Target Brief disclosed reports
                      + current session findings.
                      Same root cause = duplicate. Don't submit.
```

### Stage B — Self-Challenge (AI vs AI)

A second independent agent receives only: the endpoint, the payload, the response.
Its sole job is to find reasons the finding is NOT valid.

**Challenger asks:**
- "Is this actually exploitable or just reflected?"
- "Does the program's threat model consider this in-scope impact?"
- "Is there a simpler explanation for this response?"
- "Would a real attacker reproduce this without special access?"

**Outcome:**
- Challenger cannot disprove → finding is verified, advances to reporting
- Challenger raises valid doubt → return to Stage A for re-verification or drop

**Stage B output:** verified finding with reproducibility proof, impact statement,
CVSS score, and the challenger's failed counter-arguments.

---

## Reporting Layer

### Report Structure

```
TITLE:    One sentence. Vulnerability type + component + impact.
          Bad:  "XSS in search"
          Good: "Stored XSS in /messages allows session hijacking of any user"

SUMMARY:  3 sentences max. What, where, what an attacker gains.

STEPS:    Numbered. Exact. Reproducible by a junior engineer with no context.
          Include: URL, method, payload, expected vs actual response.

IMPACT:   Business consequence, not technical detail.
          "An attacker can take over any user account without interaction"
          not "the cookie is accessible via document.cookie"

EVIDENCE: Request/response pair. Screenshot of impact. CVSS score with justification.

SEVERITY: Researcher-suggested severity with CVSS breakdown.
          Never over-inflate — damages credibility with triage.
```

### Submission Rules

- Include challenger's failed arguments as "Mitigating factors considered and ruled out"
  — preempts triage objections, signals rigorous testing
- One finding per report — never bundle
- Submit at start of program team's business day (check timezone)

---

## Full Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│ PHASE 0.5  Target Brief                                      │
│  H1 disclosed reports + CVEs + changelog → prior intel      │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│ PHASE 1    Recon + Discovery                                 │
│  Subdomains, endpoints, parameters, tech stack              │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│ SELECTION  Priority Scoring                                  │
│  score = (severity_potential × 0.6) + (novelty × 0.4)       │
│  ≥ 0.85 → deep test   0.55–0.84 → standard   <0.55 → skip  │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│ TESTING    Hypothesis-Driven, Budget-Capped                  │
│  Form hypothesis → minimum probe → depth only if signal     │
│  Auth > file upload > API w/ IDs > search > static          │
└──────────────────────┬──────────────────────────────────────┘
                       │ (finding found)
┌──────────────────────▼──────────────────────────────────────┐
│ VERIFICATION  Stage A: Checklist (5 gates)                   │
│  Reproducible + In-scope + Impact + CVSS≥4 + Not duplicate  │
│               ↓ pass                                        │
│            Stage B: Self-Challenge                           │
│  Independent AI tries to disprove. Survives if unchallenged.│
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│ REPORTING  Structured, Impact-First                          │
│  Title + Summary + Steps + Impact + Evidence + CVSS         │
│  Challenger's failed arguments included as proof of rigor   │
└─────────────────────────────────────────────────────────────┘
```

---

## The Three Differentiators

1. **Test less, test smarter** — priority scoring concentrates depth where severity
   and novelty are highest. Average hunters test everything equally.

2. **Never submit noise** — two-stage verification (checklist + self-challenge) kills
   false positives, out-of-scope findings, and low-severity over-reporting before
   they cost credibility. nasserwashere's 6.78 signal score is this discipline.

3. **Reports sell themselves** — structured impact-first format with pre-emptive
   counter-arguments removes every triage objection before it's raised.

---

## Implementation Notes

This methodology replaces / extends the current `phased-hunter.md` pipeline.

**New components to build:**
- `engine/scoring/priority_scorer.py` — endpoint priority scoring
- `engine/verification/checklist.py` — Stage A 5-gate checklist
- `engine/verification/challenger.py` — Stage B AI self-challenge agent
- Updated `agents/phased-hunter.md` — Selection + Verification phases added

**Integrates with existing:**
- Phase 0.5 Target Brief (H1 + CVE + changelog) feeds novelty scoring
- Phase 1 recon output feeds endpoint discovery queue
- Existing quality gates in Phase 4 replaced by new Verification Layer
