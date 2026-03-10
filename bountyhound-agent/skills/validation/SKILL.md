---
name: validation
description: |
  4-layer validation protocol for confirming bug bounty findings before surfacing them.
  Use this skill when validating any potential finding. Ensures zero false positives
  reach the hunter. The hard rule: a finding that fails any layer is silently discarded.
  Load this skill whenever the validator agent runs.
model: inherit
tools: all
---

# Validation Skill

Every finding must pass 4 layers before being surfaced. You only report confirmed,
reproducible findings. A false positive (especially one the user has to challenge)
is worse than missing a real bug — it destroys trust in every future finding.

## The Hard Rule

If you are not certain a finding is real and non-intentional, **discard it.**
Certainty means: you can demonstrate it in browser, reproduce it with curl, and
articulate what an attacker can actually do with it.

## Layer 0 — By-Design Check

Run before any testing. Sources to check, in order:

1. Program policy page — is this vulnerability class explicitly excluded?
2. Public documentation — does any doc describe this behaviour as intentional?
3. GitHub issues — search for the behaviour. Closed as "by design"? Discard.
4. GitHub PRs / commits — was this intentionally implemented with an explanation?
5. Changelog / release notes — was this behaviour deliberately added?
6. Prior H1 disclosed reports for this program — same issue closed as informative? Discard.
7. Source code comments — does the code say `// intentional` or `// by spec`?
8. RFC or protocol spec — is this required behaviour per the standard?

See `references/layer-pass-conditions.md` for exact PASS/FAIL wording templates.

**PASS:** State specifically what you checked and what you did NOT find.
"I checked [all 8 sources]. [Source A] and [Source B] do not mention this behaviour.
There is no evidence this is intentional."

**FAIL:** State what you found.
"Discarded: by design. [Source] states [quote/description]."

## Layer 1 — Browser Reproduction

Execute the exploit in Chrome. Record a GIF. Proxy captures raw HTTP.

See `references/layer-pass-conditions.md` → Layer 1 table for PASS conditions
per vulnerability class. The key insight: "visible" does not always mean rendered
in the browser UI — proxy capture and DevTools count as observation.

**FAIL:** No observable impact anywhere → discard immediately. Do not proceed to Layer 2.

## Layer 2 — Curl Chain

Extract the minimal reproducible request sequence from proxy capture.

Headers to KEEP: `Authorization`, `Cookie`, `Content-Type`, `Origin`, `Referer`,
any `X-*` custom headers that affect routing or auth, `Host`.

Headers to STRIP: `Accept-Encoding`, `Accept-Language`, `Cache-Control`,
`Upgrade-Insecure-Requests`, `User-Agent` (unless UA-specific bug).

Re-run the stripped curl chain. Confirm the response matches Layer 1 observation.

**FAIL:** curl does not reproduce the same response → browser state dependency,
not a real reproducible finding. Discard.

## Layer 3 — Impact Analysis

Answer all four questions with specific, concrete answers:
1. What data or functionality is exposed or modified? (name specific data types)
2. How many users could be affected? (estimate: one, some, all)
3. Is it exploitable without special access? (unauthenticated, or low-privilege user)
4. What is the measurable business impact? (data breach, financial loss, service disruption)
5. Calculate CVSS 3.1 score.

See `references/layer-pass-conditions.md` → CVSS quick reference.

**FAIL:** No measurable impact, or requires admin access to exploit with no escalation path → discard.

## Challenge Protocol

See `references/challenge-protocol.md` for the complete protocol.

**Summary:** One challenge from the user = immediate fresh re-evaluation of Layer 0.
You do not defend the finding. You do not reference your previous check.
You report the result honestly. If any doubt: discard.
