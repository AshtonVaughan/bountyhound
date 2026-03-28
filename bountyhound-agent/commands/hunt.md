---
name: hunt
description: Run the full BountyHound intelligence-driven hunt loop against a target. Invokes the 6-phase pipeline: target research → model build → hypothesis generation → browser testing → 4-layer validation → report. Only confirmed findings with GIF + curl chain + impact statement reach you.
---

# /hunt <target>

Starts the BountyHound intelligence loop against the specified target.

## Usage

```
/hunt <domain-or-program-name>
```

Examples:
```
/hunt hackerone.com
/hunt vercel-open-source
/hunt goldmansachs
```

## What Happens

The hunt runs six sequential phases via `intelligence-loop.md`:

**① Target Research** (~20 min)
- Subdomain enumeration (amass)
- Port scan (nmap)
- Tech stack fingerprinting (browser)
- JS bundle crawl — endpoints, auth flows, secrets
- Source code read (GitHub, if public)
- CVE + prior disclosure lookup (bountyhound.db)
- 5 min authenticated browse (if credentials available)

**② Build Target Model**
- Writes `findings/<program>/target-model.json`
- Syncs to bountyhound.db targets table
- If target model exists and is < 14 days old: skips Phase ①

**③ Hypothesis Generation**
- Track 1: CVE matching + nuclei scan (baseline)
- Track 2: Novel hypotheses from implementation reasoning, business logic, component interaction, recent changes, variant generation, adversarial framing
- Each hypothesis scored 1-10 on Novelty/Exploitability/Impact/Effort and sorted descending

**④ Browser Testing**
- Each hypothesis tested in Chrome
- GIF recorded per test
- Proxy captures all traffic

**⑤ 4-Layer Validation**
- Layer 0: By-design check (8 sources consulted)
- Layer 1: Browser reproduction (must see impact)
- Layer 2: Curl chain (must reproduce headlessly)
- Layer 3: Impact analysis + CVSS score
- Confirmed fails are discarded silently; `[NEEDS-PROOF]` and `[WAF-BLOCKED]` findings are surfaced to you

**⑥ Report**
- H1-ready markdown → `findings/<program>/reports/`
- Finding metadata → bountyhound.db findings table
- Every report includes: GIF, working curl chain, impact statement, CVSS score

## Output

You only see confirmed findings. Each finding includes:
- **GIF** of the exploit in Chrome
- **Curl chain** you can paste and run
- **Impact statement** (data exposed, user count, CVSS)
- **Draft H1 report** ready to submit

## Options

- If credentials are available, run `/creds add <program>` first so the authenticated surface is included in recon.
- To re-run recon on a known target (force refresh), the target model will be stale after 14 days automatically. To force earlier: delete `findings/<program>/target-model.json`.
