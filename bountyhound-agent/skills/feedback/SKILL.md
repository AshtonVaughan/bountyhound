---
name: feedback
description: "Handle HackerOne analyst responses and triager feedback — guides how to respond to 'Needs More Info', severity disputes, duplicate claims, and out-of-scope decisions. Trigger this skill whenever an analyst responds to a report, when a submission is triaged as informative or N/A, when the user receives 'Needs More Info', when severity is downgraded, when a duplicate is claimed, or when the user asks how to respond to triager feedback. Also trigger when the user wants to appeal a decision or improve a flagged report."
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# Handling Analyst Feedback

The way you respond to analyst feedback determines your acceptance rate almost as much as the quality of your original report. Most "Needs More Info" rejections are fixable. Most severity disputes are winnable with the right framing. Most duplicate claims can be handled professionally.

---

## Step 1: Read the Feedback Carefully

Before responding to anything, read the analyst's message twice. Identify:
- **What specifically are they asking for?** (Don't respond to what you think they asked)
- **Is it a request for evidence, a request for clarification, or a decision?**
- **Are they questioning the vulnerability, the severity, or the reproduction steps?**

---

## Responding to "Needs More Info"

This is not a rejection. It means they engaged with your report and want more. Address every point they raise — not just the first one.

### They can't reproduce it

The most common reason. Fix by:

1. **Add a prerequisites section** listing exact accounts, state, and setup required
2. **Make every step executable exactly as written** — no "navigate to the settings page", instead write "Go to https://app.target.com/settings/profile"
3. **Add the exact curl commands** they can paste and run
4. **Clarify any ambiguous response** — if the proof shows `{"success":false}` but the bug is still present, explain immediately why that response confirms rather than denies the vulnerability

**Template response:**
```
Hi @{analyst},

Thank you for reviewing my report. I've updated the reproduction steps to address your questions:

## Clarification: {specific point they raised}

{clear, direct answer}

## Updated Reproduction Steps

Prerequisites:
- Account A (victim): {email}, User ID: {id}
- Account B (attacker): {email}, User ID: {id}

Steps:
1. {exact step with exact URL}
2. {exact curl command}
3. Observe: {exactly what to look for}

## Why This Confirms the Vulnerability

{if response looks ambiguous, explain upfront}

I've also attached {screenshot / video / JSON response} as additional evidence.

Please let me know if you need any further clarification.
```

### They're asking how you obtained a token or credential

Provide the exact sequence:
```
1. Navigate to https://target.com/oauth/authorize?client_id=...&response_type=code
2. Complete the OAuth flow with test account credentials: {email}
3. The authorization code appears in the redirect URL: ?code=XXXXX
4. Exchange it:
   curl -X POST https://target.com/oauth/token \
     -d "code=XXXXX&client_id=abc&grant_type=authorization_code"
5. Response contains the access_token used in subsequent requests
```

### They're questioning exploitability

Lead with the successful outcome, not the technical mechanism. Show the data that was accessed or the action that was performed. If you have a screenshot showing another user's PII in your browser — that's the lead, not the HTTP request.

---

## Responding to Severity Downgrades

Severity disputes require evidence, not argument. Don't say "I think this is critical" — show why using their own rubric.

### Strategy

1. **Map to their specific severity guidelines** — read the program's policy page and quote it back
2. **Use CVSS 3.1 scoring breakdown** — metric by metric, no rounding
3. **Reference comparable accepted reports** — search HackerOne's public reports for similar findings and their severity ratings
4. **Frame impact in business terms** — regulatory exposure, affected user count, potential financial impact

### Template for appealing a downgrade

```
Hi @{analyst},

I appreciate the triage and understand your reasoning. I'd like to provide some
additional context on severity for your consideration.

**Per {program name}'s policy ({quote the relevant section})**:
"{quote the section that supports higher severity}"

**CVSS 3.1 Breakdown:**
- Attack Vector: Network (AV:N) — exploitable remotely, no physical access needed
- Attack Complexity: Low (AC:L) — no special conditions required
- Privileges Required: Low (PR:L) — requires only a standard user account
- User Interaction: None (UI:N) — victim doesn't need to take any action
- Confidentiality: High (C:H) — attacker accesses {specific PII/data}

CVSS Score: {score} → {High/Critical}

**Comparable accepted reports:**
- HackerOne #{report_id}: {similar vulnerability} rated {severity}

I understand you have the final call on severity. I just wanted to ensure you had
the full context. Happy to answer any further questions.
```

---

## Responding to Duplicate Claims

First, verify the claim is legitimate:
- Ask for the duplicate report ID (you're entitled to see the report number)
- Check if the duplicate was already resolved or patched — if so, your report is independent
- Check if the attack surface is actually the same (same endpoint + same vulnerability class)

If the duplicate is legitimate: respond professionally, note that you discovered it independently, and ask if they have any feedback for improving your future reports. Some programs reward late duplicates with a smaller bounty.

If you believe the duplicate claim is wrong:
```
Hi @{analyst},

Could you share the report number for the claimed duplicate? I'd like to confirm
they cover the same endpoint and vulnerability class.

My report specifically covers:
- Endpoint: {exact URL}
- Vulnerability: {specific mechanism}
- Proof: {what I demonstrated}

If the referenced report covers the same surface and mechanism, I fully accept the
duplicate status. I just want to confirm before closing this out.
```

---

## When a Report Is Marked Informative or N/A

This happens for two reasons:
1. **The vulnerability isn't considered security-relevant by this program** — this is often policy, not technical disagreement. Asking "but isn't this a security issue?" won't change it.
2. **The vulnerability isn't actually exploitable** — you need to provide a working PoC.

**For policy-based N/A:**
Check if the same vulnerability class is accepted elsewhere. Move on.

**For exploitability-based N/A:**
Provide a working end-to-end demonstration. If you described the vulnerability but didn't actually exploit it — do it now and update the report.

---

## Timing

- **Respond within 48 hours** of receiving feedback — analysts move on
- **Respond during weekday business hours** when possible — faster re-review
- **Don't send multiple messages** before they respond — one comprehensive update is better
- **Thank them even if the outcome is bad** — you'll work with the same analysts again

---

## What Not to Do

- Don't argue about whether something "could potentially" be exploited — prove it
- Don't CC or escalate to HackerOne staff unless the program is unresponsive for 30+ days
- Don't publicly disclose while a report is open, even if frustrated
- Don't submit the same report twice — update the existing one
- Don't get defensive — analysts aren't adversaries, they're under-resourced and doing their best
