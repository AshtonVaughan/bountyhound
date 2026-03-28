---
name: report-psychology
description: "Writing vulnerability reports based on actual HackerOne analyst feedback and successful submissions"
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# Report Psychology - Updated from Real Analyst Feedback

## The Golden Rule (From Actual Experience)

**Analysts want to see it working, not just described.**

### What Passed Preliminary Review:
- Detailed technical evidence
- HTTP requests/responses
- Architectural context
- Multiple evidence types
- Clear impact statements

### What Triggered "Needs More Info":
- Ambiguous results (success: false)
- Missing visual proof
- Unclear reproduction steps
- Key details buried in text

## The Perfect Report Structure

```markdown
# [Vulnerability] in [Feature] leads to [Impact]

## Summary (2-3 sentences)
Lead with what you accomplished, not how you discovered it.

## Expected vs Actual Behavior (MANDATORY)
**Expected:** [What should happen]
**Actual:** [What actually happens - lead with the result]

## Steps to Reproduce
[Copy-paste ready commands]

## Impact
[Business consequences]

## Supporting Material
[Screenshots, videos, HTTP logs]

## Recommended Fix
[Actionable remediation]
```

## Title Engineering

### Formula
```
[Vulnerability Type] in [Feature/Endpoint] leads to [Impact]
```

### Real Examples That Passed

**✅ GOOD (our reports that passed):**
- "S3 Bucket Takeover - wsop-poker-stage61 allows arbitrary file hosting"
- "Systemic Authentication Bypass in GraphQL Gateway allows unauthorized mutations"
- "Gift Card Code Brute Force via applyCredit mutation"

**✅ GOOD (HackerOne examples):**
- "Stored XSS in user profile field allows script execution on profile view"
- "IDOR in /api/users/{id} allows reading any user's PII"
- "SQL Injection in search endpoint exposes entire customer database"

**❌ BAD:**
- "XSS found"
- "Bug in API"
- "CRITICAL VULNERABILITY"
- "Multiple security issues"

## Expected vs Actual Behavior (MANDATORY)

This section MUST come first after summary. HackerOne's official guidelines emphasize this.

### Template

```markdown
## Expected vs Actual Behavior

**Expected Behavior:**
[Describe what SHOULD happen from a security perspective]
[Be specific about which controls should exist]

**Actual Behavior:**
[Describe what ACTUALLY happens]
[Lead with the successful exploitation result]
```

### Real Example (From Our Reports)

```markdown
## Expected vs Actual Behavior

**Expected Behavior:**
When Account B (Consumer ID: 1125900605646813) calls reorderOrder with
Account A's orderUuid, the server should verify ownership and return:
{"errors": [{"message": "FORBIDDEN", "code": "UNAUTHORIZED"}]}

**Actual Behavior:**
The server processes Account A's orderUuid without authorization checks and
creates a cart in Account B's session:
{"data": {"reorderOrder": {"cartUuid": "1851d5cf-3903-4282-ac2a-971f9d17c90c"}}}

This cart contains Account A's complete order data including delivery address,
items ordered, and restaurant information.
```

### Why This Matters

- Analysts expect this format (it's in their official guidelines)
- Makes the vulnerability immediately clear
- Shows you understand security expectations
- Prevents confusion about "working" vs "not working"

## Steps to Reproduce - Copy-Paste Ready

Every step must be **executable exactly as written**.

### Real Example (From Our Reports)

```markdown
## Steps to Reproduce

### Prerequisites
- Account A (victim): ashtonluca+doordash@gmail.com, Consumer ID: 1120429570
- Account B (attacker): ashtonluca+dd2@gmail.com, Consumer ID: 1125900605646813

### Reproduction

1. Log into Account A at https://www.doordash.com/login
2. Place any order (or use existing order)
3. Note the orderUuid from the URL: 6053a136-3806-4d79-9210-e69094d35100

4. Log into Account B (separate browser or incognito window)

5. Open browser DevTools (F12) → Console tab

6. Execute the following (replace orderUuid with Account A's value):
   ```javascript
   fetch('/graphql/reorderOrder?operation=reorderOrder', {
     method: 'POST',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({
       query: 'mutation { reorderOrder(orderUuid: "6053a136-3806-4d79-9210-e69094d35100") { success cartUuid __typename } }'
     })
   }).then(r=>r.json()).then(console.log)
   ```

7. **Observe:** Response includes cartUuid:
   ```json
   {
     "data": {
       "reorderOrder": {
         "success": false,
         "cartUuid": "1851d5cf-3903-4282-ac2a-971f9d17c90c"
       }
     }
   }
   ```

8. **Key Finding:** Despite `success: false` (store closed), the cart WAS created

9. Verify cart contains victim's data:
   ```javascript
   fetch('/graphql/orderCart?operation=orderCart', {
     method: 'POST',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({
       query: '{ orderCart(id: "1851d5cf-3903-4282-ac2a-971f9d17c90c") { deliveryAddress { street city state zipCode } } }'
     })
   }).then(r=>r.json()).then(console.log)
   ```

10. **Result:** Account B receives Account A's delivery address
```

### Key Principles

- Start from clean state
- Include exact URLs/endpoints
- Provide working payloads
- One action per step
- Show what to observe
- Clarify ambiguous responses immediately

## Handling Ambiguous Results

If your PoC has ANY response that looks like failure, address it UPFRONT.

### ❌ What We Did Wrong (DoorDash IDOR)

```markdown
Step 7: Observe response:
{"success": false, "cartUuid": "abc-123"}

[Then 100 lines later explaining why this is actually successful]
```

**Result:** Analyst confused, requested clarification

### ✅ How to Fix It

```markdown
Step 7: **KEY FINDING** - Cart created despite "success: false"

Response:
{"success": false, "cartUuid": "1851d5cf-3903-4282-ac2a-971f9d17c90c"}

**IMPORTANT:** The `success: false` flag is business logic (store closed),
NOT an authorization error. The proof of vulnerability is:

1. ✅ cartUuid was returned (cart exists)
2. ✅ No authorization error (no FORBIDDEN/UNAUTHENTICATED)
3. ✅ Cart contains victim's data (verified in next step)

If authorization failed, the response would be:
{"errors": [{"message": "UNAUTHENTICATED"}]}
```

## Impact Statement - Business Language

### Template

```markdown
## Impact

This vulnerability allows an attacker to {specific_capability}.

**Affected Users:** {scope}

**Attack Scenario:**
1. Attacker does X
2. This reveals Y
3. Leading to Z (account takeover, data breach, financial loss)

**Business Consequences:**
- Regulatory violations: {GDPR, PCI-DSS, HIPAA}
- Financial impact: {data breach costs, fines}
- Reputational damage: {customer trust, media coverage}
```

### Real Example (From Our Reports)

```markdown
## Impact

This vulnerability allows an authenticated attacker to access ANY DoorDash
user's order information by providing the victim's orderUuid.

**Affected Users:** All 10M+ DoorDash customers

**Attack Scenario:**
1. Attacker obtains victim's orderUuid (from tracking link, shared URL, or enumeration)
2. Calls reorderOrder mutation with victim's orderUuid
3. Server creates cart containing victim's:
   - Complete delivery address (including apartment numbers)
   - Order items and quantities
   - Restaurant name and location
   - Order total and pricing

**Business Consequences:**
- **Privacy Violation:** Exposure of home addresses enables stalking, harassment
- **GDPR Violation:** Unauthorized access to personal data (Article 32)
- **Regulatory Fines:** Up to 4% annual revenue (~$240M based on $6B 2023 revenue)
- **Reputational Damage:** "DoorDash exposes customer addresses" headlines
- **Class Action Risk:** Privacy breach affecting millions of users
```

### Impact Language That Works

**✅ Money/Business Impact:**
- "Attackers could access all customer payment data"
- "Complete transaction manipulation affecting $X in daily revenue"
- "Account takeover enables fraudulent orders"

**✅ Scale Emphasis:**
- "Affects all 10M users"
- "Every order placed since 2019 is accessible"
- "Entire customer database at risk"

**✅ Regulatory/Compliance:**
- "GDPR Article 32 violation (€20M or 4% revenue penalty)"
- "PCI-DSS compliance failure (Section 6.5.8)"
- "HIPAA breach potential ($50K per violation)"

**❌ Technical (Not Business):**
- "XSS vulnerability exists"
- "Parameter is injectable"
- "Missing authorization check"

## Supporting Material - Visual Proof Required

Based on actual analyst requests, you MUST include:

### Minimum (Required)
- [ ] 2+ screenshots showing exploitation
- [ ] Raw HTTP request/response
- [ ] Proof of successful result

### Better (Recommended)
- [ ] Video demonstration (for complex flows)
- [ ] Multiple screenshots (step-by-step)
- [ ] Before/after comparison
- [ ] JSON response files

### Best (For Critical Bugs)
- [ ] Narrated video walkthrough
- [ ] Interactive HTML demonstration
- [ ] Automated PoC script
- [ ] Actual proof (claimed S3 bucket, uploaded file, etc.)

### Real Examples

**What Passed (Playtika S3):**
- Actually claimed the bucket
- Uploaded ashtonv.html file
- Provided public URL
- Showed bucket policy configuration

**What Needed Clarification (Epic Games):**
- Initial: Just described the API response
- After feedback: Created HTML demonstration page
- Uploaded token_response.json, epic_namespace_response.json
- Took full-page screenshot

**What Needed Clarification (DoorDash IDOR):**
- Initial: Text-based reproduction with ambiguous response
- After feedback: Explained cart creation in detail
- Compared vulnerable vs secure endpoints
- Clarified success:false meaning

## Technical Detail is GOOD (When Organized)

Contrary to what you might think, analysts WANT technical detail. Just organize it.

### ✅ What Works

```markdown
## Technical Analysis

**Architecture Context:**
- Platform: Next.js + Apollo GraphQL Gateway
- Backend: gRPC microservices
- Authentication: JWT via Authorization header
- API: www.doordash.com/graphql/{operation}

**Root Cause:**
The GraphQL gateway forwards mutations to backend services without
authorization middleware. Backend validates entity existence but not ownership.

**Scope - Affected Mutations:**
| Mutation | Auth Check? | Evidence |
|----------|-------------|----------|
| reorderOrder | ❌ NO | Creates cart with victim's data |
| cnrReviewDetails | ❌ NO | Returns delivery details |
| getConsumerOrderRatingForm | ❌ NO | Returns rating form data |
| deleteCart | ✅ YES | Returns FORBIDDEN (proper auth) |

**Systemic Pattern:**
The codebase HAS authorization checks (deleteCart proves this) but they're
inconsistently applied across 29 GraphQL mutations. This suggests a systemic
issue in the gateway's authentication middleware.

**Discovery Method:**
Found via Apollo Server field suggestions. Introspection is disabled but
invalid field names trigger "Did you mean..." responses that reveal schema.
```

### Why This Works

- Shows you deeply understand the vulnerability
- Proves inconsistent security (compare secure vs vulnerable)
- Helps security team understand scope
- Demonstrates professional research
- Makes it easier to fix (they know where to look)

## Common Analyst Questions & Prevention

### Question: "Can you provide more details?"

**Prevention:**
- Include Expected vs Actual section
- Show full HTTP requests/responses
- Provide video or multiple screenshots
- Clarify ambiguous responses upfront
- Lead with successful result

### Question: "Can you clarify how to obtain the token?"

**Prevention:**
- Include exact curl command
- Show OAuth flow step-by-step
- Provide credentials to use
- Note if credentials are public/documented
- Include token in actual HTTP request example

### Question: "Is this actually exploitable?"

**Prevention:**
- Lead with successful result
- Show data actually leaked/modified
- Clarify any "false" flags immediately
- Provide before/after comparison
- Don't just describe, actually exploit it

### Question: "Can you demonstrate this working?"

**Prevention:**
- Always include actual PoC
- Actually perform the attack
- Claim the bucket, upload the file, etc.
- Show success, not just theory
- Video is best for complex flows

## Severity Justification

Map to their exact guidelines:

```markdown
## Severity Justification

**Recommended Severity:** High (7.5 CVSS)

**Per HackerOne/DoorDash Guidelines:**
- Unauthorized access to PII (High severity per policy)
- No authentication required beyond basic account (increases severity)
- Affects all users at scale (High → Critical per policy)
- Easily automated for mass exploitation (increases severity)

**CVSS 3.1 Breakdown:**
- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: Low (PR:L) - requires any account
- User Interaction: None (UI:N)
- Scope: Unchanged (S:U)
- Confidentiality: High (C:H) - PII exposed
- Integrity: None (I:N)
- Availability: None (A:N)

**CVSS Vector:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
**CVSS Score:** 7.5 (High)

**Similar Public Reports:**
- HackerOne Report #123456: IDOR in Order API - rated High
- HackerOne Report #789012: User data access - rated Critical (due to scale)
```

## Timing Strategy (From Experience)

### When to Submit

**Critical/High:** Immediately (duplicates are time-sensitive)
**Medium:** Same day
**Low:** Batch weekly (maintain reputation)

### Best Days

**Tuesday-Thursday:** Fastest triage (based on our experience)
**Avoid:** Friday afternoon, weekends, holidays

### Our Data

| Report | Submitted | First Response | Status |
|--------|-----------|----------------|--------|
| DoorDash Systemic | Thu 1am | Thu 6am (5 hrs) | Passed prelim |
| DoorDash Gift Card | Thu 1am | Sat 7am (30 hrs) | Passed prelim |
| Playtika S3 | Wed 1am | Sat 6am (53 hrs) | Needs info |
| Epic Games | Wed 3am | Sat 7am (52 hrs) | Needs info |
| DoorDash IDOR | Thu 11am | Thu 5pm (6 hrs) → Sat 6am (re-review) | Needs info |

**Pattern:** Weekday submissions get faster initial triage

## Response to Analyst Feedback

### When Analyst Says "Needs More Info"

**✅ DO:**
- Thank them professionally
- Address EVERY point they raised
- Provide the exact evidence they requested
- Clarify any confusion clearly
- Update the report comprehensively

**❌ DON'T:**
- Get defensive
- Argue about severity
- Ignore their requests
- Provide partial information
- Write essays defending your report

### Template Response

```markdown
Hi @h1_analyst_name,

Thank you for reviewing my report! I've created a comprehensive
demonstration addressing your questions:

## How to Obtain the Token

[Step-by-step with exact commands]

## Security Impact

[Clear explanation of why it matters]

## Visual Demonstration

I've created an interactive demonstration page showing all steps:
http://localhost:8765/demonstration.html

I've also attached:
1. full-page-screenshot.png - Complete visual walkthrough
2. token_response.json - Raw OAuth response
3. api_response.json - Raw API response showing the issue

Please let me know if you need any additional clarification!

Best regards,
[Your name]
```

## Final Checklist

Before submitting ANY report:

### Evidence
- [ ] At least 2 screenshots
- [ ] Raw HTTP request/response
- [ ] Video (if complex)
- [ ] Actual proof (not just description)

### Structure
- [ ] Expected vs Actual section present
- [ ] Copy-paste ready reproduction steps
- [ ] Business-focused impact statement
- [ ] Ambiguous results clarified upfront

### Quality
- [ ] Lead with successful result
- [ ] No spelling/grammar errors
- [ ] Markdown properly formatted
- [ ] All sensitive data redacted

### Testing
- [ ] Actually performed the exploit
- [ ] Verified it works end-to-end
- [ ] Compared with secure endpoints
- [ ] Tested with open store/valid conditions

## Key Learnings from Real Experience

1. **Analysts WANT technical detail** - Just organize it clearly
2. **Visual proof is mandatory** - Screenshots/videos required
3. **Expected vs Actual is non-negotiable** - Always include it
4. **Ambiguous results need immediate clarification** - Don't bury it
5. **Actually exploit it** - Don't just describe, prove it works
6. **Lead with results** - Not discovery methodology
7. **Business impact matters** - Translate technical to business risk

## Success Metrics

From our actual reports:

**Passed Preliminary Review:**
- DoorDash Systemic (Critical) - passed in 5 hours
- DoorDash Gift Card (High) - passed in 30 hours

**Needed Clarification:**
- Playtika S3 - needed actual bucket claim
- Epic Games - needed token acquisition demo
- DoorDash IDOR - needed success:false clarification

**Success Rate: 40% passed immediately, 60% needed one clarification round**

**Key Insight:** Reports with visual proof and clear results pass immediately.
Reports without visual proof need clarification rounds.
