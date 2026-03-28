---
name: rate-limit-bypass
description: |
  Rate limiting, throttling, and account/IP ban evasion during authorized bug bounty testing.
  Trigger when: requests start getting 429 Too Many Requests, 403s after rapid testing,
  test accounts get locked, testing hits per-minute/per-hour caps, brute force protection
  kicks in, or any time aggressive testing is blocked by non-WAF controls. Distinct from
  waf-bypass (payload filtering) — this skill is about request velocity, account health,
  and timing. Use proactively before testing endpoints that involve auth, enumeration,
  or repeated identical requests.
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


## Authorization

This skill operates within the scope of an authorized HackerOne, Bugcrowd, or Intigriti bug bounty engagement. All techniques here are applied only to in-scope targets under formal program authorization. Rate limit bypass is used to conduct thorough authorized testing, not to attack production systems beyond the program's defined boundaries.

---

## Detection — What Type of Rate Limiting Are You Hitting?

The bypass strategy depends entirely on what is enforcing the limit. Misidentifying the limiter wastes time and may burn accounts. Identify before acting.

### 1. Per-IP Rate Limiting

**Signals:**
- HTTP `429 Too Many Requests` with a `Retry-After` header (e.g., `Retry-After: 60`)
- Same 429 appears across multiple unrelated endpoints after rapid testing
- Unauthenticated requests also hit the limit — not tied to a session
- Clears after waiting the Retry-After window
- Response body often: `{"error": "rate limit exceeded"}`, `"Too many requests from this IP"`, `X-RateLimit-Remaining: 0`

**Confirm it:** Wait the Retry-After window, make one request — if it succeeds, it's per-IP.

### 2. Per-Account Rate Limiting

**Signals:**
- 429 only occurs when authenticated (unauthenticated calls to the same endpoint are fine)
- Switching to a different test account clears the limit immediately
- Headers like `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` are present and tied to account identity
- Response body: `"You have exceeded your request quota"`, `"Account rate limit reached"`

**Confirm it:** Log out, make the same request as unauthenticated — if no 429, it's per-account.

### 3. Per-Session Rate Limiting

**Signals:**
- 429 clears when you get a new session cookie (without re-authenticating to a new account)
- Appears after N requests within the session lifetime
- Session token rotation (logout → login with the same account) resets the counter

**Confirm it:** Re-authenticate the same account, get a fresh session — if the limit resets, it's per-session.

### 4. Global / Endpoint-Level Limiting (By Design)

**Signals:**
- 429 or slowdowns appear for all users simultaneously (test from a second unrelated IP/account — both hit it)
- The endpoint is a high-cost operation: export, report generation, bulk search
- Retry-After is very long (hours), suggesting intentional throttling not abuse detection

**Action:** Accept this limit. If the threshold is unreasonably low for the endpoint's stated purpose, that may be a usability finding, but it is not a security vulnerability. Do not burn resources trying to bypass intentional design limits.

### 5. Progressive Back-off

**Signals:**
- First request succeeds, second adds delay, third adds more — the effective rate degrades linearly or exponentially
- Response headers: `X-RateLimit-Remaining` decrements but doesn't hit 0; responses just get slower
- Sometimes manifests as increased `X-Response-Time` rather than 429s

**Confirm it:** Time three consecutive requests — if RTT doubles each time, it's progressive.

### 6. Soft vs. Hard Bans

**Soft ban:**
- Temporary block with a countdown or Retry-After window
- Resolves automatically after the window
- May show a `503 Service Unavailable` or custom block page with a timer

**Hard ban:**
- IP or account is flagged persistently — requests fail even hours later
- Account login may return `"Account suspended"` or `"Contact support"`
- Hard bans on test accounts are rare in bug bounty but happen on sensitive auth flows

**Action on hard ban:** Stop testing that account/IP immediately. Switch accounts. Note in `{FINDINGS}/memory/defenses.md`. Do not attempt to circumvent a hard account ban — contact the program if a test account gets permanently locked.

### 7. CAPTCHA Gating

**Signals:**
- After N requests, response changes to a CAPTCHA challenge page or a `403` with body containing `cf-chl`, `hcaptcha`, `recaptcha`, `g-recaptcha`
- Burp/curl receives the CAPTCHA HTML — no automatic bypass
- Typically follows per-IP or per-session limiting as a second layer

**Action:** Slow down below the CAPTCHA threshold. If the threshold is very low (e.g., 3 requests triggers CAPTCHA on a non-auth endpoint), it may be worth noting as aggressive bot protection, but it is not a bypass finding.

### 8. Account Lockout (Auth Endpoints)

**Signals:**
- Occurs exclusively on authentication endpoints: `/login`, `/reset-password`, `/verify-otp`, `/mfa`
- After N failed attempts, the account enters a locked state
- Subsequent correct credentials also fail until lockout expires
- Response: `"Account locked"`, `"Too many failed attempts. Try again in 30 minutes"`, HTTP `423 Locked`

**Critical distinction:** Account lockout is a security control, not a rate limit. Never attempt to brute-force past it. The lockout threshold itself is the finding (or the absence of one is the finding).

---

## Strategy Selection Table

| Type detected | Primary strategy | Secondary strategy |
|---|---|---|
| Per-IP | Wait Retry-After + slow down | Header variation (if server trusts forwarded headers) |
| Per-account | Account rotation | Request spacing |
| Per-session | New session (re-auth same account) | Cookie refresh |
| Global / by-design | Accept it | Report only if threshold is security-relevant |
| Progressive back-off | Exponential wait matching the back-off curve | Request spacing with jitter |
| Soft ban | Wait full window + 10% | Resume from saved state |
| Hard ban | Stop, switch account/IP | Note in defenses.md |
| CAPTCHA gating | Drop below threshold | Slow-mode enumeration |
| Account lockout | Stop immediately, use fresh account | Never brute force |

---

## Core Techniques

### 1. Request Spacing (Always Try This First)

Add deliberate delays between requests. This is the lowest-risk technique and preserves account and IP health.

Target delays based on observed limits:
- 1 req/sec cap → space to 1.5s minimum
- 10 req/min cap → space to 7s minimum (60s / 10 = 6s, add 1s buffer)
- 60 req/hour cap → space to 65s minimum

Add ±20% jitter to avoid pattern-based detection:

```python
import time
import random

def rate_limited_request(session, method: str, url: str, base_delay: float = 2.0, **kwargs):
    """Make a request with jittered spacing to avoid rate limit detection."""
    response = session.request(method, url, **kwargs)
    jitter = base_delay * random.uniform(0.8, 1.2)
    time.sleep(jitter)
    return response
```

### 2. Slow-Mode Enumeration

When doing IDOR enumeration, parameter fuzzing, or directory discovery, configure tools to respect rate limits rather than hammering at full speed.

**ffuf** — use `-rate` to cap requests per second:
```bash
ffuf -w wordlist.txt -u https://target.com/api/users/FUZZ \
     -rate 5 \
     -t 1 \
     -H "Authorization: Bearer {TOKEN}"
```

**gobuster** — use `-delay` to add per-request delay:
```bash
gobuster dir -u https://target.com \
             -w wordlist.txt \
             -delay 500ms \
             --timeout 10s
```

**nuclei** — use `-rl` (rate limit) and `-c` (concurrency):
```bash
nuclei -target https://target.com \
       -rl 5 \
       -c 1 \
       -t templates/
```

Trade-off: slower testing, but avoids triggering limits and preserves account health for the full engagement.

### 3. Account Rotation

When per-account limiting kicks in, switch to a second authorized test account.

Test accounts are stored in `{FINDINGS}/credentials/{target}-creds.env`. Load the next account and continue from the same position in the test sequence.

Rules for account rotation:
- Only rotate between accounts you control and that were created for this engagement
- Track which account tested which endpoint and when — log to `{FINDINGS}/memory/defenses.md`
- If both accounts hit limits simultaneously: pause, let limits reset, then resume
- If a limit resets in under 15 minutes, waiting is faster than rotating

Do not create new test accounts to circumvent rate limits. Rapid account creation is treated as abuse by most platforms and will trigger IP-level blocks or program escalation.

### 4. Session / Cookie Refresh

When per-session limiting kicks in, re-authenticate the same account to get a fresh session token. The new session starts with a clean counter.

```python
def refresh_session(session, login_url: str, credentials: dict) -> str:
    """Re-authenticate to obtain a fresh session token."""
    response = session.post(login_url, json=credentials)
    response.raise_for_status()
    # Extract token from response — adjust path per target
    return response.json().get("token") or response.cookies.get("session")
```

This only works if the rate limit is session-scoped. If the 429 persists after re-auth with the same account, it is per-account, not per-session.

### 5. Header Variation (Low-Impact, Last Resort)

Some naive rate limiters key on specific headers rather than verified IP or account identity. This technique has limited effectiveness against properly configured infrastructure.

Headers to vary:
- `X-Forwarded-For: <synthetic IP>` — only works if the server trusts and uses this header for rate key selection
- `X-Real-IP: <synthetic IP>`
- `User-Agent: <alternate UA string>`
- `Origin: <alternate origin>`

**Critical warning:** If `X-Forwarded-For` successfully bypasses the rate limit, stop using it as a testing tool and surface it immediately as a security finding. A rate limit bypass via IP header spoofing is itself a reportable vulnerability. Do not consume the finding by continuing to use it silently — report it, then ask whether to continue testing through it.

To test whether the server acts on `X-Forwarded-For`:

```python
import requests

def test_xff_bypass(url: str, token: str) -> bool:
    """Check if X-Forwarded-For header is reflected or changes behavior."""
    headers_with_xff = {
        "Authorization": f"Bearer {token}",
        "X-Forwarded-For": "1.2.3.4",
    }
    r1 = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    r2 = requests.get(url, headers=headers_with_xff)
    # If r2 succeeds after r1 was rate-limited, XFF is being trusted
    return r1.status_code == 429 and r2.status_code != 429
```

### 6. Timing Analysis on Account Lockout

Account lockout on auth endpoints requires special handling — it is fundamentally different from rate limiting.

**Safe testing procedure:**
1. Determine the lockout threshold before hitting it. Most programs document this, or you can infer it from error messages (`"2 attempts remaining"`).
2. Stay under the threshold: if lockout triggers at N failures, make at most N-1 attempts per account per session.
3. Rotate to a fresh test account for each new test sequence.
4. Record the threshold in `{FINDINGS}/memory/defenses.md`.

**Never test lockout behavior on accounts you do not control.** If you cannot confirm an account is a dedicated test account, do not test lockout behavior on it at all.

If you observe that lockout is absent on an auth endpoint (you can make unlimited failed attempts with no block), that is itself a security finding — missing brute force protection. Document and report it.

### 7. Backing Off Correctly

When you hit a hard limit and need to wait:

```python
import time

def wait_for_rate_limit(response) -> None:
    """Wait the appropriate duration based on rate limit response."""
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        wait = int(retry_after) * 1.1  # Add 10% buffer
    elif response.status_code == 429:
        wait = 60  # Default for per-request limits
    elif response.status_code == 403:
        wait = 900  # 15 minutes for suspected per-IP ban
    else:
        wait = 60
    print(f"Rate limited. Waiting {wait:.0f}s before resuming.")
    time.sleep(wait)
```

Standard wait times when no Retry-After is present:
- Per-request 429: 60 seconds
- Per-IP ban (403 after rapid testing): 15 minutes
- Account lockout: 24 hours (or whatever the program documents)

Save your position before waiting so you can resume without re-testing already-covered ground:

```python
import json
from pathlib import Path

def save_state(state_file: str, last_tested: str, remaining: list) -> None:
    Path(state_file).write_text(json.dumps({
        "last_tested": last_tested,
        "remaining": remaining,
    }))

def load_state(state_file: str) -> dict:
    p = Path(state_file)
    if p.exists():
        return json.loads(p.read_text())
    return {}
```

State file goes to `{TMP}/rate-limit-state.json`.

---

## Defenses to Record

Every rate limit encountered during testing must be recorded in `{FINDINGS}/memory/defenses.md`. This serves two purposes: it informs safe testing for the rest of the engagement, and it documents the program's security controls if the absence of a limit becomes a finding.

Format:

```
## Rate Limits — {target}

| Endpoint | Type | Threshold | Recovery | Notes |
|---|---|---|---|---|
| /api/auth/login | Per-IP + account lockout | 5 req/15 min; lockout at 10 consecutive fails | 15 min (IP) / 30 min (lockout) | 429 with Retry-After: 900 |
| /api/search | Per-account | 30 req/min | 60s (Retry-After header) | X-RateLimit-Remaining header present |
| /api/export | Per-account, progressive | 10 req/hour | ~1 hour | No Retry-After; delays increase before 429 |
```

---

## When Rate Limiting IS the Finding

Rate limiting behavior is frequently reportable in its own right.

### Missing Rate Limiting on Auth Endpoints

Login, password reset, OTP/MFA verification, and email verification endpoints must be rate limited. If any of these accept unlimited requests with no 429, lockout, or CAPTCHA:

1. Confirm it with at least 50 rapid consecutive requests to establish the absence of limiting
2. Document exact endpoint, method, and request count tested
3. Report as: Missing Brute Force Protection — severity depends on what the endpoint protects (MFA bypass = High, login without lockout = Medium)

### Rate Limit Bypass via IP Header Spoofing

If `X-Forwarded-For` or `X-Real-IP` successfully circumvents a rate limit:

1. Stop using the bypass technique immediately
2. Document: the endpoint, the header used, the spoofed IP value, evidence that the bypass worked (before/after response comparison)
3. Report as: Rate Limit Bypass via Spoofed IP Header — severity Medium to High depending on what the endpoint does

### Account Enumeration via Lockout Difference

If locked accounts respond differently than non-existent accounts (different HTTP status, different response body, different timing), that is user enumeration via lockout behavior. Combine with the lockout timing data you recorded and report as User Enumeration.

---

## What NOT to Do

**Never brute-force credentials**, even on test accounts. Password spraying is explicitly prohibited by most bug bounty programs. Check `program-map.md` for the program's specific rules before any credential testing.

**Never create many test accounts** to rotate through rate limits. Rapid account creation is account abuse and may get your test email domain permanently banned from the program.

**Never use a VPN or proxy to rotate IPs** unless the program explicitly permits it. IP rotation from multiple geographic locations may trigger fraud detection and result in your engagement being flagged.

**Do not silently use a bypass as a tool** before surfacing it. If you discover that `X-Forwarded-For` bypasses the rate limit and you use it to complete 500 more requests before reporting it, you have consumed the finding's impact and potentially caused unintended side effects. Surface it first.

**Do not test account lockout on accounts you do not control.** If there is any ambiguity about whether an account is a real user account or a test account, do not probe lockout behavior on it.
