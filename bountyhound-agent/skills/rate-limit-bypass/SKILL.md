---
name: rate-limit-bypass
description: |
  Rate limiting, throttling, and account/IP ban evasion during authorized bug bounty testing.
  Trigger when: 429 responses, 403s after rapid testing, account lockouts, brute force
  protection kicks in, or proactively before testing auth/enumeration endpoints.
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence.**

## Phase 0 - Identify the Limiter (2 min max)

Got blocked? Run this decision tree FIRST. Wrong identification wastes time.

1. **Make the same request unauthenticated.** Still 429? It is per-IP. Succeeds? It is per-account or per-session.
2. **If per-account suspected:** Switch to second test account. Limit clears? Per-account confirmed.
3. **If per-session suspected:** Re-auth same account (fresh session cookie). Limit clears? Per-session confirmed.
4. **Both accounts hit simultaneously from different IPs?** Global/by-design limit. Accept it and move on.
5. **Response gets slower but no 429?** Progressive back-off. Match the curve.
6. **CAPTCHA appears?** Slow below threshold. Not a bypass finding.
7. **"Account locked" message on auth endpoint?** Account lockout. **STOP testing that account immediately.**

---

## Phase 1 - Bypass Procedure (ordered by safety)

Try each technique in order. Move to the next only when the current one fails.

### 1. Request spacing (always try first)

```python
import time, random

def spaced_request(session, method, url, base_delay=2.0, **kwargs):
    resp = session.request(method, url, **kwargs)
    time.sleep(base_delay * random.uniform(0.8, 1.2))
    return resp
```

- 1 req/sec cap: space to 1.5s
- 10 req/min cap: space to 7s
- 60 req/hour cap: space to 65s

Gate: Still hitting limits? Go to technique 2.

### 2. Session refresh (per-session limits only)

Re-auth the same account to get a fresh session token. New session = clean counter.

Gate: Still limited after fresh session? It is per-account, not per-session. Go to technique 3.

### 3. Account rotation (per-account limits only)

Switch to second test account from `{FINDINGS}/credentials/`. Resume from the same position.

Rules:
- Only rotate between accounts you control
- If both accounts hit limits: pause and wait
- If reset window is under 15 min, waiting beats rotating
- **Never create new accounts to circumvent limits**

Gate: Both accounts exhausted? Go to technique 4.

### 4. Wait and resume

```python
def wait_for_reset(response):
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        wait = int(retry_after) * 1.1
    elif response.status_code == 429:
        wait = 60
    elif response.status_code == 403:
        wait = 900
    else:
        wait = 60
    time.sleep(wait)
```

Save state before waiting: `{TMP}/rate-limit-state.json`

Gate: Resumed and still blocked? Go to technique 5.

### 5. IP header variation (test this - it may BE the finding)

```
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
True-Client-IP: 1.2.3.4
```

**CRITICAL:** If any header bypasses the rate limit, **STOP using it as a testing tool**. This IS a reportable vulnerability. Document it and report immediately.

Gate: No header works? Go to technique 6.

### 6. Endpoint variation

```
/api/login
/Api/Login
/API/LOGIN
/api/login/
/api//login
/./api/./login
/api/login?dummy=1
```

Also try: method switching (GET vs POST), HTTP/1.0 vs HTTP/1.1, parameter pollution.

Gate: Nothing works? Accept the limit. Use slow-mode tools:

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -rate 5 -t 1
nuclei -target https://target.com -rl 5 -c 1
```

---

## Phase 2 - Is the Rate Limit Itself a Finding?

Check each. Any "yes" is a reportable vulnerability.

### Missing rate limit on auth endpoint

Test: Send 50+ rapid requests to `/login`, `/reset-password`, `/verify-otp`, `/mfa`.

- No 429, no lockout, no CAPTCHA after 50 requests? **Finding: Missing Brute Force Protection.** Severity: Medium (login) to High (MFA/OTP bypass).

### Rate limit bypass via header spoofing

- `X-Forwarded-For` bypasses rate limit? **Finding: Rate Limit Bypass via IP Header Spoofing.** Severity: Medium-High.

### Account enumeration via lockout difference

- Locked accounts respond differently from non-existent accounts (different status code, body, or timing)? **Finding: User Enumeration.** Combine with lockout timing data.

### Missing lockout on auth endpoints

- Unlimited failed auth attempts with no lockout? **Finding: Missing Account Lockout.** Severity: Medium.

---

## Record Every Limit

Log to `{FINDINGS}/memory/defenses.md`:

```
| Endpoint | Type | Threshold | Recovery | Notes |
|---|---|---|---|---|
| /api/auth/login | Per-IP + lockout | 5/15min; lockout at 10 fails | 15min / 30min | Retry-After: 900 |
```

---

## Hard Rules

- **Never brute-force credentials.** Check `program-map.md` for program-specific rules.
- **Never create accounts to rotate through limits.** This is account abuse.
- **Never test lockout on accounts you don't control.**
- **Never silently consume a bypass.** If XFF works, report it before using it for 500 more requests.
