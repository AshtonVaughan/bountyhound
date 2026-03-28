# OAuth 2.0 Attacks — Deep Reference

## Table of Contents
1. Authorization Code Flow Attacks
2. PKCE Bypass
3. Token Endpoint Attacks
4. Client Credential Attacks
5. Dynamic Client Registration Abuse
6. Token Leakage Patterns
7. OAuth Misconfiguration Checklist

---

## 1. Authorization Code Flow Attacks

### Redirect URI — Full Bypass Techniques

The redirect_uri validation is the most commonly misconfigured OAuth parameter. Developers often whitelist a domain but not the full path.

**Validation bypass patterns:**

```
# Registered: https://app.com/callback

# Path confusion
https://app.com/callback%2F..%2Fevil
https://app.com/callback/../evil
https://app.com/callbackevil

# Open redirect on same domain
https://app.com/logout?redirect=https://evil.com
https://app.com/api/redirect?url=https://evil.com

# Subdomain (if wildcard or regex like *.app.com)
https://evil.app.com/callback
https://app.com.evil.com/callback

# URL confusion
https://app.com%40evil.com/callback
https://app.com:8080@evil.com/callback

# Fragment-based
https://app.com/callback#@evil.com

# Parameter pollution
redirect_uri=https://app.com/callback&redirect_uri=https://evil.com

# Encoded characters
redirect_uri=https://app.com%2F@evil.com
```

**How to exploit a redirect_uri bypass:**
1. Find your bypass that causes the auth server to redirect to your controlled URL
2. Start a listener (ngrok, Burp collaborator, your own server)
3. Send victim a crafted authorization URL with your modified redirect_uri
4. Victim authenticates → code or token sent to your server
5. Exchange code for access token → account takeover

---

### State Parameter CSRF

A missing or unvalidated `state` parameter allows CSRF on the OAuth flow.

**Test:**
```
# Remove state entirely
GET /oauth/authorize?client_id=xxx&response_type=code&redirect_uri=...
# (no state parameter)

# Change state value
GET /oauth/authorize?...&state=changed_value
# then submit callback with changed state — does it complete?
```

**Exploit (CSRF login):**
1. Start OAuth flow, capture the authorization URL
2. Victim visits your page with an iframe/img pointing to the authorization URL
3. If victim is logged into the OAuth provider, they get silently authorized
4. Their browser follows the redirect to your redirect_uri with the code
5. You exchange the code → you're logged into victim's account

**What to do with CSRF login:**
- Check what's in the victim's account (PII, payment methods, messages)
- If attacker controls the account victim is logged into: victim is now authenticated as attacker's identity → stored XSS, account confusion, data exposure

---

### Authorization Code Injection

If an attacker can intercept or predict authorization codes:

**Code reuse:** Use the same code twice — server should reject on second use. If not, the code is infinitely valid → any leaked code = permanent access.

**Code injection into legitimate flow:** If you can inject a code into a victim's callback (via XSS, open redirect, referrer), you authenticate them as yourself → now you have their session but can read their data from your end.

---

## 2. PKCE Bypass

PKCE (Proof Key for Code Exchange) is meant to prevent authorization code interception attacks. However, many implementations are optional or misconfigured.

**S256 downgrade to plain:**
```
# Normal PKCE S256
code_challenge_method=S256&code_challenge=<sha256_of_verifier>

# Try downgrading to plain
code_challenge_method=plain&code_challenge=<raw_verifier>
```

**Remove PKCE entirely:**
- If PKCE is not enforced server-side, simply omit `code_challenge` and `code_challenge_method`
- Complete the flow without a code verifier
- If the server doesn't require PKCE validation, the protection is absent

**code_verifier brute force:**
If `code_challenge_method=plain` is accepted, the challenge IS the verifier. If challenge is exposed (leaks in redirect), you already have the verifier.

**PKCE with redirect_uri bypass:**
PKCE protects against code interception, but if redirect_uri is bypassed, the code is delivered to you directly — PKCE doesn't help at that point.

---

## 3. Token Endpoint Attacks

### Token Request Parameter Injection
The token exchange request (`POST /oauth/token`) often accepts parameters that aren't strictly validated.

**Try adding:**
- `scope=admin openid email phone address` (add scopes)
- `grant_type=password` + credentials (if resource owner password grant enabled)
- Extra parameters that get forwarded to the resource server

### Client Secret Exposure
Look for the client_secret in:
- JavaScript source files (search for `client_secret`, `clientSecret`)
- Mobile app decompilation
- GitHub/GitLab repositories
- API documentation
- Error messages from the token endpoint

If you have the client_secret, you can exchange any valid authorization code even if you didn't initiate the flow.

### Token Revocation Issues
- POST to `/oauth/revoke` with someone else's token — does it work? (Missing authorization check)
- After password change, are all access tokens revoked?
- After account deactivation, do tokens still work?

### Refresh Token Attacks
- Refresh tokens often have much longer lifetimes — find them, protect them
- Test if refresh tokens can be used more than once
- Test if refresh token is bound to client — can you refresh from different client_id?
- After logout, is the refresh token invalidated server-side?

---

## 4. Client Credential Attacks

### Public Client Secret Exposure
For SPA and mobile apps, the client is "public" — no secret. But some implementations use secrets anyway and expose them.

**Locations to find secrets:**
```bash
# JavaScript bundles
grep -r "client_secret\|clientSecret\|CLIENT_SECRET" dist/ src/

# Android APK
jadx -d output app.apk
grep -r "client_secret" output/

# iOS IPA
unzip app.ipa
strings Payload/*.app/* | grep -i secret
```

### Client Impersonation
If you have another client's `client_id` and `client_secret`, you can impersonate that client and potentially access tokens granted to it.

---

## 5. Dynamic Client Registration Abuse

RFC 7591 allows clients to register themselves with the authorization server. If registration is open:

**Test for open registration:**
```http
POST /oauth/register
Content-Type: application/json

{
  "client_name": "test",
  "redirect_uris": ["https://attacker.com/callback"],
  "grant_types": ["authorization_code"],
  "scope": "openid email profile admin"
}
```

**If registration returns a client_id and secret:**
- You now have a legitimate client registration
- Use it to phish users into authorizing your app
- Request maximum scopes — does the server allow `admin` scope for arbitrary clients?

---

## 6. Token Leakage Patterns

### Referrer Header Leakage
If the token or code appears in a URL, and the page has any external resource (image, script, analytics):
```
# User arrives at:
https://app.com/callback?code=AUTH_CODE&state=xyz

# Page loads:
<img src="https://analytics.company.com/track">
# Referer: https://app.com/callback?code=AUTH_CODE&state=xyz
# Analytics server now has the code
```

**Find this by:** Looking at what external resources load on the callback page. Check network tab.

### Browser History / Log Endpoints
- Tokens/codes in URLs persist in browser history
- Check if the app has a `/logs`, `/debug`, `/trace` endpoint that captures recent requests
- Check if server-side logs are exposed (common in dev environments)

### Postmessage Leakage
Many SPAs use `postMessage` to communicate the token between frames/windows:
```javascript
// Search source for:
window.postMessage
parent.postMessage
window.opener.postMessage
addEventListener('message'
```

If the `postMessage` call doesn't restrict `targetOrigin` (uses `*`), any window can receive the token.

---

## 7. Misconfiguration Checklist

Run through this on every OAuth target:

```
[ ] state parameter present and validated
[ ] redirect_uri strictly validated (exact match, not prefix/regex)
[ ] authorization codes expire quickly (< 10 minutes)
[ ] authorization codes single-use only
[ ] PKCE required for public clients
[ ] tokens not in URL fragments or query params where possible
[ ] refresh tokens invalidated on logout
[ ] refresh tokens invalidated on password change
[ ] token revocation endpoint requires authentication
[ ] client_secret not exposed in frontend code
[ ] dynamic registration requires authentication
[ ] scope validation — can't request admin scope arbitrarily
[ ] CORS on token endpoint restricted to trusted origins
[ ] token endpoint rate limited
```
