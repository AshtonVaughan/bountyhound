# Auth Manager — Full Reference
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**

**Agent**: `auth-manager`
**Invoked at**: Phase 1.8 of the intelligence-loop pipeline
**Purpose**: Create test accounts on a target, extract all auth material, and write credentials to the standard `.env` path so downstream testing agents can authenticate.

---

## 0. Identity Reference

Before doing anything else, read `memory/identity.md`. The canonical email assignments are:

| Account | Email | When to use |
|---------|-------|-------------|
| Primary / User A (single) | `0xluca@wearehackerone.com` | Default — general testing, recon, all flows that don't need IDOR |
| User A (IDOR victim) | `0xlucahackerone1@ashtonvaughan.com` | IDOR / multi-account tests — the resource owner |
| User B (IDOR attacker) | `0xlucahackerone2@ashtonvaughan.com` | IDOR / multi-account tests — the unauthorized accessor |

**Default is single account.** Only create two accounts when the intelligence-loop explicitly requests `idor_mode: true` or the hunt plan includes IDOR hypotheses.

Password pattern: `BH_2026_<Target>!` where `<Target>` is the capitalized program name (e.g., `BH_2026_Exness!`). Store only in the creds file — never log inline.

---

## 1. Pre-Flight Checks

Run all of these before opening the browser. Fail fast on blockers; don't skip.

### 1.1 Existing Credentials Check

Check whether a valid creds file already exists for this target:

```
C:/Users/vaugh/Desktop/BountyHound/findings/{target}/credentials/{target}-creds.env
```

If the file exists:
1. Read `USER_A_TOKEN_EXPIRY`. If the expiry is in the future (compare against today's date), proceed to **Section 8 — Token Freshness** to validate without creating a new account.
2. If expiry is absent or in the past, proceed to account creation but attempt token refresh first (Section 8.2) before creating a new account.

### 1.2 Program Policy Check

Read the program policy on HackerOne / Bugcrowd (already fetched by the intelligence-loop). Look for:

- **Test account policy**: Does the program require pre-approved test accounts? If yes, stop and report `BLOCKED_BY_POLICY` (see Section 9).
- **Prohibited account creation**: Some programs (financial, healthcare) explicitly ban creating test accounts without written approval. If this restriction is present, stop immediately.
- **Rate limiting on registration**: Note any stated limits (e.g., "3 registrations per IP per hour") so you know when to back off.
- **Email domain restrictions**: Some programs only accept corporate email domains. If `ashtonvaughan.com` or `wearehackerone.com` would be rejected, check `identity.md` for the fallback chain and use a disposable alias approach if available.

### 1.3 Existing Account Check (De-duplication)

Before registering, navigate to the login page and attempt to log in with the target email + standard password. If login succeeds:
- The account already exists from a prior hunt session
- Skip to token extraction (Section 5) — do not create a duplicate account

If login fails with "wrong password" (not "account not found"), the email is registered with a different password. Attempt a password reset flow. If reset succeeds, continue. If not, this is a failure mode — report `ACCOUNT_LOCKED_PRIOR_SESSION`.

---

## 2. Standard Email/Password Signup Flow

### 2.1 Pre-navigation Setup

Before navigating, clear network request history so the capture is clean:

```
mcp__claude-in-chrome__navigate: https://target.com/register
```

Wait for the page to fully load (check `get_page_text` for form field presence before interacting).

### 2.2 Locate the Registration Form

Use `find` to locate input fields. Standard selectors to try in order:
1. `input[type="email"]`, `input[name="email"]`, `input[id*="email"]`
2. `input[type="text"][placeholder*="mail"]`
3. `input[name="username"]` (for username-based systems)

Use `get_page_text` if the form structure is unclear. Do not guess selectors.

### 2.3 Fill the Form

Use `form_input` for each field. Work through fields in DOM order (tab order matches submission validation):

```
mcp__claude-in-chrome__form_input:
  selector: input[name="email"]
  value: 0xluca@wearehackerone.com   # or User A email if IDOR mode

mcp__claude-in-chrome__form_input:
  selector: input[name="password"]
  value: BH_2026_Target!

mcp__claude-in-chrome__form_input:
  selector: input[name="password_confirm"]   # if present
  value: BH_2026_Target!
```

For name fields, use `Luca` (first) and `Bounty` (last). For phone fields, use `+61400000000` — it's a valid Australian format that is not a real number. For company/org fields, use `Security Research`.

Do not fill CAPTCHA fields — handle those separately in Section 4.

### 2.4 Submit and Capture the Response

After filling all fields, submit the form. Use `javascript_tool` to click the submit button if it has no stable selector:

```javascript
document.querySelector('button[type="submit"], input[type="submit"], button.register, button.signup').click();
```

Immediately after submission, call `read_network_requests` to capture the registration API response. Note:
- The HTTP status code of the registration call
- The response body (look for `user_id`, `id`, `account_id`, `uuid`)
- Any `Set-Cookie` headers on the registration response
- Any `Authorization` header in the response

### 2.5 Handle Registration Response States

| Response | Action |
|----------|--------|
| 200/201 with user object | Success — proceed to email verification |
| 200 with `"verify your email"` message | Email verification required — see 2.6 |
| 409 Conflict / "email already exists" | Account exists — attempt login instead |
| 429 Too Many Requests | Rate limited — wait 60s, retry once; if still blocked, report `RATE_LIMITED` |
| 400 with field validation errors | Read errors, fix fields, retry (counts as attempt 2) |
| 403 / "domain not allowed" | Email domain rejected — check identity.md fallback chain |
| 500+ | Server error — log it as a potential finding for the intelligence-loop, retry once |

Max 3 attempts total across all states. On attempt 3 failure, stop and report failure (Section 9).

### 2.6 Email Verification

If the registration flow requires email verification:

1. Navigate to the Gmail MCP tool: use `mcp__claude_ai_Gmail__gmail_search_messages` to search for the verification email.
   - Search query: `to:0xluca@wearehackerone.com subject:verify` (adjust email for IDOR mode)
   - For `ashtonvaughan.com` addresses — the user must forward this email or provide the link manually. Report `EMAIL_VERIFICATION_REQUIRED` to the caller with the instruction to provide the link.

2. For `wearehackerone.com` email — if Gmail MCP access is available, extract the verification link from the email body and navigate to it.

3. Confirm the account is active by navigating to the post-verification page and checking `get_page_text` for success indicators ("email confirmed", "account activated", "welcome").

### 2.7 Confirm Active Session

After registration and verification, confirm the account is active by navigating to a protected page (e.g., `/dashboard`, `/account`, `/profile`) and checking `get_page_text`:
- Look for the account email address appearing on the page
- Look for authenticated navigation elements (logout link, account menu)
- If redirected back to login, the session was not established — proceed to explicit login (Section 2.8)

### 2.8 Explicit Login (if session not established post-registration)

Some flows register without creating a session. In that case:

```
mcp__claude-in-chrome__navigate: https://target.com/login

mcp__claude-in-chrome__form_input:
  selector: input[type="email"]
  value: {registered_email}

mcp__claude-in-chrome__form_input:
  selector: input[type="password"]
  value: {password}
```

Submit, then call `read_network_requests` immediately to capture the login API response — this is the primary source of auth tokens.

---

## 3. OAuth/SSO-Protected Signup

### 3.1 Detection

After navigating to the registration page, if `get_page_text` shows one of the following and no email/password fields exist, the site uses OAuth/SSO-only signup:
- "Continue with Google"
- "Sign in with GitHub"
- "Log in with Okta"
- "Sign in with Microsoft"
- Redirect to an external identity provider URL

### 3.2 Handling Google OAuth

If Google OAuth is the only signup method:
1. Check if the intelligence-loop has provided a `BOUNTYHOUND_GOOGLE_EMAIL` environment variable. If yes, proceed with the Google flow using the built-in Chrome browser (which may have an active Google session).
2. Click "Continue with Google" and observe whether Chrome's existing Google session auto-completes the flow.
3. If Chrome completes the OAuth exchange and lands on an authenticated page, extract tokens normally (Section 5).
4. If Chrome prompts for Google account selection or credentials, report `SSO_REQUIRES_USER_INTERVENTION` and pause. Do not attempt to type Google credentials — the user must intervene.

### 3.3 Handling GitHub OAuth

Same approach as Google. If the Chrome browser has an active GitHub session, the OAuth dance may complete automatically. Extract tokens from the resulting session.

### 3.4 Handling SAML / Enterprise SSO

SAML flows (Okta, Azure AD, PingFederate) require identity provider credentials that are not available to auth-manager. Report `SSO_SAML_UNSUPPORTED` with the IdP URL and the SP entity ID (visible in the SAML AuthnRequest or the login page source). The intelligence-loop will decide whether to proceed manually.

### 3.5 Mixed OAuth + Email Signup

If the page offers both "Continue with Google" AND an email/password form, always prefer the email/password form — it gives full control over credentials and token extraction.

---

## 4. CAPTCHA Handling

### 4.1 Detection

After navigating to the registration page, check for CAPTCHA indicators via `get_page_text` and `javascript_tool`:

```javascript
// Returns true if any CAPTCHA framework is active
!!(document.querySelector('.g-recaptcha, .h-captcha, [data-sitekey], iframe[src*="recaptcha"], iframe[src*="hcaptcha"], #cf-turnstile'));
```

Also watch `read_network_requests` for calls to:
- `google.com/recaptcha`
- `hcaptcha.com`
- `challenges.cloudflare.com`

### 4.2 Attempt Once

Try submitting the registration form anyway. Some CAPTCHA implementations are misconfigured and do not actually validate server-side. If the registration succeeds despite the CAPTCHA widget being present, document this as a secondary finding candidate for the intelligence-loop (invisible CAPTCHA bypass).

### 4.3 CAPTCHA Blocked — Fallback Strategy

If the server rejects the registration with a CAPTCHA-related error (typically 400 with `"captcha"` in the response body):

1. Report `CAPTCHA_BLOCKED` to the caller.
2. Do not retry — additional attempts burn IP reputation.
3. Include in the report: the CAPTCHA type detected, the registration endpoint URL, and the form structure so the user can complete it manually and pass the resulting cookies back.

The user can solve the CAPTCHA manually, complete registration, and then run `/creds add {target}` to store the result, or paste the session cookie directly.

---

## 5. Token Extraction Protocol

Run this protocol after every successful login or account confirmation. The goal is to collect every piece of auth material the target issues.

### 5.1 Extract from Network Requests

Immediately after the login or registration response, call:

```
mcp__claude-in-chrome__read_network_requests
```

Scan all captured requests/responses for:

| Field | Where to look |
|-------|--------------|
| Bearer token / JWT | `Authorization: Bearer eyJ...` in response headers or request headers of subsequent calls |
| Access token | Response body keys: `access_token`, `token`, `jwt`, `id_token`, `authToken`, `auth_token` |
| Refresh token | Response body keys: `refresh_token`, `refreshToken` |
| Session cookie | `Set-Cookie` response header — name often `session`, `sessionid`, `PHPSESSID`, `connect.sid`, `auth`, `_session` |
| CSRF token | Response body keys `csrf_token`, `csrfToken`, `_csrf`; or `X-CSRF-Token` header |
| Expiry | `expires_in` (seconds from now), `exp` in JWT payload, `token_expiry`, `expiresAt` |

Record the full raw values — do not truncate tokens.

### 5.2 Extract from localStorage

```javascript
// Run via javascript_tool
const result = {};
for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    const val = localStorage.getItem(key);
    // Only capture auth-related keys
    if (/token|auth|jwt|session|access|refresh|credential|user|bearer/i.test(key)) {
        result[key] = val;
    }
}
return JSON.stringify(result, null, 2);
```

### 5.3 Extract from sessionStorage

```javascript
// Run via javascript_tool
const result = {};
for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    const val = sessionStorage.getItem(key);
    if (/token|auth|jwt|session|access|refresh|credential|user|bearer/i.test(key)) {
        result[key] = val;
    }
}
return JSON.stringify(result, null, 2);
```

### 5.4 Extract Cookies

```javascript
// Run via javascript_tool — gets JS-accessible cookies
// Note: HttpOnly cookies won't appear here; get those from read_network_requests Set-Cookie headers
document.cookie.split(';').map(c => c.trim());
```

For HttpOnly cookies, rely on `read_network_requests` — they appear in `Set-Cookie` response headers and in `Cookie` request headers on subsequent API calls.

### 5.5 Extract from Page State / Window Object

Some SPAs store auth state in global variables:

```javascript
// Run via javascript_tool
const candidates = ['__auth', '__store', 'store', 'app', '__nuxt', 'angular', 'React', '__NEXT_DATA__'];
const result = {};
for (const key of candidates) {
    if (window[key]) {
        try {
            const str = JSON.stringify(window[key]);
            if (/token|jwt|auth|bearer/i.test(str)) {
                result[key] = str.substring(0, 500); // truncate large state objects
            }
        } catch (e) {}
    }
}
// Also check __NEXT_DATA__ which often contains session data
if (document.getElementById('__NEXT_DATA__')) {
    result['__NEXT_DATA__'] = document.getElementById('__NEXT_DATA__').textContent.substring(0, 1000);
}
return JSON.stringify(result);
```

### 5.6 Decode JWT to Get Expiry

If a JWT was found, decode the payload to extract `exp`:

```python
import base64, json

def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification."""
    parts = token.split('.')
    if len(parts) != 3:
        return {}
    payload = parts[1]
    # Add padding
    payload += '=' * (4 - len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload)
    return json.loads(decoded)

payload = decode_jwt_payload(raw_token)
exp_unix = payload.get('exp')
if exp_unix:
    from datetime import datetime, timezone
    expiry = datetime.fromtimestamp(exp_unix, tz=timezone.utc).isoformat()
```

Use this expiry value for `USER_A_TOKEN_EXPIRY` in the creds file.

### 5.7 Trigger an Authenticated API Call to Confirm Tokens

Navigate to `/api/me`, `/api/v1/profile`, `/account`, or equivalent. Observe the request in `read_network_requests` — the `Authorization` or `Cookie` header on this outbound call confirms which token material the app actually uses. Prefer the token from live requests over what was parsed from storage.

---

## 6. Credential File Format

Write the file to:
```
C:/Users/vaugh/Desktop/BountyHound/findings/{target}/credentials/{target}-creds.env
```

Create the directory if it does not exist:
```bash
mkdir -p "C:/Users/vaugh/Desktop/BountyHound/findings/{target}/credentials"
```

### 6.1 Single-Account Format

Use when `idor_mode` is false (default):

```bash
# ============================================================
# Target: {target}
# Created: {YYYY-MM-DDTHH:MM:SSZ}
# Mode: single-account
# ============================================================

# --- User A (primary) ---
USER_A_EMAIL=0xluca@wearehackerone.com
USER_A_PASSWORD=BH_2026_Target!
USER_A_AUTH_TOKEN=Bearer eyJ...
USER_A_SESSION_COOKIE={cookie_name}={cookie_value}
USER_A_CSRF_TOKEN={csrf_token_value_or_NONE}
USER_A_REFRESH_TOKEN={refresh_token_or_NONE}
USER_A_TOKEN_EXPIRY={ISO8601_datetime_or_UNKNOWN}
USER_A_USER_ID={user_id_from_profile_or_UNKNOWN}
USER_A_ACCOUNT_CREATED={YYYY-MM-DDTHH:MM:SSZ}
```

### 6.2 IDOR Two-Account Format

Use when `idor_mode` is true:

```bash
# ============================================================
# Target: {target}
# Created: {YYYY-MM-DDTHH:MM:SSZ}
# Mode: idor-two-account
# ============================================================

# --- User A (victim / resource owner) ---
USER_A_EMAIL=0xlucahackerone1@ashtonvaughan.com
USER_A_PASSWORD=BH_2026_Target!
USER_A_AUTH_TOKEN=Bearer eyJ...
USER_A_SESSION_COOKIE={cookie_name}={cookie_value}
USER_A_CSRF_TOKEN={csrf_token_value_or_NONE}
USER_A_REFRESH_TOKEN={refresh_token_or_NONE}
USER_A_TOKEN_EXPIRY={ISO8601_datetime_or_UNKNOWN}
USER_A_USER_ID={user_id_from_profile_or_UNKNOWN}
USER_A_ACCOUNT_CREATED={YYYY-MM-DDTHH:MM:SSZ}

# --- User B (attacker / unauthorized accessor) ---
USER_B_EMAIL=0xlucahackerone2@ashtonvaughan.com
USER_B_PASSWORD=BH_2026_Target!
USER_B_AUTH_TOKEN=Bearer eyJ...
USER_B_SESSION_COOKIE={cookie_name}={cookie_value}
USER_B_CSRF_TOKEN={csrf_token_value_or_NONE}
USER_B_REFRESH_TOKEN={refresh_token_or_NONE}
USER_B_TOKEN_EXPIRY={ISO8601_datetime_or_UNKNOWN}
USER_B_USER_ID={user_id_from_profile_or_UNKNOWN}
USER_B_ACCOUNT_CREATED={YYYY-MM-DDTHH:MM:SSZ}
```

### 6.3 Field Rules

- `USER_A_AUTH_TOKEN`: Include the scheme prefix (`Bearer ` or `Token ` or `Basic `). If the app uses raw token with no scheme, prefix with `RAW `.
- `USER_A_SESSION_COOKIE`: Format is `{cookie_name}={raw_cookie_value}`. If multiple session cookies exist (e.g., session ID + CSRF cookie), concatenate with `; ` separator.
- `USER_A_CSRF_TOKEN`: Raw token value only, no header name. Use `NONE` if not present.
- `USER_A_REFRESH_TOKEN`: Raw value. Use `NONE` if not present.
- `USER_A_TOKEN_EXPIRY`: ISO 8601 UTC (e.g., `2026-04-15T12:00:00Z`). Use `UNKNOWN` if not determinable.
- `USER_A_USER_ID`: The account's internal ID — UUID, integer, or slug. Extract from `/api/me` response. Use `UNKNOWN` if not found.

Never write placeholder strings like `<fill in>` — if a value cannot be determined, write `NONE` or `UNKNOWN` as specified.

---

## 7. IDOR Setup — Two Independent Accounts

### 7.1 Why Two Accounts Must Be Truly Independent

For IDOR testing to be valid, User A and User B must:
- Be registered with different emails
- Have separate session tokens with no overlap
- Not share any session cookies
- Be able to create resources independently that are truly owned only by that user

If the target uses a shared-secret CSRF token or a global session mechanism, note this in the completion report — it may limit IDOR testability.

### 7.2 Browser Isolation Strategy

**Preferred — Incognito Window for User B:**

After completing User A setup (tokens extracted, logged in on main window), open an incognito window for User B:

```javascript
// Check if incognito can be triggered via keyboard shortcut
// Use: mcp__claude-in-chrome__shortcuts_execute with Ctrl+Shift+N
```

Then navigate to the registration page in the incognito window and repeat the full signup flow (Sections 2–5) for `0xlucahackerone2@ashtonvaughan.com`.

The incognito window provides a clean cookie jar — no session bleed between User A and User B.

**Alternative — Tab Isolation:**

If incognito is not available, create a new tab and clear cookies before registering User B:

```javascript
// This clears cookies only if the tab is on the same origin — incognito is strongly preferred
document.cookie.split(';').forEach(c => {
    document.cookie = c.replace(/^ +/, '').replace(/=.*/, '=;expires=' + new Date().toUTCString() + ';path=/');
});
```

Note in the completion report whether incognito or tab isolation was used.

### 7.3 Verifying Account Separation

After both accounts are created and tokens extracted, perform this verification:

1. **Log in as User A.** Create a resource (e.g., create a project, upload a file, add an item). Note the resource ID.
2. **Log in as User B** (using User B's token in a separate context). Attempt to access that resource ID directly via API: `GET /api/resource/{user_a_resource_id}`.
3. If the response is `403 Forbidden` or `404 Not Found` — accounts are properly isolated. IDOR testing is ready.
4. If the response returns User A's resource — this is itself a finding. Report it as IDOR-confirmed and note it in the completion report.

If the target has no resource-creation flow accessible immediately after signup, skip step 1-4 and note `isolation_verified: false` in the completion report. The testing agent will perform isolation verification during its own IDOR tests.

### 7.4 Capture Both User IDs

Both `USER_A_USER_ID` and `USER_B_USER_ID` must be populated in the creds file. They are the foundation of every IDOR test. To find them:
- `/api/me`, `/api/v1/profile`, `/api/account` — most common
- JWT payload `sub` claim
- `user_id` field in the registration response body (captured in Section 2.4)
- URL of the profile page (e.g., `/users/12345` → ID is `12345`)

---

## 8. Token Freshness — Check Before Creating New Accounts

### 8.1 Staleness Check

Read the existing creds file and check `USER_A_TOKEN_EXPIRY`:

```python
import os
from datetime import datetime, timezone

def is_token_fresh(target: str) -> bool:
    path = f"C:/Users/vaugh/Desktop/BountyHound/findings/{target}/credentials/{target}-creds.env"
    if not os.path.exists(path):
        return False
    with open(path) as f:
        for line in f:
            if line.startswith('USER_A_TOKEN_EXPIRY='):
                val = line.split('=', 1)[1].strip()
                if val in ('UNKNOWN', 'NONE', ''):
                    return False  # treat unknown expiry as stale
                try:
                    expiry = datetime.fromisoformat(val.replace('Z', '+00:00'))
                    # Consider fresh if more than 30 minutes remain
                    return expiry > datetime.now(tz=timezone.utc).replace(microsecond=0)
                except ValueError:
                    return False
    return False
```

If `is_token_fresh` returns True, skip account creation and go directly to Section 8.3 (live validation).

### 8.2 Token Refresh (Without Creating a New Account)

If the token is expired but a `USER_A_REFRESH_TOKEN` exists:

1. Navigate to the target's token refresh endpoint. Common patterns:
   - `POST /api/auth/refresh` with body `{"refresh_token": "..."}`
   - `POST /api/v1/token/refresh`
   - `POST /oauth/token` with `grant_type=refresh_token`

2. Send the refresh request via `javascript_tool`:
   ```javascript
   const resp = await fetch('/api/auth/refresh', {
       method: 'POST',
       headers: {'Content-Type': 'application/json'},
       body: JSON.stringify({refresh_token: 'REFRESH_TOKEN_VALUE'})
   });
   const data = await resp.json();
   return JSON.stringify({status: resp.status, body: data});
   ```

3. If refresh succeeds (200 with new `access_token`), update the creds file with the new token and new expiry. Do not create a new account.

4. If refresh returns 401 (expired/invalid refresh token), proceed to full account creation — but first try logging in with the stored password (the account may still exist).

### 8.3 Live Token Validation

Even if the token appears fresh by expiry date, validate it against a real endpoint:

```javascript
// Replace endpoint with target's profile/me API
const resp = await fetch('/api/me', {
    headers: {
        'Authorization': 'Bearer TOKEN_VALUE',
        'Cookie': 'SESSION_COOKIE_VALUE'
    }
});
return JSON.stringify({status: resp.status, ok: resp.ok});
```

- `200` → Token is live. Return existing creds to the caller. No new account needed.
- `401` / `403` → Token is invalid. Attempt refresh (Section 8.2), then full login, then new account creation.
- `404` → Endpoint path wrong — try alternate profile endpoints. Do not assume the token is invalid.

---

## 9. Failure Modes and What to Report

When a step fails, stop at that step and report back immediately. Do not attempt workarounds beyond what is described in this document — escalate to the intelligence-loop for a decision.

### 9.1 Failure Report Structure

```
STATUS: FAILED
FAILURE_CODE: {code from table below}
STEP_FAILED: {which section failed, e.g., "2.5 — Registration Response"}
ATTEMPT_COUNT: {1|2|3}
DETAIL: {what actually happened — HTTP status, error message, redirect URL}
EVIDENCE: {URL of the page or the network response snippet}
RECOVERY_OPTIONS: {what the user can do manually}
```

### 9.2 Failure Codes

| Code | Meaning | Recovery |
|------|---------|----------|
| `BLOCKED_BY_POLICY` | Program policy prohibits creating test accounts without written approval | User must request test account from the program |
| `SSO_ONLY` | No email/password registration — only SSO | User completes OAuth manually, then passes session cookie |
| `SSO_REQUIRES_USER_INTERVENTION` | OAuth flow started but Chrome could not complete it automatically | User must click through the OAuth flow in Chrome |
| `SSO_SAML_UNSUPPORTED` | SAML/enterprise SSO — auth-manager cannot handle | User or intelligence-loop must decide how to proceed |
| `CAPTCHA_BLOCKED` | CAPTCHA rejected the registration attempt | User must complete manually and run `/creds add {target}` |
| `EMAIL_DOMAIN_REJECTED` | Target rejects `wearehackerone.com` or `ashtonvaughan.com` | Check identity.md fallback; user may need to provide alternate email |
| `EMAIL_VERIFICATION_REQUIRED` | Verification email sent to `ashtonvaughan.com` — cannot auto-read | User must provide verification link |
| `RATE_LIMITED` | Registration endpoint returned 429 after retry | Wait and retry later; or user completes manually |
| `MAX_ATTEMPTS_REACHED` | 3 attempts exhausted with no success | Full failure — surface all error details so user can debug |
| `ACCOUNT_LOCKED_PRIOR_SESSION` | Email registered with unknown password; reset failed | User must recover account via support or use alternate email |
| `TOKEN_EXTRACTION_FAILED` | Account created but no tokens found in storage, cookies, or network | Report what was found; user may need to navigate further into the app to trigger token issuance |
| `ISOLATION_VERIFICATION_FAILED` | User A and User B can see each other's resources (IDOR confirmed) | Surface as a finding to the intelligence-loop |

---

## 10. Completion Report Format

When auth-manager completes successfully, return this exact structure to the intelligence-loop caller:

```
STATUS: SUCCESS
TARGET: {target}
MODE: {single-account | idor-two-account}
CREDS_FILE: C:/Users/vaugh/Desktop/BountyHound/findings/{target}/credentials/{target}-creds.env

USER_A:
  email: {email}
  user_id: {user_id}
  token_type: {Bearer|Cookie|NONE}
  token_present: {true|false}
  session_cookie_present: {true|false}
  csrf_token_present: {true|false}
  refresh_token_present: {true|false}
  token_expiry: {ISO8601 or UNKNOWN}
  account_status: {new|existing|refreshed}

USER_B:   # omit this block if mode is single-account
  email: {email}
  user_id: {user_id}
  token_type: {Bearer|Cookie|NONE}
  token_present: {true|false}
  session_cookie_present: {true|false}
  csrf_token_present: {true|false}
  refresh_token_present: {true|false}
  token_expiry: {ISO8601 or UNKNOWN}
  account_status: {new|existing|refreshed}

ISOLATION_VERIFIED: {true|false|skipped}
SECONDARY_FINDINGS: {list any findings identified during setup, e.g., "CAPTCHA not validated server-side", "Registration returns user enumeration via response timing"}
NOTES: {anything the testing agent should know — unusual auth flow, token format, session mechanics}
```

For a failure, use the failure format from Section 9.1.

Keep the report under 30 lines inline. Full credential details stay in the file at `CREDS_FILE`. Never print raw token values or passwords in the completion report.

---

## Appendix A: Quick Reference — Browser Tool Calls

| Action | Tool | Key Parameters |
|--------|------|----------------|
| Navigate to URL | `mcp__claude-in-chrome__navigate` | `url` |
| Fill a form field | `mcp__claude-in-chrome__form_input` | `selector`, `value` |
| Click element | `mcp__claude-in-chrome__find` + `computer` | find element, then click |
| Run JavaScript | `mcp__claude-in-chrome__javascript_tool` | `script` |
| Read page text | `mcp__claude-in-chrome__get_page_text` | — |
| Find elements | `mcp__claude-in-chrome__find` | `selector` |
| Read network traffic | `mcp__claude-in-chrome__read_network_requests` | — |
| Take screenshot | `mcp__claude-in-chrome__computer` | action: screenshot |
| Open incognito | `mcp__claude-in-chrome__shortcuts_execute` | `Ctrl+Shift+N` |

## Appendix B: Common Token Storage Locations by Framework

| Framework / Stack | Primary Token Location |
|-------------------|----------------------|
| Next.js + NextAuth | `__Secure-next-auth.session-token` cookie; `next-auth.session-token` (non-HTTPS) |
| Django REST Framework | `Authorization: Token <key>` header; `sessionid` cookie |
| Laravel | `laravel_session` cookie + `X-XSRF-TOKEN` header |
| Rails | `_session_id` cookie |
| Express + Passport.js | `connect.sid` cookie |
| Spring Boot + JWT | `Authorization: Bearer` header; sometimes `access_token` in localStorage |
| Firebase Auth | `localStorage['firebase:authUser:...:DEFAULT']` |
| Supabase | `localStorage['supabase.auth.token']` |
| Auth0 | `localStorage['@@auth0spajs@@::...']` |
| Cognito | `localStorage['{pool_id}.{client_id}.accessToken']` |
| Okta | `localStorage['okta-token-storage']` |

## Appendix C: Handling `ashtonvaughan.com` Email Rejection

If the target rejects `ashtonvaughan.com` (common pattern: "Please use a work email" or "Disposable email addresses not allowed"):

1. Try `0xluca@wearehackerone.com` as a fallback for User A even in IDOR mode.
2. For User B, check `memory/identity.md` for any additional email aliases listed.
3. If no fallback works, report `EMAIL_DOMAIN_REJECTED` and include the exact error message. The user will need to provide alternate addresses.
4. Never attempt to generate fake email addresses or use third-party disposable services — they are unreliable and create noise.
