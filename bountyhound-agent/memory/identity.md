# Hunter Identity — Test Account Emails

Emails to use when creating test accounts on targets. Read this before any account creation.

## Available Addresses

| Email | Role | Use For |
|-------|------|---------|
| `0xluca@wearehackerone.com` | Primary single account | Default for any program that only needs one account — general testing, recon, auth flows |
| `0xlucahackerone1@ashtonvaughan.com` | User A (victim) | IDOR and multi-account tests — the account that owns the resource |
| `0xlucahackerone2@ashtonvaughan.com` | User B (attacker) | IDOR and multi-account tests — the account attempting unauthorized access |

## Account Creation Rules

**Single-account testing (most programs):**
- Use `0xluca@wearehackerone.com` as the primary account
- This is the default unless you specifically need two accounts

**Multi-account / IDOR testing:**
- User A (victim/resource owner): `0xlucahackerone1@ashtonvaughan.com`
- User B (attacker): `0xlucahackerone2@ashtonvaughan.com`
- If a target rejects `ashtonvaughan.com` (disposable email block), fall back to the `auth-manager` agent's temp address fallback chain

**Three-account scenarios** (team/org features, complex privilege escalation):
- User A: `0xlucahackerone1@ashtonvaughan.com`
- User B: `0xlucahackerone2@ashtonvaughan.com`
- User C / Admin: `0xluca@wearehackerone.com`

Passwords: use a strong memorable pattern like `BH_2026_Target!` — store in `{FINDINGS}/credentials/{target}-creds.env`

## Standard .env Format

```bash
# Single-account testing
USER_A_EMAIL=0xluca@wearehackerone.com
USER_A_PASSWORD=<set at registration>
USER_A_AUTH_TOKEN=Bearer <extracted after login>
USER_A_SESSION_COOKIE=<extracted after login>
USER_A_CSRF_TOKEN=<extracted if present>
USER_A_TOKEN_EXPIRY=<date>

# Multi-account / IDOR testing (add User B block when needed)
USER_A_EMAIL=0xlucahackerone1@ashtonvaughan.com
USER_A_PASSWORD=<set at registration>
USER_A_AUTH_TOKEN=Bearer <extracted after login>
USER_A_SESSION_COOKIE=<extracted after login>
USER_A_CSRF_TOKEN=<extracted if present>
USER_A_TOKEN_EXPIRY=<date>

USER_B_EMAIL=0xlucahackerone2@ashtonvaughan.com
USER_B_PASSWORD=<set at registration>
USER_B_AUTH_TOKEN=Bearer <extracted after login>
USER_B_SESSION_COOKIE=<extracted after login>
USER_B_CSRF_TOKEN=<extracted if present>
USER_B_TOKEN_EXPIRY=<date>
```
