# Layer Pass Conditions Reference

## Layer 0 — Pass/Fail Wording

**PASS template:**
"Layer 0 passed. I checked: program policy, public docs, GitHub issues/PRs,
changelog, H1 disclosures, source comments, and relevant RFCs. None of these
sources describe [the observed behaviour] as intentional. Proceeding to Layer 1."

**FAIL template:**
"Discarded at Layer 0: by design.
Evidence: [Source] — [direct quote or description of what it says].
This finding will not be surfaced."

## Layer 1 — Pass Conditions by Vulnerability Class

| Vulnerability Class | PASS condition |
|--------------------|---------------|
| XSS (reflected/stored) | Alert or DOM manipulation visible in browser UI |
| CSRF | State-changing action completed from attacker origin, confirmed in proxy |
| IDOR / BOLA | Another user's data returned in response body, visible in browser or proxy |
| Auth bypass | Restricted resource returns 200 with content without valid session |
| SQL injection | DB error message in response, or data not belonging to current user returned |
| SSRF | Outbound request to attacker-controlled URL captured in proxy or OAST tool |
| Open redirect | Browser navigates to external attacker domain, confirmed in URL bar or proxy |
| Information disclosure | Sensitive data (secrets, PII, internal paths) in response headers, body, or DevTools Network tab |
| Missing security header | Expected header absent in proxy capture of the relevant response |
| Clickjacking | Target page rendered in iframe on attacker-controlled page |
| Business logic | Unintended application state achieved and visible in UI or API response |
| Command injection | Command output in response, or timing difference >2s for sleep-based detection |
| Path traversal | File content from outside webroot in response body |
| XXE | File content or SSRF callback in response or OOB channel |
| SSTI | Template evaluation result (e.g., `49` for `{{7*7}}`) in response body |

## Layer 2 — Curl Chain Format

```bash
# Minimal working curl chain format:
curl -s -X POST "https://target.com/api/endpoint" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=<session>" \
  -d '{"param": "payload"}' | python -m json.tool
```

The chain must be pasteable and runnable with only token/session substitution.
If the chain requires multiple sequential requests, number them and show full flow.

## CVSS 3.1 Quick Reference

| Severity | Score Range | Common Example |
|----------|------------|----------------|
| Critical | 9.0–10.0 | Unauth RCE, ATO of all users, mass data breach |
| High | 7.0–8.9 | Auth bypass, mass IDOR, stored XSS on admin panel |
| Medium | 4.0–6.9 | Reflected XSS (user interaction needed), limited IDOR |
| Low | 0.1–3.9 | Info disclosure of non-sensitive data, missing header |

**Most common High finding vector:**
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5 (Medium)
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5 (High — unauthenticated)
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1 (Critical — unauth + write)
