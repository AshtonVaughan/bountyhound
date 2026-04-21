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

**Note:** "Observable" does not only mean browser UI. It includes: proxy capture,
DevTools Network/Console, OOB/OAST callbacks, and timing measurements. Each class
has its own observation channel.

### Server-side (proof in HTTP response)

| Vulnerability Class | PASS condition |
|--------------------|---------------|
| IDOR / BOLA | Another user's data returned in response body, visible in browser or proxy |
| Auth bypass | Restricted resource returns 200 with content without valid session |
| SQL injection (error/union) | DB error message in response, or data not belonging to current user returned |
| SSRF (non-blind) | Internal/sensitive data returned in response from internal resource |
| Information disclosure | Sensitive data (secrets, PII, internal paths) in response headers, body, or DevTools Network tab |
| Missing security header | Expected header absent in proxy capture of the relevant response |
| Business logic | Unintended application state achieved and visible in UI or API response |
| Command injection (non-blind) | Command output in response body |
| Path traversal | File content from outside webroot in response body |
| XXE (non-blind) | File content in response body |
| SSTI | Template evaluation result (e.g., `49` for `{{7*7}}`) in response body |

### Blind / out-of-band (proof on YOUR server, not in response)

| Vulnerability Class | PASS condition |
|--------------------|---------------|
| Blind SSRF | OOB callback received on your collaborator/OAST server from the target |
| Blind XXE | OOB callback or file content exfiltrated to your server via OOB channel |
| Blind command injection | OOB callback (e.g., `curl` to your server) or timing difference >2s |
| Blind XSS (stored) | Payload fires on admin/internal page — OOB callback to your server confirms execution |
| SQL injection (time-based) | Consistent timing difference (e.g., `SLEEP(5)` → 5s+ response vs <1s baseline, repeated 3x) |
| SQL injection (boolean) | Different response content/length for true vs false conditions |

### Browser-dependent (proof requires browser rendering — curl CANNOT reproduce, that's expected)

| Vulnerability Class | PASS condition |
|--------------------|---------------|
| XSS (reflected/stored) | Alert or DOM manipulation visible in browser UI |
| DOM XSS | Payload executes in browser via client-side JS. PoC HTML page triggers it. |
| CSRF | State-changing action completed from attacker-origin PoC page, confirmed in proxy |
| Clickjacking | Target page rendered in iframe on attacker-controlled page, action clickable |
| Open redirect | Browser navigates to external attacker domain, confirmed in URL bar or proxy. **Standalone open redirect is N/A or Low on most programs.** Pass requires either: (a) demonstrated impact chain (OAuth token theft via redirect_uri, phishing on a trusted domain context, session token in Referer), or (b) the program explicitly pays for open redirect — check bounty table. Surface without a chain as [NEEDS-PROOF] for user to decide whether to chain it. |
| PostMessage | Attacker page receives/sends postMessage to target, data exfiltrated or action triggered |
| Cache poisoning | Poisoned response served to browser from cache, different from origin response |
| CORS misconfiguration | Attacker-origin JS reads cross-origin response AND the response contains sensitive data (credentials, tokens, PII, account data, internal paths). `Access-Control-Allow-Origin: *` on a public endpoint returning `{"status":"ok"}` is intentional and not a finding. PASS requires: (1) your origin can read the response cross-origin, AND (2) the response contains data that provides meaningful access to an attacker. |

### Claimable resources (proof = you own the resource)

| Vulnerability Class | PASS condition |
|--------------------|---------------|
| Subdomain takeover | Your content served on the dangling subdomain (claimed with user authorization, screenshot taken) |
| Dangling S3/cloud storage | Bucket/blob claimed (user authorized), proof file uploaded, screenshot of file + app referencing it |
| Dangling DNS | Zone claimed via NS provider (user authorized), DNS resolves to your controlled IP |
| Dependency confusion | Evidence that package is unclaimed + app imports it. Only register with user authorization AND program policy approval. |

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
