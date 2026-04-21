# BountyHound Missing Components - Complete List
## Everything Needed for Production-Ready Bug Bounty Hunting

**Date**: February 10, 2026
**Status**: Implementation Roadmap

---

## 🔴 CRITICAL (Must Have - Week 1-2)

### 1. scope-permission-mapper.md
**Location**: `agents/scope-permission-mapper.md`
**Purpose**: Map OAuth scopes, RBAC roles, API permissions
**Why Critical**: Prevents "intended functionality" rejections (60% of our rejections)

**Features Needed**:
- OAuth scope discovery from docs/endpoints
- RBAC role mapping (admin, user, guest)
- API key hierarchy detection (public, private, internal)
- Automatic token generation with missing scopes
- Scope requirement documentation per endpoint

**Example Use Case**:
```
Endpoint: /api/customers/create
Required Scope: write_customers
Test 1: Token WITH write_customers → baseline (should work)
Test 2: Token WITHOUT write_customers → test (should fail)
If Test 2 succeeds → REPORT (scope bypass)
If Test 2 fails → DON'T REPORT (working correctly)
```

---

### 2. rejection-filter.py
**Location**: `agents/rejection-filter.py`
**Purpose**: Executable Python script for quality gate
**Why Critical**: Currently documented but not implemented

**Features Needed**:
```python
#!/usr/bin/env python3
class RejectionFilter:
    def load_finding(self, markdown_file)
    def check_pattern_1_intended_functionality(self)
    def check_pattern_2_ambiguous_exploitation(self)
    def check_pattern_3_operational_issue(self)
    def check_pattern_4_impractical_attack(self)
    def calculate_acceptance_score(self)
    def evaluate(self) -> Dict[verdict, score, reason]
```

**Integration**:
- CLI: `python3 rejection-filter.py finding.md`
- Output: JSON with verdict, score, reason
- Batch mode: Process entire directory
- Metrics export: Save to quality-gate-metrics.json

---

### 3. poc-validator.md Enhancements
**Location**: `agents/poc-validator.md`
**Current**: Basic curl validation
**Needed**: Enforce "no ambiguous results" rule

**New Validation Rules**:
```yaml
Rules to Add:
  - Reject if HTTP != 200/201
  - Reject if response contains: success: false, error: true
  - Reject if response body < 50 chars (empty/minimal)
  - Reject if no sensitive data found (email, address, phone)
  - Require: Screenshot showing actual leaked data
  - Require: "Expected vs Actual" section in report
```

**Example Success Criteria**:
```python
def validate_idor_finding(response):
    if response.status_code != 200:
        return False, "Not HTTP 200"

    if 'success":false' in response.text:
        return False, "Ambiguous: success:false in response"

    sensitive_fields = ['email', 'address', 'phone', 'ssn', 'dob']
    if not any(field in response.text.lower() for field in sensitive_fields):
        return False, "No sensitive data leaked"

    return True, "Valid IDOR with clear data leakage"
```

---

### 4. CLAUDE.md Update
**Location**: `CLAUDE.md`
**Current**: Describes v1.0 pipeline
**Needed**: Document v2.0 changes

**Sections to Add**:
```markdown
## Pipeline v2.0 - Authorization-First Testing

The pipeline now prioritizes authorization testing over vulnerability scanning.

### Key Changes:
- Phase 2: Authorization Boundary Testing (NEW)
- Phase 4: Quality Gate / Rejection Filter (NEW)
- Multi-account testing (User A + User B) is MANDATORY
- Findings must pass quality gate before reporting

### New Agents:
- authorization-boundary-tester: Tests unauthorized access
- rejection-pattern-filter: Blocks rejectable findings
- scope-permission-mapper: Maps OAuth scopes and permissions

### Credential Requirements:
ALL hunts now require:
- User A credentials (victim account)
- User B credentials (attacker account)
- Setup via: /creds add <target>
```

---

## 🟡 HIGH PRIORITY (Should Have - Week 3-4)

### 5. Multi-Account Setup Automation
**Location**: `agents/account-creator.md`
**Purpose**: Automate User A + User B account creation
**Why Needed**: Manual setup is time-consuming, error-prone

**Features**:
- Detect registration flow (email, OAuth, phone)
- Create User A account (victim)
- Create User B account (attacker)
- Extract auth tokens automatically
- Save to credentials .env file
- Handle CAPTCHA via manual override
- Support email verification (temp-mail.org integration)

**Example Flow**:
```bash
/creds create example.com

→ Navigate to example.com/signup
→ Fill form: ashtonluca+usera@gmail.com
→ Solve CAPTCHA (manual)
→ Verify email (automated via temp-mail)
→ Extract auth token from localStorage
→ Repeat for User B
→ Save to ~/bounty-findings/example.com/credentials/example.com-creds.env
```

---

### 6. GraphQL Mutation Enumerator
**Location**: `agents/graphql-enumerator.md`
**Purpose**: Discover all GraphQL mutations via field suggestions
**Why Needed**: Many targets disable introspection but leave field suggestions enabled

**Features**:
- Apollo field suggestions technique
- Batch testing with aliases (20 mutations per request)
- Schema reconstruction from suggestions
- Mutation input schema discovery
- Automatic mutation categorization (read, write, delete, admin)

**Example**:
```graphql
# Send invalid field to trigger suggestions
mutation {
  invalidFieldNamezzz { __typename }
}

# Response reveals real mutations:
"Did you mean: deleteOrder, updateOrder, createOrder?"

# Then test each with authorization-boundary-tester
```

---

### 7. Evidence Collector Agent
**Location**: `agents/evidence-collector.md`
**Purpose**: Automatically capture all evidence for reports
**Why Needed**: Manual evidence collection is time-consuming

**Features**:
- Auto-screenshot before/after exploitation
- Capture HTTP request/response
- Save curl commands with actual tokens (redacted in report)
- Video recording for complex exploits
- Network traffic capture (HAR file)
- Console logs / error messages
- Timeline of actions taken

**Output Structure**:
```
~/bounty-findings/<target>/evidence/<finding-id>/
├── 01-initial-state.png
├── 02-user-a-profile.png
├── 03-user-b-request.png
├── 04-leaked-data.png
├── request.txt
├── response.txt
├── curl-command.sh
├── network-traffic.har
└── video.mp4 (optional)
```

---

### 8. Rate Limit Tester
**Location**: `agents/rate-limit-tester.md`
**Purpose**: Test rate limiting systematically
**Why Needed**: "No rate limiting" alone isn't reportable - need to prove exploitation

**Features**:
- Test 100+ requests to same endpoint
- Measure: requests/second threshold
- Detect: 429 Too Many Requests, 403 blocking
- Test: IP-based vs token-based rate limits
- Prove: Realistic brute force attack (4-digit PINs, etc.)

**Rejection Prevention**:
```yaml
❌ DON'T REPORT: "No rate limiting on login endpoint"
✅ DO REPORT: "Brute forced 4-digit PIN in 15 minutes (10,000 attempts)"

Evidence Required:
  - Show 100+ successful requests
  - Calculate time to exhaust search space
  - Demonstrate actual account compromise
```

---

### 9. JWT Analyzer Agent
**Location**: `agents/jwt-analyzer.md`
**Purpose**: Comprehensive JWT security testing
**Why Needed**: JWT vulns are common and high-value

**Tests**:
- Algorithm confusion (RS256 → HS256)
- None algorithm
- Weak secret brute force
- Kid header injection
- JKU header manipulation
- Expiration bypass (exp claim)
- Signature validation bypass
- Token reuse across accounts

**Example Output**:
```
JWT Analysis: target.com
├─ Algorithm: RS256 ✓
├─ Signature: Valid ✓
├─ Expiration: 1h ✓
├─ Claims: {sub, role, iat, exp}
└─ Tests:
   ├─ Algorithm confusion: FAILED (RS256 → HS256 blocked) ✓
   ├─ None algorithm: FAILED (rejected) ✓
   ├─ Weak secret: TESTING (wordlist: 10000 keys)
   ├─ Kid injection: VULNERABLE! ❌
   └─ Cross-account reuse: VULNERABLE! ❌
```

---

### 10. Session Analyzer Agent
**Location**: `agents/session-analyzer.md`
**Purpose**: Test session management security
**Why Needed**: Session vulns lead to account takeover

**Tests**:
- Session fixation
- Session hijacking (token reuse)
- Cookie security (HttpOnly, Secure, SameSite)
- CSRF token validation
- Logout invalidation
- Session timeout
- Concurrent session handling

---

### 11. CORS Tester Agent
**Location**: `agents/cors-tester.md`
**Purpose**: Comprehensive CORS misconfiguration testing
**Why Needed**: CORS vulns enable cross-origin attacks

**Tests**:
- Test ACAO: * with credentials
- Test ACAO: null origin
- Test ACAO: arbitrary subdomains
- Test ACAO: origin reflection
- Test ACAC: true with ACAO: *
- Test preflight bypass
- Test wildcard misconfigurations

**Evidence Required**:
```bash
# Test CORS
curl -H "Origin: https://evil.com" \
     -H "Cookie: session=..." \
     https://target.com/api/me

# Check response:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

# Prove exploitation with HTML PoC showing data theft
```

---

## 🟢 MEDIUM PRIORITY (Nice to Have - Week 5-6)

### 12. API Parameter Fuzzer
**Location**: `agents/api-fuzzer.md`
**Purpose**: Discover hidden parameters and mass assignment vulns

**Features**:
- Common parameter wordlist (id, user_id, admin, role, etc.)
- JSON parameter injection
- Array vs object confusion
- Type juggling (string → int, etc.)
- Hidden admin parameters

---

### 13. Business Logic Tester
**Location**: `agents/business-logic-tester.md`
**Purpose**: Find logic flaws that automated scanners miss

**Test Categories**:
- Price manipulation (negative quantities, $0.00 checkout)
- Workflow bypass (skip payment, skip verification)
- Race conditions (double spending, parallel requests)
- State manipulation (order status changes)
- Referral/promo code abuse

---

### 14. File Upload Tester
**Location**: `agents/file-upload-tester.md`
**Purpose**: Comprehensive file upload security testing

**Tests**:
- Extension bypass (.php.jpg, .pHp, etc.)
- Content-Type manipulation
- Magic byte bypass
- Path traversal (../../etc/passwd)
- XXE via SVG/XML
- Polyglot files (valid image + valid PHP)
- Size limit bypass
- Unrestricted file upload → RCE

---

### 15. SQL Injection Tester (Advanced)
**Location**: `agents/sqli-tester.md`
**Purpose**: Beyond basic SQLi - time-based, blind, second-order

**Tests**:
- Time-based blind (SLEEP, WAITFOR)
- Boolean-based blind
- Error-based (UNION, extractvalue)
- Second-order SQLi
- ORM injection (Hibernate, SQLAlchemy)
- NoSQL injection (MongoDB, etc.)

---

### 16. XSS Tester (Context-Aware)
**Location**: `agents/xss-tester.md`
**Purpose**: Test XSS in all contexts, bypass WAFs

**Contexts**:
- HTML context: `<script>alert(1)</script>`
- Attribute context: `" onerror=alert(1) x="`
- JavaScript context: `';alert(1);//`
- CSS context: `</style><script>alert(1)</script>`
- URL context: `javascript:alert(1)`

**WAF Bypass**:
- Case variation: `<ScRiPt>`
- Encoding: `&#60;script&#62;`
- Event handlers: `<img src=x onerror=alert(1)>`
- Template injection: `{{constructor.constructor('alert(1)')()}}`

---

### 17. SSRF Tester
**Location**: `agents/ssrf-tester.md`
**Purpose**: Test for Server-Side Request Forgery

**Tests**:
- Internal IP access (127.0.0.1, 169.254.169.254)
- Cloud metadata endpoints (AWS, GCP, Azure)
- Port scanning via SSRF
- Protocol smuggling (gopher://, file://)
- DNS rebinding
- Blind SSRF via timing

---

### 18. XXE Tester
**Location**: `agents/xxe-tester.md`
**Purpose**: XML External Entity injection testing

**Tests**:
- Classic XXE (read /etc/passwd)
- Blind XXE (OOB via HTTP)
- XXE via file upload (SVG, DOCX, XLSX)
- SSRF via XXE
- Denial of Service (billion laughs)

---

### 19. Deserialization Tester
**Location**: `agents/deserialization-tester.md`
**Purpose**: Test for insecure deserialization

**Languages/Frameworks**:
- Java (RMI, JMX, Apache Commons)
- Python (pickle, PyYAML)
- PHP (unserialize)
- Ruby (Marshal)
- .NET (BinaryFormatter)

---

### 20. Command Injection Tester
**Location**: `agents/command-injection-tester.md`
**Purpose**: OS command injection testing

**Payloads**:
- Basic: `; ls`, `| whoami`, `&& cat /etc/passwd`
- Blind: `; sleep 5`, `; curl attacker.com`
- Bypass: Backticks, $(), ${IFS}, etc.

---

## 🔵 ADVANCED FEATURES (Week 7-8)

### 21. Chain Discovery Engine
**Location**: `agents/chain-discovery.md`
**Purpose**: Find vulnerability chains (low + low = critical)

**Examples**:
- Info disclosure + IDOR = account takeover
- SSRF + cloud metadata = AWS creds
- XSS + CSRF = admin account takeover
- Open redirect + OAuth = token theft

**Features**:
- Graph all findings by type
- Identify combinable vulnerabilities
- Test chain exploitation automatically
- Generate chain PoC reports

---

### 22. Zero-Day Hunter Agent
**Location**: `agents/zero-day-hunter.md`
**Purpose**: Creative testing for novel vulnerabilities

**Techniques**:
- Uncommon HTTP methods (TRACE, TRACK, etc.)
- HTTP/2 specific attacks (request smuggling)
- WebSocket hijacking
- DNS rebinding
- Browser cache poisoning
- HTTP header injection

---

### 23. CVE Mapper Agent
**Location**: `agents/cve-mapper.md`
**Purpose**: Map discovered tech stack to known CVEs

**Features**:
- Extract versions from headers, errors
- Query CVE databases (NVD, ExploitDB)
- Check if patches applied
- Generate CVE-specific PoCs
- Prioritize by CVSS score

---

### 24. Subdomain Takeover Hunter
**Location**: `agents/subdomain-takeover.md`
**Purpose**: Comprehensive subdomain takeover testing

**Services Tested**:
- AWS S3, CloudFront
- Azure Blob Storage
- GitHub Pages
- Heroku
- Shopify
- Tumblr, WordPress.com
- 50+ other services

**Features**:
- CNAME enumeration
- Service fingerprinting
- Claimability testing
- Automatic claiming (with permission)

---

### 25. API Schema Analyzer
**Location**: `agents/api-schema-analyzer.md`
**Purpose**: Analyze OpenAPI/Swagger/GraphQL schemas for issues

**Checks**:
- Undocumented endpoints
- Deprecated endpoints still active
- Example values containing real data
- Security scheme misconfigurations
- Rate limit documentation vs reality

---

### 26. Credential Stuffing Tester
**Location**: `agents/credential-stuffing.md`
**Purpose**: Test for credential stuffing vulnerabilities

**Tests**:
- Rate limiting on login
- Account lockout after N failures
- CAPTCHA after N failures
- IP-based blocking
- Device fingerprinting

**Ethical Note**: Use only dummy credentials, never real leaked data

---

### 27. Password Policy Analyzer
**Location**: `agents/password-policy.md`
**Purpose**: Test password security requirements

**Checks**:
- Minimum length enforcement
- Complexity requirements
- Common password blocking
- Password history
- Account enumeration via reset
- Password reset token security

---

### 28. 2FA Bypass Tester
**Location**: `agents/2fa-bypass.md`
**Purpose**: Test Two-Factor Authentication security

**Tests**:
- Direct endpoint access (bypass 2FA)
- Response manipulation (success: false → true)
- Code reuse
- Code predictability
- Backup codes security
- Rate limiting on code attempts

---

### 29. OAuth Flow Tester
**Location**: `agents/oauth-tester.md`
**Purpose**: Comprehensive OAuth 2.0 security testing

**Tests**:
- Authorization code interception
- CSRF on redirect_uri
- Open redirect via redirect_uri
- State parameter validation
- Token leakage via Referer
- Account linking vulnerabilities

---

### 30. WebSocket Security Tester
**Location**: `agents/websocket-tester.md`
**Purpose**: Test WebSocket-specific vulnerabilities

**Tests**:
- Authentication bypass
- CSRF via WebSocket
- Message injection
- Rate limiting
- Origin validation
- Protocol smuggling

---

## 🟣 INFRASTRUCTURE & TOOLING (Week 9-10)

### 31. Report Generator (Advanced)
**Location**: `agents/report-generator-pro.md`
**Purpose**: Generate platform-specific reports (HackerOne, Bugcrowd, Intigriti)

**Features**:
- HackerOne format (Expected vs Actual)
- Bugcrowd format (CVSS calculator)
- Intigriti format
- Video PoC generation
- PDF export
- Markdown → HTML converter

---

### 32. Screenshot Automation
**Location**: `skills/screenshot-helper.md`
**Purpose**: Intelligent screenshot capture

**Features**:
- Auto-detect important moments
- Annotate screenshots (arrows, highlights)
- Redact sensitive info (emails, IPs)
- Create comparison images (before/after)
- Optimize file sizes
- Add captions

---

### 33. Video PoC Generator
**Location**: `skills/video-poc-generator.md`
**Purpose**: Create professional video demonstrations

**Features**:
- Screen recording
- Add voiceover/text overlay
- Highlight mouse cursor
- Speed up boring parts
- Add intro/outro
- Export to MP4

---

### 34. Curl Command Generator
**Location**: `skills/curl-generator.md`
**Purpose**: Generate reproducible curl commands

**Features**:
- Capture from browser (Playwright)
- Redact sensitive tokens
- Add comments explaining each parameter
- Generate Bash, Python, JavaScript versions
- Include expected response

---

### 35. Token Refresh Automation
**Location**: `skills/token-refresher.md`
**Purpose**: Auto-refresh expired auth tokens

**Features**:
- Detect token expiry
- Call refresh endpoint
- Update credentials .env file
- Notify if refresh fails
- Support OAuth, JWT, session cookies

---

### 36. Notification System
**Location**: `skills/notifier.md`
**Purpose**: Send notifications for important events

**Channels**:
- Slack webhook
- Discord webhook
- Email (SMTP)
- Desktop notification
- SMS (Twilio)

**Events**:
- Hunt completed
- Critical finding discovered
- Quality gate blocked finding
- Report submitted
- Bounty awarded

---

### 37. Metrics Dashboard
**Location**: `tools/dashboard.html`
**Purpose**: Visualize hunting metrics

**Metrics**:
- Findings per target
- Rejection rate over time
- Acceptance likelihood scores
- Time spent per phase
- Quality gate block rate
- Bounty earnings

---

### 38. Historical Data Analyzer
**Location**: `agents/learning-agent.md`
**Purpose**: Learn from past hunts

**Features**:
- What worked on similar targets
- Common rejection reasons per program
- Successful vulnerability patterns
- Time estimation based on history
- Recommend which programs to target

---

### 39. Program Selector Agent
**Location**: `agents/program-selector.md`
**Purpose**: Choose best programs to target

**Criteria**:
- Response time (fast triage)
- Bounty amounts
- Acceptance rate
- Scope size
- Technology stack (expertise match)
- Competition level

---

### 40. Scope Parser (Enhanced)
**Location**: `skills/scope-parser/` (upgrade existing)
**Purpose**: Comprehensive scope understanding

**Features**:
- Parse HackerOne, Bugcrowd, Intigriti scopes
- Identify wildcards (*.example.com)
- Detect exclusions
- Validate findings against scope
- Warn before testing out-of-scope

---

## 🟤 INTEGRATION & PLATFORM (Week 11-12)

### 41. HackerOne API Integration
**Location**: `integrations/hackerone.py`
**Purpose**: Automate HackerOne interactions

**Features**:
- Submit reports via API
- Check Signal score
- Track report status
- Download program scope
- Get response times

---

### 42. Bugcrowd API Integration
**Location**: `integrations/bugcrowd.py`
**Purpose**: Automate Bugcrowd interactions

---

### 43. Intigriti API Integration
**Location**: `integrations/intigriti.py`
**Purpose**: Automate Intigriti interactions

---

### 44. GitHub Integration
**Location**: `integrations/github.py`
**Purpose**: Search for exposed secrets, leaked code

**Features**:
- Search GitHub for target's repos
- Find leaked API keys, tokens
- Find leaked credentials
- Find sensitive file commits
- Subdomain enumeration via GitHub

---

### 45. Shodan Integration
**Location**: `integrations/shodan.py`
**Purpose**: Discover exposed services

---

### 46. Censys Integration
**Location**: `integrations/censys.py`
**Purpose**: Alternative to Shodan

---

### 47. VirusTotal Integration
**Location**: `integrations/virustotal.py`
**Purpose**: Subdomain enumeration, hash lookups

---

### 48. SecurityTrails Integration
**Location**: `integrations/securitytrails.py`
**Purpose**: Historical DNS data, subdomain discovery

---

### 49. Wayback Machine Integration
**Location**: `integrations/wayback.py`
**Purpose**: Find old endpoints, leaked parameters

**Features**:
- Enumerate historical URLs
- Find removed endpoints still active
- Discover old API versions
- Find leaked admin panels

---

### 50. OAST (Out-of-Band) Server
**Location**: `tools/oast-server/`
**Purpose**: Detect blind vulnerabilities

**Use Cases**:
- Blind SSRF (DNS callback)
- Blind XXE (HTTP callback)
- Blind XSS (HTTP callback)
- Email injection (SMTP callback)

**Features**:
- DNS server (capture DNS queries)
- HTTP server (capture HTTP requests)
- SMTP server (capture emails)
- Unique token generation per test
- Callback notification

---

## 📊 SUMMARY BY PRIORITY

| Priority | Count | Components |
|----------|-------|------------|
| 🔴 CRITICAL | 4 | scope-mapper, rejection-filter.py, poc-validator, CLAUDE.md |
| 🟡 HIGH | 11 | account-creator, graphql-enum, evidence-collector, rate-limit, JWT, session, CORS, etc. |
| 🟢 MEDIUM | 9 | api-fuzzer, business-logic, file-upload, SQLi, XSS, SSRF, XXE, deserial, cmd-injection |
| 🔵 ADVANCED | 10 | chain-discovery, zero-day, CVE-mapper, subdomain-takeover, etc. |
| 🟣 INFRASTRUCTURE | 10 | report-gen, screenshot, video-poc, curl-gen, metrics, dashboard, etc. |
| 🟤 INTEGRATION | 10 | HackerOne API, Bugcrowd, Shodan, GitHub, OAST, etc. |

**Total**: 54 additional components identified

---

## IMPLEMENTATION TIMELINE

### Week 1-2: Critical Foundation
- scope-permission-mapper.md
- rejection-filter.py
- poc-validator enhancements
- CLAUDE.md update

### Week 3-4: Core Testing Agents
- account-creator
- graphql-enumerator
- evidence-collector
- rate-limit-tester
- jwt-analyzer

### Week 5-6: Vulnerability-Specific Testers
- sqli-tester
- xss-tester
- cors-tester
- session-analyzer

### Week 7-8: Advanced Features
- chain-discovery
- zero-day-hunter
- cve-mapper

### Week 9-10: Infrastructure
- report-generator-pro
- metrics-dashboard
- video-poc-generator

### Week 11-12: Integrations
- hackerone-api
- shodan-integration
- oast-server

---

## EFFORT ESTIMATION

- **Critical (4)**: ~6 days (1.5 days each)
- **High (11)**: ~22 days (2 days each)
- **Medium (9)**: ~18 days (2 days each)
- **Advanced (10)**: ~20 days (2 days each)
- **Infrastructure (10)**: ~15 days (1.5 days each)
- **Integration (10)**: ~10 days (1 day each)

**Total**: ~91 days (4.5 months) for full implementation

**Realistic Timeline**: 6 months with testing and iteration

---

## WHAT TO BUILD FIRST?

**My Recommendation - "Quick Wins" Path**:

1. **scope-permission-mapper** (2 days) - Prevents Shopify-style rejections
2. **rejection-filter.py** (1 day) - Makes quality gate functional
3. **CLAUDE.md update** (0.5 days) - Documentation
4. **account-creator** (2 days) - Automates tedious manual work
5. **evidence-collector** (1.5 days) - Saves hours per report
6. **graphql-enumerator** (1.5 days) - High-value for API targets

**Total**: ~8.5 days to get core system working at 80% effectiveness

Then iterate based on what targets you're hunting on most.

---

**Remember**: Perfect is the enemy of good. Start with CRITICAL, ship it, measure results, then iterate.
