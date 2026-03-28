# Advanced Authentication Bypass Techniques

## Purpose

Document authentication bypass techniques for security testing. These patterns identify weaknesses in authentication implementations, MFA systems, OAuth/OIDC flows, and session management.

**Scope**: Authorized penetration testing and bug bounty programs only.

---

## 1. MFA Bypass Patterns

### 1.1 Response Manipulation

```yaml
response_manipulation:
  status_field_tampering:
    description: "Modify server response to indicate MFA success"
    technique:
      intercept: "Response from MFA verification endpoint"
      modify:
        original: '{"success": false, "error": "invalid_code"}'
        tampered: '{"success": true}'
      indicators:
        - Client-side MFA validation
        - Response determines redirect
        - No server-side session check

    test_patterns:
      - '{"success":false}' -> '{"success":true}'
      - '{"verified":false}' -> '{"verified":true}'
      - '{"mfa_required":true}' -> '{"mfa_required":false}'
      - '{"status":"failed"}' -> '{"status":"passed"}'
      - '"error":' -> remove entirely
      - 'HTTP 403' -> 'HTTP 200'

  redirect_manipulation:
    description: "Modify redirect URL to skip MFA"
    technique:
      intercept: "302 redirect after failed MFA"
      modify:
        original: "Location: /mfa/verify"
        tampered: "Location: /dashboard"

  step_indicator_bypass:
    description: "Modify step tracking to skip MFA"
    patterns:
      - 'step=2' -> 'step=3'
      - 'auth_stage=mfa' -> 'auth_stage=complete'
      - Cookie 'mfa_pending=true' -> 'mfa_pending=false'
```

### 1.2 Direct Endpoint Access

```yaml
direct_access:
  skip_mfa_step:
    description: "Access post-MFA endpoints directly"
    technique:
      1: "Complete password authentication"
      2: "Note redirect to MFA page"
      3: "Instead, directly request protected endpoint"
      4: "Check if session already has access"

    common_post_mfa_endpoints:
      - /dashboard
      - /home
      - /account
      - /api/v1/me
      - /api/user/profile

  api_vs_web:
    description: "API endpoints may not require MFA"
    test:
      - "Authenticate via web (triggers MFA)"
      - "Use same session/token for API calls"
      - "API may accept pre-MFA session"
```

### 1.3 Backup Code Attacks

```yaml
backup_code_attacks:
  brute_force:
    description: "Backup codes often have limited entropy"
    analysis:
      format_examples:
        - "8 alphanumeric characters"
        - "12 digit numeric"
        - "XXXX-XXXX pattern"
      rate_limit_check:
        - "Are backup codes rate limited separately?"
        - "Is lockout per-code or per-account?"

  code_reuse:
    description: "Backup code not invalidated after use"
    test:
      1: "Use valid backup code"
      2: "Note successful authentication"
      3: "Logout and try same code again"
      4: "Check if code still valid"

  code_prediction:
    description: "Predictable backup code generation"
    analysis:
      - "Sequential generation (CODE001, CODE002)"
      - "Timestamp-based patterns"
      - "User ID included in seed"
      - "Weak random number generator"
```

### 1.4 Race Conditions in MFA

```yaml
mfa_race_conditions:
  simultaneous_sessions:
    description: "MFA state not properly locked"
    technique:
      1: "Start two authentication sessions"
      2: "Complete password auth on both"
      3: "Complete MFA on session A"
      4: "Session B may inherit MFA completion"

  code_replay:
    description: "Same code valid in brief window"
    technique:
      1: "Capture valid MFA code"
      2: "Send multiple parallel requests with same code"
      3: "Multiple sessions may be authenticated"

  totp_window_abuse:
    description: "Large TOTP validity window"
    test:
      - "How many time periods are accepted?"
      - "Previous period code still valid?"
      - "Next period code valid early?"
```

### 1.5 Fallback Method Weakness

```yaml
fallback_bypass:
  weaker_method_available:
    description: "Switch to less secure MFA method"
    technique:
      - "Request SMS instead of authenticator app"
      - "Request email instead of hardware key"
      - "Use 'alternative method' option"
    test:
      - "Is there rate limiting on method switching?"
      - "Are all methods equally protected?"

  recovery_flow_bypass:
    description: "Account recovery bypasses MFA"
    technique:
      - "Initiate password reset"
      - "Complete reset without MFA"
      - "New password may not require MFA setup"
    targets:
      - "/forgot-password"
      - "/account/recovery"
      - "Support ticket to disable MFA"
```

---

## 2. Session Fixation Attacks

### 2.1 Classic Session Fixation

```yaml
session_fixation_classic:
  technique:
    1: "Attacker obtains session ID (unauthenticated)"
    2: "Attacker sends session ID to victim (URL, hidden form)"
    3: "Victim authenticates using attacker's session"
    4: "Attacker uses same session ID - now authenticated"

  injection_vectors:
    url_parameter:
      example: "https://app.com/login?JSESSIONID=attacker123"
      test: "Does app accept session ID in URL?"

    meta_tag:
      example: '<meta http-equiv="Set-Cookie" content="session=attacker123">'
      requires: "XSS or HTML injection"

    subdomain_cookie:
      example: "Set cookie on attacker.example.com for .example.com"
      requires: "Subdomain access"

  detection_test:
    steps:
      1: "Note session ID before authentication"
      2: "Complete authentication"
      3: "Compare session ID after authentication"
      4: "Vulnerable if session ID unchanged"
```

### 2.2 Session Donation

```yaml
session_donation:
  description: "Force victim into attacker's authenticated session"
  technique:
    1: "Attacker authenticates to own account"
    2: "Attacker extracts session cookie"
    3: "Attacker injects session into victim's browser"
    4: "Victim performs actions as attacker"
    5: "Attacker views victim's actions in account"

  use_cases:
    - "Capture victim credit card during checkout"
    - "Capture victim personal info during profile update"
    - "Capture victim file uploads"
```

### 2.3 Cross-Subdomain Session Issues

```yaml
subdomain_session:
  cookie_scope_attack:
    description: "Exploit overly broad cookie scope"
    test:
      1: "Check cookie domain attribute"
      2: "If .example.com, any subdomain can set"
      3: "Attacker-controlled subdomain sets session"
      4: "Victim visits main site with attacker session"

  session_sharing_abuse:
    description: "Sessions shared across trust boundaries"
    scenarios:
      - "User portal and admin portal share sessions"
      - "Production and staging share session cookies"
      - "Different applications share session domain"
```

---

## 3. Token Prediction Attacks

### 3.1 Sequential Tokens

```yaml
sequential_tokens:
  detection:
    steps:
      1: "Collect multiple tokens (create accounts, request resets)"
      2: "Analyze token patterns"
      3: "Look for sequential components"

  patterns:
    numeric_increment:
      examples: ["1000", "1001", "1002"]
      prediction: "Next token is current + 1"

    timestamp_based:
      examples: ["1707048000", "1707048001", "1707048002"]
      prediction: "Token contains/is Unix timestamp"

    uuid_v1:
      pattern: "Contains timestamp and MAC address"
      extraction: "First 8 chars = timestamp, bytes 10-15 = MAC"
```

### 3.2 Weak Randomness

```yaml
weak_randomness:
  insufficient_entropy:
    test:
      1: "Generate many tokens rapidly"
      2: "Look for patterns or collisions"
      3: "Analyze with statistical tools"

    tools:
      - "Burp Sequencer"
      - "Custom entropy analysis"
      - "NIST randomness tests"

  seeded_prng:
    description: "Predictable seed allows token prediction"
    common_seeds:
      - "Current timestamp"
      - "Process ID"
      - "User ID"
      - "IP address hash"

    test:
      1: "Determine seed factors"
      2: "Replicate PRNG state"
      3: "Generate future tokens"

  truncated_hash:
    description: "Hash truncation reduces collision resistance"
    example:
      full_hash: "a3f2b8c9d4e1f0..."
      truncated: "a3f2"  # Only 4 hex chars = 65536 possibilities
```

### 3.3 Password Reset Token Analysis

```yaml
reset_token_analysis:
  collection:
    steps:
      1: "Request multiple reset tokens for same account"
      2: "Request tokens for different accounts"
      3: "Request tokens at known time intervals"
      4: "Compare token structures"

  components_to_identify:
    - "User identifier (ID, email hash)"
    - "Timestamp (creation, expiry)"
    - "Random component"
    - "Signature/checksum"

  attack_scenarios:
    user_id_known:
      test: "Can you generate valid token knowing user ID?"

    timestamp_predictable:
      test: "Can you brute-force timestamp component?"

    missing_signature:
      test: "Can you modify token components freely?"
```

---

## 4. OAuth Misconfiguration Exploitation

### 4.1 Redirect URI Manipulation

```yaml
redirect_uri_attacks:
  open_redirect:
    description: "Redirect to attacker-controlled domain"
    payloads:
      # Domain-based bypasses
      - "https://attacker.com"
      - "https://legitimate.com@attacker.com"
      - "https://legitimate.com.attacker.com"
      - "https://attacker.com/legitimate.com"
      - "https://attacker.com?.legitimate.com"
      - "https://attacker.com#.legitimate.com"

      # Path traversal
      - "https://legitimate.com/../../../attacker.com"
      - "https://legitimate.com/..%2F..%2Fattacker.com"

      # Scheme confusion
      - "javascript://legitimate.com/%0aalert(1)"
      - "data:text/html,<script>alert(1)</script>"

      # Subdomain abuse
      - "https://anything.legitimate.com" # If wildcard allowed
      - "https://attacker-legitimate.com"

  parameter_pollution:
    description: "Inject additional redirect_uri"
    payloads:
      - "redirect_uri=legit.com&redirect_uri=attacker.com"
      - "redirect_uri=legit.com%26redirect_uri%3Dattacker.com"
      - "redirect_uri[]=legit.com&redirect_uri[]=attacker.com"

  path_confusion:
    description: "Exploit path matching weaknesses"
    if_allowed: "https://legitimate.com/callback"
    payloads:
      - "https://legitimate.com/callback/../attacker"
      - "https://legitimate.com/callback?x=/../attacker"
      - "https://legitimate.com/callback#/../attacker"
      - "https://legitimate.com/callbackattacker"
```

### 4.2 State Parameter Attacks

```yaml
state_parameter:
  missing_state:
    description: "CSRF attack on OAuth flow"
    technique:
      1: "Start OAuth flow, get authorize URL"
      2: "Send URL to victim (without state)"
      3: "Victim completes OAuth"
      4: "Attacker's account linked to victim"

  state_fixation:
    description: "Predictable or reusable state"
    test:
      - "Is state random enough?"
      - "Is state bound to session?"
      - "Can state be reused?"
      - "Is state validated server-side?"

  state_injection:
    description: "Inject malicious data in state"
    if_state_reflected:
      - "XSS via state parameter"
      - "Header injection via state"
```

### 4.3 Token Leakage

```yaml
token_leakage:
  referer_leakage:
    description: "Token in URL leaked via Referer header"
    conditions:
      - "Token in URL fragment or query"
      - "Page has external resources"
      - "Referrer-Policy not set"
    test:
      1: "Complete OAuth flow"
      2: "Check if token in URL"
      3: "Check for external resources on landing page"
      4: "Capture Referer header to external sites"

  fragment_leakage:
    description: "Implicit flow token exposed to JS"
    conditions:
      - "Implicit grant (response_type=token)"
      - "XSS on callback page"
    test:
      1: "Check callback page for XSS"
      2: "Token in fragment accessible to malicious JS"

  logs_and_history:
    description: "Tokens persisted in server logs or browser history"
    checks:
      - "Server access logs with query strings"
      - "Browser history stores token URLs"
      - "Analytics services capture token URLs"
```

### 4.4 Scope Manipulation

```yaml
scope_manipulation:
  scope_upgrade:
    description: "Request higher privileges than granted"
    payloads:
      - "scope=openid profile email admin"
      - "scope=openid%20profile%20email%20admin"
      - "scope=openid+profile+email+admin"
      - "scope[]=openid&scope[]=admin"

  scope_bypass:
    description: "Access resources outside granted scope"
    test:
      1: "Obtain token with limited scope"
      2: "Access endpoints requiring higher scope"
      3: "Check if scope validated per-request"

  dynamic_scope:
    description: "Scope determined at runtime"
    test:
      - "Modify claims in JWT"
      - "Inject into scope-checking logic"
```

### 4.5 Client Authentication Bypass

```yaml
client_auth_bypass:
  missing_client_secret:
    description: "Token endpoint accepts request without secret"
    test:
      1: "Capture legitimate token request"
      2: "Remove client_secret parameter"
      3: "Check if request still succeeds"

  client_secret_exposure:
    sources:
      - "Mobile app decompilation"
      - "JavaScript bundle"
      - "GitHub/GitLab repositories"
      - "Server error messages"
      - "API documentation examples"

  pkce_bypass:
    description: "Server doesn't validate code_verifier"
    test:
      1: "Start auth flow with code_challenge"
      2: "Exchange code without code_verifier"
      3: "Or with incorrect code_verifier"
```

---

## 5. SAML Signature Bypass

### 5.1 Signature Exclusion

```yaml
signature_exclusion:
  remove_signature:
    description: "Server accepts unsigned assertions"
    technique:
      1: "Intercept SAML response"
      2: "Remove Signature element entirely"
      3: "Modify assertion claims"
      4: "Forward to SP"

  empty_signature:
    description: "Server accepts empty signature value"
    payloads:
      - '<ds:SignatureValue></ds:SignatureValue>'
      - '<ds:SignatureValue>AA==</ds:SignatureValue>'
```

### 5.2 Signature Wrapping (XSW)

```yaml
xsw_attacks:
  description: "Signature covers different element than processed"

  xsw_1:
    technique: "Clone assertion, signature covers original, SP processes clone"
    structure:
      - "Response"
      - "  Signature (signs Assertion ID=orig)"
      - "  Assertion ID=orig (signed, ignored)"
      - "  Assertion ID=evil (unsigned, processed)"

  xsw_2:
    technique: "Move signature before assertion"
    structure:
      - "Response"
      - "  Signature (signs Assertion ID=orig)"
      - "  Assertion ID=evil (processed)"
      - "  Assertion ID=orig (signed, ignored)"

  xsw_3_to_8:
    description: "Various structural manipulations"
    tools:
      - "SAML Raider (Burp extension)"
      - "saml-decoder"
      - "Manual XML manipulation"

  detection:
    check: "Does SP validate signature before processing assertion?"
    indicators:
      - "SP uses XPath to find assertion"
      - "SP validates signature separately from extraction"
```

### 5.3 Certificate Attacks

```yaml
certificate_attacks:
  self_signed:
    description: "SP accepts self-signed certificate"
    technique:
      1: "Generate self-signed cert"
      2: "Sign forged assertion with private key"
      3: "Include cert in SAML response"
      4: "Check if SP validates cert chain"

  certificate_injection:
    description: "SP trusts embedded certificate"
    technique:
      1: "Generate key pair"
      2: "Create certificate"
      3: "Sign assertion with new key"
      4: "Embed cert in KeyInfo element"
      5: "SP may trust any embedded cert"

  key_confusion:
    description: "Exploit key type confusion"
    test:
      - "Swap RSA for DSA parameters"
      - "Use public key as HMAC secret"
```

### 5.4 Assertion Replay

```yaml
assertion_replay:
  no_replay_protection:
    description: "Assertion accepted multiple times"
    test:
      1: "Capture valid SAML response"
      2: "Complete authentication"
      3: "Replay same response"
      4: "Check for new session"

  time_skew_abuse:
    description: "Large time tolerance allows old assertions"
    test:
      - "Modify NotBefore to past date"
      - "Modify NotOnOrAfter to future date"
      - "Check acceptable time window"

  one_time_assertion_id:
    description: "InResponseTo and ID not tracked"
    test:
      - "Reuse assertion with same ID"
      - "Send assertion without valid InResponseTo"
```

### 5.5 Attribute Manipulation

```yaml
attribute_manipulation:
  privilege_escalation:
    description: "Modify assertion attributes for higher privileges"
    targets:
      - '<Attribute Name="role"><AttributeValue>admin</AttributeValue>'
      - '<Attribute Name="groups"><AttributeValue>administrators</AttributeValue>'
      - '<Attribute Name="permissions"><AttributeValue>*</AttributeValue>'

  identity_spoofing:
    description: "Change user identity in assertion"
    targets:
      - '<NameID>admin@example.com</NameID>'
      - '<Attribute Name="email"><AttributeValue>victim@example.com</AttributeValue>'
      - '<Attribute Name="uid"><AttributeValue>1</AttributeValue>'

  attribute_injection:
    description: "Add attributes not in original assertion"
    technique:
      - "Add new Attribute elements"
      - "Check if SP processes unrecognized attributes"
      - "Look for attribute-based authorization"
```

---

## Testing Methodology

```yaml
auth_bypass_methodology:
  reconnaissance:
    1: "Identify authentication mechanism"
    2: "Map authentication flow"
    3: "Identify MFA methods"
    4: "Document session handling"
    5: "Check for OAuth/SAML"

  mfa_testing:
    1: "Test response manipulation"
    2: "Attempt direct endpoint access"
    3: "Test backup code handling"
    4: "Check for race conditions"
    5: "Evaluate fallback methods"

  session_testing:
    1: "Check session regeneration on login"
    2: "Test session fixation vectors"
    3: "Analyze session token entropy"
    4: "Test cross-domain session handling"

  oauth_testing:
    1: "Test redirect_uri validation"
    2: "Check state parameter handling"
    3: "Test token leakage vectors"
    4: "Attempt scope manipulation"
    5: "Check client authentication"

  saml_testing:
    1: "Test signature validation"
    2: "Attempt XSW attacks"
    3: "Check certificate validation"
    4: "Test replay protection"
    5: "Attempt attribute manipulation"
```

---

## Tools Reference

```yaml
tools:
  burp_extensions:
    - "SAML Raider"
    - "Autorize"
    - "Auth Analyzer"
    - "JWT Editor"
    - "OAuth 2.0 Scan"

  standalone:
    - "jwt_tool"
    - "SAMLReplay"
    - "oauth2-attacker"
    - "saml-decoder"

  browser_extensions:
    - "SAML-tracer"
    - "OIDC DevTools"
    - "EditThisCookie"
```

---

## Evidence Collection

```yaml
evidence_for_reports:
  mfa_bypass:
    - "Request/response showing MFA skip"
    - "Session state before/after"
    - "Steps to reproduce"

  session_fixation:
    - "Session ID before/after auth"
    - "Proof of session reuse"
    - "Attack flow diagram"

  oauth_vuln:
    - "Malicious redirect_uri accepted"
    - "Token exposure proof"
    - "Scope escalation evidence"

  saml_bypass:
    - "Forged assertion"
    - "Signature bypass proof"
    - "Successful authentication with forged SAML"
```

---

## Remediation Guidance

```yaml
remediation:
  mfa:
    - "Server-side MFA state validation"
    - "Rate limit all MFA attempts"
    - "Invalidate backup codes after use"
    - "Bind MFA to specific session"

  sessions:
    - "Regenerate session ID on authentication"
    - "Use secure random session generation"
    - "Implement proper session timeout"
    - "Bind sessions to client fingerprint"

  oauth:
    - "Strict redirect_uri validation"
    - "Require and validate state parameter"
    - "Use authorization code flow with PKCE"
    - "Validate scopes on every request"

  saml:
    - "Validate signature before processing"
    - "Check certificate chain"
    - "Implement replay protection"
    - "Use narrow time windows"
```
