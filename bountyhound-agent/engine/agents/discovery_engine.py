"""
Discovery Engine - Generates vulnerability hypotheses from recon data.

5 Reasoning Tracks + Tool-Augmented Synthesis:
1. Pattern Synthesis: tech stack + known vulnerability patterns
2. Behavioral Anomaly: endpoint inconsistencies (+ katana/gau/ffuf tool data)
3. Code Research: source code sink patterns (+ trufflehog/secrets findings)
4. Cross-Domain Transfer: past hunt successes applied to new targets
5. LLM-powered novel hypothesis generation
6. Tool-Augmented Synthesis: arjun/dalfox/interactsh/sqlmap discovered params

Outputs HypothesisCards with confidence levels that feed into Phase 2 testing.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional



class Confidence(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class HypothesisCard:
    id: str
    title: str
    confidence: Confidence
    test_method: str  # curl, browser, script
    payload: str
    success_indicator: str
    reasoning_track: str  # pattern_synthesis, behavioral_anomaly, code_research, cross_domain


# Tech stack -> common vulnerability patterns
TECH_VULN_PATTERNS: Dict[str, List[Dict[str, Any]]] = {
    "rails": [
        {"title": "Mass assignment via unprotected params", "confidence": "MEDIUM", "test": "curl", "indicator": "Unexpected field updated"},
        {"title": "Ruby deserialization RCE", "confidence": "LOW", "test": "curl", "indicator": "Command execution or error"},
        {"title": "Rails debug mode information disclosure", "confidence": "MEDIUM", "test": "curl", "indicator": "Debug page with stack trace"},
        {"title": "Rails credentials.yml.enc key exposure via misconfigured S3", "confidence": "LOW", "test": "curl", "indicator": "Encrypted credentials file accessible"},
    ],
    "graphql": [
        {"title": "GraphQL introspection enabled", "confidence": "HIGH", "test": "curl", "indicator": "__schema in response"},
        {"title": "GraphQL batch query DoS", "confidence": "MEDIUM", "test": "curl", "indicator": "Server processes >100 aliases"},
        {"title": "GraphQL IDOR via direct object reference", "confidence": "HIGH", "test": "curl", "indicator": "Other user's data returned"},
        {"title": "GraphQL mutation without authentication", "confidence": "HIGH", "test": "curl", "indicator": "Mutation succeeds without auth token"},
        {"title": "GraphQL field suggestion bypass", "confidence": "MEDIUM", "test": "curl", "indicator": "Did you mean suggestions reveal schema"},
        {"title": "GraphQL query depth/complexity abuse", "confidence": "MEDIUM", "test": "curl", "indicator": "Deeply nested query completes without error"},
    ],
    "node.js": [
        {"title": "Prototype pollution via JSON merge", "confidence": "MEDIUM", "test": "curl", "indicator": "__proto__ accepted in input"},
        {"title": "SSRF via URL parameter", "confidence": "MEDIUM", "test": "curl", "indicator": "Internal service response"},
        {"title": "JWT none algorithm bypass", "confidence": "MEDIUM", "test": "curl", "indicator": "Accepted unsigned JWT"},
        {"title": "npm dependency confusion attack", "confidence": "LOW", "test": "script", "indicator": "Internal package resolvable from public registry"},
    ],
    "express": [
        {"title": "Path traversal via URL encoding", "confidence": "MEDIUM", "test": "curl", "indicator": "File contents returned"},
        {"title": "CORS misconfiguration", "confidence": "HIGH", "test": "curl", "indicator": "ACAO reflects origin"},
        {"title": "Express-session secret hardcoded", "confidence": "MEDIUM", "test": "curl", "indicator": "Session forgeable with known secret"},
    ],
    "react": [
        {"title": "DOM XSS via dangerouslySetInnerHTML", "confidence": "MEDIUM", "test": "browser", "indicator": "Script execution"},
        {"title": "Client-side secrets in JS bundle", "confidence": "HIGH", "test": "curl", "indicator": "API keys in source"},
        {"title": "React source maps exposed with full source", "confidence": "MEDIUM", "test": "curl", "indicator": ".map file returns unminified source"},
    ],
    "next.js": [
        {"title": "Next.js /api/ route missing auth", "confidence": "HIGH", "test": "curl", "indicator": "API data returned without token"},
        {"title": "Next.js server-side props leaking sensitive data", "confidence": "HIGH", "test": "curl", "indicator": "__NEXT_DATA__ contains credentials/tokens"},
        {"title": "Next.js _next/static/ source maps exposed", "confidence": "MEDIUM", "test": "curl", "indicator": "Sourcemap with business logic returned"},
        {"title": "Next.js getServerSideProps SSRF via fetch", "confidence": "MEDIUM", "test": "curl", "indicator": "Internal endpoint response proxied"},
        {"title": "Next.js middleware bypass via path confusion", "confidence": "HIGH", "test": "curl", "indicator": "Auth middleware skipped for certain paths"},
    ],
    "django": [
        {"title": "Django admin panel exposed at /admin/", "confidence": "HIGH", "test": "browser", "indicator": "Django admin login page accessible"},
        {"title": "Django DEBUG=True information disclosure", "confidence": "HIGH", "test": "curl", "indicator": "Stack trace with env vars returned on error"},
        {"title": "Django CSRF token missing on state-change endpoints", "confidence": "MEDIUM", "test": "curl", "indicator": "POST accepted without CSRF token"},
        {"title": "Django SQL injection in raw() queries", "confidence": "MEDIUM", "test": "curl", "indicator": "SQL error or unexpected data returned"},
        {"title": "Django user enumeration via password reset", "confidence": "MEDIUM", "test": "curl", "indicator": "Different response for valid vs invalid email"},
    ],
    "laravel": [
        {"title": "Laravel .env file exposed at /.env", "confidence": "HIGH", "test": "curl", "indicator": "APP_KEY, DB_PASSWORD in response"},
        {"title": "Laravel debug mode (APP_DEBUG=true)", "confidence": "HIGH", "test": "curl", "indicator": "Stack trace on error with source code"},
        {"title": "Laravel mass assignment via fillable bypass", "confidence": "MEDIUM", "test": "curl", "indicator": "Protected field updated via API"},
        {"title": "Laravel storage/logs publicly accessible", "confidence": "MEDIUM", "test": "curl", "indicator": "Log files or uploaded files readable"},
        {"title": "Laravel Eloquent SQL injection in raw expressions", "confidence": "MEDIUM", "test": "curl", "indicator": "SQL error or boolean-based difference"},
    ],
    "spring": [
        {"title": "Spring Boot Actuator endpoints exposed", "confidence": "HIGH", "test": "curl", "indicator": "/actuator/env, /actuator/heapdump accessible"},
        {"title": "Spring Boot heapdump credential extraction", "confidence": "HIGH", "test": "script", "indicator": "heapdump contains credentials in memory"},
        {"title": "Spring Security misconfigured antMatchers", "confidence": "HIGH", "test": "curl", "indicator": "Protected endpoint accessible"},
        {"title": "Spring Boot DevTools remote code execution", "confidence": "LOW", "test": "curl", "indicator": "Restart/reload endpoint responds"},
        {"title": "Spring SSRF via RestTemplate URL injection", "confidence": "MEDIUM", "test": "curl", "indicator": "Internal service proxied via user-supplied URL"},
    ],
    "java": [
        {"title": "Java deserialization RCE via ysoserial", "confidence": "LOW", "test": "script", "indicator": "DNS callback or command execution"},
        {"title": "Java Log4j2 RCE (Log4Shell)", "confidence": "HIGH", "test": "curl", "indicator": "DNS/JNDI callback received"},
        {"title": "Java XML deserialization XXE", "confidence": "MEDIUM", "test": "curl", "indicator": "Internal file contents or SSRF"},
    ],
    "php": [
        {"title": "PHP type juggling authentication bypass", "confidence": "MEDIUM", "test": "curl", "indicator": "Login accepted with 0 or 'true' as password"},
        {"title": "PHP file inclusion via path traversal", "confidence": "MEDIUM", "test": "curl", "indicator": "Server-side file contents returned"},
        {"title": "PHP object injection via unserialize()", "confidence": "LOW", "test": "curl", "indicator": "Error with class name or command execution"},
        {"title": "phpinfo() exposed at /phpinfo.php or /?phpinfo", "confidence": "HIGH", "test": "curl", "indicator": "PHP configuration page returned"},
        {"title": "PHP open_basedir bypass via symlink", "confidence": "LOW", "test": "curl", "indicator": "Files outside webroot accessible"},
    ],
    "wordpress": [
        {"title": "WordPress user enumeration via /?author=1", "confidence": "HIGH", "test": "curl", "indicator": "Username in redirect URL"},
        {"title": "WordPress xmlrpc.php brute-force", "confidence": "MEDIUM", "test": "curl", "indicator": "xmlrpc.php responds to system.listMethods"},
        {"title": "WordPress plugin/theme arbitrary file read", "confidence": "MEDIUM", "test": "curl", "indicator": "File contents returned via vulnerable plugin"},
        {"title": "WordPress REST API user disclosure at /wp-json/wp/v2/users", "confidence": "HIGH", "test": "curl", "indicator": "User list including usernames returned"},
        {"title": "WordPress wp-config.php exposed via backup", "confidence": "MEDIUM", "test": "curl", "indicator": "wp-config.php.bak or wp-config.txt readable"},
    ],
    "redis": [
        {"title": "Cache injection via unsanitized key", "confidence": "LOW", "test": "curl", "indicator": "Cache poisoned"},
        {"title": "Session fixation via Redis session store", "confidence": "MEDIUM", "test": "curl", "indicator": "Session accepted from another user"},
        {"title": "Redis exposed without auth on port 6379", "confidence": "HIGH", "test": "curl", "indicator": "Redis PING responds with PONG"},
    ],
    "postgresql": [
        {"title": "SQL injection in search/filter params", "confidence": "MEDIUM", "test": "curl", "indicator": "SQL error or data leak"},
        {"title": "Boolean-based blind SQLi", "confidence": "LOW", "test": "script", "indicator": "Different responses for true/false"},
        {"title": "PostgreSQL extension loading RCE", "confidence": "LOW", "test": "script", "indicator": "pg_read_file or CREATE EXTENSION succeeds"},
    ],
    "mongodb": [
        {"title": "NoSQL injection via $where or $regex", "confidence": "HIGH", "test": "curl", "indicator": "All records returned or auth bypassed"},
        {"title": "MongoDB exposed without auth on port 27017", "confidence": "HIGH", "test": "curl", "indicator": "DB listing without credentials"},
        {"title": "Mass assignment via MongoDB $set injection", "confidence": "MEDIUM", "test": "curl", "indicator": "Protected field updated via nested object"},
    ],
    "aws": [
        {"title": "S3 bucket misconfiguration", "confidence": "HIGH", "test": "curl", "indicator": "Bucket listing or file access"},
        {"title": "SSRF to AWS metadata (IMDSv1)", "confidence": "HIGH", "test": "curl", "indicator": "169.254.169.254 response"},
        {"title": "IAM role assumption abuse", "confidence": "MEDIUM", "test": "script", "indicator": "AssumeRole succeeds"},
        {"title": "S3 presigned URL abuse (extended TTL)", "confidence": "MEDIUM", "test": "curl", "indicator": "Presigned URL valid beyond intended window"},
        {"title": "AWS Cognito unauthenticated identity pool", "confidence": "HIGH", "test": "curl", "indicator": "GetCredentialsForIdentity returns keys without auth"},
        {"title": "Exposed AWS keys in JS/env files", "confidence": "HIGH", "test": "curl", "indicator": "AKIA... key found in client-side code"},
    ],
    "kubernetes": [
        {"title": "K8s API server exposed without auth", "confidence": "HIGH", "test": "curl", "indicator": "/api/v1/pods returns pod list"},
        {"title": "K8s dashboard exposed without auth", "confidence": "HIGH", "test": "browser", "indicator": "Dashboard accessible without credentials"},
        {"title": "K8s RBAC privilege escalation via service account", "confidence": "MEDIUM", "test": "script", "indicator": "Service account token can create cluster-admin bindings"},
        {"title": "K8s secrets accessible via etcd", "confidence": "LOW", "test": "script", "indicator": "etcd data readable without encryption"},
    ],
    "firebase": [
        {"title": "Firebase database open read rules", "confidence": "HIGH", "test": "curl", "indicator": "/.json returns all data without auth"},
        {"title": "Firebase storage open read/write", "confidence": "HIGH", "test": "curl", "indicator": "Files listable or uploadable without auth"},
        {"title": "Firebase API key exposed in client JS", "confidence": "HIGH", "test": "curl", "indicator": "apiKey in Firebase config in source"},
        {"title": "Firebase Auth bypass via custom token", "confidence": "MEDIUM", "test": "script", "indicator": "Arbitrary UID accepted in custom token"},
    ],
    "stripe": [
        {"title": "Stripe webhook signature not validated", "confidence": "HIGH", "test": "curl", "indicator": "Forged webhook event processed"},
        {"title": "Stripe test mode keys in production", "confidence": "HIGH", "test": "curl", "indicator": "sk_test_ key in response or JS"},
        {"title": "Price manipulation via client-side amount", "confidence": "HIGH", "test": "curl", "indicator": "Payment processed with modified amount"},
    ],
    "flask": [
        {"title": "Flask debug mode RCE via Werkzeug console", "confidence": "HIGH", "test": "browser", "indicator": "Interactive Python console on error pages"},
        {"title": "Flask secret_key hardcoded or weak", "confidence": "HIGH", "test": "script", "indicator": "Session cookie forgeable with known secret"},
        {"title": "Flask SSTI via Jinja2 template injection", "confidence": "HIGH", "test": "curl", "indicator": "{{7*7}} evaluates to 49 in response"},
    ],
    "golang": [
        {"title": "Go debug pprof exposed at /debug/pprof/", "confidence": "HIGH", "test": "curl", "indicator": "CPU/memory profile or goroutine dump accessible"},
        {"title": "Go expvar debug endpoint at /debug/vars", "confidence": "MEDIUM", "test": "curl", "indicator": "Internal metrics and variables exposed"},
        {"title": "Go SSRF via http.Get with user-supplied URL", "confidence": "MEDIUM", "test": "curl", "indicator": "Internal service response proxied"},
    ],
}

# Endpoint patterns that suggest specific vulnerabilities
ENDPOINT_PATTERNS = [
    {"pattern": "/api/", "vulns": ["IDOR", "Auth bypass", "Rate limit", "Mass assignment"]},
    {"pattern": "/admin", "vulns": ["Auth bypass", "Privilege escalation", "Admin takeover"]},
    {"pattern": "/upload", "vulns": ["File upload RCE", "Path traversal", "MIME bypass"]},
    {"pattern": "/login", "vulns": ["Credential stuffing", "2FA bypass", "Account lockout bypass", "User enumeration"]},
    {"pattern": "/graphql", "vulns": ["Introspection", "Batch query", "IDOR via mutation", "Auth missing on mutation"]},
    {"pattern": "/webhook", "vulns": ["SSRF", "Webhook replay", "Signature bypass"]},
    {"pattern": "/oauth", "vulns": ["OAuth redirect manipulation", "Token leakage", "State param missing"]},
    {"pattern": "/reset", "vulns": ["Password reset poisoning", "Token prediction", "Host header injection"]},
    {"pattern": "/export", "vulns": ["IDOR on export", "CSV injection", "DoS via large export"]},
    {"pattern": "/search", "vulns": ["SQL injection", "XSS reflected", "Info disclosure", "SSRF via URL param"]},
    # Modern API patterns
    {"pattern": "/v1/", "vulns": ["IDOR", "Auth bypass", "Deprecated endpoint with weaker auth"]},
    {"pattern": "/v2/", "vulns": ["IDOR", "Auth bypass", "Version-specific behavior difference"]},
    {"pattern": "/v3/", "vulns": ["IDOR", "Auth bypass", "Version-specific behavior difference"]},
    {"pattern": "/trpc", "vulns": ["Missing input validation", "IDOR via procedure args", "Batch request abuse"]},
    {"pattern": "/actuator", "vulns": ["Spring Boot heapdump", "Env credential leak", "Shutdown endpoint"]},
    {"pattern": "/health", "vulns": ["Info disclosure", "Internal service topology leak"]},
    {"pattern": "/metrics", "vulns": ["Prometheus metric scrape", "Internal data exposure"]},
    {"pattern": "/debug", "vulns": ["Debug console RCE", "Stack trace disclosure", "Env var leak"]},
    {"pattern": "/internal", "vulns": ["Auth bypass for internal routes", "SSRF pivot", "Privileged API access"]},
    {"pattern": "/swagger", "vulns": ["API documentation leak", "Undocumented endpoints", "Test mode accessible"]},
    {"pattern": "/openapi", "vulns": ["API schema leak", "Auth requirements visible"]},
    {"pattern": "/api-docs", "vulns": ["API schema leak", "Undocumented endpoints visible"]},
    {"pattern": "/.well-known", "vulns": ["Security.txt disclosure", "ACME challenge replay", "OAuth metadata"]},
    {"pattern": "/socket.io", "vulns": ["WebSocket auth missing", "Namespace enum", "Event injection"]},
    {"pattern": "/ws", "vulns": ["WebSocket auth missing", "Message injection", "Subscription IDOR"]},
    {"pattern": "/callback", "vulns": ["Open redirect", "OAuth callback hijack", "SSRF via callback URL"]},
    {"pattern": "/proxy", "vulns": ["SSRF", "Blind SSRF via proxy endpoint", "Internal service pivoting"]},
    {"pattern": "/redirect", "vulns": ["Open redirect", "Phishing via redirect", "OAuth token theft"]},
    {"pattern": "/download", "vulns": ["Path traversal", "IDOR on file download", "LFI"]},
    {"pattern": "/preview", "vulns": ["SSRF via URL preview", "XSS in preview render", "IDOR on previewed content"]},
    {"pattern": "/invite", "vulns": ["Invitation token brute force", "Account takeover via invite", "IDOR via user enumeration"]},
    {"pattern": "/payment", "vulns": ["Price manipulation", "Payment bypass", "Currency confusion"]},
    {"pattern": "/checkout", "vulns": ["Race condition", "Price tampering", "Coupon stacking"]},
    {"pattern": "/settings", "vulns": ["CSRF on settings change", "Mass assignment", "Sensitive data in response"]},
    {"pattern": "/profile", "vulns": ["XSS via stored profile data", "IDOR on profile access", "Mass assignment"]},
    {"pattern": "/delete", "vulns": ["Missing CSRF protection", "IDOR on deletion", "Account deletion without confirmation"]},
    {"pattern": "/batch", "vulns": ["Batch operation IDOR", "Rate limit bypass via batching", "DoS via large batch"]},
]

# Second wave patterns (when first wave fails)
SECOND_WAVE_PATTERNS = {
    "waf_bypass": [
        {"title": "WAF bypass via Unicode normalization", "test": "curl"},
        {"title": "WAF bypass via chunked encoding", "test": "curl"},
        {"title": "WAF bypass via HTTP/2 downgrade", "test": "curl"},
        {"title": "WAF bypass via multipart/form-data encoding", "test": "curl"},
        {"title": "WAF bypass via case-insensitive header injection", "test": "curl"},
        {"title": "WAF bypass via double URL encoding", "test": "curl"},
    ],
    "timing": [
        {"title": "Timing-based username enumeration", "test": "script"},
        {"title": "Race condition in checkout flow", "test": "script"},
        {"title": "Time-based blind SQL injection", "test": "script"},
        {"title": "Race condition in coupon/promo application", "test": "script"},
        {"title": "Timing side-channel in password reset token comparison", "test": "script"},
    ],
    "business_logic": [
        {"title": "Business logic flaw: negative quantity", "test": "curl"},
        {"title": "Business logic flaw: price manipulation", "test": "curl"},
        {"title": "Business logic flaw: coupon reuse", "test": "curl"},
        {"title": "Business logic flaw: step skipping", "test": "browser"},
        {"title": "Business logic flaw: currency unit confusion", "test": "curl"},
        {"title": "Business logic flaw: referral self-referral loop", "test": "curl"},
        {"title": "Business logic flaw: 2FA enrollment bypass via account state", "test": "curl"},
        {"title": "Business logic flaw: subscription tier downgrade without losing features", "test": "browser"},
    ],
    "chaining": [
        {"title": "Chain: info disclosure + SSRF", "test": "curl"},
        {"title": "Chain: open redirect + OAuth token theft", "test": "browser"},
        {"title": "Chain: XSS + CSRF for account takeover", "test": "browser"},
        {"title": "Chain: subdomain takeover + cookie scope escalation", "test": "curl"},
        {"title": "Chain: IDOR + privilege escalation → admin access", "test": "curl"},
        {"title": "Chain: exposed API key + admin function → RCE or data dump", "test": "script"},
        {"title": "Chain: path traversal + file write → webshell upload", "test": "curl"},
    ],
    "oob_probes": [
        {"title": "Blind SSRF via OOB interactsh probe on URL parameters", "test": "script"},
        {"title": "Log4j JNDI injection via User-Agent/X-Forwarded-For", "test": "curl"},
        {"title": "Blind XXE via OOB DNS exfiltration", "test": "curl"},
        {"title": "Blind XSS via stored payload with interactsh callback", "test": "browser"},
        {"title": "Email header injection via OOB SMTP probe", "test": "curl"},
    ],
    "modern_injection": [
        {"title": "SSTI via Flask/Jinja2 template rendering: {{7*7}}", "test": "curl"},
        {"title": "GraphQL injection via inline fragment aliases", "test": "curl"},
        {"title": "NoSQL injection via MongoDB $where operator", "test": "curl"},
        {"title": "LDAP injection in search filters", "test": "curl"},
        {"title": "XPath injection in XML-based API", "test": "curl"},
        {"title": "HTTP parameter pollution via duplicate params", "test": "curl"},
    ],
}

# Subdomain patterns indicating interesting attack surfaces
SUBDOMAIN_VULN_PATTERNS = {
    "admin": ["Admin panel auth bypass", "Privileged API access", "Internal tool exposure"],
    "api": ["Undocumented API endpoints", "Auth missing on API routes", "IDOR via API"],
    "gateway": ["API gateway bypass", "Auth header stripping", "Route enumeration"],
    "staging": ["Debug mode enabled", "Test credentials active", "Less strict rate limits"],
    "dev": ["Debug mode enabled", "Test credentials active", "Source code exposure"],
    "test": ["Test credentials active", "Less strict rate limits", "Permissive CORS"],
    "internal": ["Unauthenticated internal routes", "SSRF pivot target", "Employee-only data"],
    "mail": ["Email header injection", "Open relay test", "Mail server misconfiguration"],
    "s3": ["Bucket listing", "Public file access", "Bucket takeover"],
    "cdn": ["CDN cache poisoning", "Host header injection", "Stored XSS via CDN"],
    "vpn": ["VPN config exposure", "Client cert extraction", "Auth bypass"],
    "dashboard": ["Auth bypass on dashboard", "Sensitive metrics exposed", "Admin without 2FA"],
    "monitor": ["Grafana/Kibana unauthenticated", "Log exposure", "Alert rule injection"],
    "jenkins": ["Jenkins unauthenticated RCE", "Script console access", "Build log secrets"],
    "jira": ["Jira project enumeration", "Internal ticket disclosure", "Attachment IDOR"],
    "git": ["Git repository exposure", "GitLab/Gitea auth bypass", "CI/CD secret theft"],
    "registry": ["Container registry public access", "Image pull without auth", "Dockerfile secrets"],
}


class DiscoveryEngine:
    """Generates vulnerability hypotheses from recon data."""

    def __init__(self):
        self._card_counter = 0

    def generate_hypotheses(self, recon_data: Dict[str, Any]) -> List[HypothesisCard]:
        """Generate hypothesis cards from recon data using all reasoning tracks.

        recon_data keys consumed:
          - tech_stack: List[str]          - detected technologies
          - endpoints: List[str]           - discovered URLs
          - subdomains: List[str]          - enumerated subdomains
          - findings: List[dict]           - existing findings
          - prior_patterns: List[str]      - historically successful vuln types
          - successful_vuln_types: List[str] - vuln types that paid before
          # New tool outputs:
          - katana_endpoints: List[str]    - JS-parsed endpoints from katana
          - gau_urls: List[str]            - historical URLs from Wayback/CC/OTX
          - trufflehog_findings: List[dict] - secrets found by trufflehog
          - arjun_params: Dict[str, List]  - hidden params found by arjun per URL
          - interactsh_payload: str        - OOB URL to embed in payloads
          - ffuf_paths: List[str]          - paths found by ffuf fuzzing
          - feroxbuster_paths: List[str]   - paths found by feroxbuster
          - dnsx_cnames: List[dict]        - DNS CNAME records (for takeover)
          - sqlmap_params: List[str]       - params flagged injectable by sqlmap
        """
        cards = []

        # Track 1: Pattern Synthesis (tech stack -> known vulns)
        cards.extend(self._pattern_synthesis(recon_data))

        # Track 2: Behavioral Anomaly (endpoint patterns + katana/gau/ffuf/feroxbuster)
        cards.extend(self._behavioral_anomaly(recon_data))

        # Track 3: Code Research (subdomain-based + trufflehog secrets + dnsx)
        cards.extend(self._code_research(recon_data))

        # Track 4: Cross-Domain Transfer (past successes)
        cards.extend(self._cross_domain_transfer(recon_data))

        # Track 5: LLM-powered novel hypothesis generation
        cards.extend(self._llm_hypotheses(recon_data))

        # Track 6: Tool-Augmented Synthesis (arjun params + interactsh OOB + sqlmap)
        cards.extend(self._tool_augmented_synthesis(recon_data))

        # Boost confidence for vuln types that worked before on this target or similar
        successful_types = recon_data.get("successful_vuln_types", [])
        prior_patterns = recon_data.get("prior_patterns", [])
        all_boosts = [t.lower() for t in successful_types + prior_patterns]
        for card in cards:
            for vtype in all_boosts:
                if vtype.lower() in card.title.lower():
                    card.confidence = Confidence.HIGH

        # Deduplicate by title
        seen = set()
        unique_cards = []
        for card in cards:
            if card.title not in seen:
                seen.add(card.title)
                unique_cards.append(card)

        # Sort: HIGH first, then MEDIUM, then LOW
        priority = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
        unique_cards.sort(key=lambda c: priority[c.confidence])

        return unique_cards

    def generate_second_wave(self, first_wave_results: Dict[str, Any]) -> List[HypothesisCard]:
        """Generate second wave hypotheses when first wave finds nothing.

        Second wave focuses on harder-to-detect classes: timing, business logic,
        WAF bypass, OOB blind probes, and modern injection techniques.
        """
        cards = []
        defenses = " ".join(first_wave_results.get("defenses_observed", [])).lower()
        has_interactsh = bool(first_wave_results.get("interactsh_payload", ""))

        # If WAF detected, add bypass techniques
        if any(waf in defenses for waf in ("waf", "cloudflare", "akamai", "imperva", "f5", "fastly")):
            for pattern in SECOND_WAVE_PATTERNS["waf_bypass"]:
                cards.append(self._make_card(
                    pattern["title"], Confidence.MEDIUM, pattern["test"],
                    "WAF signature bypassed — payload reaches backend", "cross_domain",
                ))

        # Always add timing and business logic
        for pattern in SECOND_WAVE_PATTERNS["timing"]:
            cards.append(self._make_card(
                pattern["title"], Confidence.MEDIUM, pattern["test"],
                "Measurable timing difference or race success", "behavioral_anomaly",
            ))

        for pattern in SECOND_WAVE_PATTERNS["business_logic"]:
            cards.append(self._make_card(
                pattern["title"], Confidence.MEDIUM, pattern["test"],
                "Unexpected business state change", "behavioral_anomaly",
            ))

        # Add chaining opportunities
        for pattern in SECOND_WAVE_PATTERNS["chaining"]:
            cards.append(self._make_card(
                pattern["title"], Confidence.LOW, pattern["test"],
                "Chain produces higher impact", "cross_domain",
            ))

        # If interactsh available, add OOB blind probes as second wave
        if has_interactsh:
            for pattern in SECOND_WAVE_PATTERNS["oob_probes"]:
                cards.append(self._make_card(
                    pattern["title"], Confidence.MEDIUM, pattern["test"],
                    "OOB DNS/HTTP callback received confirming blind vuln", "tool_synthesis",
                ))

        # Modern injection patterns that standard scanners miss
        for pattern in SECOND_WAVE_PATTERNS["modern_injection"]:
            cards.append(self._make_card(
                pattern["title"], Confidence.MEDIUM, pattern["test"],
                "Injection confirmed by response or OOB callback", "behavioral_anomaly",
            ))

        return cards

    def _pattern_synthesis(self, recon_data: Dict) -> List[HypothesisCard]:
        """Track 1: Map tech stack to known vulnerability patterns."""
        cards = []
        tech_stack = [t.lower() for t in recon_data.get("tech_stack", [])]

        for tech in tech_stack:
            patterns = TECH_VULN_PATTERNS.get(tech, [])
            for p in patterns:
                conf = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}
                cards.append(self._make_card(
                    p["title"], conf[p["confidence"]], p["test"],
                    p["indicator"], "pattern_synthesis",
                ))

        return cards

    def _behavioral_anomaly(self, recon_data: Dict) -> List[HypothesisCard]:
        """Track 2: Identify suspicious endpoint patterns.

        Consumes: endpoints, katana_endpoints, gau_urls, ffuf_paths, feroxbuster_paths
        """
        cards = []

        # Aggregate all endpoint sources
        endpoints = list(recon_data.get("endpoints", []))
        endpoints.extend(recon_data.get("katana_endpoints", []))
        endpoints.extend(recon_data.get("gau_urls", []))
        endpoints.extend(recon_data.get("ffuf_paths", []))
        endpoints.extend(recon_data.get("feroxbuster_paths", []))

        # Deduplicate endpoints
        seen_endpoints: set = set()
        unique_endpoints = []
        for ep in endpoints:
            key = str(ep).split('?')[0].lower()  # strip query params for dedup
            if key not in seen_endpoints:
                seen_endpoints.add(key)
                unique_endpoints.append(ep)

        for endpoint in unique_endpoints:
            for ep in ENDPOINT_PATTERNS:
                if ep["pattern"] in str(endpoint).lower():
                    # Boost confidence for endpoints found via passive sources (gau = historical)
                    source_boost = endpoint in recon_data.get("gau_urls", [])
                    conf = Confidence.HIGH if source_boost else Confidence.MEDIUM
                    for vuln in ep["vulns"][:3]:  # cap at 3 vulns per endpoint to avoid explosion
                        cards.append(self._make_card(
                            f"{vuln} in {endpoint}",
                            conf,
                            "curl",
                            f"Unexpected behavior at {endpoint}",
                            "behavioral_anomaly",
                        ))

        # Flag Wayback/GAU-discovered URLs that returned 404 but may be partially accessible
        gau_urls = recon_data.get("gau_urls", [])
        if gau_urls:
            cards.append(self._make_card(
                f"Historical endpoint resurrection: {len(gau_urls)} URLs from Wayback/GAU may be partially accessible",
                Confidence.MEDIUM, "curl",
                "Removed endpoint returns data or redirects differently",
                "behavioral_anomaly",
            ))

        return cards

    def _code_research(self, recon_data: Dict) -> List[HypothesisCard]:
        """Track 3: Subdomain + trufflehog secrets + dnsx CNAME hypothesis generation.

        Consumes: subdomains, trufflehog_findings, dnsx_cnames
        """
        cards = []
        subdomains = recon_data.get("subdomains", [])

        for sub in subdomains:
            sub_lower = sub.lower()
            matched = False
            for keyword, vulns in SUBDOMAIN_VULN_PATTERNS.items():
                if keyword in sub_lower:
                    for vuln in vulns[:2]:  # top 2 per subdomain keyword
                        cards.append(self._make_card(
                            f"{vuln} on {sub}",
                            Confidence.HIGH if keyword in ("admin", "internal", "jenkins", "git") else Confidence.MEDIUM,
                            "browser" if keyword in ("admin", "dashboard", "jenkins") else "curl",
                            f"Sensitive functionality at {sub}", "code_research",
                        ))
                    matched = True
                    break

            if not matched:
                # Generic: any new subdomain is worth an API enumeration attempt
                if sub_lower.count('.') <= 3:  # avoid deep subdomain noise
                    cards.append(self._make_card(
                        f"API endpoint enumeration on {sub}",
                        Confidence.LOW, "curl",
                        "Undocumented endpoints or loose auth", "code_research",
                    ))

        # Trufflehog verified secrets → immediate HIGH confidence test
        trufflehog_findings = recon_data.get("trufflehog_findings", [])
        for secret in trufflehog_findings:
            detector = secret.get("detector", "unknown")
            verified = secret.get("verified", False)
            cards.append(self._make_card(
                f"{'VERIFIED' if verified else 'Potential'} {detector} secret leaked in JS/git — test for API access",
                Confidence.HIGH if verified else Confidence.MEDIUM,
                "curl",
                f"API call with leaked {detector} key succeeds with privileged access",
                "code_research",
            ))

        # DNS CNAME records → subdomain takeover candidates
        dnsx_cnames = recon_data.get("dnsx_cnames", [])
        for record in dnsx_cnames:
            cname = record.get("cname", "")
            subdomain = record.get("subdomain", "")
            # Check for dangling CNAMEs (common takeover services)
            takeover_services = ["github.io", "heroku", "s3.amazonaws.com", "azurewebsites.net",
                                  "cloudfront.net", "fastly.net", "shopify.com", "zendesk.com",
                                  "helpscout.net", "surge.sh", "netlify.app", "pages.dev"]
            for svc in takeover_services:
                if svc in cname:
                    cards.append(self._make_card(
                        f"Subdomain takeover via dangling CNAME {subdomain} → {cname}",
                        Confidence.HIGH, "curl",
                        f"Claiming {cname} service returns controlled content on {subdomain}",
                        "code_research",
                    ))

        return cards

    def _cross_domain_transfer(self, recon_data: Dict) -> List[HypothesisCard]:
        """Track 4: Apply lessons from past hunts."""
        cards = []
        # Universal high-value checks that work across most targets
        universal = [
            ("CORS misconfiguration", Confidence.HIGH, "curl", "ACAO reflects arbitrary origin"),
            ("Open redirect via login/OAuth flow", Confidence.MEDIUM, "browser", "Redirect to external domain"),
            ("IDOR via predictable IDs in API", Confidence.HIGH, "curl", "Other user's data returned"),
            ("JWT secret brute force", Confidence.LOW, "script", "JWT verified with common secret"),
            ("Subdomain takeover via dangling CNAME", Confidence.MEDIUM, "curl", "NXDOMAIN or unclaimed service"),
        ]
        for title, conf, method, indicator in universal:
            cards.append(self._make_card(title, conf, method, indicator, "cross_domain"))

        return cards

    def _tool_augmented_synthesis(self, recon_data: Dict) -> List[HypothesisCard]:
        """Track 6: Generate targeted hypotheses from tool-specific discoveries.

        Consumes: arjun_params, interactsh_payload, sqlmap_params, ffuf_paths, feroxbuster_paths
        """
        cards = []

        # Arjun discovered hidden parameters → test each for injection + IDOR
        arjun_params = recon_data.get("arjun_params", {})  # {url: [param1, param2, ...]}
        for url, params in arjun_params.items():
            for param in params:
                cards.append(self._make_card(
                    f"Hidden parameter '{param}' at {url} — test for IDOR, SQLi, SSRF, XSS",
                    Confidence.HIGH, "curl",
                    f"Parameter '{param}' accepts unexpected input or returns another user's data",
                    "tool_synthesis",
                ))

        # Interactsh OOB available → probe blind vuln classes
        interactsh_payload = recon_data.get("interactsh_payload", "")
        if interactsh_payload:
            oob_tests = [
                ("Blind SSRF via URL parameter with OOB callback", "curl"),
                ("Log4j JNDI injection probe via User-Agent header with OOB callback", "curl"),
                ("Blind XXE via OOB DNS exfiltration with interactsh", "curl"),
                ("Blind XSS via stored payload — interactsh callback on admin view", "browser"),
                ("Email header injection via interactsh OOB SMTP probe", "curl"),
                ("XSS via PDF/CSV export with OOB script callback", "curl"),
            ]
            for title, method in oob_tests:
                cards.append(self._make_card(
                    title,
                    Confidence.MEDIUM, method,
                    f"OOB DNS/HTTP interaction received at {interactsh_payload}",
                    "tool_synthesis",
                ))

        # SQLmap flagged parameters → high confidence SQLi hypothesis
        sqlmap_params = recon_data.get("sqlmap_params", [])
        for param in sqlmap_params:
            cards.append(self._make_card(
                f"SQL injection confirmed by sqlmap in parameter: {param}",
                Confidence.HIGH, "script",
                f"sqlmap confirmed injection — extract DB version or credentials from '{param}'",
                "tool_synthesis",
            ))

        # ffuf/feroxbuster found interesting backup/config paths
        all_discovered = (
            list(recon_data.get("ffuf_paths", [])) +
            list(recon_data.get("feroxbuster_paths", []))
        )
        interesting_extensions = [".bak", ".old", ".sql", ".env", ".log", ".config",
                                   ".zip", ".tar.gz", ".dump", ".json.bak"]
        interesting_names = ["backup", "config", ".env", "phpinfo", "info.php",
                             "test.php", "debug", "server-status", "web.config"]
        for path in all_discovered:
            path_lower = str(path).lower()
            if any(ext in path_lower for ext in interesting_extensions):
                cards.append(self._make_card(
                    f"Sensitive backup/config file discovered: {path}",
                    Confidence.HIGH, "curl",
                    "File contains credentials, source code, or sensitive configuration",
                    "tool_synthesis",
                ))
            elif any(name in path_lower for name in interesting_names):
                cards.append(self._make_card(
                    f"High-value path discovered by fuzzing: {path}",
                    Confidence.MEDIUM, "curl",
                    "Path reveals debug information, configuration, or internal functionality",
                    "tool_synthesis",
                ))

        return cards

    def _llm_hypotheses(self, recon_data: Dict) -> List[HypothesisCard]:
        """Track 5: LLM-powered hypothesis generation for novel attack vectors.

        Uses the LLM bridge to generate hypotheses that template-based tracks
        can't produce. Falls back gracefully when API key is unavailable.
        """
        cards = []
        target = recon_data.get('target', recon_data.get('domain', ''))

        try:
            from engine.core.llm_bridge import LLMBridge
            bridge = LLMBridge(target)
            if not bridge.available:
                return cards

            findings = recon_data.get('findings', [])
            prior_patterns = recon_data.get('prior_patterns', [])

            llm_hypotheses = bridge.generate_hypotheses(recon_data, findings, prior_patterns)

            conf_map = {'HIGH': Confidence.HIGH, 'MEDIUM': Confidence.MEDIUM, 'LOW': Confidence.LOW}
            for h in llm_hypotheses:
                conf = conf_map.get(h.get('confidence', 'MEDIUM'), Confidence.MEDIUM)
                cards.append(self._make_card(
                    h.get('title', 'LLM hypothesis'),
                    conf,
                    h.get('test_method', 'curl') if 'curl' in str(h.get('test', '')) else 'curl',
                    h.get('rationale', 'LLM-generated hypothesis')[:100],
                    'llm_reasoning',
                ))

        except Exception:
            pass  # LLM unavailable, degrade gracefully

        return cards

    def _make_card(self, title: str, confidence: Confidence, test_method: str,
                   success_indicator: str, track: str) -> HypothesisCard:
        self._card_counter += 1
        return HypothesisCard(
            id=f"H{self._card_counter:03d}",
            title=title,
            confidence=confidence,
            test_method=test_method,
            payload="",  # Filled by the testing phase
            success_indicator=success_indicator,
            reasoning_track=track,
        )
