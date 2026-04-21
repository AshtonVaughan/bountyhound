"""
quality_gates.py - Quality control system for BountyHound findings.

Classifies findings, prevents false positives, validates state changes,
and determines whether a finding is worth submitting to a bug bounty program.

All classes use static methods so they can be called without instantiation
from any agent in the swarm.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# gRPC canonical status codes we care about
_GRPC_NOT_VULNERABILITY = {
    5: ("NOT_FOUND", "Resource does not exist. This is not an authorization issue."),
    7: ("PERMISSION_DENIED", "Authorization is working correctly. Access was properly denied."),
    12: ("UNIMPLEMENTED", "Method does not exist on the server. Not a vulnerability."),
}

_GRPC_SERVER_ERROR = {
    2: ("UNKNOWN", "Server returned an unknown error. This is a server-side issue, not an auth bypass."),
    13: ("INTERNAL", "Internal server error. This is a server-side issue, not an auth bypass."),
}

# Patterns that indicate a GraphQL response contains only schema metadata
_GRAPHQL_TYPENAME_ONLY = re.compile(
    r'^\s*\{\s*"data"\s*:\s*\{[^}]*"__typename"\s*:\s*"[^"]*"\s*\}\s*\}\s*$'
)

# Patterns for sensitive data detection in info-disclosure checks
_API_KEY_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}'),
    re.compile(r'(?i)(secret|token|password|passwd|pwd)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{8,}'),
    re.compile(r'(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}'),
    re.compile(r'(?i)aws[_-]?(secret|access)[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{20,}'),
]

_PII_PATTERNS = [
    re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
    re.compile(r'(?i)\b\d{3}[-.]?\d{2}[-.]?\d{4}\b'),  # SSN-like
]

_DB_CONN_PATTERNS = [
    re.compile(r'(?i)(mysql|postgres|mongodb|redis|mssql)://[^\s"\']+'),
    re.compile(r'(?i)jdbc:[a-z]+://[^\s"\']+'),
    re.compile(r'(?i)Data Source\s*=\s*[^\s;]+'),
]

_INTERNAL_IP_PATTERN = re.compile(
    r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})\b'
)

_STACK_TRACE_PATTERNS = [
    re.compile(r'(?i)(traceback|stack\s*trace|at\s+[\w.]+\([\w.]+:\d+\))'),
    re.compile(r'(?i)File\s+"[^"]+",\s+line\s+\d+'),
    re.compile(r'(?i)at\s+[\w.$]+\.[\w.$]+\([\w.]+\.java:\d+\)'),
    re.compile(r'(?i)in\s+[\w/\\]+\.(php|py|rb|js|ts):\d+'),
]


# ---------------------------------------------------------------------------
# 1. ErrorClassifier
# ---------------------------------------------------------------------------

class ErrorClassifier:
    """Classifies HTTP and protocol errors to prevent misinterpretation as
    vulnerabilities.

    gRPC, GraphQL, and standard HTTP responses each have error patterns that
    look alarming but are perfectly normal.  This classifier prevents those
    patterns from being reported as security findings.
    """

    @staticmethod
    def classify(
        status_code: int,
        response_body: str,
        protocol: str = "http",
    ) -> Dict[str, Any]:
        """Classify an error response and determine if it indicates a real
        vulnerability.

        Args:
            status_code: HTTP status code, or gRPC status code when
                ``protocol`` is ``"grpc"``.
            response_body: The raw response body as a string.
            protocol: One of ``"http"``, ``"grpc"``, or ``"graphql"``.

        Returns:
            A dict with keys ``is_vulnerability`` (bool), ``category`` (str),
            ``explanation`` (str), and ``confidence`` (float 0-1).
        """
        protocol = protocol.lower().strip()

        if protocol == "grpc":
            return ErrorClassifier._classify_grpc(status_code, response_body)
        if protocol == "graphql":
            return ErrorClassifier._classify_graphql(status_code, response_body)
        return ErrorClassifier._classify_http(status_code, response_body)

    # -- internal helpers --------------------------------------------------

    @staticmethod
    def _classify_grpc(code: int, body: str) -> Dict[str, Any]:
        if code in _GRPC_NOT_VULNERABILITY:
            name, explanation = _GRPC_NOT_VULNERABILITY[code]
            return {
                "is_vulnerability": False,
                "category": f"grpc_{name.lower()}",
                "explanation": explanation,
                "confidence": 0.95,
            }

        if code in _GRPC_SERVER_ERROR:
            name, explanation = _GRPC_SERVER_ERROR[code]
            return {
                "is_vulnerability": False,
                "category": f"grpc_{name.lower()}",
                "explanation": explanation,
                "confidence": 0.90,
            }

        # gRPC UNAUTHENTICATED (16) means auth IS enforced
        if code == 16:
            return {
                "is_vulnerability": False,
                "category": "grpc_unauthenticated",
                "explanation": "Server correctly requires authentication. Auth is enforced.",
                "confidence": 0.95,
            }

        # For other gRPC codes, we cannot make a definitive call
        return {
            "is_vulnerability": False,
            "category": "grpc_unknown_code",
            "explanation": (
                f"gRPC status {code} received. Requires manual analysis "
                "to determine if this indicates a vulnerability."
            ),
            "confidence": 0.30,
        }

    @staticmethod
    def _classify_graphql(status_code: int, body: str) -> Dict[str, Any]:
        # GraphQL ALWAYS returns HTTP 200 -- an errors[] array does not mean
        # we successfully exploited anything.
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            parsed = {}

        errors = parsed.get("errors", [])
        data = parsed.get("data")

        # Case 1: errors present in response
        if errors:
            error_messages = " | ".join(
                e.get("message", "") for e in errors if isinstance(e, dict)
            )
            # Check for auth-related error messages that prove auth IS working
            auth_keywords = [
                "unauthenticated", "unauthorized", "not authenticated",
                "authentication required", "access denied", "forbidden",
            ]
            if any(kw in error_messages.lower() for kw in auth_keywords):
                return {
                    "is_vulnerability": False,
                    "category": "graphql_auth_enforced",
                    "explanation": (
                        "GraphQL returned authentication/authorization error. "
                        "Auth is working correctly."
                    ),
                    "confidence": 0.95,
                }

            return {
                "is_vulnerability": False,
                "category": "graphql_error_response",
                "explanation": (
                    "GraphQL HTTP 200 with errors[] is NOT success. "
                    f"Errors: {error_messages[:300]}"
                ),
                "confidence": 0.85,
            }

        # Case 2: __typename only response -- no real data
        if data and isinstance(data, dict):
            # Check if every value is either None or a dict with only __typename
            if ErrorClassifier._is_typename_only(data):
                return {
                    "is_vulnerability": False,
                    "category": "graphql_typename_only",
                    "explanation": (
                        "Response contains only __typename metadata, not actual "
                        "data. This does NOT prove data access."
                    ),
                    "confidence": 0.90,
                }

        # Case 3: data is entirely null
        if data is None and not errors:
            return {
                "is_vulnerability": False,
                "category": "graphql_null_data",
                "explanation": "GraphQL returned null data with no errors. No data was accessed.",
                "confidence": 0.80,
            }

        # If we got here, there IS data -- but we still need state-change proof
        return {
            "is_vulnerability": False,
            "category": "graphql_data_present",
            "explanation": (
                "GraphQL response contains data, but this alone does not confirm "
                "a vulnerability. State change verification is still required."
            ),
            "confidence": 0.40,
        }

    @staticmethod
    def _is_typename_only(data: Any) -> bool:
        """Return True if the data dict contains only __typename fields."""
        if not isinstance(data, dict):
            return False
        for key, value in data.items():
            if key == "__typename":
                continue
            if value is None:
                continue
            if isinstance(value, dict):
                if not ErrorClassifier._is_typename_only(value):
                    return False
            else:
                # Non-None, non-dict, non-__typename value means real data
                return False
        return True

    @staticmethod
    def _classify_http(status_code: int, body: str) -> Dict[str, Any]:
        # 400 Bad Request -- input validation, not missing auth
        if status_code == 400:
            return {
                "is_vulnerability": False,
                "category": "http_input_validation",
                "explanation": (
                    "HTTP 400 indicates input validation rejected the request. "
                    "If this occurs before a 401 check, it means input validation "
                    "runs first -- NOT that auth is missing."
                ),
                "confidence": 0.85,
            }

        # 403 Forbidden -- access control working correctly
        if status_code == 403:
            return {
                "is_vulnerability": False,
                "category": "http_access_denied",
                "explanation": "HTTP 403 means access was correctly denied. Authorization is working.",
                "confidence": 0.95,
            }

        # 405 Method Not Allowed -- not a vulnerability
        if status_code == 405:
            return {
                "is_vulnerability": False,
                "category": "http_method_not_allowed",
                "explanation": "HTTP 405 means the HTTP method is not supported. Not a vulnerability.",
                "confidence": 0.95,
            }

        # 500 with stack trace -- info disclosure (LOW)
        if status_code == 500:
            has_trace = any(p.search(body) for p in _STACK_TRACE_PATTERNS)
            if has_trace:
                return {
                    "is_vulnerability": True,
                    "category": "info_disclosure_stack_trace",
                    "explanation": (
                        "HTTP 500 with stack trace is an information disclosure "
                        "vulnerability. Severity: LOW only."
                    ),
                    "confidence": 0.70,
                }
            return {
                "is_vulnerability": False,
                "category": "http_server_error",
                "explanation": "HTTP 500 without sensitive information is a server error, not a vulnerability.",
                "confidence": 0.80,
            }

        # 502/503/504 -- infrastructure issues
        if status_code in (502, 503, 504):
            return {
                "is_vulnerability": False,
                "category": "http_infrastructure_error",
                "explanation": (
                    f"HTTP {status_code} is an infrastructure/proxy error. "
                    "Not a security vulnerability."
                ),
                "confidence": 0.95,
            }

        # 401 -- auth is enforced
        if status_code == 401:
            return {
                "is_vulnerability": False,
                "category": "http_auth_enforced",
                "explanation": "HTTP 401 means authentication is required and enforced.",
                "confidence": 0.95,
            }

        # 200 -- could be anything, needs further analysis
        if status_code == 200:
            return {
                "is_vulnerability": False,
                "category": "http_success",
                "explanation": (
                    "HTTP 200 alone does not confirm a vulnerability. "
                    "State change verification and data analysis are required."
                ),
                "confidence": 0.30,
            }

        # Everything else -- unknown, needs manual review
        return {
            "is_vulnerability": False,
            "category": "http_unknown",
            "explanation": f"HTTP {status_code} requires manual analysis.",
            "confidence": 0.20,
        }


# ---------------------------------------------------------------------------
# 2. CORSValidator
# ---------------------------------------------------------------------------

class CORSValidator:
    """Checks whether a CORS misconfiguration is actually exploitable in a
    real browser environment.

    Many scanners flag CORS headers that are technically spec-compliant or
    that browsers actively block.  This validator separates exploitable
    misconfigurations from noise.
    """

    @staticmethod
    def is_exploitable(
        acao_header: str,
        acac_header: str,
        origin_tested: str,
    ) -> Dict[str, Any]:
        """Determine if the CORS configuration is exploitable.

        Args:
            acao_header: Value of the ``Access-Control-Allow-Origin`` header.
            acac_header: Value of the ``Access-Control-Allow-Credentials``
                header (typically ``"true"`` or absent/empty).
            origin_tested: The ``Origin`` header value that was sent in the
                request.

        Returns:
            A dict with ``exploitable`` (bool), ``reason`` (str), and
            ``severity`` (str -- one of CRITICAL, HIGH, MEDIUM, LOW, INFO).
        """
        acao = (acao_header or "").strip()
        acac = (acac_header or "").strip().lower() == "true"
        origin = (origin_tested or "").strip()

        # Rule 1: ACAO: * with ACAC: true -- browsers block this per spec
        if acao == "*" and acac:
            return {
                "exploitable": False,
                "reason": (
                    "ACAO: * combined with ACAC: true is explicitly blocked by "
                    "browsers per the CORS specification. Credentials will never "
                    "be sent. Not exploitable."
                ),
                "severity": "INFO",
            }

        # Rule 2: ACAO: * without ACAC: true -- no credentials sent
        if acao == "*" and not acac:
            return {
                "exploitable": False,
                "reason": (
                    "ACAO: * without ACAC: true means browsers will not send "
                    "credentials (cookies, auth headers). Only exploitable if the "
                    "response itself contains sensitive data that requires no auth. "
                    "Verify manually."
                ),
                "severity": "LOW",
            }

        # Rule 3: ACAO: null with ACAC: true -- exploitable via sandboxed iframe
        if acao.lower() == "null" and acac:
            return {
                "exploitable": True,
                "reason": (
                    "ACAO: null with ACAC: true is exploitable. An attacker can "
                    "use a sandboxed iframe (sandbox='allow-scripts allow-forms') "
                    "which sends Origin: null. Credentials will be included."
                ),
                "severity": "MEDIUM",
            }

        # Rule 4: ACAO reflects the attacker-controlled origin with ACAC: true
        if acao == origin and acac and origin:
            return {
                "exploitable": True,
                "reason": (
                    f"Server reflects the attacker's origin ({origin}) in ACAO "
                    "and sets ACAC: true. An attacker's website can make "
                    "authenticated cross-origin requests and read responses. "
                    "This is a full CORS bypass."
                ),
                "severity": "HIGH",
            }

        # Rule 5: ACAO reflects origin without ACAC -- limited impact
        if acao == origin and not acac and origin:
            return {
                "exploitable": False,
                "reason": (
                    f"Server reflects origin ({origin}) in ACAO but does not set "
                    "ACAC: true. Browsers will not send credentials. Only "
                    "exploitable if the endpoint returns sensitive data without "
                    "authentication."
                ),
                "severity": "LOW",
            }

        # Rule 6: ACAO is a specific different domain with ACAC: true
        if acao and acao != "*" and acao.lower() != "null" and acac:
            # Check if the ACAO is the same as origin (already handled above)
            # This catches cases where ACAO is a whitelisted domain
            if acao != origin:
                return {
                    "exploitable": False,
                    "reason": (
                        f"ACAO is set to {acao} (not the tested origin {origin}). "
                        "The server allows a specific domain, not arbitrary origins. "
                        "Only exploitable if you control the allowed domain."
                    ),
                    "severity": "LOW",
                }

        # Default: inconclusive
        return {
            "exploitable": False,
            "reason": (
                f"CORS configuration (ACAO: {acao!r}, ACAC: {acac}) does not "
                "match a known exploitable pattern. Manual review recommended."
            ),
            "severity": "INFO",
        }


# ---------------------------------------------------------------------------
# 3. InfoDisclosureClassifier
# ---------------------------------------------------------------------------

class InfoDisclosureClassifier:
    """Determines whether an information disclosure finding is actually worth
    reporting to a bug bounty program.

    Many scanners generate dozens of INFO-level disclosures that programs
    either explicitly exclude from scope or mark as informational / won't-fix.
    This classifier filters out the noise.
    """

    # Disclosure types that are almost never worth reporting alone
    _NOISE_TYPES = {
        "server_version",
        "technology_fingerprint",
        "framework_version",
        "x_powered_by",
        "server_header",
    }

    @staticmethod
    def classify(disclosure_type: str, data: str) -> Dict[str, Any]:
        """Classify an information disclosure finding.

        Args:
            disclosure_type: A short label such as ``"server_version"``,
                ``"stack_trace"``, ``"api_key"``, ``"pii"``,
                ``"internal_ip"``, ``"source_code"``, ``"db_connection"``,
                ``"framework_version"``, ``"technology_fingerprint"``, etc.
            data: The actual disclosed data (header value, response body
                snippet, etc.).

        Returns:
            A dict with ``worth_reporting`` (bool), ``severity`` (str), and
            ``reason`` (str).
        """
        dtype = disclosure_type.lower().strip().replace("-", "_").replace(" ", "_")

        # --- Definitely worth reporting ---

        # API keys / tokens / secrets
        if dtype in ("api_key", "token", "secret", "credential", "credentials"):
            return {
                "worth_reporting": True,
                "severity": "HIGH",
                "reason": (
                    "API keys, tokens, or credentials in the response are always "
                    "reportable. Verify the key is valid and active."
                ),
            }

        # Check data for API key patterns regardless of declared type
        if any(p.search(data) for p in _API_KEY_PATTERNS):
            return {
                "worth_reporting": True,
                "severity": "HIGH",
                "reason": (
                    "Response body contains patterns matching API keys, secrets, "
                    "or tokens. Verify validity before reporting."
                ),
            }

        # Database connection strings
        if dtype in ("db_connection", "database_connection", "connection_string"):
            return {
                "worth_reporting": True,
                "severity": "CRITICAL",
                "reason": (
                    "Database connection strings expose host, credentials, and "
                    "database names. Always report."
                ),
            }

        if any(p.search(data) for p in _DB_CONN_PATTERNS):
            return {
                "worth_reporting": True,
                "severity": "CRITICAL",
                "reason": (
                    "Response contains a database connection string. "
                    "Always report -- this can lead to direct database access."
                ),
            }

        # PII of other users
        if dtype in ("pii", "personal_data", "user_data"):
            return {
                "worth_reporting": True,
                "severity": "HIGH",
                "reason": (
                    "Personal Identifiable Information (emails, names, addresses) "
                    "of OTHER users is a privacy violation. Always report."
                ),
            }

        # Source code disclosure
        if dtype in ("source_code", "sourcecode", "code_disclosure"):
            # Severity depends on what's in the source
            if any(p.search(data) for p in _API_KEY_PATTERNS):
                return {
                    "worth_reporting": True,
                    "severity": "HIGH",
                    "reason": "Source code disclosure containing hardcoded secrets.",
                }
            return {
                "worth_reporting": True,
                "severity": "MEDIUM",
                "reason": (
                    "Source code disclosure reveals internal logic, file paths, "
                    "and potentially exploitable patterns."
                ),
            }

        # Stack traces with file paths
        if dtype in ("stack_trace", "stacktrace", "error_trace"):
            has_paths = any(p.search(data) for p in _STACK_TRACE_PATTERNS)
            if has_paths:
                # If the stack trace also leaks secrets, bump severity
                if any(p.search(data) for p in _API_KEY_PATTERNS):
                    return {
                        "worth_reporting": True,
                        "severity": "MEDIUM",
                        "reason": (
                            "Stack trace exposes file paths AND contains "
                            "sensitive data (keys/tokens)."
                        ),
                    }
                return {
                    "worth_reporting": True,
                    "severity": "LOW",
                    "reason": (
                        "Stack trace exposes internal file paths and framework "
                        "details. Worth reporting as LOW."
                    ),
                }
            return {
                "worth_reporting": False,
                "severity": "INFO",
                "reason": "Error message without meaningful file paths or sensitive data.",
            }

        # Internal IP addresses
        if dtype in ("internal_ip", "private_ip", "ip_disclosure"):
            if _INTERNAL_IP_PATTERN.search(data):
                return {
                    "worth_reporting": True,
                    "severity": "LOW",
                    "reason": (
                        "Internal/private IP address disclosed. Reveals network "
                        "topology information."
                    ),
                }
            return {
                "worth_reporting": False,
                "severity": "INFO",
                "reason": "No RFC-1918 private IP address found in the data.",
            }

        # Check data itself for internal IPs even if type doesn't say so
        if _INTERNAL_IP_PATTERN.search(data) and dtype not in InfoDisclosureClassifier._NOISE_TYPES:
            return {
                "worth_reporting": True,
                "severity": "LOW",
                "reason": "Response contains internal IP address(es).",
            }

        # --- Not worth reporting alone ---

        # Framework version -- only worth it if a known CVE exists
        if dtype in ("framework_version", "library_version"):
            # We cannot check CVE databases here (no network), so flag for
            # manual review but default to not worth reporting.
            return {
                "worth_reporting": False,
                "severity": "INFO",
                "reason": (
                    "Framework/library version disclosure is informational. "
                    "Only worth reporting if a known CVE exists for this "
                    "specific version. Check CVE databases manually."
                ),
            }

        # Server version, technology fingerprint, X-Powered-By
        if dtype in InfoDisclosureClassifier._NOISE_TYPES:
            return {
                "worth_reporting": False,
                "severity": "INFO",
                "reason": (
                    f"'{disclosure_type}' is informational and almost never "
                    "accepted by bug bounty programs. Not worth reporting alone."
                ),
            }

        # Fallback: unknown type -- check data heuristically
        if any(p.search(data) for p in _PII_PATTERNS):
            return {
                "worth_reporting": True,
                "severity": "HIGH",
                "reason": (
                    "Data contains patterns matching PII (emails, SSN-like numbers). "
                    "Verify these belong to other users before reporting."
                ),
            }

        return {
            "worth_reporting": False,
            "severity": "INFO",
            "reason": (
                f"Disclosure type '{disclosure_type}' with the provided data "
                "does not match a clearly reportable pattern. Manual review needed."
            ),
        }


# ---------------------------------------------------------------------------
# 4. StateChangeVerifier
# ---------------------------------------------------------------------------

class StateChangeVerifier:
    """Enforces the 'prove it actually worked' rule.

    Every vulnerability claim MUST demonstrate a real state change or
    unauthorized data access.  This class generates verification plans and
    evaluates before/after evidence.

    Protocol:
        1. READ state (before)
        2. ATTEMPT exploit / mutation
        3. READ state (after)
        4. COMPARE -- did anything actually change?
    """

    # Maps vulnerability types to their verification plans
    _PLANS: Dict[str, Dict[str, Any]] = {
        "idor": {
            "steps": [
                "Authenticate as User B (the victim) and read the target resource. Record the full response.",
                "Authenticate as User A (the attacker) and attempt to access/modify the same resource using User B's resource ID.",
                "Authenticate as User B again and read the target resource. Record the full response.",
                "Compare the before and after states. For read IDOR: did User A receive User B's data? For write IDOR: did User B's resource change?",
            ],
            "success_criteria": (
                "For read IDOR: User A's response contains User B's private data "
                "(not just a 200 status or __typename). "
                "For write IDOR: User B's resource state differs between step 1 and step 3."
            ),
        },
        "bola": {
            "steps": [
                "As the victim account, read the target object and record its state.",
                "As the attacker account (different role/tenant), attempt the unauthorized operation on the victim's object.",
                "As the victim account, read the target object again.",
                "Compare: did the attacker's operation actually take effect on the victim's object?",
            ],
            "success_criteria": (
                "The victim's object state changed as a result of the attacker's "
                "operation, proving the authorization check is missing."
            ),
        },
        "xss": {
            "steps": [
                "Load the target page and capture the DOM / page source. Record relevant section.",
                "Submit the XSS payload via the vulnerable input vector.",
                "Load the page where the payload should render. Capture the DOM / page source.",
                "Verify the payload appears in the DOM unescaped and is executable (not inside a comment, attribute, or escaped context).",
            ],
            "success_criteria": (
                "The injected payload is present in the DOM in an executable "
                "context. For stored XSS: the payload persists across page loads. "
                "Use document.title='XSS-FIRED' as proof, NOT alert()."
            ),
        },
        "auth_bypass": {
            "steps": [
                "Attempt to access the protected endpoint WITHOUT any authentication token. Record the response.",
                "Attempt to access the same endpoint WITH a valid authentication token. Record the response.",
                "Compare the two responses. A true auth bypass means the unauthenticated request returns the same (or equivalent) data as the authenticated one.",
            ],
            "success_criteria": (
                "The unauthenticated response contains the same protected data or "
                "functionality as the authenticated response. A mere HTTP 200 is "
                "NOT sufficient -- the response body must contain actual protected data."
            ),
        },
        "csrf": {
            "steps": [
                "As the victim, read the current state of the target resource/setting. Record it.",
                "From a different origin (attacker's site), send a forged request that attempts to change the victim's resource/setting. Do NOT include any CSRF token.",
                "As the victim, read the state of the target resource/setting again.",
                "Compare: did the forged request actually change the victim's state?",
            ],
            "success_criteria": (
                "The victim's resource/setting state changed between step 1 and "
                "step 3, proving the forged cross-origin request was accepted "
                "without a valid CSRF token."
            ),
        },
        "sqli": {
            "steps": [
                "Send a baseline request with normal input. Record the response.",
                "Send the SQL injection payload. Record the response.",
                "Compare: does the injected response contain data that should not be accessible, or does it show database errors that confirm injection?",
                "For blind SQLi: use time-based or boolean-based techniques and compare response times or content differences.",
            ],
            "success_criteria": (
                "The injection payload caused the application to return data from "
                "the database that differs from the baseline, OR caused a "
                "measurable time delay (for blind SQLi), OR returned database "
                "error messages confirming SQL execution."
            ),
        },
        "ssrf": {
            "steps": [
                "Set up an out-of-band callback listener (OAST/Burp Collaborator/webhook).",
                "Send the SSRF payload pointing to your callback listener.",
                "Check the callback listener for incoming requests from the target server.",
                "Verify the request came from the target's infrastructure (check source IP, headers, timing).",
            ],
            "success_criteria": (
                "The callback listener received a request originating from the "
                "target's server infrastructure, proving the server made an "
                "outbound request to the attacker-controlled URL."
            ),
        },
        "privilege_escalation": {
            "steps": [
                "Authenticate as a low-privilege user. Record accessible resources and permissions.",
                "Attempt the privileged action (e.g., admin endpoint, role change, feature toggle).",
                "Verify: did the action succeed? Check by reading the state as the low-privilege user.",
                "Confirm the privilege was actually escalated (e.g., new permissions visible, admin data returned).",
            ],
            "success_criteria": (
                "The low-privilege user successfully performed an action restricted "
                "to higher-privilege roles, AND the effect is visible/persistent."
            ),
        },
    }

    @staticmethod
    def create_verification_plan(vuln_type: str, endpoint: str) -> Dict[str, Any]:
        """Generate a step-by-step verification plan for a vulnerability type.

        Args:
            vuln_type: The vulnerability type (e.g., ``"idor"``, ``"xss"``,
                ``"auth_bypass"``, ``"csrf"``, ``"sqli"``, ``"ssrf"``).
            endpoint: The target endpoint or URL being tested.

        Returns:
            A dict with ``steps`` (list of step descriptions) and
            ``success_criteria`` (string describing what proves the vuln).
        """
        key = vuln_type.lower().strip().replace("-", "_").replace(" ", "_")

        plan = StateChangeVerifier._PLANS.get(key)
        if plan is None:
            return {
                "steps": [
                    f"Read the current state of {endpoint}. Record it.",
                    f"Attempt the exploit against {endpoint}. Record the response.",
                    f"Read the state of {endpoint} again.",
                    "Compare before and after states to verify the exploit had a real effect.",
                ],
                "success_criteria": (
                    f"The state of {endpoint} changed as a direct result of the "
                    "exploit attempt, proving the vulnerability is real."
                ),
            }

        # Inject endpoint into step descriptions for context
        steps = [
            step.replace("the target", f"the target ({endpoint})")
            if "the target" in step
            else step
            for step in plan["steps"]
        ]

        return {
            "steps": steps,
            "success_criteria": plan["success_criteria"],
        }

    @staticmethod
    def verify_state_change(
        before_state: Any,
        after_state: Any,
        vuln_type: str,
    ) -> Dict[str, Any]:
        """Compare before and after states to verify a real state change.

        Args:
            before_state: The recorded state before the exploit attempt.
                Can be a string, dict, list, or any serializable type.
            after_state: The recorded state after the exploit attempt.
            vuln_type: The vulnerability type for context-specific checks.

        Returns:
            A dict with ``verified`` (bool), ``evidence`` (str describing what
            changed), and ``explanation`` (str).
        """
        # Normalize to strings for comparison if needed
        before_str = (
            json.dumps(before_state, sort_keys=True, default=str)
            if not isinstance(before_state, str)
            else before_state
        )
        after_str = (
            json.dumps(after_state, sort_keys=True, default=str)
            if not isinstance(after_state, str)
            else after_state
        )

        # Identical states -- nothing changed
        if before_str == after_str:
            return {
                "verified": False,
                "evidence": "No change detected.",
                "explanation": (
                    "Before and after states are identical. The exploit attempt "
                    "did NOT cause any observable state change. This is likely a "
                    "false positive."
                ),
            }

        # States differ -- analyse the difference
        vtype = vuln_type.lower().strip().replace("-", "_").replace(" ", "_")

        # For dict-like states, try to identify what specifically changed
        changes: List[str] = []
        if isinstance(before_state, dict) and isinstance(after_state, dict):
            all_keys = set(before_state.keys()) | set(after_state.keys())
            for key in sorted(all_keys):
                bval = before_state.get(key)
                aval = after_state.get(key)
                if bval != aval:
                    changes.append(
                        f"Field '{key}' changed from {bval!r} to {aval!r}"
                    )

        if changes:
            evidence = "; ".join(changes)
        else:
            # Fallback: show a summary of the text difference
            if len(before_str) < 500 and len(after_str) < 500:
                evidence = f"Before: {before_str}\nAfter: {after_str}"
            else:
                evidence = (
                    f"State changed. Before length: {len(before_str)}, "
                    f"After length: {len(after_str)}. "
                    f"Before preview: {before_str[:200]}... "
                    f"After preview: {after_str[:200]}..."
                )

        # Context-specific sanity checks
        if vtype in ("xss",):
            # For XSS, check that the payload is in the after state
            return {
                "verified": True,
                "evidence": evidence,
                "explanation": (
                    "DOM/page source changed after payload injection. Verify that "
                    "the change represents executable script in the browser context, "
                    "not just reflected text in a safe context (e.g., inside an "
                    "HTML comment or escaped attribute)."
                ),
            }

        if vtype in ("idor", "bola"):
            return {
                "verified": True,
                "evidence": evidence,
                "explanation": (
                    "Resource state changed between before and after readings. "
                    "This indicates the unauthorized operation had a real effect. "
                    "Confirm that the change was caused by YOUR request and not "
                    "by a concurrent legitimate operation."
                ),
            }

        return {
            "verified": True,
            "evidence": evidence,
            "explanation": (
                f"State change detected for {vuln_type} vulnerability. "
                "The before and after states differ, indicating the exploit "
                "had a real effect. Include this evidence in the report."
            ),
        }


# ---------------------------------------------------------------------------
# 5. SubmissionGatekeeper
# ---------------------------------------------------------------------------

class SubmissionGatekeeper:
    """The final 'would I actually submit this?' check.

    Applies a strict set of rules to decide whether a finding should be
    submitted to a bug bounty program, held for more evidence, or rejected.
    """

    # Severity-based bounty estimates (conservative, broad ranges)
    _BOUNTY_ESTIMATES = {
        "CRITICAL": "$5,000 - $50,000+",
        "HIGH": "$2,000 - $15,000",
        "MEDIUM": "$500 - $5,000",
        "LOW": "$100 - $1,000",
        "INFO": "$0 (not bounty-eligible)",
    }

    @staticmethod
    def evaluate(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate whether a finding should be submitted.

        Args:
            finding: A dict with keys:
                - ``title`` (str): Finding title
                - ``severity`` (str): CRITICAL, HIGH, MEDIUM, LOW, or INFO
                - ``vuln_type`` (str): Vulnerability type
                - ``evidence`` (str): Description of evidence gathered
                - ``target`` (str): Target domain/application
                - ``verified`` (bool): Was it independently confirmed?
                - ``state_change_proven`` (bool): Was a real state change
                  demonstrated?

        Returns:
            A dict with ``submit`` (bool), ``confidence`` (float 0-1),
            ``reasons`` (list of strings), and ``estimated_bounty`` (str).
        """
        title = finding.get("title", "")
        severity = finding.get("severity", "INFO").upper().strip()
        vuln_type = finding.get("vuln_type", "").lower().strip()
        evidence = finding.get("evidence", "")
        target = finding.get("target", "")
        verified = bool(finding.get("verified", False))
        state_change = bool(finding.get("state_change_proven", False))

        reasons: List[str] = []
        confidence = 0.0

        # --- Hard rejects ---

        # Not verified at all
        if not verified:
            reasons.append("REJECT: Finding has not been independently verified.")
            return {
                "submit": False,
                "confidence": 0.0,
                "reasons": reasons,
                "estimated_bounty": "$0",
            }

        # INFO severity -- only report if it's PII, creds, or source code
        if severity == "INFO":
            info_reportable = any(
                kw in vuln_type
                for kw in ("pii", "credential", "source_code", "api_key", "secret", "token")
            )
            if not info_reportable:
                reasons.append(
                    "REJECT: INFO severity findings are not bounty-eligible "
                    "unless they involve PII, credentials, or source code."
                )
                return {
                    "submit": False,
                    "confidence": 0.0,
                    "reasons": reasons,
                    "estimated_bounty": "$0",
                }

        # Evidence is only error codes or status codes
        if evidence and SubmissionGatekeeper._is_only_error_codes(evidence):
            reasons.append(
                "REJECT: Evidence consists only of error codes / HTTP status "
                "codes. This does not demonstrate actual data access or state "
                "change."
            )
            return {
                "submit": False,
                "confidence": 0.1,
                "reasons": reasons,
                "estimated_bounty": "$0",
            }

        # --- Scoring ---

        # Verified baseline
        confidence += 0.3
        reasons.append("PASS: Finding has been independently verified.")

        # State change proven
        if state_change:
            confidence += 0.35
            reasons.append("PASS: Real state change has been demonstrated.")
        else:
            reasons.append(
                "CONCERN: No state change proven. Finding may be a false positive."
            )

        # Severity-based bonus
        severity_bonus = {
            "CRITICAL": 0.2,
            "HIGH": 0.15,
            "MEDIUM": 0.1,
            "LOW": 0.05,
            "INFO": 0.0,
        }
        confidence += severity_bonus.get(severity, 0.0)

        # Evidence quality bonus
        if evidence and len(evidence) > 100:
            confidence += 0.05
            reasons.append("PASS: Detailed evidence provided.")

        # Cap at 1.0
        confidence = min(confidence, 1.0)

        # --- Decision ---

        estimated_bounty = SubmissionGatekeeper._BOUNTY_ESTIMATES.get(
            severity, "$0"
        )

        # Strong submit: verified + state change + high severity
        if verified and state_change and severity in ("CRITICAL", "HIGH"):
            reasons.append(
                f"SUBMIT: Verified {severity} finding with proven state change. "
                "High confidence."
            )
            return {
                "submit": True,
                "confidence": confidence,
                "reasons": reasons,
                "estimated_bounty": estimated_bounty,
            }

        # Medium severity with state change -- submit with moderate confidence
        if verified and state_change and severity == "MEDIUM":
            reasons.append(
                "SUBMIT: Verified MEDIUM finding with proven state change."
            )
            return {
                "submit": True,
                "confidence": confidence,
                "reasons": reasons,
                "estimated_bounty": estimated_bounty,
            }

        # Verified but no state change -- hold
        if verified and not state_change:
            reasons.append(
                "HOLD: Finding is verified but no state change proven. "
                "Gather more evidence before submitting."
            )
            return {
                "submit": False,
                "confidence": confidence,
                "reasons": reasons,
                "estimated_bounty": estimated_bounty,
            }

        # LOW severity with state change -- submit cautiously
        if verified and state_change and severity == "LOW":
            reasons.append(
                "HOLD: Verified LOW finding with state change. "
                "Bounty may be minimal but still worth reporting."
            )
            return {
                "submit": False,
                "confidence": confidence,
                "reasons": reasons,
                "estimated_bounty": estimated_bounty,
            }

        # Fallback
        reasons.append("HOLD: Does not meet clear submission criteria.")
        return {
            "submit": False,
            "confidence": confidence,
            "reasons": reasons,
            "estimated_bounty": estimated_bounty,
        }

    @staticmethod
    def _is_only_error_codes(evidence: str) -> bool:
        """Return True if the evidence string contains only HTTP status codes,
        error code references, and no substantive data."""
        # Strip whitespace and common filler words
        cleaned = re.sub(
            r'(?i)\b(http|status|code|error|response|returned|got|received)\b',
            '',
            evidence,
        )
        cleaned = re.sub(r'[:\-,.\s]+', ' ', cleaned).strip()

        # If what remains is just numbers (status codes), it's empty evidence
        tokens = cleaned.split()
        if not tokens:
            return True

        numeric_count = sum(1 for t in tokens if re.match(r'^\d{3}$', t))
        return numeric_count >= len(tokens) * 0.8


# ---------------------------------------------------------------------------
# 6. ConfidenceScorer
# ---------------------------------------------------------------------------

class ConfidenceScorer:
    """Computes an overall confidence score for a finding based on weighted
    factors.

    Each factor is scored 0.0 to 1.0 and combined with fixed weights to
    produce a final score and letter grade.
    """

    # Factor weights -- must sum to 1.0
    _WEIGHTS: Dict[str, float] = {
        "verified_with_curl": 0.30,
        "state_change_proven": 0.25,
        "severity_appropriate": 0.15,
        "not_false_positive_pattern": 0.15,
        "clear_impact": 0.15,
    }

    # Grade thresholds
    _GRADE_THRESHOLDS: List[Tuple[float, str]] = [
        (0.85, "A"),
        (0.70, "B"),
        (0.55, "C"),
        (0.40, "D"),
        (0.00, "F"),
    ]

    @staticmethod
    def score(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Compute the confidence score for a finding.

        The ``finding`` dict should contain the following keys (all optional,
        defaulting to 0.0):

        - ``verified_with_curl`` (float 0-1): Was the finding independently
          confirmed with a raw curl/HTTP request (not just a browser or
          scanner)?
        - ``state_change_proven`` (float 0-1): How conclusively was a real
          state change demonstrated?  1.0 = full before/after proof,
          0.5 = partial, 0.0 = none.
        - ``severity_appropriate`` (float 0-1): Is the claimed severity
          justified by the evidence?  1.0 = perfectly matched,
          0.5 = arguably inflated, 0.0 = wildly inappropriate.
        - ``not_false_positive_pattern`` (float 0-1): Does the finding avoid
          known false positive patterns?  1.0 = clearly not a FP,
          0.5 = ambiguous, 0.0 = matches a known FP pattern.
        - ``clear_impact`` (float 0-1): Is the business impact obvious and
          explainable?  1.0 = impact is crystal clear, 0.0 = no clear impact.

        Returns:
            A dict with ``score`` (float 0-1), ``grade`` (str A-F),
            ``factors`` (dict mapping factor names to their individual scores),
            and ``recommendation`` (str).
        """
        factors: Dict[str, float] = {}
        for factor_name in ConfidenceScorer._WEIGHTS:
            raw = finding.get(factor_name, 0.0)
            # Clamp to [0.0, 1.0]
            factors[factor_name] = max(0.0, min(1.0, float(raw)))

        # Weighted sum
        total = sum(
            factors[name] * weight
            for name, weight in ConfidenceScorer._WEIGHTS.items()
        )
        total = round(total, 4)

        # Determine grade
        grade = "F"
        for threshold, letter in ConfidenceScorer._GRADE_THRESHOLDS:
            if total >= threshold:
                grade = letter
                break

        # Recommendation based on grade
        if grade in ("A", "B"):
            recommendation = (
                f"Grade {grade} ({total:.2f}): This finding meets the quality "
                "bar for submission. Proceed with report generation."
            )
        elif grade == "C":
            recommendation = (
                f"Grade {grade} ({total:.2f}): This finding is borderline. "
                "Consider gathering additional evidence before submitting."
            )
        elif grade == "D":
            recommendation = (
                f"Grade {grade} ({total:.2f}): This finding is weak. "
                "Significant additional verification is needed."
            )
        else:
            recommendation = (
                f"Grade {grade} ({total:.2f}): This finding does not meet "
                "quality standards. Do NOT submit. Re-evaluate whether this "
                "is a real vulnerability."
            )

        return {
            "score": total,
            "grade": grade,
            "factors": factors,
            "recommendation": recommendation,
        }


# ---------------------------------------------------------------------------
# Convenience: run all gates on a single finding
# ---------------------------------------------------------------------------

def run_all_gates(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Run a finding through all quality gates and return a consolidated report.

    This is a convenience function that agents can call as a single
    entry point.  It returns the results from SubmissionGatekeeper and
    ConfidenceScorer together.

    Args:
        finding: A dict containing at minimum the keys expected by
            ``SubmissionGatekeeper.evaluate()`` and ``ConfidenceScorer.score()``.

    Returns:
        A dict with ``gatekeeper`` (SubmissionGatekeeper result),
        ``confidence`` (ConfidenceScorer result), and ``final_verdict``
        (str: SUBMIT, HOLD, or REJECT).
    """
    gate_result = SubmissionGatekeeper.evaluate(finding)
    confidence_result = ConfidenceScorer.score(finding)

    if gate_result["submit"] and confidence_result["grade"] in ("A", "B", "C"):
        verdict = "SUBMIT"
    elif gate_result["submit"] or confidence_result["grade"] in ("A", "B", "C"):
        verdict = "HOLD"
    else:
        verdict = "REJECT"

    return {
        "gatekeeper": gate_result,
        "confidence": confidence_result,
        "final_verdict": verdict,
    }
