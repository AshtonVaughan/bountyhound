#!/usr/bin/env python3
"""
Script to complete the content_security_policy_tester.py implementation.
This script appends the missing code to the partially created file.
"""

# Read the current partial file
with open('engine/agents/content_security_policy_tester.py', 'r', encoding='utf-8') as f:
    current_content = f.read()

# Check if file is already complete
if 'class ContentSecurityPolicyTester' in current_content:
    print("File already appears complete!")
    exit(0)

# Append the complete implementation
additional_code = '''

class CSPSeverity(Enum):
    """CSP vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CSPVulnType(Enum):
    """Types of CSP vulnerabilities."""
    UNSAFE_INLINE = "CSP_UNSAFE_INLINE"
    UNSAFE_EVAL = "CSP_UNSAFE_EVAL"
    MISSING_DIRECTIVE = "CSP_MISSING_DIRECTIVE"
    WEAK_SOURCE = "CSP_WEAK_SOURCE"
    JSONP_BYPASS = "CSP_JSONP_BYPASS"
    BASE_URI_BYPASS = "CSP_BASE_URI_BYPASS"
    STATIC_NONCE = "CSP_STATIC_NONCE"
    WEAK_NONCE = "CSP_WEAK_NONCE"
    WILDCARD_SUBDOMAIN = "CSP_WILDCARD_SUBDOMAIN"
    PROTOCOL_DOWNGRADE = "CSP_PROTOCOL_DOWNGRADE"
    OVERLY_PERMISSIVE = "CSP_OVERLY_PERMISSIVE"


@dataclass
class CSPFinding:
    """Represents a CSP security finding."""
    title: str
    severity: CSPSeverity
    vuln_type: CSPVulnType
    description: str
    endpoint: str
    directive: Optional[str] = None
    source: Optional[str] = None
    csp_raw: Optional[str] = None
    poc: str = ""
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class CSPTestResult:
    """Result from a CSP test."""
    endpoint: str
    has_csp: bool
    csp_header: Optional[str] = None
    csp_meta: Optional[str] = None
    report_only: Optional[str] = None
    directives: Dict[str, List[str]] = field(default_factory=dict)
    is_vulnerable: bool = False
    vulnerability_types: List[CSPVulnType] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary."""
        data = asdict(self)
        data['vulnerability_types'] = [vt.value for vt in self.vulnerability_types]
        return data
'''

print(f"Current file: {len(current_content)} chars, {len(current_content.splitlines())} lines")
print(f"Adding: {len(additional_code)} chars, {len(additional_code.splitlines())} lines")

# This is part 1 - write enums and dataclasses
with open('engine/agents/content_security_policy_tester.py', 'a', encoding='utf-8') as f:
    f.write(additional_code)

print("Part 1 complete: Enums and dataclasses added")
print(f"New size: {len(current_content) + len(additional_code)} chars")
