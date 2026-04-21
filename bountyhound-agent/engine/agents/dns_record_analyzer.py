"""
DNS Record Analyzer Agent

Focused DNS record security analyzer that identifies misconfigurations in:
- SPF (Sender Policy Framework) records
- DMARC (Domain-based Message Authentication, Reporting & Conformance) records
- DKIM (DomainKeys Identified Mail) selectors
- CAA (Certification Authority Authorization) records
- MX (Mail Exchanger) records

This agent provides deep analysis of email and DNS security posture.

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import base64
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from enum import Enum


try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DNSRecordSeverity(Enum):
    """DNS record vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DNSRecordVulnType(Enum):
    """Types of DNS record vulnerabilities."""
    SPF_PERMISSIVE = "SPF_PERMISSIVE"
    SPF_MISSING = "SPF_MISSING"
    SPF_SOFTFAIL = "SPF_SOFTFAIL"
    SPF_NEUTRAL = "SPF_NEUTRAL"
    SPF_TOO_MANY_LOOKUPS = "SPF_TOO_MANY_LOOKUPS"
    DMARC_MISSING = "DMARC_MISSING"
    DMARC_POLICY_NONE = "DMARC_POLICY_NONE"
    DMARC_POLICY_QUARANTINE = "DMARC_POLICY_QUARANTINE"
    DMARC_PARTIAL_ENFORCEMENT = "DMARC_PARTIAL_ENFORCEMENT"
    DKIM_MISSING = "DKIM_MISSING"
    DKIM_WEAK_KEY = "DKIM_WEAK_KEY"
    CAA_MISSING = "CAA_MISSING"
    CAA_WILDCARD = "CAA_WILDCARD"
    MX_MISSING = "MX_MISSING"
    MX_UNREACHABLE = "MX_UNREACHABLE"


@dataclass
class DNSRecordFinding:
    """Represents a DNS record security finding."""
    title: str
    severity: DNSRecordSeverity
    vuln_type: DNSRecordVulnType
    description: str
    domain: str
    record_type: str  # SPF, DMARC, DKIM, CAA, MX
    record_value: Optional[str] = None
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
class SPFAnalysis:
    """SPF record analysis result."""
    domain: str
    record: Optional[str]
    exists: bool
    mechanisms: List[str] = field(default_factory=list)
    qualifiers: Dict[str, str] = field(default_factory=dict)
    includes: List[str] = field(default_factory=list)
    all_qualifier: Optional[str] = None  # +, -, ~, ?
    lookup_count: int = 0
    issues: List[str] = field(default_factory=list)
    severity: DNSRecordSeverity = DNSRecordSeverity.INFO


@dataclass
class DMARCAnalysis:
    """DMARC record analysis result."""
    domain: str
    record: Optional[str]
    exists: bool
    policy: str = "none"  # none, quarantine, reject
    subdomain_policy: Optional[str] = None
    percentage: int = 100
    alignment_spf: str = "r"  # r=relaxed, s=strict
    alignment_dkim: str = "r"
    aggregate_reports: Optional[str] = None
    forensic_reports: Optional[str] = None
    issues: List[str] = field(default_factory=list)
    severity: DNSRecordSeverity = DNSRecordSeverity.INFO


@dataclass
class DKIMAnalysis:
    """DKIM selector analysis result."""
    domain: str
    selectors_found: List[str] = field(default_factory=list)
    selectors_tested: int = 0
    key_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    issues: List[str] = field(default_factory=list)
    severity: DNSRecordSeverity = DNSRecordSeverity.INFO


@dataclass
class CAAAnalysis:
    """CAA record analysis result."""
    domain: str
    records: List[str] = field(default_factory=list)
    exists: bool = False
    issuers: List[str] = field(default_factory=list)
    wildcard_allowed: bool = False
    issue_wild: List[str] = field(default_factory=list)
    iodef: Optional[str] = None
    issues: List[str] = field(default_factory=list)
    severity: DNSRecordSeverity = DNSRecordSeverity.INFO


@dataclass
class MXAnalysis:
    """MX record analysis result."""
    domain: str
    records: List[Tuple[int, str]] = field(default_factory=list)
    exists: bool = False
    providers: List[str] = field(default_factory=list)
    unreachable_hosts: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    severity: DNSRecordSeverity = DNSRecordSeverity.INFO


class DNSRecordAnalyzer:
    """
    DNS Record Security Analyzer.

    Performs comprehensive analysis of DNS records for security misconfigurations:
    - SPF record analysis (permissive policies, lookup limits)
    - DMARC policy validation (enforcement levels, alignment)
    - DKIM selector enumeration (key strength, common selectors)
    - CAA record validation (certificate authority controls)
    - MX record enumeration (mail server configuration)

    Usage:
        analyzer = DNSRecordAnalyzer(domain="example.com")
        findings = analyzer.analyze_all()
    """

    # Common DKIM selectors to test
    COMMON_SELECTORS = [
        'default', 'google', 'k1', 'k2', 's1', 's2',
        'selector1', 'selector2', 'dkim', 'mail', 'email',
        'smtp', 'mx', 'mandrill', 'mailgun', 'sendgrid',
        'amazonses', 'ses', 'postmark', 'sparkpost', 'mailjet',
        'em', 'cm', 'pm', 'mta', 'mx1', 'mx2'
    ]

    # Known email providers
    EMAIL_PROVIDERS = {
        'google.com': 'Google Workspace',
        'googlemail.com': 'Gmail',
        'outlook.com': 'Microsoft 365',
        'office365.com': 'Microsoft 365',
        'protection.outlook.com': 'Microsoft 365',
        'mimecast.com': 'Mimecast',
        'proofpoint.com': 'Proofpoint',
        'barracuda.com': 'Barracuda',
        'messagelabs.com': 'Symantec',
        'mailgun.org': 'Mailgun',
        'sendgrid.net': 'SendGrid',
        'amazonses.com': 'Amazon SES',
        'postmarkapp.com': 'Postmark'
    }

    def __init__(self, domain: str, timeout: int = 10):
        """
        Initialize DNS Record Analyzer.

        Args:
            domain: Target domain to analyze
            timeout: DNS query timeout in seconds
        """
        if not DNS_AVAILABLE:
            raise ImportError("dnspython library is required. Install with: pip install dnspython")

        self.domain = domain.lower().strip()
        self.timeout = timeout

        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

        # Results storage
        self.spf_analysis: Optional[SPFAnalysis] = None
        self.dmarc_analysis: Optional[DMARCAnalysis] = None
        self.dkim_analysis: Optional[DKIMAnalysis] = None
        self.caa_analysis: Optional[CAAAnalysis] = None
        self.mx_analysis: Optional[MXAnalysis] = None
        self.findings: List[DNSRecordFinding] = []

    def analyze_all(self) -> Dict[str, Any]:
        """
        Run all DNS record analyses.

        Returns:
            dict: Complete analysis report with findings
        """
        print(f"[*] Starting DNS record analysis for {self.domain}")

        # Analyze each record type
        self.analyze_spf()
        self.analyze_dmarc()
        self.analyze_dkim()
        self.analyze_caa()
        self.analyze_mx()

        # Generate findings from analyses
        self._generate_findings()

        # Return complete report
        return self.generate_report()

    def analyze_spf(self) -> SPFAnalysis:
        """Analyze SPF record configuration."""
        print(f"[*] Analyzing SPF record for {self.domain}")

        analysis = SPFAnalysis(domain=self.domain, record=None, exists=False)

        try:
            # Query TXT records for SPF
            answers = self.resolver.resolve(self.domain, 'TXT')
            spf_records = [str(rdata).strip('"') for rdata in answers
                          if str(rdata).startswith('v=spf1')]

            if not spf_records:
                analysis.exists = False
                analysis.issues.append("No SPF record found")
                analysis.severity = DNSRecordSeverity.HIGH
                self.spf_analysis = analysis
                return analysis

            # Analyze first SPF record (should only be one)
            spf_record = spf_records[0]
            analysis.record = spf_record
            analysis.exists = True

            # Parse SPF mechanisms
            tokens = spf_record.split()
            for token in tokens[1:]:  # Skip v=spf1
                # Extract qualifier and mechanism
                if token[0] in ['+', '-', '~', '?']:
                    qualifier = token[0]
                    mechanism = token[1:]
                else:
                    qualifier = '+'
                    mechanism = token

                analysis.mechanisms.append(mechanism)
                analysis.qualifiers[mechanism] = qualifier

                # Track includes for lookup count
                if mechanism.startswith('include:'):
                    include_domain = mechanism[8:]
                    analysis.includes.append(include_domain)
                    analysis.lookup_count += 1

                # Check for 'all' mechanism
                if mechanism == 'all':
                    analysis.all_qualifier = qualifier

            # Analyze for issues
            if analysis.all_qualifier == '+':
                analysis.issues.append("SPF uses +all (allows any sender)")
                analysis.severity = DNSRecordSeverity.CRITICAL
            elif analysis.all_qualifier == '~':
                analysis.issues.append("SPF uses ~all (soft fail)")
                analysis.severity = DNSRecordSeverity.HIGH
            elif analysis.all_qualifier == '?':
                analysis.issues.append("SPF uses ?all (neutral)")
                analysis.severity = DNSRecordSeverity.MEDIUM

            # Check lookup count (RFC 7208: max 10 lookups)
            if analysis.lookup_count > 10:
                analysis.issues.append(f"SPF has {analysis.lookup_count} lookups (exceeds RFC limit of 10)")
                if analysis.severity == DNSRecordSeverity.INFO:
                    analysis.severity = DNSRecordSeverity.MEDIUM
            elif analysis.lookup_count > 5:
                analysis.issues.append(f"SPF has {analysis.lookup_count} lookups (approaching limit)")

            # Check for broad IP ranges
            for mechanism in analysis.mechanisms:
                if mechanism.startswith('ip4:') and '/' in mechanism:
                    cidr = mechanism.split('/')[1]
                    if int(cidr) < 16:
                        analysis.issues.append(f"Broad IP4 range: {mechanism}")

            if not analysis.issues:
                analysis.issues.append("SPF record looks secure")

        except dns.resolver.NXDOMAIN:
            analysis.issues.append("Domain does not exist")
            analysis.severity = DNSRecordSeverity.INFO
        except dns.resolver.NoAnswer:
            analysis.exists = False
            analysis.issues.append("No SPF record found")
            analysis.severity = DNSRecordSeverity.HIGH
        except Exception as e:
            analysis.issues.append(f"Error querying SPF: {str(e)}")

        self.spf_analysis = analysis
        return analysis

    def analyze_dmarc(self) -> DMARCAnalysis:
        """Analyze DMARC policy configuration."""
        print(f"[*] Analyzing DMARC record for {self.domain}")

        dmarc_domain = f"_dmarc.{self.domain}"
        analysis = DMARCAnalysis(domain=self.domain, record=None, exists=False)

        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [str(rdata).strip('"') for rdata in answers
                            if str(rdata).startswith('v=DMARC1')]

            if not dmarc_records:
                analysis.exists = False
                analysis.issues.append("No DMARC record found")
                analysis.severity = DNSRecordSeverity.HIGH
                self.dmarc_analysis = analysis
                return analysis

            # Parse DMARC record
            dmarc_record = dmarc_records[0]
            analysis.record = dmarc_record
            analysis.exists = True

            # Parse DMARC tags
            tags = {}
            for tag in dmarc_record.split(';'):
                tag = tag.strip()
                if '=' in tag:
                    key, value = tag.split('=', 1)
                    tags[key.strip()] = value.strip()

            # Extract values
            analysis.policy = tags.get('p', 'none')
            analysis.subdomain_policy = tags.get('sp')
            analysis.percentage = int(tags.get('pct', '100'))
            analysis.alignment_spf = tags.get('aspf', 'r')
            analysis.alignment_dkim = tags.get('adkim', 'r')
            analysis.aggregate_reports = tags.get('rua')
            analysis.forensic_reports = tags.get('ruf')

            # Analyze for issues
            if analysis.policy == 'none':
                analysis.issues.append("DMARC policy is 'none' (monitoring only)")
                analysis.severity = DNSRecordSeverity.HIGH
            elif analysis.policy == 'quarantine':
                analysis.issues.append("DMARC policy is 'quarantine' (moderate protection)")
                analysis.severity = DNSRecordSeverity.MEDIUM
            elif analysis.policy == 'reject':
                analysis.issues.append("DMARC policy is 'reject' (strong protection)")
                analysis.severity = DNSRecordSeverity.INFO

            if not analysis.subdomain_policy:
                analysis.issues.append("No subdomain policy (sp=) specified")
                if analysis.severity == DNSRecordSeverity.INFO:
                    analysis.severity = DNSRecordSeverity.LOW

            if analysis.percentage < 100:
                analysis.issues.append(f"DMARC applied to {analysis.percentage}% of messages (partial enforcement)")
                if analysis.severity == DNSRecordSeverity.INFO:
                    analysis.severity = DNSRecordSeverity.MEDIUM

            if analysis.alignment_spf == 'r':
                analysis.issues.append("SPF alignment is relaxed (aspf=r)")
            if analysis.alignment_dkim == 'r':
                analysis.issues.append("DKIM alignment is relaxed (adkim=r)")

            if not analysis.aggregate_reports:
                analysis.issues.append("No aggregate reporting address (rua=)")
            if not analysis.forensic_reports:
                analysis.issues.append("No forensic reporting address (ruf=)")

        except dns.resolver.NXDOMAIN:
            analysis.exists = False
            analysis.issues.append("No DMARC record found")
            analysis.severity = DNSRecordSeverity.HIGH
        except Exception as e:
            analysis.issues.append(f"Error querying DMARC: {str(e)}")

        self.dmarc_analysis = analysis
        return analysis

    def analyze_dkim(self) -> DKIMAnalysis:
        """Enumerate and analyze DKIM selectors."""
        print(f"[*] Analyzing DKIM selectors for {self.domain}")

        analysis = DKIMAnalysis(domain=self.domain)

        for selector in self.COMMON_SELECTORS:
            analysis.selectors_tested += 1
            dkim_domain = f"{selector}._domainkey.{self.domain}"

            try:
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    record = str(rdata).strip('"')
                    if 'p=' in record:
                        analysis.selectors_found.append(selector)

                        # Parse DKIM record
                        key_info = self._parse_dkim_record(record)
                        analysis.key_details[selector] = key_info

                        # Check key strength
                        if key_info.get('key_length') and key_info['key_length'] < 1024:
                            issue = f"DKIM selector '{selector}' uses weak key (<1024 bits)"
                            analysis.issues.append(issue)
                            analysis.severity = DNSRecordSeverity.MEDIUM

                        break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                continue

        if not analysis.selectors_found:
            analysis.issues.append(f"No DKIM selectors found (tested {analysis.selectors_tested} common selectors)")
            analysis.severity = DNSRecordSeverity.MEDIUM
        else:
            analysis.issues.append(f"Found DKIM selectors: {', '.join(analysis.selectors_found)}")

        self.dkim_analysis = analysis
        return analysis

    def analyze_caa(self) -> CAAAnalysis:
        """Analyze CAA records."""
        print(f"[*] Analyzing CAA records for {self.domain}")

        analysis = CAAAnalysis(domain=self.domain)

        try:
            answers = self.resolver.resolve(self.domain, 'CAA')
            for rdata in answers:
                record_str = str(rdata)
                analysis.records.append(record_str)
                analysis.exists = True

                # Parse CAA record format: flags tag value
                parts = record_str.split(None, 2)
                if len(parts) >= 3:
                    tag = parts[1]
                    value = parts[2].strip('"')

                    if tag == 'issue':
                        analysis.issuers.append(value)
                    elif tag == 'issuewild':
                        analysis.issue_wild.append(value)
                        analysis.wildcard_allowed = True
                    elif tag == 'iodef':
                        analysis.iodef = value

            if not analysis.exists:
                analysis.issues.append("No CAA records found (any CA can issue certificates)")
                analysis.severity = DNSRecordSeverity.LOW
            else:
                if not analysis.issuers:
                    analysis.issues.append("CAA records exist but no 'issue' tag")
                else:
                    analysis.issues.append(f"Authorized CAs: {', '.join(analysis.issuers)}")

                if analysis.wildcard_allowed:
                    analysis.issues.append(f"Wildcard certificates allowed: {', '.join(analysis.issue_wild)}")

        except dns.resolver.NoAnswer:
            analysis.issues.append("No CAA records found")
            analysis.severity = DNSRecordSeverity.LOW
        except Exception as e:
            analysis.issues.append(f"Error querying CAA: {str(e)}")

        self.caa_analysis = analysis
        return analysis

    def analyze_mx(self) -> MXAnalysis:
        """Analyze MX records."""
        print(f"[*] Analyzing MX records for {self.domain}")

        analysis = MXAnalysis(domain=self.domain)

        try:
            answers = self.resolver.resolve(self.domain, 'MX')
            for rdata in answers:
                priority = rdata.preference
                hostname = str(rdata.exchange).rstrip('.')
                analysis.records.append((priority, hostname))
                analysis.exists = True

                # Identify email provider
                for provider_domain, provider_name in self.EMAIL_PROVIDERS.items():
                    if provider_domain in hostname:
                        if provider_name not in analysis.providers:
                            analysis.providers.append(provider_name)
                        break

                # Check if MX host is reachable
                try:
                    self.resolver.resolve(hostname, 'A')
                except dns.resolver.NXDOMAIN:
                    analysis.unreachable_hosts.append(hostname)
                    analysis.issues.append(f"MX host '{hostname}' does not resolve (potential takeover)")
                    analysis.severity = DNSRecordSeverity.CRITICAL
                except Exception:
                    pass

            # Sort by priority
            analysis.records.sort(key=lambda x: x[0])

            if analysis.exists:
                if analysis.providers:
                    analysis.issues.append(f"Email provider(s): {', '.join(analysis.providers)}")
                else:
                    analysis.issues.append("Using custom mail servers")

                if len(analysis.records) == 1:
                    analysis.issues.append("Single MX record (no failover)")
                    if analysis.severity == DNSRecordSeverity.INFO:
                        analysis.severity = DNSRecordSeverity.LOW
            else:
                analysis.issues.append("No MX records found")
                analysis.severity = DNSRecordSeverity.MEDIUM

        except dns.resolver.NoAnswer:
            analysis.issues.append("No MX records found")
            analysis.severity = DNSRecordSeverity.MEDIUM
        except Exception as e:
            analysis.issues.append(f"Error querying MX: {str(e)}")

        self.mx_analysis = analysis
        return analysis

    def _parse_dkim_record(self, record: str) -> Dict[str, Any]:
        """Parse DKIM TXT record."""
        result = {}

        # Extract public key
        match = re.search(r'p=([A-Za-z0-9+/=]+)', record)
        if match:
            pubkey_b64 = match.group(1)
            result['public_key_b64'] = pubkey_b64

            # Estimate key length
            try:
                pubkey = base64.b64decode(pubkey_b64)
                result['key_length'] = len(pubkey) * 8
            except Exception:
                result['key_length'] = None

        # Extract other tags
        result['version'] = re.search(r'v=([^;]+)', record)
        result['key_type'] = re.search(r'k=([^;]+)', record)
        result['hash_algorithms'] = re.search(r'h=([^;]+)', record)
        result['service_type'] = re.search(r's=([^;]+)', record)

        return result

    def _generate_findings(self):
        """Generate security findings from analyses."""
        # SPF findings
        if self.spf_analysis:
            if not self.spf_analysis.exists:
                finding = DNSRecordFinding(
                    title="Missing SPF Record",
                    severity=DNSRecordSeverity.HIGH,
                    vuln_type=DNSRecordVulnType.SPF_MISSING,
                    description=f"Domain {self.domain} has no SPF record configured",
                    domain=self.domain,
                    record_type="SPF",
                    impact="Email spoofing is easier without SPF records. Attackers can send emails appearing to come from this domain.",
                    recommendation="Implement SPF record with strict policy (-all). Example: v=spf1 include:_spf.google.com -all",
                    cwe_id="CWE-346"
                )
                self.findings.append(finding)
            elif self.spf_analysis.all_qualifier == '+':
                finding = DNSRecordFinding(
                    title="Permissive SPF Record (+all)",
                    severity=DNSRecordSeverity.CRITICAL,
                    vuln_type=DNSRecordVulnType.SPF_PERMISSIVE,
                    description=f"SPF record allows any server to send email for {self.domain}",
                    domain=self.domain,
                    record_type="SPF",
                    record_value=self.spf_analysis.record,
                    impact="Any server on the internet can send email claiming to be from this domain.",
                    recommendation="Change +all to -all in SPF record",
                    cwe_id="CWE-346"
                )
                self.findings.append(finding)
            elif self.spf_analysis.all_qualifier == '~':
                finding = DNSRecordFinding(
                    title="Weak SPF Record (~all soft fail)",
                    severity=DNSRecordSeverity.HIGH,
                    vuln_type=DNSRecordVulnType.SPF_SOFTFAIL,
                    description=f"SPF record uses soft fail, which only suggests rejection",
                    domain=self.domain,
                    record_type="SPF",
                    record_value=self.spf_analysis.record,
                    impact="Email spoofing is possible. Many receivers may still accept unauthorized emails.",
                    recommendation="Change ~all to -all for strict SPF enforcement",
                    cwe_id="CWE-346"
                )
                self.findings.append(finding)

            if self.spf_analysis.lookup_count > 10:
                finding = DNSRecordFinding(
                    title="SPF Exceeds DNS Lookup Limit",
                    severity=DNSRecordSeverity.MEDIUM,
                    vuln_type=DNSRecordVulnType.SPF_TOO_MANY_LOOKUPS,
                    description=f"SPF record requires {self.spf_analysis.lookup_count} DNS lookups (RFC limit: 10)",
                    domain=self.domain,
                    record_type="SPF",
                    record_value=self.spf_analysis.record,
                    impact="SPF validation may fail, causing legitimate emails to be rejected or SPF to be ignored.",
                    recommendation="Reduce number of include: statements or flatten SPF record",
                    cwe_id="CWE-16"
                )
                self.findings.append(finding)

        # DMARC findings
        if self.dmarc_analysis:
            if not self.dmarc_analysis.exists:
                finding = DNSRecordFinding(
                    title="Missing DMARC Record",
                    severity=DNSRecordSeverity.HIGH,
                    vuln_type=DNSRecordVulnType.DMARC_MISSING,
                    description=f"Domain {self.domain} has no DMARC policy configured",
                    domain=self.domain,
                    record_type="DMARC",
                    impact="No enforcement of SPF/DKIM failures. Email spoofing attacks are easier.",
                    recommendation="Implement DMARC policy starting with p=none for monitoring, then p=quarantine or p=reject",
                    cwe_id="CWE-346"
                )
                self.findings.append(finding)
            elif self.dmarc_analysis.policy == 'none':
                finding = DNSRecordFinding(
                    title="DMARC Policy Set to 'none'",
                    severity=DNSRecordSeverity.HIGH,
                    vuln_type=DNSRecordVulnType.DMARC_POLICY_NONE,
                    description=f"DMARC policy is monitoring-only (p=none)",
                    domain=self.domain,
                    record_type="DMARC",
                    record_value=self.dmarc_analysis.record,
                    impact="Failed authentication results in no action. Email spoofing is possible.",
                    recommendation="Upgrade to p=quarantine or p=reject after monitoring period",
                    cwe_id="CWE-346"
                )
                self.findings.append(finding)
            elif self.dmarc_analysis.policy == 'quarantine':
                finding = DNSRecordFinding(
                    title="DMARC Policy Set to 'quarantine'",
                    severity=DNSRecordSeverity.MEDIUM,
                    vuln_type=DNSRecordVulnType.DMARC_POLICY_QUARANTINE,
                    description=f"DMARC policy quarantines failed emails (p=quarantine)",
                    domain=self.domain,
                    record_type="DMARC",
                    record_value=self.dmarc_analysis.record,
                    impact="Moderate protection. Some spoofed emails may reach spam folders.",
                    recommendation="Consider upgrading to p=reject for maximum protection",
                    cwe_id="CWE-346"
                )
                self.findings.append(finding)

            if self.dmarc_analysis.percentage < 100:
                finding = DNSRecordFinding(
                    title="DMARC Partial Enforcement",
                    severity=DNSRecordSeverity.MEDIUM,
                    vuln_type=DNSRecordVulnType.DMARC_PARTIAL_ENFORCEMENT,
                    description=f"DMARC policy applies to only {self.dmarc_analysis.percentage}% of messages",
                    domain=self.domain,
                    record_type="DMARC",
                    record_value=self.dmarc_analysis.record,
                    impact=f"{100 - self.dmarc_analysis.percentage}% of spoofed emails may bypass DMARC",
                    recommendation="Set pct=100 for full enforcement",
                    cwe_id="CWE-346"
                )
                self.findings.append(finding)

        # DKIM findings
        if self.dkim_analysis:
            if not self.dkim_analysis.selectors_found:
                finding = DNSRecordFinding(
                    title="No DKIM Selectors Found",
                    severity=DNSRecordSeverity.MEDIUM,
                    vuln_type=DNSRecordVulnType.DKIM_MISSING,
                    description=f"No DKIM selectors found for {self.domain} (tested {self.dkim_analysis.selectors_tested} common selectors)",
                    domain=self.domain,
                    record_type="DKIM",
                    impact="Email authentication relies only on SPF. DKIM provides additional protection.",
                    recommendation="Configure DKIM signing for outbound email",
                    cwe_id="CWE-346"
                )
                self.findings.append(finding)

            for selector, key_info in self.dkim_analysis.key_details.items():
                if key_info.get('key_length') and key_info['key_length'] < 1024:
                    finding = DNSRecordFinding(
                        title=f"Weak DKIM Key for selector '{selector}'",
                        severity=DNSRecordSeverity.MEDIUM,
                        vuln_type=DNSRecordVulnType.DKIM_WEAK_KEY,
                        description=f"DKIM key length is {key_info['key_length']} bits (below 1024-bit minimum)",
                        domain=self.domain,
                        record_type="DKIM",
                        impact="Weak DKIM keys are vulnerable to cryptographic attacks.",
                        recommendation="Upgrade to at least 1024-bit RSA key, preferably 2048-bit",
                        cwe_id="CWE-326",
                        metadata={'selector': selector, 'key_length': key_info['key_length']}
                    )
                    self.findings.append(finding)

        # CAA findings
        if self.caa_analysis and not self.caa_analysis.exists:
            finding = DNSRecordFinding(
                title="No CAA Records",
                severity=DNSRecordSeverity.LOW,
                vuln_type=DNSRecordVulnType.CAA_MISSING,
                description=f"No CAA records found for {self.domain}",
                domain=self.domain,
                record_type="CAA",
                impact="Any Certificate Authority can issue certificates for this domain.",
                recommendation="Add CAA records to restrict which CAs can issue certificates",
                cwe_id="CWE-295"
            )
            self.findings.append(finding)

        # MX findings
        if self.mx_analysis:
            if self.mx_analysis.unreachable_hosts:
                for host in self.mx_analysis.unreachable_hosts:
                    finding = DNSRecordFinding(
                        title=f"MX Host Unreachable: {host}",
                        severity=DNSRecordSeverity.CRITICAL,
                        vuln_type=DNSRecordVulnType.MX_UNREACHABLE,
                        description=f"MX record points to {host} which does not resolve",
                        domain=self.domain,
                        record_type="MX",
                        impact="Potential subdomain takeover. Attacker could claim the hostname and intercept emails.",
                        recommendation=f"Remove MX record for {host} or reclaim the hostname",
                        cwe_id="CWE-350",
                        metadata={'mx_host': host}
                    )
                    self.findings.append(finding)

            if not self.mx_analysis.exists:
                finding = DNSRecordFinding(
                    title="No MX Records",
                    severity=DNSRecordSeverity.MEDIUM,
                    vuln_type=DNSRecordVulnType.MX_MISSING,
                    description=f"No MX records found for {self.domain}",
                    domain=self.domain,
                    record_type="MX",
                    impact="Domain cannot receive email via standard MX lookup.",
                    recommendation="Configure MX records if email reception is needed",
                    cwe_id="CWE-16"
                )
                self.findings.append(finding)

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive DNS record analysis report."""
        report = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(self.findings),
                'critical': sum(1 for f in self.findings if f.severity == DNSRecordSeverity.CRITICAL),
                'high': sum(1 for f in self.findings if f.severity == DNSRecordSeverity.HIGH),
                'medium': sum(1 for f in self.findings if f.severity == DNSRecordSeverity.MEDIUM),
                'low': sum(1 for f in self.findings if f.severity == DNSRecordSeverity.LOW),
                'info': sum(1 for f in self.findings if f.severity == DNSRecordSeverity.INFO)
            },
            'analyses': {
                'spf': asdict(self.spf_analysis) if self.spf_analysis else None,
                'dmarc': asdict(self.dmarc_analysis) if self.dmarc_analysis else None,
                'dkim': asdict(self.dkim_analysis) if self.dkim_analysis else None,
                'caa': asdict(self.caa_analysis) if self.caa_analysis else None,
                'mx': asdict(self.mx_analysis) if self.mx_analysis else None
            },
            'findings': [f.to_dict() for f in self.findings],
            'recommendations': self._generate_recommendations()
        }

        return report

    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Critical issues first
        if any(f.severity == DNSRecordSeverity.CRITICAL for f in self.findings):
            recommendations.append("URGENT: Fix critical DNS security issues immediately")

        # SPF recommendations
        if self.spf_analysis:
            if not self.spf_analysis.exists:
                recommendations.append("Implement SPF record with strict policy (-all)")
            elif self.spf_analysis.all_qualifier in ['+', '~']:
                recommendations.append("Strengthen SPF policy to use -all")

        # DMARC recommendations
        if self.dmarc_analysis:
            if not self.dmarc_analysis.exists:
                recommendations.append("Implement DMARC policy (start with p=none for monitoring)")
            elif self.dmarc_analysis.policy == 'none':
                recommendations.append("Upgrade DMARC policy to p=quarantine or p=reject")

        # DKIM recommendations
        if self.dkim_analysis and not self.dkim_analysis.selectors_found:
            recommendations.append("Configure DKIM signing for outbound email")

        # CAA recommendations
        if self.caa_analysis and not self.caa_analysis.exists:
            recommendations.append("Add CAA records to restrict certificate issuance")

        # MX recommendations
        if self.mx_analysis and self.mx_analysis.unreachable_hosts:
            recommendations.append("Fix or remove unreachable MX records to prevent subdomain takeover")

        return recommendations


def main():
    """CLI entry point for DNS record analyzer."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dns_record_analyzer.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    print(f"DNS Record Analyzer v1.0.0")
    print(f"=" * 80)

    analyzer = DNSRecordAnalyzer(domain=domain)
    report = analyzer.analyze_all()

    print(f"\n{'=' * 80}")
    print(f"DNS RECORD ANALYSIS REPORT")
    print(f"{'=' * 80}")
    print(f"Domain: {report['domain']}")
    print(f"Timestamp: {report['timestamp']}")

    print(f"\nSummary:")
    print(f"  Total Findings: {report['summary']['total_findings']}")
    print(f"  Critical: {report['summary']['critical']}")
    print(f"  High: {report['summary']['high']}")
    print(f"  Medium: {report['summary']['medium']}")
    print(f"  Low: {report['summary']['low']}")

    print(f"\nRecommendations:")
    for rec in report['recommendations']:
        print(f"  - {rec}")

    # Save detailed report
    import json
    filename = f"{domain.replace('.', '_')}_dns_records.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\nDetailed report saved to {filename}")


if __name__ == '__main__':
    main()
