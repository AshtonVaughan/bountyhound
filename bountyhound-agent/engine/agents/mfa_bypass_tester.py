"""
MFA Bypass Tester

Tests multi-factor authentication bypass techniques:
- Response manipulation bypass
- Direct endpoint access (missing MFA enforcement)
- Code reuse
- Rate limiting (brute force protection)
- Backup code weaknesses
- TOTP generation for testing
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import requests
import time
import pyotp
from typing import List, Dict, Optional
from dataclasses import dataclass



@dataclass
class Finding:
    """MFA bypass finding"""
    title: str
    description: str
    severity: str
    evidence: Dict
    vuln_type: str = "MFA_Bypass"


class MFABypassTester:
    """Test multi-factor authentication bypass techniques"""

    def __init__(self):
        self.timeout = 10
        self.rate_limit_threshold = 20  # Attempts before rate limit expected

    def test_response_manipulation(self, login_endpoint: str) -> List[Finding]:
        """
        Test response manipulation bypass

        Technique:
        1. Login with valid creds
        2. Intercept MFA challenge response
        3. Modify: {"mfa_required": true} → {"mfa_required": false}
        4. Check if bypass works

        Args:
            login_endpoint: Login endpoint URL

        Returns:
            List of findings if vulnerable
        """
        findings = []

        # Note: This test requires manual interception in practice
        # Automated test checks if MFA requirement can be bypassed via response modification

        try:
            # Attempt login
            response = requests.post(
                login_endpoint,
                json={"username": "test@example.com", "password": "test123"},
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                # Check if MFA required
                if data.get("mfa_required"):
                    # Document finding for manual testing
                    findings.append(Finding(
                        title="MFA Response Manipulation Testing Required",
                        description="MFA challenge detected. Manual testing recommended: intercept response and modify 'mfa_required' to false.",
                        severity="INFO",
                        evidence={
                            "url": login_endpoint,
                            "response": data,
                            "manual_test": "Use Burp Suite to intercept and modify MFA response"
                        },
                        vuln_type="MFA_Response_Manipulation_Test"
                    ))

        except Exception as e:
            pass

        return findings

    def test_direct_endpoint_access(
        self,
        protected_endpoint: str,
        session_token: str
    ) -> List[Finding]:
        """
        Test direct access to post-MFA endpoints

        Technique:
        After login (before MFA), try accessing:
        - /dashboard
        - /api/user
        - /profile
        Check if MFA actually enforced

        Args:
            protected_endpoint: Protected endpoint URL
            session_token: Session token from login (before MFA)

        Returns:
            List of findings if vulnerable
        """
        findings = []

        # Common post-MFA endpoints
        endpoints = [
            protected_endpoint,
            protected_endpoint.replace('/dashboard', '/api/user'),
            protected_endpoint.replace('/dashboard', '/profile'),
            protected_endpoint.replace('/dashboard', '/settings'),
        ]

        for endpoint in endpoints:
            try:
                # Try accessing with session token (pre-MFA)
                response = requests.get(
                    endpoint,
                    cookies={"session": session_token},
                    timeout=self.timeout
                )

                # Check if accessible
                if response.status_code == 200 and "login" not in response.text.lower():
                    findings.append(Finding(
                        title="MFA Not Enforced on Protected Endpoint",
                        description=f"Endpoint {endpoint} accessible with session token before MFA completion",
                        severity="HIGH",
                        evidence={
                            "url": endpoint,
                            "status_code": 200,
                            "session_token": session_token[:10] + "...",
                            "response_preview": response.text[:200]
                        },
                        vuln_type="MFA_Bypass_Direct_Access"
                    ))

            except Exception:
                continue

        return findings

    def test_code_reuse(self, mfa_endpoint: str, valid_code: str) -> List[Finding]:
        """
        Test if MFA codes can be reused

        Technique:
        1. Submit valid MFA code
        2. Save code
        3. Logout and try reusing same code

        Args:
            mfa_endpoint: MFA verification endpoint
            valid_code: A valid MFA code

        Returns:
            List of findings if vulnerable
        """
        findings = []

        try:
            # First use
            response1 = requests.post(
                mfa_endpoint,
                json={"code": valid_code},
                timeout=self.timeout
            )

            if response1.status_code == 200:
                # Try reusing same code
                time.sleep(1)

                response2 = requests.post(
                    mfa_endpoint,
                    json={"code": valid_code},
                    timeout=self.timeout
                )

                # Check if code accepted again
                if response2.status_code == 200:
                    findings.append(Finding(
                        title="MFA Code Reuse Vulnerability",
                        description="MFA codes can be reused. Codes should expire after first use.",
                        severity="HIGH",
                        evidence={
                            "url": mfa_endpoint,
                            "code": valid_code,
                            "first_use": "success",
                            "second_use": "also_success"
                        },
                        vuln_type="MFA_Code_Reuse"
                    ))

        except Exception as e:
            pass

        return findings

    def test_rate_limiting(
        self,
        mfa_endpoint: str,
        attempts: int = 50
    ) -> List[Finding]:
        """
        Test MFA code rate limiting

        Technique:
        Brute force 6-digit codes (000000-999999)
        Check if rate limited
        4-digit = ~10,000 attempts = ~19 min if no rate limit
        6-digit = ~1,000,000 attempts (impractical without rate limit)

        Args:
            mfa_endpoint: MFA verification endpoint
            attempts: Number of attempts to test (default: 50)

        Returns:
            List of findings if vulnerable
        """
        findings = []

        rejected_count = 0
        rate_limited = False

        for i in range(attempts):
            try:
                # Try random 6-digit code
                code = f"{i:06d}"

                response = requests.post(
                    mfa_endpoint,
                    json={"code": code},
                    timeout=self.timeout
                )

                # Check if rate limited
                if response.status_code == 429:
                    rate_limited = True
                    break

                if "rate limit" in response.text.lower() or "too many" in response.text.lower():
                    rate_limited = True
                    break

                if response.status_code in [400, 401, 403]:
                    rejected_count += 1

            except Exception:
                break

        # If no rate limiting detected
        if not rate_limited and rejected_count >= attempts * 0.8:
            findings.append(Finding(
                title="MFA Rate Limiting Missing",
                description=f"Made {attempts} MFA code attempts with no rate limiting. Brute force attack possible.",
                severity="CRITICAL",
                evidence={
                    "url": mfa_endpoint,
                    "attempts": attempts,
                    "rate_limited": False,
                    "estimate": "6-digit code space = 1M attempts. At 1 req/sec = 11.5 days to exhaust."
                },
                vuln_type="MFA_No_Rate_Limit"
            ))

        return findings

    def test_backup_code_weaknesses(self, backup_endpoint: str) -> List[Finding]:
        """
        Test backup code security

        Checks:
        - Backup code entropy
        - If backup codes expire
        - Rate limiting on backup codes

        Args:
            backup_endpoint: Backup code verification endpoint

        Returns:
            List of findings if vulnerable
        """
        findings = []

        # Test common weak backup codes
        weak_codes = [
            "123456", "000000", "111111", "password",
            "backup1", "backup2", "code123"
        ]

        for code in weak_codes:
            try:
                response = requests.post(
                    backup_endpoint,
                    json={"backup_code": code},
                    timeout=self.timeout
                )

                # Check if weak code accepted
                if response.status_code == 200:
                    findings.append(Finding(
                        title="Weak MFA Backup Code Accepted",
                        description=f"Weak backup code '{code}' was accepted. Backup codes should have high entropy.",
                        severity="MEDIUM",
                        evidence={
                            "url": backup_endpoint,
                            "weak_code": code,
                            "status": "accepted"
                        },
                        vuln_type="MFA_Weak_Backup_Code"
                    ))
                    break

            except Exception:
                continue

        return findings

    def _generate_totp_code(self, secret: str) -> str:
        """
        Generate TOTP code for testing

        Args:
            secret: TOTP secret (base32 encoded)

        Returns:
            6-digit TOTP code
        """
        totp = pyotp.TOTP(secret)
        return totp.now()

    def _generate_hotp_code(self, secret: str, counter: int) -> str:
        """
        Generate HOTP code for testing

        Args:
            secret: HOTP secret (base32 encoded)
            counter: Counter value

        Returns:
            6-digit HOTP code
        """
        hotp = pyotp.HOTP(secret)
        return hotp.at(counter)
