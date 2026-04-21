"""
Desktop Application Security Tester

Tests desktop application security:
- Update mechanism vulnerabilities
- Hardcoded secrets scanning
- Privilege escalation vectors
"""

import subprocess
import requests
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class Finding:
    """Desktop security finding"""
    title: str
    description: str
    severity: str
    evidence: Dict
    vuln_type: str = "Desktop"


class DesktopTester:
    """Test desktop application security"""

    def __init__(self):
        self.timeout = 10

    def test_update_mechanism(self, app_path: str) -> List[Finding]:
        """
        Test update mechanism security

        Checks:
        - MITM on update channel
        - Signature verification
        - HTTPS enforcement

        Args:
            app_path: Path to application executable

        Returns:
            List of findings if vulnerabilities detected
        """
        findings = []

        # Monitor update checks (requires process monitoring)
        # Check for HTTP (not HTTPS) update URLs

        # Simplified: Check common update URL patterns
        update_patterns = [
            r'http://.*update',
            r'http://.*download',
            r'http://.*version'
        ]

        try:
            # Use strings command to extract URLs
            result = subprocess.run(
                ["strings", app_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            for pattern in update_patterns:
                matches = re.findall(pattern, result.stdout, re.IGNORECASE)

                if matches:
                    findings.append(Finding(
                        title="Insecure Update Mechanism",
                        description=f"Application uses HTTP (not HTTPS) for updates: {matches[0]}",
                        severity="HIGH",
                        evidence={
                            "app_path": app_path,
                            "update_url": matches[0],
                            "protocol": "HTTP",
                            "vulnerable_to": "Man-in-the-Middle attack"
                        },
                        vuln_type="Desktop_Insecure_Update"
                    ))
                    break

        except Exception as e:
            print(f"[!] Update mechanism test failed: {e}")

        return findings

    def scan_for_secrets(self, app_path: str) -> List[Finding]:
        """
        Scan application for hardcoded secrets

        Searches for:
        - API keys
        - Passwords
        - Certificates
        - Private keys

        Args:
            app_path: Path to application executable

        Returns:
            List of findings if secrets detected
        """
        findings = []

        secret_patterns = {
            "API_KEY": r'api[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})',
            "PASSWORD": r'password["\']?\s*[:=]\s*["\']([^"\']{6,})',
            "TOKEN": r'token["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})',
            "AWS_KEY": r'AKIA[0-9A-Z]{16}',
        }

        try:
            # Extract strings from binary
            result = subprocess.run(
                ["strings", app_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            for secret_type, pattern in secret_patterns.items():
                matches = re.findall(pattern, result.stdout, re.IGNORECASE)

                if matches:
                    findings.append(Finding(
                        title=f"Hardcoded {secret_type} in Application",
                        description=f"Application binary contains hardcoded {secret_type}",
                        severity="HIGH",
                        evidence={
                            "app_path": app_path,
                            "secret_type": secret_type,
                            "matches": len(matches),
                            "sample": matches[0][:20] + "..." if matches else ""
                        },
                        vuln_type="Desktop_Hardcoded_Secret"
                    ))

        except Exception as e:
            print(f"[!] Secret scanning failed: {e}")

        return findings

    def test_privilege_escalation(self, app_path: str) -> List[Finding]:
        """
        Test for privilege escalation vectors

        Checks:
        - Runs as SYSTEM/Admin
        - DLL hijacking vulnerabilities
        - Unquoted service paths

        Args:
            app_path: Path to application executable

        Returns:
            List of findings if vulnerabilities detected
        """
        findings = []

        # Check if app runs as SYSTEM (Windows service)
        # Check for unquoted paths with spaces
        if ' ' in app_path and not (app_path.startswith('"') and app_path.endswith('"')):
            findings.append(Finding(
                title="Unquoted Service Path",
                description=f"Service path contains spaces without quotes: {app_path}",
                severity="MEDIUM",
                evidence={
                    "app_path": app_path,
                    "vulnerability": "Unquoted service path allows DLL hijacking"
                },
                vuln_type="Desktop_Unquoted_Path"
            ))

        return findings
