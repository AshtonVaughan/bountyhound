"""
Azure Security Tester

Tests Azure-specific security configurations and vulnerabilities.
Covers: Blob Storage, App Services, Azure AD, Key Vault, Functions.
"""

import subprocess
import json
import re
from typing import Dict, List, Optional, Tuple
from engine.cloud import CloudFinding

# Backwards-compatible alias
AzureFinding = CloudFinding


class AzureBlobTester:
    """Test Azure Blob Storage for misconfigurations."""

    @staticmethod
    def check_public_container(storage_account: str, container: str = "", timeout: int = 10) -> List[AzureFinding]:
        """Check if Azure blob containers are publicly accessible."""
        findings = []

        containers_to_test = [container] if container else [
            '$web', 'public', 'uploads', 'images', 'assets', 'static',
            'data', 'backup', 'backups', 'files', 'documents', 'media',
            'logs', 'temp', 'cdn', 'content', 'downloads', 'export',
            'reports', 'archive', 'attachments', 'resources'
        ]

        for c in containers_to_test:
            url = f"https://{storage_account}.blob.core.windows.net/{c}?restype=container&comp=list"
            try:
                result = subprocess.run(
                    ['curl', '-s', '-m', str(timeout), '-o', '/dev/null', '-w', '%{http_code}', url],
                    capture_output=True, text=True, timeout=timeout + 5
                )
                status = result.stdout.strip()
                if status == '200':
                    # Fetch content to verify
                    body_result = subprocess.run(
                        ['curl', '-s', '-m', str(timeout), url],
                        capture_output=True, text=True, timeout=timeout + 5
                    )
                    if '<Blob>' in body_result.stdout or '<Name>' in body_result.stdout:
                        blob_count = body_result.stdout.count('<Blob>')
                        findings.append(AzureFinding(
                            title=f"Public Azure Blob Container: {c}",
                            severity="HIGH",
                            service="Azure Blob Storage",
                            evidence=f"Container '{c}' on {storage_account} is publicly listable ({blob_count} blobs)",
                            url=url,
                            remediation="Set container access level to 'Private' in Azure Portal"
                        ))
            except Exception:
                continue
        return findings

    @staticmethod
    def check_blob_anonymous_read(storage_account: str, container: str, blob_name: str, timeout: int = 10) -> Optional[AzureFinding]:
        """Check if individual blobs are anonymously readable."""
        url = f"https://{storage_account}.blob.core.windows.net/{container}/{blob_name}"
        try:
            result = subprocess.run(
                ['curl', '-sI', '-m', str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if '200' in result.stdout.split('\n')[0]:
                content_type = ''
                for line in result.stdout.split('\n'):
                    if 'content-type' in line.lower():
                        content_type = line.split(':', 1)[1].strip()
                        break
                return AzureFinding(
                    title=f"Anonymously Readable Blob: {blob_name}",
                    severity="MEDIUM",
                    service="Azure Blob Storage",
                    evidence=f"Blob '{blob_name}' is publicly readable (Content-Type: {content_type})",
                    url=url,
                    remediation="Remove anonymous read access or move to private container"
                )
        except Exception:
            pass
        return None


class AzureAppServiceTester:
    """Test Azure App Service security configurations."""

    @staticmethod
    def check_kudu_console(domain: str, timeout: int = 10) -> Optional[AzureFinding]:
        """Check if Kudu/SCM console is exposed."""
        scm_url = f"https://{domain.replace('.azurewebsites.net', '')}.scm.azurewebsites.net/"
        try:
            result = subprocess.run(
                ['curl', '-sI', '-m', str(timeout), scm_url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            status_line = result.stdout.split('\n')[0] if result.stdout else ''
            if '200' in status_line or '302' in status_line:
                return AzureFinding(
                    title="Exposed Kudu/SCM Console",
                    severity="HIGH",
                    service="Azure App Service",
                    evidence=f"Kudu console accessible at {scm_url}",
                    url=scm_url,
                    remediation="Restrict SCM access via IP restrictions or disable"
                )
        except Exception:
            pass
        return None

    @staticmethod
    def check_debug_endpoints(domain: str, timeout: int = 10) -> List[AzureFinding]:
        """Check for exposed debug/diagnostic endpoints."""
        findings = []
        debug_paths = [
            '/.env', '/web.config', '/applicationhost.config',
            '/elmah.axd', '/trace.axd', '/api/diagnostics',
            '/api/health', '/api/debug', '/_debugbar',
            '/swagger', '/swagger/index.html', '/swagger/v1/swagger.json',
        ]
        for path in debug_paths:
            url = f"https://{domain}{path}"
            try:
                result = subprocess.run(
                    ['curl', '-s', '-m', str(timeout), '-o', '/dev/null', '-w', '%{http_code}', url],
                    capture_output=True, text=True, timeout=timeout + 5
                )
                if result.stdout.strip() == '200':
                    findings.append(AzureFinding(
                        title=f"Exposed Debug Endpoint: {path}",
                        severity="MEDIUM" if 'config' not in path else "HIGH",
                        service="Azure App Service",
                        evidence=f"Debug endpoint accessible at {url}",
                        url=url,
                        remediation="Remove or restrict access to debug endpoints"
                    ))
            except Exception:
                continue
        return findings

    @staticmethod
    def check_default_pages(domain: str, timeout: int = 10) -> List[AzureFinding]:
        """Check for default Azure pages indicating misconfiguration."""
        findings = []
        try:
            result = subprocess.run(
                ['curl', '-s', '-m', str(timeout), f"https://{domain}"],
                capture_output=True, text=True, timeout=timeout + 5
            )
            body = result.stdout.lower()
            if 'hey, app service developers' in body or 'your app service app is up and running' in body:
                findings.append(AzureFinding(
                    title="Default Azure App Service Page",
                    severity="INFO",
                    service="Azure App Service",
                    evidence="Default landing page is displayed - app may not be deployed",
                    url=f"https://{domain}",
                    remediation="Deploy application or disable the App Service"
                ))
        except Exception:
            pass
        return findings


class AzureFunctionsTester:
    """Test Azure Functions for security issues."""

    @staticmethod
    def check_anonymous_functions(domain: str, timeout: int = 10) -> List[AzureFinding]:
        """Check for Azure Functions that don't require authentication."""
        findings = []
        common_function_paths = [
            '/api/HttpTrigger', '/api/webhook', '/api/process',
            '/api/data', '/api/upload', '/api/export', '/api/import',
            '/api/notify', '/api/callback', '/api/health',
        ]
        for path in common_function_paths:
            url = f"https://{domain}{path}"
            try:
                result = subprocess.run(
                    ['curl', '-s', '-m', str(timeout), '-o', '/dev/null', '-w', '%{http_code}', url],
                    capture_output=True, text=True, timeout=timeout + 5
                )
                status = result.stdout.strip()
                if status in ('200', '204', '400'):  # 400 = reached function but bad input
                    findings.append(AzureFinding(
                        title=f"Anonymous Azure Function: {path}",
                        severity="MEDIUM",
                        service="Azure Functions",
                        evidence=f"Function at {url} responds without auth key (HTTP {status})",
                        url=url,
                        remediation="Set authLevel to 'function' or 'admin' in function.json"
                    ))
            except Exception:
                continue
        return findings


class AzureSecurityTester:
    """Main Azure security testing orchestrator."""

    def __init__(self, target: str):
        self.target = target
        self.findings: List[AzureFinding] = []

    def run_all_tests(self) -> List[AzureFinding]:
        """Run all Azure security tests."""
        # Detect Azure services
        if '.blob.core.windows.net' in self.target:
            storage_account = self.target.split('.')[0]
            self.findings.extend(AzureBlobTester.check_public_container(storage_account))

        if '.azurewebsites.net' in self.target or '.azure.com' in self.target:
            self.findings.extend(AzureAppServiceTester.check_debug_endpoints(self.target))
            self.findings.extend(AzureAppServiceTester.check_default_pages(self.target))
            kudu = AzureAppServiceTester.check_kudu_console(self.target)
            if kudu:
                self.findings.append(kudu)

        if '.azurewebsites.net' in self.target:
            self.findings.extend(AzureFunctionsTester.check_anonymous_functions(self.target))

        # Generic tests for any target
        self.findings.extend(AzureAppServiceTester.check_debug_endpoints(self.target))

        return self.findings

    def generate_report(self) -> str:
        """Generate findings report."""
        if not self.findings:
            return f"No Azure-specific findings for {self.target}"

        lines = [f"Azure Security Report: {self.target}", "=" * 50, ""]
        for f in self.findings:
            lines.append(f"[{f.severity}] {f.title}")
            lines.append(f"  Service: {f.service}")
            lines.append(f"  Evidence: {f.evidence}")
            if f.url:
                lines.append(f"  URL: {f.url}")
            lines.append(f"  Fix: {f.remediation}")
            lines.append("")
        return '\n'.join(lines)
