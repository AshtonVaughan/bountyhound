"""
GCP Security Tester

Tests Google Cloud Platform security configurations and vulnerabilities.
Covers: Cloud Storage, App Engine, Cloud Functions, Firebase, IAM.
"""

import subprocess
import json
import re
from typing import Dict, List, Optional, Tuple
from engine.cloud import CloudFinding

# Backwards-compatible alias
GCPFinding = CloudFinding


class GCSBucketTester:
    """Test Google Cloud Storage buckets for misconfigurations."""

    @staticmethod
    def check_public_bucket(bucket_name: str, timeout: int = 10) -> List[GCPFinding]:
        """Check if GCS bucket is publicly accessible."""
        findings = []

        # Test listing
        list_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o"
        try:
            result = subprocess.run(
                ['curl', '-s', '-m', str(timeout), list_url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if '"kind": "storage#objects"' in result.stdout:
                items = json.loads(result.stdout).get('items', [])
                findings.append(GCPFinding(
                    title=f"Publicly Listable GCS Bucket: {bucket_name}",
                    severity="HIGH",
                    service="Cloud Storage",
                    evidence=f"Bucket contains {len(items)} publicly listable objects",
                    url=list_url,
                    remediation="Remove 'allUsers' and 'allAuthenticatedUsers' from bucket IAM"
                ))
        except Exception:
            pass

        # Test direct XML API
        xml_url = f"https://storage.googleapis.com/{bucket_name}"
        try:
            result = subprocess.run(
                ['curl', '-s', '-m', str(timeout), xml_url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if '<ListBucketResult' in result.stdout:
                findings.append(GCPFinding(
                    title=f"GCS Bucket XML Listing: {bucket_name}",
                    severity="HIGH",
                    service="Cloud Storage",
                    evidence="Bucket responds to XML listing API",
                    url=xml_url,
                    remediation="Disable public access on bucket"
                ))
            elif 'NoSuchBucket' in result.stdout:
                findings.append(GCPFinding(
                    title=f"GCS Bucket Takeover Possible: {bucket_name}",
                    severity="CRITICAL",
                    service="Cloud Storage",
                    evidence="Bucket does not exist - can be claimed",
                    url=xml_url,
                    remediation="Create the bucket in your GCP project to prevent takeover"
                ))
        except Exception:
            pass

        return findings

    @staticmethod
    def check_public_object(bucket_name: str, object_name: str, timeout: int = 10) -> Optional[GCPFinding]:
        """Check if a specific object is publicly readable."""
        url = f"https://storage.googleapis.com/{bucket_name}/{object_name}"
        try:
            result = subprocess.run(
                ['curl', '-sI', '-m', str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if '200' in result.stdout.split('\n')[0]:
                return GCPFinding(
                    title=f"Publicly Readable Object: {object_name}",
                    severity="MEDIUM",
                    service="Cloud Storage",
                    evidence=f"Object '{object_name}' in bucket '{bucket_name}' is publicly readable",
                    url=url,
                    remediation="Set object ACL to private"
                )
        except Exception:
            pass
        return None


class FirebaseTester:
    """Test Firebase for security misconfigurations."""

    @staticmethod
    def check_open_database(project_id: str, timeout: int = 10) -> List[GCPFinding]:
        """Check if Firebase Realtime Database is open."""
        findings = []
        url = f"https://{project_id}-default-rtdb.firebaseio.com/.json"
        try:
            result = subprocess.run(
                ['curl', '-s', '-m', str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if result.stdout.strip() != 'null' and '"error"' not in result.stdout:
                data_size = len(result.stdout)
                findings.append(GCPFinding(
                    title=f"Open Firebase Realtime Database: {project_id}",
                    severity="CRITICAL",
                    service="Firebase",
                    evidence=f"Database is publicly readable ({data_size} bytes returned)",
                    url=url,
                    remediation="Update Firebase security rules to require authentication"
                ))
        except Exception:
            pass

        # Check Firestore
        firestore_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
        try:
            result = subprocess.run(
                ['curl', '-s', '-m', str(timeout), firestore_url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if '"documents"' in result.stdout:
                findings.append(GCPFinding(
                    title=f"Open Firestore Database: {project_id}",
                    severity="CRITICAL",
                    service="Firebase Firestore",
                    evidence="Firestore is publicly readable",
                    url=firestore_url,
                    remediation="Update Firestore security rules to require authentication"
                ))
        except Exception:
            pass

        return findings

    @staticmethod
    def check_firebase_config(url: str, timeout: int = 10) -> List[GCPFinding]:
        """Check for exposed Firebase configuration."""
        findings = []
        config_paths = [
            '/__/firebase/init.json',
            '/__/firebase/init.js',
            '/firebase-config.json',
            '/firebaseConfig.js',
        ]
        for path in config_paths:
            full_url = f"{url.rstrip('/')}{path}"
            try:
                result = subprocess.run(
                    ['curl', '-s', '-m', str(timeout), full_url],
                    capture_output=True, text=True, timeout=timeout + 5
                )
                if 'apiKey' in result.stdout and 'projectId' in result.stdout:
                    findings.append(GCPFinding(
                        title=f"Exposed Firebase Config: {path}",
                        severity="LOW",
                        service="Firebase",
                        evidence=f"Firebase configuration exposed at {full_url}",
                        url=full_url,
                        remediation="Firebase configs are public by design; ensure security rules are strict"
                    ))
                    break
            except Exception:
                continue
        return findings

    @staticmethod
    def check_firebase_signup(api_key: str, timeout: int = 10) -> Optional[GCPFinding]:
        """Check if Firebase allows unrestricted user signup."""
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
        try:
            result = subprocess.run(
                ['curl', '-s', '-m', str(timeout), '-X', 'POST',
                 '-H', 'Content-Type: application/json',
                 '-d', '{"returnSecureToken":true}',
                 url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if 'idToken' in result.stdout:
                return GCPFinding(
                    title="Firebase Anonymous Signup Enabled",
                    severity="MEDIUM",
                    service="Firebase Auth",
                    evidence="Anonymous user creation is enabled via API",
                    url=url,
                    remediation="Disable anonymous authentication if not needed"
                )
        except Exception:
            pass
        return None


class GCPCloudFunctionsTester:
    """Test GCP Cloud Functions for security issues."""

    @staticmethod
    def check_unauthenticated_functions(domain: str, timeout: int = 10) -> List[GCPFinding]:
        """Check for Cloud Functions that don't require authentication."""
        findings = []
        regions = ['us-central1', 'us-east1', 'europe-west1', 'asia-east1']

        # Try common function patterns
        common_functions = [
            'function-1', 'webhook', 'api', 'process', 'handler',
            'callback', 'notify', 'export', 'import', 'health'
        ]

        for func_name in common_functions:
            for region in regions[:2]:  # Limit to reduce requests
                url = f"https://{region}-{domain}.cloudfunctions.net/{func_name}"
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-m', str(timeout), '-o', '/dev/null', '-w', '%{http_code}', url],
                        capture_output=True, text=True, timeout=timeout + 5
                    )
                    status = result.stdout.strip()
                    if status in ('200', '204', '400', '405'):
                        findings.append(GCPFinding(
                            title=f"Unauthenticated Cloud Function: {func_name}",
                            severity="MEDIUM",
                            service="Cloud Functions",
                            evidence=f"Function at {url} responds without auth (HTTP {status})",
                            url=url,
                            remediation="Set invoker IAM to specific service accounts instead of allUsers"
                        ))
                except Exception:
                    continue
        return findings


class GCPMetadataTester:
    """Test for GCP metadata SSRF vulnerabilities."""

    METADATA_ENDPOINTS = [
        '/computeMetadata/v1/project/project-id',
        '/computeMetadata/v1/instance/service-accounts/default/token',
        '/computeMetadata/v1/instance/service-accounts/default/email',
        '/computeMetadata/v1/instance/hostname',
        '/computeMetadata/v1/instance/zone',
        '/computeMetadata/v1/project/attributes/',
    ]

    @staticmethod
    def generate_ssrf_payloads() -> List[Dict]:
        """Generate SSRF payloads targeting GCP metadata service."""
        base = "http://metadata.google.internal"
        payloads = []
        for endpoint in GCPMetadataTester.METADATA_ENDPOINTS:
            payloads.append({
                'url': f"{base}{endpoint}",
                'headers': {'Metadata-Flavor': 'Google'},
                'description': f"GCP metadata: {endpoint}",
                'severity': 'CRITICAL' if 'token' in endpoint else 'HIGH'
            })
        return payloads


class GCPSecurityTester:
    """Main GCP security testing orchestrator."""

    def __init__(self, target: str):
        self.target = target
        self.findings: List[GCPFinding] = []

    def run_all_tests(self) -> List[GCPFinding]:
        """Run all GCP security tests."""
        # Detect GCS buckets
        if '.storage.googleapis.com' in self.target or 'storage.googleapis.com/' in self.target:
            bucket = self.target.split('storage.googleapis.com/')[-1].split('/')[0]
            self.findings.extend(GCSBucketTester.check_public_bucket(bucket))

        # Detect Firebase
        if '.firebaseio.com' in self.target or 'firebase' in self.target.lower():
            project = self.target.split('.')[0].split('//')[-1]
            self.findings.extend(FirebaseTester.check_open_database(project))
            self.findings.extend(FirebaseTester.check_firebase_config(f"https://{self.target}"))

        # Cloud Functions
        if '.cloudfunctions.net' in self.target:
            self.findings.extend(GCPCloudFunctionsTester.check_unauthenticated_functions(self.target))

        # Generic tests
        self.findings.extend(FirebaseTester.check_firebase_config(f"https://{self.target}"))

        return self.findings

    def generate_report(self) -> str:
        """Generate findings report."""
        if not self.findings:
            return f"No GCP-specific findings for {self.target}"
        lines = [f"GCP Security Report: {self.target}", "=" * 50, ""]
        for f in self.findings:
            lines.append(f"[{f.severity}] {f.title}")
            lines.append(f"  Service: {f.service}")
            lines.append(f"  Evidence: {f.evidence}")
            if f.url:
                lines.append(f"  URL: {f.url}")
            lines.append(f"  Fix: {f.remediation}")
            lines.append("")
        return '\n'.join(lines)
