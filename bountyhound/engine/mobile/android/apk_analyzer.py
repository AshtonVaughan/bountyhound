"""
APK Security Analyzer
Decompiles and analyzes Android APK files for security vulnerabilities
"""

import os
import re
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from colorama import Fore, Style

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] androguard not installed. Install with: pip install androguard{Style.RESET_ALL}")


class APKAnalyzer:
    """
    Comprehensive APK security analyzer
    """

    def __init__(self, apk_path: str, target: Optional[str] = None):
        """
        Initialize APK analyzer

        Args:
            apk_path: Path to APK file
            target: Target identifier for database tracking (default: package name)

        Raises:
            ValueError: If path contains shell metacharacters, is not an APK, or doesn't exist
        """
        # Validate input before Path conversion to prevent command injection
        self._validate_apk_path(apk_path)

        self.apk_path = Path(apk_path).resolve()
        self.apk = None
        self.findings = []
        self.target = target

        # Double-check after resolution
        if not self.apk_path.exists() or not self.apk_path.is_file():
            raise ValueError(f"Invalid APK path: {apk_path}")

        if ANDROGUARD_AVAILABLE:
            self.apk = APK(str(self.apk_path))
            # Use package name as target if not provided
            if not self.target:
                self.target = self.apk.get_package()

        # Fallback to filename if package name unavailable
        if not self.target:
            self.target = self.apk_path.stem

        self.output_dir = self.apk_path.parent / f"{self.apk_path.stem}_analysis"
        self.output_dir.mkdir(exist_ok=True)

    def _validate_apk_path(self, apk_path: str) -> None:
        """
        Validate APK path to prevent command injection

        Args:
            apk_path: Path to validate

        Raises:
            ValueError: If path is invalid or contains dangerous characters
        """
        # Check for shell metacharacters that could enable command injection
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '<', '>', '(', ')']
        if any(char in apk_path for char in dangerous_chars):
            raise ValueError(f"Invalid APK path: contains shell metacharacters")

        # Check file extension
        if not apk_path.lower().endswith('.apk'):
            raise ValueError(f"File must be .apk, got: {apk_path}")

        # Basic path traversal check
        if '..' in apk_path:
            raise ValueError(f"Invalid APK path: path traversal detected")

        # Check path exists (basic check before resolution)
        path_obj = Path(apk_path)
        if not path_obj.exists():
            raise ValueError(f"Invalid APK path: file does not exist")

    def analyze(self) -> Dict:
        """
        Run complete APK analysis

        Returns:
            Dictionary containing all findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'apk_analyzer')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP]  SKIP: {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return {
                "skipped": True,
                "reason": context['reason'],
                "findings": []
            }
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Analyzing APK: {self.apk_path.name}{Style.RESET_ALL}")

        results = {
            "apk_info": self.get_apk_info(),
            "permissions": self.analyze_permissions(),
            "api_endpoints": self.extract_api_endpoints(),
            "secrets": self.find_hardcoded_secrets(),
            "activities": self.get_activities(),
            "services": self.get_services(),
            "receivers": self.get_receivers(),
            "exported_components": self.find_exported_components(),
            "insecure_methods": self.find_insecure_methods(),
            "findings": self.findings
        }

        # Record tool run
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'apk_analyzer',
            findings_count=len(self.findings),
            success=True
        )

        self.save_report(results)
        return results

    def get_apk_info(self) -> Dict:
        """Extract basic APK information"""
        if not self.apk:
            return {}

        info = {
            "package": self.apk.get_package(),
            "version_name": self.apk.get_androidversion_name(),
            "version_code": self.apk.get_androidversion_code(),
            "min_sdk": self.apk.get_min_sdk_version(),
            "target_sdk": self.apk.get_target_sdk_version(),
            "permissions_count": len(self.apk.get_permissions()),
            "activities_count": len(self.apk.get_activities()),
            "services_count": len(self.apk.get_services()),
        }

        print(f"{Fore.GREEN}[+] Package: {info['package']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Version: {info['version_name']} ({info['version_code']}){Style.RESET_ALL}")

        return info

    def analyze_permissions(self) -> List[Dict]:
        """Analyze dangerous permissions"""
        if not self.apk:
            return []

        permissions = self.apk.get_permissions()
        dangerous_perms = []

        DANGEROUS_PERMISSIONS = {
            "READ_CONTACTS": "Access to contacts",
            "READ_SMS": "Read SMS messages",
            "SEND_SMS": "Send SMS messages",
            "CAMERA": "Camera access",
            "RECORD_AUDIO": "Microphone access",
            "ACCESS_FINE_LOCATION": "Precise location",
            "READ_EXTERNAL_STORAGE": "Storage read access",
            "WRITE_EXTERNAL_STORAGE": "Storage write access",
            "GET_ACCOUNTS": "Access account list",
            "READ_CALL_LOG": "Call history access"
        }

        for perm in permissions:
            perm_name = perm.split('.')[-1]
            if perm_name in DANGEROUS_PERMISSIONS:
                dangerous_perms.append({
                    "permission": perm,
                    "risk": "HIGH",
                    "description": DANGEROUS_PERMISSIONS[perm_name]
                })
                self.add_finding("MEDIUM", "Dangerous Permission",
                               f"App requests {perm_name}: {DANGEROUS_PERMISSIONS[perm_name]}")

        print(f"{Fore.YELLOW}[!] Dangerous permissions: {len(dangerous_perms)}{Style.RESET_ALL}")
        return dangerous_perms

    def extract_api_endpoints(self) -> List[str]:
        """Extract API endpoints and URLs"""
        if not self.apk:
            return []

        urls = []

        # Decompile first
        self.decompile_apk()

        # Search for URLs in decompiled code
        decompiled_dir = self.output_dir / "decompiled"
        if decompiled_dir.exists():
            url_pattern = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+')

            for file in decompiled_dir.rglob('*.java'):
                try:
                    content = file.read_text(errors='ignore')
                    found_urls = url_pattern.findall(content)
                    urls.extend(found_urls)
                except:
                    continue

        # Deduplicate
        urls = list(set(urls))

        # Filter out common false positives
        urls = [u for u in urls if not any(fp in u for fp in ['schema.org', 'w3.org', 'example.com'])]

        print(f"{Fore.GREEN}[+] Found {len(urls)} API endpoints{Style.RESET_ALL}")

        for url in urls[:10]:  # Show first 10
            print(f"    {url}")

        return urls

    def find_hardcoded_secrets(self) -> List[Dict]:
        """Find hardcoded API keys, tokens, passwords"""
        secrets = []

        decompiled_dir = self.output_dir / "decompiled"
        if not decompiled_dir.exists():
            return secrets

        # Secret patterns
        patterns = {
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret Key": r'[\'"][0-9a-zA-Z/+]{40}[\'"]',
            "GitHub Token": r'ghp_[a-zA-Z0-9]{36}',
            "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
            "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
            "Private Key": r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----',
            "Generic API Key": r'["\']api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']'
        }

        for file in decompiled_dir.rglob('*.java'):
            try:
                content = file.read_text(errors='ignore')

                for secret_type, pattern in patterns.items():
                    matches = re.findall(pattern, content)
                    for match in matches:
                        secrets.append({
                            "type": secret_type,
                            "value": match[:50] + "..." if len(match) > 50 else match,
                            "file": str(file.relative_to(decompiled_dir)),
                            "severity": "CRITICAL"
                        })
                        self.add_finding("CRITICAL", f"Hardcoded {secret_type}",
                                       f"Found in {file.name}: {match[:30]}...")
            except:
                continue

        if secrets:
            print(f"{Fore.RED}[!] CRITICAL: Found {len(secrets)} hardcoded secrets!{Style.RESET_ALL}")

        return secrets

    def get_activities(self) -> List[str]:
        """Get list of activities"""
        if not self.apk:
            return []
        return self.apk.get_activities()

    def get_services(self) -> List[str]:
        """Get list of services"""
        if not self.apk:
            return []
        return self.apk.get_services()

    def get_receivers(self) -> List[str]:
        """Get list of broadcast receivers"""
        if not self.apk:
            return []
        return self.apk.get_receivers()

    def find_exported_components(self) -> List[Dict]:
        """Find exported components (potential attack surface)"""
        if not self.apk:
            return []

        exported = []

        # Check activities
        for activity in self.apk.get_activities():
            if self.is_exported(activity, "activity"):
                exported.append({
                    "type": "activity",
                    "name": activity,
                    "risk": "MEDIUM"
                })
                self.add_finding("MEDIUM", "Exported Activity",
                               f"Activity {activity} is exported and accessible to other apps")

        # Check services
        for service in self.apk.get_services():
            if self.is_exported(service, "service"):
                exported.append({
                    "type": "service",
                    "name": service,
                    "risk": "HIGH"
                })
                self.add_finding("HIGH", "Exported Service",
                               f"Service {service} is exported - potential privilege escalation")

        # Check receivers
        for receiver in self.apk.get_receivers():
            if self.is_exported(receiver, "receiver"):
                exported.append({
                    "type": "receiver",
                    "name": receiver,
                    "risk": "MEDIUM"
                })

        if exported:
            print(f"{Fore.YELLOW}[!] Found {len(exported)} exported components{Style.RESET_ALL}")

        return exported

    def _is_exported(self, exported_value) -> bool:
        """
        Check if a component is exported, handling both boolean and string types.

        Args:
            exported_value: The 'exported' attribute value from XML (can be bool, str, or None)

        Returns:
            True if component is exported, False otherwise

        Note:
            XML parsers may return boolean True/False or string "true"/"false"
            depending on the parser and XML structure.
        """
        if exported_value is None:
            return False

        # Handle boolean type
        if isinstance(exported_value, bool):
            return exported_value

        # Handle string type (case-insensitive)
        if isinstance(exported_value, str):
            return exported_value.lower() == 'true'

        # Unknown type
        return False

    def is_exported(self, component: str, comp_type: str) -> bool:
        """Check if component is exported"""
        # Use androguard's built-in method to check if component is exported
        if not self.apk:
            return False

        try:
            # Get the AndroidManifest.xml
            manifest = self.apk.get_android_manifest_xml()

            # Find the component in the manifest
            for elem in manifest.iter():
                # Check if this is the right component type
                if elem.tag.endswith(comp_type):
                    # Get the name attribute (with namespace)
                    name_attr = elem.get('{http://schemas.android.com/apk/res/android}name')

                    # Check if this is our component
                    if name_attr and (name_attr == component or name_attr.endswith('.' + component.split('.')[-1])):
                        # Get the exported attribute
                        exported_attr = elem.get('{http://schemas.android.com/apk/res/android}exported')
                        return self._is_exported(exported_attr)

            # If component not found in manifest, assume not exported
            return False

        except Exception:
            # Fallback: if we can't parse manifest, assume not exported for safety
            return False

    def find_insecure_methods(self) -> List[Dict]:
        """Find usage of insecure methods"""
        insecure = []

        decompiled_dir = self.output_dir / "decompiled"
        if not decompiled_dir.exists():
            return insecure

        # Insecure method patterns
        insecure_patterns = {
            "setJavaScriptEnabled(true)": "WebView JavaScript enabled",
            "setAllowFileAccess(true)": "WebView file access enabled",
            "MODE_WORLD_READABLE": "World-readable file created",
            "MODE_WORLD_WRITEABLE": "World-writable file created",
            "TrustManager": "Custom TrustManager - potential SSL bypass",
            "HostnameVerifier": "Custom HostnameVerifier - potential SSL bypass"
        }

        for file in decompiled_dir.rglob('*.java'):
            try:
                content = file.read_text(errors='ignore')

                for pattern, description in insecure_patterns.items():
                    if pattern in content:
                        insecure.append({
                            "method": pattern,
                            "description": description,
                            "file": str(file.relative_to(decompiled_dir)),
                            "severity": "HIGH"
                        })
                        self.add_finding("HIGH", f"Insecure Method: {pattern}", description)
            except:
                continue

        return insecure

    def decompile_apk(self):
        """Decompile APK using apktool and jadx"""
        decompiled_dir = self.output_dir / "decompiled"

        if decompiled_dir.exists():
            print(f"{Fore.YELLOW}[*] Using cached decompilation{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}[*] Decompiling APK...{Style.RESET_ALL}")

        # Try jadx first (better for Java decompilation)
        try:
            subprocess.run([
                "jadx",
                "-d", str(decompiled_dir),
                str(self.apk_path)
            ], check=True, capture_output=True)
            print(f"{Fore.GREEN}[+] Decompilation complete{Style.RESET_ALL}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Fore.YELLOW}[!] jadx not found, install with: apt install jadx{Style.RESET_ALL}")

    def add_finding(self, severity: str, title: str, description: str):
        """Add security finding"""
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description
        })

    def save_report(self, results: Dict):
        """Save analysis report"""
        report_path = self.output_dir / "security_report.json"

        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n{Fore.GREEN}[+] Report saved: {report_path}{Style.RESET_ALL}")

        # Print summary
        print(f"\n{Fore.CYAN}=== ANALYSIS SUMMARY ==={Style.RESET_ALL}")
        print(f"API Endpoints: {len(results['api_endpoints'])}")
        print(f"Hardcoded Secrets: {len(results['secrets'])}")
        print(f"Exported Components: {len(results['exported_components'])}")
        print(f"Total Findings: {len(results['findings'])}")

        # Severity breakdown
        critical = sum(1 for f in self.findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in self.findings if f['severity'] == 'HIGH')
        medium = sum(1 for f in self.findings if f['severity'] == 'MEDIUM')

        if critical:
            print(f"{Fore.RED}CRITICAL: {critical}{Style.RESET_ALL}")
        if high:
            print(f"{Fore.YELLOW}HIGH: {high}{Style.RESET_ALL}")
        if medium:
            print(f"{Fore.CYAN}MEDIUM: {medium}{Style.RESET_ALL}")


def main():
    """CLI interface"""
    import sys

    if len(sys.argv) != 2:
        print("Usage: python apk_analyzer.py <apk_file>")
        sys.exit(1)

    apk_path = sys.argv[1]
    analyzer = APKAnalyzer(apk_path)
    analyzer.analyze()


if __name__ == "__main__":
    main()
