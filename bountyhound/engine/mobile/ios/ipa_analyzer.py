"""
IPA Security Analyzer
Analyzes iOS IPA files for security vulnerabilities
"""

import os
import zipfile
import plistlib
import re
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional
from colorama import Fore, Style

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class IPAAnalyzer:
    """
    iOS IPA security analyzer
    """

    def __init__(self, ipa_path: str, target: Optional[str] = None):
        """
        Initialize IPA analyzer

        Args:
            ipa_path: Path to IPA file
            target: Target identifier for database tracking (default: bundle ID)
        """
        self.ipa_path = Path(ipa_path)
        self.findings = []
        self.target = target or self.ipa_path.stem  # Use filename as initial target

        if not self.ipa_path.exists():
            raise FileNotFoundError(f"IPA not found: {ipa_path}")

        self.output_dir = self.ipa_path.parent / f"{self.ipa_path.stem}_analysis"
        self.output_dir.mkdir(exist_ok=True)

    def analyze(self) -> Dict:
        """Run complete IPA analysis"""
        # Extract IPA first to get bundle ID
        self.extract_ipa()

        # Try to get bundle ID from Info.plist for better targeting
        app_info = self.get_app_info()
        if app_info.get('bundle_id') and not self.target.endswith('.ipa'):
            self.target = app_info['bundle_id']

        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'ipa_analyzer')

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

        print(f"{Fore.CYAN}[*] Analyzing IPA: {self.ipa_path.name}{Style.RESET_ALL}")

        results = {
            "app_info": app_info,
            "entitlements": self.check_entitlements(),
            "url_schemes": self.find_url_schemes(),
            "api_endpoints": self.extract_api_endpoints(),
            "secrets": self.find_hardcoded_secrets(),
            "insecure_storage": self.check_insecure_storage(),
            "findings": self.findings
        }

        # Record tool run
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'ipa_analyzer',
            findings_count=len(self.findings),
            success=True
        )

        return results

    def extract_ipa(self):
        """Extract IPA (ZIP archive) with path traversal protection"""
        extract_dir = self.output_dir / "extracted"

        if extract_dir.exists():
            print(f"{Fore.YELLOW}[*] Using cached extraction{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}[*] Extracting IPA...{Style.RESET_ALL}")

        # Validate paths BEFORE extraction
        with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
            # Get canonical extraction directory
            extract_dir_resolved = extract_dir.resolve()

            # Check each member for path traversal
            for member in zip_ref.namelist():
                # Resolve the full path where this file would be extracted
                member_path = (extract_dir / member).resolve()

                # Ensure the resolved path is within the extraction directory
                try:
                    member_path.relative_to(extract_dir_resolved)
                except ValueError:
                    # Path is outside extraction directory
                    raise ValueError(f"Path traversal detected in ZIP member: {member}")

            # All paths validated, safe to extract
            zip_ref.extractall(extract_dir)

        print(f"{Fore.GREEN}[+] Extraction complete{Style.RESET_ALL}")

    def get_app_info(self) -> Dict:
        """Extract app information from Info.plist"""
        plist_path = self.find_info_plist()

        if not plist_path:
            return {}

        with open(plist_path, 'rb') as f:
            plist = plistlib.load(f)

        info = {
            "bundle_id": plist.get('CFBundleIdentifier', ''),
            "version": plist.get('CFBundleShortVersionString', ''),
            "build": plist.get('CFBundleVersion', ''),
            "min_os": plist.get('MinimumOSVersion', ''),
            "device_family": plist.get('UIDeviceFamily', [])
        }

        print(f"{Fore.GREEN}[+] Bundle ID: {info['bundle_id']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Version: {info['version']} ({info['build']}){Style.RESET_ALL}")

        return info

    def find_info_plist(self) -> Optional[Path]:
        """Find Info.plist in extracted IPA"""
        extract_dir = self.output_dir / "extracted"

        for plist_path in extract_dir.rglob('Info.plist'):
            if '/Payload/' in str(plist_path):
                return plist_path

        return None

    def check_entitlements(self) -> List[Dict]:
        """Check app entitlements"""
        # Would parse embedded.mobileprovision
        # For now, return placeholder
        return []

    def extract_strings(self) -> dict:
        """
        Extract strings from iOS binary using the strings command.

        Returns:
            dict: Categorized strings including URLs, potential secrets, and file paths
        """
        try:
            # Find the main executable binary
            app_dir = self.output_dir / "extracted" / "Payload"

            # Find .app directory
            app_dirs = list(app_dir.glob("*.app"))
            if not app_dirs:
                print(f"{Fore.YELLOW}[*] No .app directory found{Style.RESET_ALL}")
                return {}

            # Find the binary inside the .app
            binary_path = app_dirs[0] / app_dirs[0].stem

            if not binary_path.exists():
                print(f"{Fore.YELLOW}[*] Binary not found at {binary_path}{Style.RESET_ALL}")
                return {}

            print(f"{Fore.CYAN}[*] Extracting strings from binary...{Style.RESET_ALL}")

            # Run strings command (supports ASCII and Unicode)
            result = subprocess.run(
                ['strings', '-a', str(binary_path)],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                print(f"{Fore.YELLOW}[*] strings command failed{Style.RESET_ALL}")
                return {}

            # Categorize the extracted strings
            categorized = {
                'urls': [],
                'potential_secrets': [],
                'file_paths': [],
                'interesting': []
            }

            # Process each line
            for line in result.stdout.split('\n'):
                line = line.strip()

                if len(line) < 4:  # Skip very short strings
                    continue

                # Detect URLs
                if line.startswith(('http://', 'https://', 'ftp://')):
                    categorized['urls'].append({
                        'type': 'URL',
                        'value': line
                    })

                # Detect potential API keys and secrets
                elif any(pattern in line.lower() for pattern in [
                    'api_key', 'apikey', 'secret', 'password', 'token',
                    'aws_access', 'akia', 'sk_live', 'sk_test', 'ghp_'
                ]):
                    categorized['potential_secrets'].append({
                        'type': 'Potential Secret',
                        'value': line
                    })

                # Detect file paths
                elif line.startswith('/') and '/' in line[1:]:
                    categorized['file_paths'].append({
                        'type': 'File Path',
                        'value': line
                    })

                # Interesting strings (long, alphanumeric, might be config)
                elif len(line) > 20 and any(c.isalnum() for c in line):
                    categorized['interesting'].append({
                        'type': 'Interesting String',
                        'value': line[:100]  # Truncate very long strings
                    })

            # Print summary
            print(f"{Fore.GREEN}[+] String extraction complete:{Style.RESET_ALL}")
            print(f"    URLs: {len(categorized['urls'])}")
            print(f"    Potential Secrets: {len(categorized['potential_secrets'])}")
            print(f"    File Paths: {len(categorized['file_paths'])}")
            print(f"    Interesting: {len(categorized['interesting'])}")

            # Save to JSON
            report_path = self.output_dir / "strings_analysis.json"
            with open(report_path, 'w') as f:
                json.dump(categorized, f, indent=2)

            print(f"{Fore.GREEN}[+] Strings saved to {report_path}{Style.RESET_ALL}")

            return categorized

        except FileNotFoundError:
            print(f"{Fore.YELLOW}[*] 'strings' command not found. Install binutils.{Style.RESET_ALL}")
            return {}
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting strings: {e}{Style.RESET_ALL}")
            return {}

    def find_url_schemes(self) -> List[str]:
        """Find custom URL schemes (deeplinks)"""
        plist_path = self.find_info_plist()

        if not plist_path:
            return []

        with open(plist_path, 'rb') as f:
            plist = plistlib.load(f)

        url_types = plist.get('CFBundleURLTypes', [])
        schemes = []

        for url_type in url_types:
            url_schemes = url_type.get('CFBundleURLSchemes', [])
            schemes.extend(url_schemes)

        if schemes:
            print(f"{Fore.YELLOW}[!] Found {len(schemes)} URL schemes (deeplinks){Style.RESET_ALL}")
            for scheme in schemes:
                print(f"    {scheme}://")
                self.add_finding("MEDIUM", "Custom URL Scheme",
                               f"App registers URL scheme: {scheme}:// - potential deeplink vulnerability")

        return schemes

    def extract_api_endpoints(self) -> List[str]:
        """Extract API endpoints from binary"""
        # Would use strings on Mach-O binary
        # Placeholder for now
        return []

    def find_hardcoded_secrets(self) -> List[Dict]:
        """Find hardcoded secrets in binary"""
        # Would scan strings in Mach-O binary
        # Placeholder for now
        return []

    def check_insecure_storage(self) -> List[Dict]:
        """Check for insecure data storage"""
        findings = []

        # Check for plist files
        extract_dir = self.output_dir / "extracted"

        for plist_file in extract_dir.rglob('*.plist'):
            if 'Info.plist' not in str(plist_file):
                findings.append({
                    "file": str(plist_file.name),
                    "risk": "MEDIUM",
                    "description": "Plist file may contain sensitive data"
                })

        return findings

    def add_finding(self, severity: str, title: str, description: str):
        """Add security finding"""
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description
        })


def main():
    """CLI interface"""
    import sys

    if len(sys.argv) != 2:
        print("Usage: python ipa_analyzer.py <ipa_file>")
        sys.exit(1)

    ipa_path = sys.argv[1]
    analyzer = IPAAnalyzer(ipa_path)
    results = analyzer.analyze()

    print(f"\n{Fore.CYAN}=== ANALYSIS COMPLETE ==={Style.RESET_ALL}")
    print(f"URL Schemes: {len(results['url_schemes'])}")
    print(f"Total Findings: {len(results['findings'])}")


if __name__ == "__main__":
    main()
