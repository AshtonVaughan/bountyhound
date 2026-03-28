"""
Hardcoded Secrets Scanner
Find API keys, tokens, passwords, and other secrets in source code
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Optional
from colorama import Fore, Style

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


def mask_secret(secret: str) -> str:
    """
    Mask a secret for terminal display.
    Shows first 4 and last 4 characters, masks the middle.

    Args:
        secret: The secret to mask

    Returns:
        Masked version safe for terminal display

    Example:
        >>> mask_secret("AKIAIOSFODNN7EXAMPLE")
        "AKIA...MPLE"
    """
    if not secret:
        return "****"

    if len(secret) <= 8:
        # Very short secrets - show almost nothing
        return "****"

    # Show first 4 and last 4 characters
    return f"{secret[:4]}...{secret[-4:]}"


class SecretsScanner:
    """
    Scan source code for hardcoded secrets
    """

    def __init__(self, repo_path: str, target: Optional[str] = None):
        """
        Initialize secrets scanner

        Args:
            repo_path: Path to source code repository
            target: Target identifier for database tracking (default: repo name)
        """
        self.repo_path = Path(repo_path)
        self.target = target or self.repo_path.name  # Use repo name as target
        self.findings = []

        # Secret patterns
        self.patterns = {
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret Key": r'[\'"][0-9a-zA-Z/+=]{40}[\'"]',
            "GitHub Token": r'ghp_[a-zA-Z0-9]{36}',
            "GitHub OAuth": r'gho_[a-zA-Z0-9]{36}',
            "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
            "Google OAuth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            "Slack Token": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}',
            "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
            "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
            "Private SSH Key": r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            "Private PGP Key": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            "Heroku API Key": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            "Stripe API Key": r'sk_live_[0-9a-zA-Z]{24,}',
            "Stripe Restricted Key": r'rk_live_[0-9a-zA-Z]{24,}',
            "Square Access Token": r'sq0atp-[0-9A-Za-z\-_]{22}',
            "Square OAuth Secret": r'sq0csp-[0-9A-Za-z\-_]{43}',
            "PayPal Token": r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            "Telegram Bot Token": r'[0-9]+:AA[0-9A-Za-z\-_]{33}',
            "Generic API Key": r'["\']api[_-]?key["\']\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Generic Secret": r'["\']secret["\']\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Generic Password": r'["\']password["\']\s*[:=]\s*["\'][^"\']{8,}["\']',
            "Database Connection": r'(mysql|postgres|mongodb)://[^:]+:[^@]+@',
            "JWT Token": r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'
        }

        # File extensions to scan
        self.scan_extensions = [
            '.py', '.js', '.ts', '.java', '.go', '.rb', '.php',
            '.env', '.config', '.yaml', '.yml', '.json', '.xml',
            '.sh', '.bash', '.properties', '.conf'
        ]

        # Directories to skip
        self.skip_dirs = {
            'node_modules', '.git', 'venv', 'env', '__pycache__',
            'dist', 'build', 'vendor', '.idea', '.vscode'
        }

    def scan(self) -> List[Dict]:
        """
        Scan repository for secrets

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'secrets_scanner')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Scanning for secrets in: {self.repo_path}{Style.RESET_ALL}")

        if not self.repo_path.exists():
            raise FileNotFoundError(f"Path not found: {self.repo_path}")

        # Scan all files
        for file_path in self.get_files_to_scan():
            self.scan_file(file_path)

        # Print summary
        print(f"\n{Fore.CYAN}=== SCAN COMPLETE ==={Style.RESET_ALL}")
        print(f"Files scanned: {self.files_scanned}")
        print(f"Secrets found: {len(self.findings)}")

        # Group by type
        by_type = {}
        for finding in self.findings:
            secret_type = finding['type']
            by_type[secret_type] = by_type.get(secret_type, 0) + 1

        if by_type:
            print(f"\n{Fore.YELLOW}Breakdown:{Style.RESET_ALL}")
            for secret_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
                print(f"  {secret_type}: {count}")

        # Record tool run
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'secrets_scanner',
            findings_count=len(self.findings),
            success=True
        )

        return self.findings

    def get_files_to_scan(self):
        """Get list of files to scan"""
        self.files_scanned = 0

        for root, dirs, files in os.walk(self.repo_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]

            for file in files:
                # Check extension
                if any(file.endswith(ext) for ext in self.scan_extensions):
                    self.files_scanned += 1
                    yield Path(root) / file

    def scan_file(self, file_path: Path):
        """Scan a single file for secrets"""
        try:
            content = file_path.read_text(errors='ignore')

            for secret_type, pattern in self.patterns.items():
                matches = re.findall(pattern, content)

                for match in matches:
                    # Skip false positives
                    if self.is_false_positive(match, secret_type):
                        continue

                    # Calculate line number
                    line_num = content[:content.find(match)].count('\n') + 1

                    # Store FULL secret in findings (for JSON report)
                    finding = {
                        "type": secret_type,
                        "secret": match,  # Full secret preserved
                        "file": str(file_path.relative_to(self.repo_path)),
                        "line": line_num,
                        "severity": "CRITICAL"
                    }

                    self.findings.append(finding)

                    # Print MASKED version to terminal (for security)
                    masked_secret = mask_secret(match)
                    print(f"{Fore.RED}[!] {secret_type} found:{Style.RESET_ALL}")
                    print(f"    File: {finding['file']}:{line_num}")
                    print(f"    Value: {Fore.YELLOW}{masked_secret}{Style.RESET_ALL} (masked for security)")

        except Exception as e:
            pass  # Skip files that can't be read

    def is_false_positive(self, match: str, secret_type: str) -> bool:
        """Check if match is a false positive"""
        false_positives = [
            'example', 'test', 'sample', 'demo', 'fake',
            'YOUR_', 'INSERT_', 'REPLACE_', 'TODO',
            '0' * 10, '1' * 10, 'a' * 10, 'x' * 10
        ]

        match_lower = match.lower()

        return any(fp in match_lower for fp in false_positives)


def main():
    """CLI interface"""
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python secrets_scanner.py <repo_path>")
        sys.exit(1)

    repo_path = sys.argv[1]
    scanner = SecretsScanner(repo_path)
    findings = scanner.scan()

    # Generate JSON report with FULL secrets (for security team review only)
    # IMPORTANT: Handle this file with care - contains unmasked secrets
    output_file = "secrets_report.json"
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=2)

    print(f"\n{Fore.GREEN}[+] Report saved: {output_file}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
