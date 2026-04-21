"""
Semgrep SAST Runner
Run Semgrep static analysis with custom security rules
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional
from colorama import Fore, Style

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class SemgrepRunner:
    """
    Run Semgrep static analysis on source code
    """

    def __init__(self, repo_path: str, target: Optional[str] = None):
        """
        Initialize Semgrep runner

        Args:
            repo_path: Path to source code repository
            target: Target identifier for database tracking (default: repo name)
        """
        self.repo_path = Path(repo_path)
        self.target = target or self.repo_path.name  # Use repo name as target
        self.findings = []

    def scan(self, config: str = "auto") -> List[Dict]:
        """
        Run Semgrep scan

        Args:
            config: Semgrep config/ruleset (default: "auto" for automatic rules)

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'semgrep_runner')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP]  SKIP: {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Running Semgrep on {self.repo_path}...{Style.RESET_ALL}")

        try:
            # Run Semgrep
            result = subprocess.run(
                [
                    'semgrep',
                    '--config', config,
                    '--json',
                    '--quiet',
                    str(self.repo_path)
                ],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.stdout:
                data = json.loads(result.stdout)
                results = data.get('results', [])

                self.findings = self.process_findings(results)

                print(f"{Fore.GREEN}[+] Found {len(self.findings)} issues{Style.RESET_ALL}")
                self.print_summary()

                # Record tool run
                db = BountyHoundDB()
                db.record_tool_run(
                    self.target,
                    'semgrep_runner',
                    findings_count=len(self.findings),
                    success=True
                )

                return self.findings

        except FileNotFoundError:
            print(f"{Fore.RED}[-] Semgrep not found. Install: pip install semgrep{Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Scan timeout (5min limit){Style.RESET_ALL}")
        except json.JSONDecodeError:
            print(f"{Fore.YELLOW}[!] Invalid JSON output{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

        return []

    def process_findings(self, results: List[Dict]) -> List[Dict]:
        """Process Semgrep findings"""
        findings = []

        severity_map = {
            'ERROR': 'HIGH',
            'WARNING': 'MEDIUM',
            'INFO': 'LOW'
        }

        for result in results:
            finding = {
                "severity": severity_map.get(result.get('extra', {}).get('severity', 'INFO'), 'MEDIUM'),
                "title": result.get('check_id', ''),
                "description": result.get('extra', {}).get('message', ''),
                "file": result.get('path', ''),
                "line": result.get('start', {}).get('line', 0),
                "code": result.get('extra', {}).get('lines', '')
            }

            # Categorize by vulnerability type
            check_id = finding['title'].lower()

            if 'sql' in check_id:
                finding['category'] = 'SQL Injection'
                finding['severity'] = 'CRITICAL'
            elif 'xss' in check_id or 'cross-site' in check_id:
                finding['category'] = 'XSS'
                finding['severity'] = 'HIGH'
            elif 'command' in check_id and 'injection' in check_id:
                finding['category'] = 'Command Injection'
                finding['severity'] = 'CRITICAL'
            elif 'secret' in check_id or 'password' in check_id or 'api' in check_id:
                finding['category'] = 'Hardcoded Secret'
                finding['severity'] = 'CRITICAL'
            elif 'deserialize' in check_id:
                finding['category'] = 'Insecure Deserialization'
                finding['severity'] = 'HIGH'
            else:
                finding['category'] = 'Security Issue'

            findings.append(finding)

        return findings

    def print_summary(self):
        """Print findings summary"""
        if not self.findings:
            return

        # Count by severity
        by_severity = {}
        for finding in self.findings:
            sev = finding['severity']
            by_severity[sev] = by_severity.get(sev, 0) + 1

        # Count by category
        by_category = {}
        for finding in self.findings:
            cat = finding.get('category', 'Other')
            by_category[cat] = by_category.get(cat, 0) + 1

        print(f"\n{Fore.CYAN}Severity:{Style.RESET_ALL}")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if sev in by_severity:
                color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.YELLOW,
                    'MEDIUM': Fore.CYAN,
                    'LOW': Fore.WHITE
                }.get(sev, Fore.WHITE)
                print(f"  {color}{sev}: {by_severity[sev]}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}Categories:{Style.RESET_ALL}")
        for cat, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
            print(f"  {cat}: {count}")

    def scan_with_custom_rules(self, rules_path: str) -> List[Dict]:
        """
        Scan with custom Semgrep rules

        Args:
            rules_path: Path to custom rules file or directory
        """
        return self.scan(config=rules_path)


def main():
    """CLI interface"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python semgrep_runner.py <repo_path> [config]")
        sys.exit(1)

    repo_path = sys.argv[1]
    config = sys.argv[2] if len(sys.argv) > 2 else "auto"

    runner = SemgrepRunner(repo_path)
    findings = runner.scan(config)

    # Save report
    with open('semgrep_report.json', 'w') as f:
        json.dump(findings, f, indent=2)

    print(f"\n{Fore.GREEN}[+] Report saved: semgrep_report.json{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
