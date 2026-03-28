"""
Mythril Symbolic Execution Runner
Wrapper for Mythril smart contract security analyzer
"""

import subprocess
import json
import re
from pathlib import Path
from typing import List, Dict, Optional
from colorama import Fore, Style

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class MythrilRunner:
    """
    Run Mythril symbolic execution on Solidity contracts
    """

    def __init__(self, contract_path: str, target: Optional[str] = None):
        """
        Initialize Mythril runner

        Args:
            contract_path: Path to Solidity file
            target: Target identifier for database tracking
        """
        self.contract_path = Path(contract_path)
        self.target = target or self.contract_path.stem
        self.findings = []

        if not self.contract_path.exists():
            raise FileNotFoundError(f"Contract not found: {contract_path}")

    def run(self, execution_timeout: int = 60, max_depth: int = 128,
            output_format: str = 'text') -> List[Dict]:
        """
        Run Mythril symbolic execution

        Args:
            execution_timeout: Timeout in seconds for execution
            max_depth: Maximum recursion depth
            output_format: Output format ('text' or 'json')

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'mythril_runner')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] SKIP: {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Running Mythril symbolic execution on {self.contract_path.name}...{Style.RESET_ALL}")

        try:
            # Build command
            cmd = [
                'myth',
                'analyze',
                str(self.contract_path),
                '--execution-timeout', str(execution_timeout),
                '--max-depth', str(max_depth)
            ]

            if output_format == 'json':
                cmd.extend(['-o', 'json'])

            # Run Mythril
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=execution_timeout + 60  # Add buffer to subprocess timeout
            )

            if result.stdout:
                if output_format == 'json':
                    self.findings = self.parse_json_output(result.stdout)
                else:
                    self.findings = self.parse_text_output(result.stdout)

                print(f"{Fore.GREEN}[+] Found {len(self.findings)} issues{Style.RESET_ALL}")
                self.print_summary()

                # Record tool run
                db = BountyHoundDB()
                db.record_tool_run(
                    self.target,
                    'mythril_runner',
                    findings_count=len(self.findings),
                    success=True
                )

                return self.findings

        except FileNotFoundError:
            print(f"{Fore.RED}[-] Mythril not found. Install: pip install mythril{Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Analysis timeout (>{execution_timeout}s){Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

        return []

    def parse_json_output(self, output: str) -> List[Dict]:
        """
        Parse Mythril JSON output

        Args:
            output: JSON output from Mythril

        Returns:
            List of findings
        """
        findings = []

        try:
            data = json.loads(output)

            if 'issues' in data:
                for issue in data['issues']:
                    finding = {
                        'severity': self.map_severity(issue.get('severity', 'Low')),
                        'swc_id': issue.get('swc-id', 'Unknown'),
                        'title': issue.get('title', 'Unknown Issue'),
                        'description': issue.get('description', ''),
                        'contract': issue.get('contract', ''),
                        'function': issue.get('function', ''),
                        'address': issue.get('address', '')
                    }
                    findings.append(finding)

        except json.JSONDecodeError:
            print(f"{Fore.YELLOW}[!] Failed to parse JSON output{Style.RESET_ALL}")

        return findings

    def parse_text_output(self, output: str) -> List[Dict]:
        """
        Parse Mythril text output

        Args:
            output: Text output from Mythril

        Returns:
            List of findings
        """
        findings = []

        # Look for SWC patterns
        swc_pattern = r'SWC ID:\s*(\d+)'
        severity_pattern = r'Severity:\s*(\w+)'
        title_pattern = r'====\s*(.+?)\s*===='

        # Split by issue blocks
        if 'SWC ID:' in output:
            # Parse each vulnerability block
            blocks = re.split(r'====.*?====', output)

            for block in blocks:
                if 'SWC ID:' in block:
                    swc_match = re.search(swc_pattern, block)
                    severity_match = re.search(severity_pattern, block)

                    swc_id = swc_match.group(1) if swc_match else 'Unknown'
                    severity = severity_match.group(1) if severity_match else 'Low'

                    finding = {
                        'severity': self.map_severity(severity),
                        'swc_id': swc_id,
                        'title': self.get_swc_title(swc_id),
                        'description': block.strip()[:500],  # First 500 chars
                        'raw_output': block.strip()
                    }
                    findings.append(finding)

            # If we found issues, record them
            if findings:
                return findings

            # Fallback: generic finding for any SWC mention
            finding = {
                'severity': 'HIGH',
                'swc_id': 'Multiple',
                'title': 'Mythril: Security Issues Found',
                'description': output[:500]
            }
            findings.append(finding)

        return findings

    def map_severity(self, mythril_severity: str) -> str:
        """
        Map Mythril severity to standard severity levels

        Args:
            mythril_severity: Mythril severity string

        Returns:
            Mapped severity
        """
        severity_map = {
            'High': 'CRITICAL',
            'Medium': 'HIGH',
            'Low': 'MEDIUM',
            'Informational': 'INFO'
        }

        return severity_map.get(mythril_severity, 'MEDIUM')

    def get_swc_title(self, swc_id: str) -> str:
        """
        Get human-readable title for SWC ID

        Args:
            swc_id: SWC identifier

        Returns:
            Human-readable title
        """
        swc_titles = {
            '101': 'Integer Overflow and Underflow',
            '105': 'Unprotected Ether Withdrawal',
            '107': 'Reentrancy',
            '108': 'State Variable Default Visibility',
            '109': 'Uninitialized Storage Pointer',
            '110': 'Assert Violation',
            '112': 'Delegatecall to Untrusted Callee',
            '113': 'DoS with Failed Call',
            '114': 'Transaction Order Dependence',
            '115': 'Authorization through tx.origin',
            '116': 'Timestamp Dependence',
            '120': 'Weak Sources of Randomness',
            '123': 'Requirement Violation',
            '124': 'Write to Arbitrary Storage Location'
        }

        return swc_titles.get(swc_id, f'SWC-{swc_id}')

    def print_summary(self):
        """Print findings summary"""
        if not self.findings:
            return

        by_severity = {}
        for finding in self.findings:
            sev = finding['severity']
            by_severity[sev] = by_severity.get(sev, 0) + 1

        print(f"\n{Fore.CYAN}Severity breakdown:{Style.RESET_ALL}")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']:
            if sev in by_severity:
                count = by_severity[sev]
                color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.YELLOW,
                    'MEDIUM': Fore.CYAN,
                    'INFO': Fore.WHITE
                }.get(sev, Fore.WHITE)
                print(f"{color}{sev}: {count}{Style.RESET_ALL}")

    def get_critical_findings(self) -> List[Dict]:
        """
        Get only CRITICAL findings

        Returns:
            List of critical findings
        """
        return [f for f in self.findings if f['severity'] == 'CRITICAL']


def main():
    """CLI interface"""
    import sys

    if len(sys.argv) != 2:
        print("Usage: python mythril_runner.py <contract.sol>")
        sys.exit(1)

    runner = MythrilRunner(sys.argv[1])
    findings = runner.run()

    # Save to file
    with open('mythril_findings.json', 'w') as f:
        json.dump(findings, f, indent=2)

    print(f"\n{Fore.GREEN}[+] Report saved: mythril_findings.json{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
