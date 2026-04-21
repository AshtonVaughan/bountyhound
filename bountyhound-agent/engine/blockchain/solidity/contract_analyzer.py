"""
Smart Contract Security Analyzer
Comprehensive Solidity security analysis using multiple tools
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional
from colorama import Fore, Style

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class ContractAnalyzer:
    """
    Comprehensive smart contract security analyzer
    Combines Slither, Mythril, and manual checks
    """

    def __init__(self, contract_path: str, target: Optional[str] = None):
        """
        Initialize contract analyzer

        Args:
            contract_path: Path to Solidity file or directory
            target: Target identifier for database tracking (default: contract filename)
        """
        self.contract_path = Path(contract_path)
        self.target = target or self.contract_path.stem  # Use contract name as target
        self.findings = []

        if not self.contract_path.exists():
            raise FileNotFoundError(f"Contract not found: {contract_path}")

    def analyze(self) -> Dict:
        """
        Run complete security analysis

        Returns:
            Dictionary containing all findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'contract_analyzer')

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

        print(f"{Fore.CYAN}[*] Analyzing contract: {self.contract_path.name}{Style.RESET_ALL}")

        results = {
            "contract": str(self.contract_path),
            "static_analysis": self.run_slither(),
            "symbolic_execution": self.run_mythril(),
            "manual_checks": self.manual_security_checks(),
            "findings": self.findings
        }

        # Record tool run
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'contract_analyzer',
            findings_count=len(self.findings),
            success=True
        )

        self.print_summary(results)
        return results

    def run_slither(self) -> List[Dict]:
        """
        Run Slither static analysis

        Returns:
            List of Slither findings
        """
        print(f"{Fore.CYAN}[*] Running Slither static analysis...{Style.RESET_ALL}")

        try:
            result = subprocess.run(
                ['slither', str(self.contract_path), '--json', '-'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0 or result.stdout:
                data = json.loads(result.stdout)
                findings = data.get('results', {}).get('detectors', [])

                print(f"{Fore.GREEN}[+] Slither found {len(findings)} issues{Style.RESET_ALL}")

                for finding in findings:
                    severity = finding.get('impact', 'UNKNOWN').upper()
                    title = finding.get('check', '')
                    description = finding.get('description', '')

                    self.add_finding(severity, f"Slither: {title}", description)

                return findings

        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] Slither not installed. Install: pip install slither-analyzer{Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Slither timeout{Style.RESET_ALL}")
        except json.JSONDecodeError:
            print(f"{Fore.YELLOW}[!] Slither output not JSON{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Slither error: {e}{Style.RESET_ALL}")

        return []

    def run_mythril(self) -> List[Dict]:
        """
        Run Mythril symbolic execution

        Returns:
            List of Mythril findings
        """
        print(f"{Fore.CYAN}[*] Running Mythril symbolic execution...{Style.RESET_ALL}")

        try:
            result = subprocess.run(
                ['myth', 'analyze', str(self.contract_path), '--execution-timeout', '60'],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.stdout:
                print(f"{Fore.GREEN}[+] Mythril analysis complete{Style.RESET_ALL}")

                # Parse Mythril output
                if "SWC ID:" in result.stdout:
                    self.add_finding("HIGH", "Mythril: Vulnerability found",
                                   result.stdout[:500])

                return [{"output": result.stdout}]

        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] Mythril not installed. Install: pip install mythril{Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Mythril timeout{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Mythril error: {e}{Style.RESET_ALL}")

        return []

    def manual_security_checks(self) -> List[Dict]:
        """
        Manual security pattern checks

        Returns:
            List of manual findings
        """
        print(f"{Fore.CYAN}[*] Running manual security checks...{Style.RESET_ALL}")

        checks = []

        # Read contract source
        try:
            source = self.contract_path.read_text()
        except:
            return checks

        # Check 1: Reentrancy patterns
        if self.check_reentrancy(source):
            checks.append({
                "check": "Reentrancy",
                "severity": "CRITICAL",
                "description": "Potential reentrancy vulnerability detected"
            })
            self.add_finding("CRITICAL", "Reentrancy Risk",
                           "External call before state update - check for reentrancy")

        # Check 2: Unchecked external calls
        if "call.value" in source or ".call{value:" in source:
            if "require(" not in source.split("call")[1].split("\n")[0]:
                checks.append({
                    "check": "Unchecked Call",
                    "severity": "HIGH",
                    "description": "External call without return value check"
                })
                self.add_finding("HIGH", "Unchecked External Call",
                               "External call without checking return value")

        # Check 3: tx.origin usage
        if "tx.origin" in source:
            checks.append({
                "check": "tx.origin",
                "severity": "MEDIUM",
                "description": "Using tx.origin for authorization is insecure"
            })
            self.add_finding("MEDIUM", "tx.origin Usage",
                           "Use msg.sender instead of tx.origin for auth")

        # Check 4: Delegatecall to user-controlled data
        if "delegatecall" in source:
            checks.append({
                "check": "Delegatecall",
                "severity": "CRITICAL",
                "description": "delegatecall usage - verify target address is trusted"
            })
            self.add_finding("CRITICAL", "Delegatecall Risk",
                           "delegatecall can execute arbitrary code - ensure target is trusted")

        # Check 5: Selfdestruct
        if "selfdestruct" in source or "suicide" in source:
            checks.append({
                "check": "Selfdestruct",
                "severity": "HIGH",
                "description": "Contract has selfdestruct - check access control"
            })
            self.add_finding("HIGH", "Selfdestruct Present",
                           "Verify selfdestruct has proper access control")

        print(f"{Fore.GREEN}[+] Manual checks found {len(checks)} issues{Style.RESET_ALL}")

        return checks

    def check_reentrancy(self, source: str) -> bool:
        """
        Check for reentrancy patterns

        Simple heuristic: external call before state change
        """
        lines = source.split('\n')

        for i, line in enumerate(lines):
            # Look for external calls
            if any(pattern in line for pattern in ['.call{', '.transfer(', '.send(']):
                # Check if state update happens after
                for j in range(i + 1, min(i + 5, len(lines))):
                    if '=' in lines[j] and 'balance' in lines[j].lower():
                        return True  # Potential reentrancy

        return False

    def add_finding(self, severity: str, title: str, description: str):
        """Add security finding"""
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description
        })

    def print_summary(self, results: Dict):
        """Print analysis summary"""
        print(f"\n{Fore.CYAN}=== ANALYSIS SUMMARY ==={Style.RESET_ALL}")
        print(f"Contract: {results['contract']}")
        print(f"Total findings: {len(self.findings)}")

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
        print("Usage: python contract_analyzer.py <contract.sol>")
        sys.exit(1)

    contract_path = sys.argv[1]
    analyzer = ContractAnalyzer(contract_path)
    results = analyzer.analyze()

    # Save report
    output_file = "contract_security_report.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n{Fore.GREEN}[+] Report saved: {output_file}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
