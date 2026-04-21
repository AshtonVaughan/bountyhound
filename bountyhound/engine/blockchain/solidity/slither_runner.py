"""
Slither Static Analyzer Runner
Wrapper for Slither smart contract analyzer
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional
from colorama import Fore, Style

# Database integration
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


class SlitherRunner:
    """
    Run Slither static analysis on Solidity contracts
    """

    def __init__(self, contract_path: str, target: Optional[str] = None):
        self.contract_path = Path(contract_path)
        self.target = target or self.contract_path.stem  # Use contract name as target
        self.findings = []

    def run(self) -> List[Dict]:
        """
        Run Slither analysis

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'slither_runner')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP]  SKIP: {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Running Slither on {self.contract_path.name}...{Style.RESET_ALL}")

        try:
            # Run Slither with JSON output
            result = subprocess.run(
                [
                    'slither',
                    str(self.contract_path),
                    '--json', '-',
                    '--exclude-dependencies'
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.stdout:
                data = json.loads(result.stdout)
                detectors = data.get('results', {}).get('detectors', [])

                self.findings = self.process_findings(detectors)

                print(f"{Fore.GREEN}[+] Found {len(self.findings)} issues{Style.RESET_ALL}")
                self.print_summary()

                # Record tool run
                db = BountyHoundDB()
                db.record_tool_run(
                    self.target,
                    'slither_runner',
                    findings_count=len(self.findings),
                    success=True
                )

                return self.findings

        except FileNotFoundError:
            print(f"{Fore.RED}[-] Slither not found. Install: pip install slither-analyzer{Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Analysis timeout{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

        return []

    def process_findings(self, detectors: List[Dict]) -> List[Dict]:
        """Process and categorize Slither findings"""
        findings = []

        impact_map = {
            'High': 'CRITICAL',
            'Medium': 'HIGH',
            'Low': 'MEDIUM',
            'Informational': 'INFO'
        }

        for detector in detectors:
            finding = {
                "severity": impact_map.get(detector.get('impact', 'Low'), 'MEDIUM'),
                "title": detector.get('check', ''),
                "description": detector.get('description', ''),
                "confidence": detector.get('confidence', ''),
                "locations": []
            }

            # Extract code locations
            for element in detector.get('elements', []):
                if 'source_mapping' in element:
                    location = element['source_mapping']
                    finding['locations'].append({
                        "file": location.get('filename_short', ''),
                        "lines": location.get('lines', [])
                    })

            findings.append(finding)

        return findings

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
        """Get only CRITICAL findings"""
        return [f for f in self.findings if f['severity'] == 'CRITICAL']


def main():
    """CLI interface"""
    import sys

    if len(sys.argv) != 2:
        print("Usage: python slither_runner.py <contract.sol>")
        sys.exit(1)

    runner = SlitherRunner(sys.argv[1])
    findings = runner.run()

    # Save to file
    with open('slither_findings.json', 'w') as f:
        json.dump(findings, f, indent=2)

    print(f"\n{Fore.GREEN}[+] Report saved: slither_findings.json{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
