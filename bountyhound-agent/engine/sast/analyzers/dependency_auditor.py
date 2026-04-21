"""
Dependency Security Auditor
Analyze package manifests for known vulnerabilities and outdated dependencies
"""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from colorama import Fore, Style

from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


@dataclass
class DependencyFinding:
    """A vulnerability found in a dependency"""
    package: str
    version: str
    manifest_file: str
    severity: str
    cve: str
    description: str
    fixed_version: str = ''
    ecosystem: str = ''  # npm, pip, maven, gem, go


# Known vulnerable package versions (curated high-impact CVEs)
# Format: {ecosystem: {package: [(vuln_version_range, cve, severity, description, fixed_version)]}}
KNOWN_VULNS = {
    'npm': {
        'lodash': [('<4.17.21', 'CVE-2021-23337', 'CRITICAL', 'Prototype pollution via template', '4.17.21')],
        'express': [('<4.17.3', 'CVE-2022-24999', 'HIGH', 'Open redirect via qs', '4.17.3')],
        'minimist': [('<1.2.6', 'CVE-2021-44906', 'CRITICAL', 'Prototype pollution', '1.2.6')],
        'jsonwebtoken': [('<9.0.0', 'CVE-2022-23529', 'HIGH', 'Insecure key handling', '9.0.0')],
        'axios': [('<0.21.2', 'CVE-2021-3749', 'HIGH', 'ReDoS via trim', '0.21.2')],
        'node-fetch': [('<2.6.7', 'CVE-2022-0235', 'HIGH', 'Cookie leakage on redirect', '2.6.7')],
        'qs': [('<6.10.3', 'CVE-2022-24999', 'HIGH', 'Prototype pollution', '6.10.3')],
        'moment': [('<2.29.4', 'CVE-2022-31129', 'HIGH', 'ReDoS in date parsing', '2.29.4')],
        'underscore': [('<1.13.6', 'CVE-2021-23358', 'CRITICAL', 'Arbitrary code execution via template', '1.13.6')],
        'tar': [('<6.1.9', 'CVE-2021-37713', 'CRITICAL', 'Path traversal', '6.1.9')],
        'glob-parent': [('<5.1.2', 'CVE-2020-28469', 'HIGH', 'ReDoS', '5.1.2')],
        'path-parse': [('<1.0.7', 'CVE-2021-23343', 'HIGH', 'ReDoS', '1.0.7')],
        'shelljs': [('<0.8.5', 'CVE-2022-0144', 'HIGH', 'Improper privilege management', '0.8.5')],
        'nanoid': [('<3.1.31', 'CVE-2021-23566', 'MEDIUM', 'Predictable random values', '3.1.31')],
    },
    'pip': {
        'django': [('<3.2.25', 'CVE-2024-24680', 'HIGH', 'Denial of service in intcomma', '3.2.25')],
        'flask': [('<2.3.2', 'CVE-2023-30861', 'HIGH', 'Session cookie vulnerability', '2.3.2')],
        'requests': [('<2.31.0', 'CVE-2023-32681', 'MEDIUM', 'Proxy credential leak', '2.31.0')],
        'pillow': [('<10.0.1', 'CVE-2023-44271', 'HIGH', 'DoS via large images', '10.0.1')],
        'cryptography': [('<41.0.4', 'CVE-2023-38325', 'HIGH', 'NULL-dereference in PKCS7', '41.0.4')],
        'pyyaml': [('<6.0.1', 'CVE-2020-14343', 'CRITICAL', 'Arbitrary code execution', '6.0.1')],
        'jinja2': [('<3.1.3', 'CVE-2024-22195', 'MEDIUM', 'XSS in xmlattr filter', '3.1.3')],
        'urllib3': [('<2.0.7', 'CVE-2023-45803', 'MEDIUM', 'Request body leak on redirect', '2.0.7')],
        'sqlalchemy': [('<1.4.49', 'CVE-2023-30533', 'MEDIUM', 'SQL injection in Textual SQL', '1.4.49')],
        'paramiko': [('<3.4.0', 'CVE-2023-48795', 'HIGH', 'Terrapin attack on SSH', '3.4.0')],
    },
    'maven': {
        'log4j-core': [('<2.17.1', 'CVE-2021-44228', 'CRITICAL', 'Log4Shell RCE', '2.17.1')],
        'spring-core': [('<5.3.18', 'CVE-2022-22965', 'CRITICAL', 'Spring4Shell RCE', '5.3.18')],
        'commons-text': [('<1.10.0', 'CVE-2022-42889', 'CRITICAL', 'Text4Shell RCE', '1.10.0')],
        'jackson-databind': [('<2.13.4.1', 'CVE-2022-42003', 'HIGH', 'Deserialization gadget chain', '2.13.4.1')],
        'snakeyaml': [('<2.0', 'CVE-2022-1471', 'CRITICAL', 'Arbitrary code execution via Constructor', '2.0')],
        'commons-collections': [('<3.2.2', 'CVE-2015-7501', 'CRITICAL', 'Deserialization RCE', '3.2.2')],
        'spring-security-core': [('<5.7.5', 'CVE-2022-31692', 'HIGH', 'Authorization bypass', '5.7.5')],
    },
    'gem': {
        'rails': [('<7.0.4.1', 'CVE-2023-22795', 'HIGH', 'ReDoS in Action Dispatch', '7.0.4.1')],
        'nokogiri': [('<1.14.3', 'CVE-2023-29469', 'HIGH', 'libxml2 DoS', '1.14.3')],
        'rack': [('<2.2.6.2', 'CVE-2023-27530', 'HIGH', 'DoS via multipart parsing', '2.2.6.2')],
        'puma': [('<5.6.5', 'CVE-2022-24790', 'CRITICAL', 'HTTP request smuggling', '5.6.5')],
    },
}

# Manifest files to look for
MANIFEST_FILES = {
    'package.json': 'npm',
    'package-lock.json': 'npm',
    'yarn.lock': 'npm',
    'requirements.txt': 'pip',
    'Pipfile.lock': 'pip',
    'setup.py': 'pip',
    'pyproject.toml': 'pip',
    'pom.xml': 'maven',
    'build.gradle': 'maven',
    'Gemfile': 'gem',
    'Gemfile.lock': 'gem',
    'go.mod': 'go',
    'go.sum': 'go',
    'Cargo.toml': 'cargo',
    'composer.json': 'php',
}


class DependencyAuditor:
    """Audit dependencies for known vulnerabilities"""

    def __init__(self, repo_path: str, target: Optional[str] = None):
        self.repo_path = Path(repo_path)
        self.target = target or self.repo_path.name
        self.findings: List[DependencyFinding] = []
        self.manifests_found: List[str] = []
        self.dependencies: Dict[str, Dict[str, str]] = {}  # {ecosystem: {pkg: version}}

    def audit(self) -> List[DependencyFinding]:
        """Full dependency audit"""
        context = DatabaseHooks.before_test(self.target, 'dependency_auditor')
        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            return self.findings

        self.findings = []
        self._discover_manifests()

        for manifest in self.manifests_found:
            self._parse_manifest(manifest)

        self._check_known_vulns()

        # Try npm audit / pip-audit if available
        self._run_npm_audit()
        self._run_pip_audit()

        db = BountyHoundDB()
        db.record_tool_run(self.target, 'dependency_auditor',
                          findings_count=len(self.findings), duration_seconds=0)
        return self.findings

    def _discover_manifests(self):
        """Find all manifest files in repo"""
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in {'node_modules', '.git', 'vendor', 'venv', '.venv'}]
            for f in files:
                if f in MANIFEST_FILES:
                    self.manifests_found.append(str(Path(root) / f))

    def _parse_manifest(self, manifest_path: str):
        """Parse a manifest file to extract dependencies"""
        path = Path(manifest_path)
        ecosystem = MANIFEST_FILES.get(path.name, 'unknown')

        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return

        if path.name == 'package.json':
            self._parse_package_json(content, ecosystem)
        elif path.name == 'requirements.txt':
            self._parse_requirements_txt(content, ecosystem)
        elif path.name == 'Gemfile':
            self._parse_gemfile(content, ecosystem)
        elif path.name == 'go.mod':
            self._parse_go_mod(content, ecosystem)
        elif path.name == 'pom.xml':
            self._parse_pom_xml(content, ecosystem)
        elif path.name == 'pyproject.toml':
            self._parse_pyproject_toml(content, ecosystem)

    def _parse_package_json(self, content: str, ecosystem: str):
        try:
            data = json.loads(content)
            for section in ['dependencies', 'devDependencies']:
                for pkg, ver in data.get(section, {}).items():
                    clean_ver = re.sub(r'[^0-9.]', '', ver)
                    if clean_ver:
                        self.dependencies.setdefault(ecosystem, {})[pkg] = clean_ver
        except json.JSONDecodeError:
            pass

    def _parse_requirements_txt(self, content: str, ecosystem: str):
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            match = re.match(r'([a-zA-Z0-9_-]+)\s*(?:==|>=|~=)\s*([0-9.]+)', line)
            if match:
                self.dependencies.setdefault(ecosystem, {})[match.group(1).lower()] = match.group(2)

    def _parse_gemfile(self, content: str, ecosystem: str):
        for line in content.split('\n'):
            match = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:.*['\"]([~>=<\s]*[0-9.]+)['\"])?", line)
            if match:
                ver = re.sub(r'[^0-9.]', '', match.group(2) or '0')
                if ver:
                    self.dependencies.setdefault(ecosystem, {})[match.group(1)] = ver

    def _parse_go_mod(self, content: str, ecosystem: str):
        for line in content.split('\n'):
            match = re.match(r'\s+([a-zA-Z0-9./\-_]+)\s+v([0-9.]+)', line)
            if match:
                self.dependencies.setdefault(ecosystem, {})[match.group(1).split('/')[-1]] = match.group(2)

    def _parse_pom_xml(self, content: str, ecosystem: str):
        # Simple regex for Maven deps
        for match in re.finditer(r'<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>', content):
            self.dependencies.setdefault(ecosystem, {})[match.group(1)] = match.group(2)

    def _parse_pyproject_toml(self, content: str, ecosystem: str):
        # Simple extraction from [project.dependencies]
        in_deps = False
        for line in content.split('\n'):
            if '[project.dependencies]' in line or 'dependencies' in line:
                in_deps = True
                continue
            if in_deps and line.startswith('['):
                break
            if in_deps:
                match = re.match(r'"?([a-zA-Z0-9_-]+)[>=~!]*([0-9.]+)?', line.strip().strip('"').strip("'"))
                if match and match.group(2):
                    self.dependencies.setdefault(ecosystem, {})[match.group(1).lower()] = match.group(2)

    def _version_lt(self, v1: str, v2: str) -> bool:
        """Compare version strings: returns True if v1 < v2"""
        try:
            parts1 = [int(x) for x in v1.split('.')[:3]]
            parts2 = [int(x) for x in v2.strip('<').split('.')[:3]]
            while len(parts1) < 3:
                parts1.append(0)
            while len(parts2) < 3:
                parts2.append(0)
            return parts1 < parts2
        except (ValueError, IndexError):
            return False

    def _check_known_vulns(self):
        """Check discovered dependencies against known vulnerability database"""
        for ecosystem, deps in self.dependencies.items():
            known = KNOWN_VULNS.get(ecosystem, {})
            for pkg, version in deps.items():
                if pkg in known:
                    for vuln_range, cve, severity, desc, fixed in known[pkg]:
                        threshold = vuln_range.strip('<')
                        if self._version_lt(version, threshold):
                            self.findings.append(DependencyFinding(
                                package=pkg, version=version,
                                manifest_file=f'{ecosystem} manifest',
                                severity=severity, cve=cve,
                                description=desc, fixed_version=fixed,
                                ecosystem=ecosystem,
                            ))

    def _run_npm_audit(self):
        """Run npm audit if available and package-lock.json exists"""
        lock_files = [m for m in self.manifests_found if 'package-lock.json' in m]
        if not lock_files:
            return
        try:
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                cwd=str(Path(lock_files[0]).parent),
                capture_output=True, text=True, timeout=60
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for vuln_name, vuln_data in data.get('vulnerabilities', {}).items():
                    if isinstance(vuln_data, dict):
                        self.findings.append(DependencyFinding(
                            package=vuln_name,
                            version=vuln_data.get('range', 'unknown'),
                            manifest_file='npm audit',
                            severity=vuln_data.get('severity', 'MEDIUM').upper(),
                            cve=vuln_data.get('via', [{}])[0].get('url', '') if isinstance(vuln_data.get('via', [{}])[0], dict) else '',
                            description=vuln_data.get('via', [{}])[0].get('title', '') if isinstance(vuln_data.get('via', [{}])[0], dict) else str(vuln_data.get('via', '')),
                            ecosystem='npm',
                        ))
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

    def _run_pip_audit(self):
        """Run pip-audit if available"""
        req_files = [m for m in self.manifests_found if 'requirements.txt' in m]
        if not req_files:
            return
        try:
            result = subprocess.run(
                ['pip-audit', '-r', req_files[0], '--format', 'json'],
                capture_output=True, text=True, timeout=120
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for vuln in data:
                    self.findings.append(DependencyFinding(
                        package=vuln.get('name', ''),
                        version=vuln.get('version', ''),
                        manifest_file='pip-audit',
                        severity='HIGH',
                        cve=vuln.get('id', ''),
                        description=vuln.get('description', ''),
                        fixed_version=vuln.get('fix_versions', [''])[0] if vuln.get('fix_versions') else '',
                        ecosystem='pip',
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

    def summary(self) -> Dict:
        return {
            'manifests_found': len(self.manifests_found),
            'total_dependencies': sum(len(d) for d in self.dependencies.values()),
            'total_findings': len(self.findings),
            'by_severity': {s: sum(1 for f in self.findings if f.severity == s)
                           for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']},
            'by_ecosystem': {e: sum(1 for f in self.findings if f.ecosystem == e)
                            for e in set(f.ecosystem for f in self.findings)},
        }

    def print_report(self):
        severity_colors = {'CRITICAL': Fore.RED, 'HIGH': Fore.YELLOW, 'MEDIUM': Fore.CYAN, 'LOW': Fore.WHITE}
        for f in sorted(self.findings, key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW'].index(x.severity)):
            color = severity_colors.get(f.severity, Fore.WHITE)
            print(f"{color}[{f.severity}] {f.package} {f.version} - {f.cve}{Style.RESET_ALL}")
            print(f"  {f.description}")
            if f.fixed_version:
                print(f"  Fix: upgrade to {f.fixed_version}")
        s = self.summary()
        print(f"\n{Fore.GREEN}=== Dependency Audit Summary ==={Style.RESET_ALL}")
        print(f"  Manifests: {s['manifests_found']}, Dependencies: {s['total_dependencies']}, Findings: {s['total_findings']}")
