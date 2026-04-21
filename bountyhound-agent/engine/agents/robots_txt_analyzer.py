"""
Robots.txt Analyzer Agent

Advanced robots.txt analysis agent that discovers sensitive paths, backup files,
admin panels, and other security-relevant information disclosed via robots.txt.

This agent analyzes:
- Disallowed paths (admin, backup, private, staging, etc.)
- Sitemap locations
- Crawl-delay directives
- User-agent specific rules
- Sensitive path patterns
- Information disclosure via robots.txt
- Wildcard patterns and directory structures

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class RobotsSeverity(Enum):
    """Severity levels for robots.txt findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PathCategory(Enum):
    """Categories of disallowed paths."""
    ADMIN = "admin"
    BACKUP = "backup"
    PRIVATE = "private"
    STAGING = "staging"
    CONFIG = "config"
    DATABASE = "database"
    API = "api"
    INTERNAL = "internal"
    DEVELOPMENT = "development"
    CREDENTIALS = "credentials"
    UPLOADS = "uploads"
    LOGS = "logs"
    UNKNOWN = "unknown"


@dataclass
class DisallowedPath:
    """Represents a disallowed path from robots.txt."""
    path: str
    category: PathCategory
    user_agent: str = "*"
    sensitivity: str = "medium"
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['category'] = self.category.value
        return data


@dataclass
class SitemapEntry:
    """Represents a sitemap entry."""
    url: str
    accessible: bool = False
    status_code: Optional[int] = None
    size_bytes: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class RobotsFinding:
    """Represents a robots.txt security finding."""
    title: str
    severity: RobotsSeverity
    description: str
    paths: List[str] = field(default_factory=list)
    sitemaps: List[str] = field(default_factory=list)
    poc: str = ""
    impact: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = "CWE-200"
    discovered_date: str = field(default_factory=lambda: date.today().isoformat())
    category: str = "information_disclosure"
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with enum handling."""
        data = asdict(self)
        data['severity'] = self.severity.value
        return data


class RobotsTxtAnalyzer:
    """
    Advanced Robots.txt Analyzer.

    Performs comprehensive robots.txt analysis including:
    - Sensitive path discovery
    - Admin panel detection
    - Backup file identification
    - Sitemap extraction and validation
    - Information disclosure analysis
    - Path categorization
    - Security misconfiguration detection

    Usage:
        analyzer = RobotsTxtAnalyzer(target="https://example.com")
        findings = analyzer.analyze()
    """

    # Sensitive path patterns
    SENSITIVE_PATTERNS = {
        PathCategory.ADMIN: [
            r'/admin', r'/administrator', r'/wp-admin', r'/cpanel',
            r'/phpmyadmin', r'/adminer', r'/admin_area', r'/admincp',
            r'/manage', r'/manager', r'/control', r'/backend', r'/dashboard'
        ],
        PathCategory.BACKUP: [
            r'/backup', r'/backups', r'\.bak', r'\.old', r'\.backup',
            r'/old', r'\.sql', r'\.dump', r'\.gz', r'\.tar', r'\.zip',
            r'/archive', r'/archives', r'~$', r'\.save'
        ],
        PathCategory.PRIVATE: [
            r'/private', r'/internal', r'/secret', r'/confidential',
            r'/restricted', r'/hidden', r'/_private', r'/priv'
        ],
        PathCategory.STAGING: [
            r'/staging', r'/stage', r'/dev', r'/development', r'/test',
            r'/testing', r'/qa', r'/uat', r'/preprod', r'/beta'
        ],
        PathCategory.CONFIG: [
            r'/config', r'/configuration', r'/settings', r'\.ini',
            r'\.conf', r'\.config', r'/cfg', r'\.yml', r'\.yaml',
            r'\.json', r'\.xml', r'/env', r'\.env'
        ],
        PathCategory.DATABASE: [
            r'/db', r'/database', r'/sql', r'/mysql', r'/postgres',
            r'/mongo', r'/redis', r'\.mdb', r'\.db', r'\.sqlite'
        ],
        PathCategory.API: [
            r'/api/v1', r'/api/v2', r'/api/internal', r'/api/admin',
            r'/api/private', r'/graphql', r'/_api', r'/rest'
        ],
        PathCategory.INTERNAL: [
            r'/internal', r'/_internal', r'/system', r'/_system',
            r'/core', r'/_core', r'/lib', r'/vendor'
        ],
        PathCategory.DEVELOPMENT: [
            r'/debug', r'/debugger', r'\.git', r'/.svn', r'/\.hg',
            r'/node_modules', r'/vendor', r'\.log', r'/tmp', r'/temp'
        ],
        PathCategory.CREDENTIALS: [
            r'/credentials', r'/creds', r'/auth', r'/password',
            r'/passwd', r'/ssh', r'/ssl', r'/keys', r'\.pem',
            r'\.key', r'\.crt', r'\.p12', r'\.jks'
        ],
        PathCategory.UPLOADS: [
            r'/uploads', r'/upload', r'/files', r'/media',
            r'/attachments', r'/documents', r'/images'
        ],
        PathCategory.LOGS: [
            r'/logs', r'/log', r'\.log', r'/error_log', r'/access_log',
            r'/debug.log', r'/trace', r'/audit'
        ]
    }

    # High-value targets (higher severity)
    HIGH_VALUE_KEYWORDS = [
        'admin', 'backup', 'config', 'password', 'credential',
        'secret', 'private', 'internal', 'database', 'sql',
        '.git', '.env', 'phpmyadmin', 'staging', 'dev'
    ]

    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = True,
                 test_paths: bool = True):
        """
        Initialize the Robots.txt Analyzer.

        Args:
            target: Target URL (e.g., https://example.com)
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            test_paths: Whether to test discovered paths for accessibility
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.target = target
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.test_paths = test_paths

        # Parse target URL
        self.parsed_url = urllib.parse.urlparse(
            target if '://' in target else f'https://{target}'
        )
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.domain = self.parsed_url.netloc

        # Storage
        self.robots_content: str = ""
        self.disallowed_paths: List[DisallowedPath] = []
        self.sitemaps: List[SitemapEntry] = []
        self.user_agents: Set[str] = set()
        self.crawl_delays: Dict[str, int] = {}
        self.findings: List[RobotsFinding] = []

    def analyze(self) -> List[RobotsFinding]:
        """
        Perform comprehensive robots.txt analysis.

        Returns:
            List of findings
        """
        # Fetch robots.txt
        if not self._fetch_robots_txt():
            return self.findings

        # Parse robots.txt
        self._parse_robots_txt()

        # Test sitemaps if requested
        if self.test_paths:
            self._test_sitemaps()

        # Categorize paths
        self._categorize_paths()

        # Generate findings
        self._generate_findings()

        return self.findings

    def _fetch_robots_txt(self) -> bool:
        """
        Fetch robots.txt from target.

        Returns:
            True if successful, False otherwise
        """
        robots_url = urllib.parse.urljoin(self.base_url, '/robots.txt')

        try:
            response = requests.get(
                robots_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers={'User-Agent': 'Mozilla/5.0 BountyHound Security Scanner'}
            )

            if response.status_code == 200:
                self.robots_content = response.text
                return True
            elif response.status_code == 404:
                # No robots.txt - generate INFO finding
                self._add_no_robots_finding()
                return False
            else:
                return False

        except requests.exceptions.RequestException:
            return False

    def _parse_robots_txt(self):
        """Parse robots.txt content."""
        if not self.robots_content:
            return

        current_user_agent = "*"

        for line in self.robots_content.split('\n'):
            # Clean line
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Parse directives
            if ':' not in line:
                continue

            directive, value = line.split(':', 1)
            directive = directive.strip().lower()
            value = value.strip()

            if directive == 'user-agent':
                current_user_agent = value
                self.user_agents.add(value)

            elif directive == 'disallow':
                if value:  # Ignore empty disallow
                    path = DisallowedPath(
                        path=value,
                        category=PathCategory.UNKNOWN,
                        user_agent=current_user_agent
                    )
                    self.disallowed_paths.append(path)

            elif directive == 'sitemap':
                sitemap = SitemapEntry(url=value)
                self.sitemaps.append(sitemap)

            elif directive == 'crawl-delay':
                try:
                    self.crawl_delays[current_user_agent] = int(value)
                except ValueError:
                    pass

    def _categorize_paths(self):
        """Categorize disallowed paths by sensitivity."""
        for path_obj in self.disallowed_paths:
            path = path_obj.path.lower()

            # Check against patterns
            for category, patterns in self.SENSITIVE_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        path_obj.category = category

                        # Determine sensitivity
                        if category in [PathCategory.ADMIN, PathCategory.BACKUP,
                                      PathCategory.CREDENTIALS, PathCategory.DATABASE]:
                            path_obj.sensitivity = "high"
                        elif category in [PathCategory.CONFIG, PathCategory.PRIVATE,
                                        PathCategory.STAGING]:
                            path_obj.sensitivity = "medium"
                        else:
                            path_obj.sensitivity = "low"

                        # Add reason
                        path_obj.reason = f"Matches {category.value} pattern: {pattern}"
                        break

                if path_obj.category != PathCategory.UNKNOWN:
                    break

    def _test_sitemaps(self):
        """Test sitemap URLs for accessibility."""
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self._test_sitemap, sitemap): sitemap
                      for sitemap in self.sitemaps}

            for future in as_completed(futures):
                sitemap = futures[future]
                result = future.result()

                if result:
                    sitemap.accessible = result[0]
                    sitemap.status_code = result[1]
                    sitemap.size_bytes = result[2]

    def _test_sitemap(self, sitemap: SitemapEntry) -> Optional[Tuple[bool, int, Optional[int]]]:
        """
        Test if sitemap is accessible.

        Returns:
            Tuple of (accessible, status_code, size_bytes) or None
        """
        try:
            response = requests.get(
                sitemap.url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers={'User-Agent': 'Mozilla/5.0'}
            )

            accessible = response.status_code == 200
            size = len(response.content) if accessible else None

            return (accessible, response.status_code, size)

        except requests.exceptions.RequestException:
            return None

    def _generate_findings(self):
        """Generate security findings from analysis."""
        # Group paths by category
        by_category: Dict[PathCategory, List[DisallowedPath]] = {}
        for path in self.disallowed_paths:
            if path.category not in by_category:
                by_category[path.category] = []
            by_category[path.category].append(path)

        # Generate findings for high-sensitivity categories
        high_sensitivity = [PathCategory.ADMIN, PathCategory.BACKUP,
                          PathCategory.CREDENTIALS, PathCategory.DATABASE,
                          PathCategory.CONFIG, PathCategory.PRIVATE]

        for category in high_sensitivity:
            if category in by_category and by_category[category]:
                self._create_category_finding(category, by_category[category])

        # Generate sitemap finding
        if self.sitemaps:
            self._create_sitemap_finding()

        # Generate user-agent specific finding
        if len(self.user_agents) > 1 and '*' not in self.user_agents:
            self._create_user_agent_finding()

        # Generate overall information disclosure finding
        if len(self.disallowed_paths) > 10:
            self._create_info_disclosure_finding()

    def _create_category_finding(self, category: PathCategory, paths: List[DisallowedPath]):
        """Create finding for a specific path category."""
        # Determine severity
        severity_map = {
            PathCategory.ADMIN: RobotsSeverity.HIGH,
            PathCategory.BACKUP: RobotsSeverity.HIGH,
            PathCategory.CREDENTIALS: RobotsSeverity.CRITICAL,
            PathCategory.DATABASE: RobotsSeverity.HIGH,
            PathCategory.CONFIG: RobotsSeverity.MEDIUM,
            PathCategory.PRIVATE: RobotsSeverity.MEDIUM,
        }

        severity = severity_map.get(category, RobotsSeverity.LOW)

        # Build description
        path_list = [p.path for p in paths]
        description = f"robots.txt discloses {len(paths)} {category.value}-related path(s). "
        description += "These paths may contain sensitive functionality or data."

        # Build POC
        poc = f"# Access robots.txt\ncurl '{self.base_url}/robots.txt'\n\n"
        poc += f"# Disclosed {category.value} paths:\n"
        for path in path_list[:10]:  # Limit to 10 examples
            full_url = urllib.parse.urljoin(self.base_url, path)
            poc += f"# {full_url}\n"

        # Build impact
        impact_map = {
            PathCategory.ADMIN: "An attacker can:\n- Discover admin panel locations\n- Attempt unauthorized access\n- Enumerate admin functionality\n- Target specific admin exploits",
            PathCategory.BACKUP: "An attacker can:\n- Download backup files containing sensitive data\n- Extract source code and credentials\n- Access historical data and configurations\n- Reverse engineer application logic",
            PathCategory.CREDENTIALS: "An attacker can:\n- Access credential files and private keys\n- Compromise authentication mechanisms\n- Gain unauthorized access to systems\n- Escalate privileges",
            PathCategory.DATABASE: "An attacker can:\n- Discover database endpoints and files\n- Attempt database access and extraction\n- Download database dumps\n- Identify database technology stack",
            PathCategory.CONFIG: "An attacker can:\n- Access configuration files\n- Extract API keys and secrets\n- Understand system architecture\n- Identify misconfigurations",
            PathCategory.PRIVATE: "An attacker can:\n- Access private functionality\n- Enumerate internal features\n- Discover undocumented endpoints\n- Test for authorization flaws",
        }

        impact = impact_map.get(category, "An attacker can discover and attempt to access sensitive paths.")

        # Build recommendation
        recommendation = f"1. Remove {category.value} paths from robots.txt\n"
        recommendation += "2. Use proper access controls instead of obscurity\n"
        recommendation += "3. Implement authentication/authorization at application level\n"
        recommendation += "4. Monitor access to sensitive paths\n"
        recommendation += "5. Consider using X-Robots-Tag header instead"

        # Determine CWE
        cwe_map = {
            PathCategory.ADMIN: "CWE-200",
            PathCategory.BACKUP: "CWE-530",
            PathCategory.CREDENTIALS: "CWE-532",
            PathCategory.DATABASE: "CWE-200",
            PathCategory.CONFIG: "CWE-209",
            PathCategory.PRIVATE: "CWE-200",
        }

        finding = RobotsFinding(
            title=f"Sensitive {category.value.title()} Paths Disclosed in robots.txt",
            severity=severity,
            description=description,
            paths=path_list,
            poc=poc,
            impact=impact,
            recommendation=recommendation,
            cwe_id=cwe_map.get(category, "CWE-200"),
            category=category.value,
            raw_data={'paths': [p.to_dict() for p in paths]}
        )

        self.findings.append(finding)

    def _create_sitemap_finding(self):
        """Create finding for sitemap disclosure."""
        accessible_sitemaps = [s for s in self.sitemaps if s.accessible]

        severity = RobotsSeverity.INFO
        if len(accessible_sitemaps) > 0:
            severity = RobotsSeverity.LOW

        description = f"robots.txt discloses {len(self.sitemaps)} sitemap(s). "
        if accessible_sitemaps:
            description += f"{len(accessible_sitemaps)} are publicly accessible and may reveal site structure."

        poc = f"# Access robots.txt\ncurl '{self.base_url}/robots.txt'\n\n"
        poc += "# Disclosed sitemaps:\n"
        for sitemap in self.sitemaps[:5]:
            poc += f"curl '{sitemap.url}'\n"

        impact = "An attacker can:\n"
        impact += "- Enumerate all site pages and endpoints\n"
        impact += "- Discover hidden or unlisted pages\n"
        impact += "- Understand site structure and organization\n"
        impact += "- Identify high-value targets for testing"

        recommendation = "1. Ensure sitemaps don't expose sensitive or internal pages\n"
        recommendation += "2. Use authentication for admin/internal sitemaps\n"
        recommendation += "3. Review sitemap contents for information disclosure\n"
        recommendation += "4. Consider using sitemap index files for organization"

        finding = RobotsFinding(
            title="Sitemap Disclosure in robots.txt",
            severity=severity,
            description=description,
            sitemaps=[s.url for s in self.sitemaps],
            poc=poc,
            impact=impact,
            recommendation=recommendation,
            cwe_id="CWE-200",
            category="sitemap",
            raw_data={'sitemaps': [s.to_dict() for s in self.sitemaps]}
        )

        self.findings.append(finding)

    def _create_user_agent_finding(self):
        """Create finding for user-agent specific rules."""
        description = f"robots.txt contains rules for {len(self.user_agents)} specific user-agent(s). "
        description += "This may indicate different access levels or hidden content."

        poc = f"# Access robots.txt\ncurl '{self.base_url}/robots.txt'\n\n"
        poc += "# User-agents with specific rules:\n"
        for ua in self.user_agents:
            poc += f"# {ua}\n"

        impact = "An attacker can:\n"
        impact += "- Identify user-agent specific content restrictions\n"
        impact += "- Spoof user-agents to access different content\n"
        impact += "- Discover bot-specific or crawler-specific paths\n"
        impact += "- Bypass certain restrictions by changing user-agent"

        recommendation = "1. Review user-agent specific rules for security implications\n"
        recommendation += "2. Don't rely on user-agent for access control\n"
        recommendation += "3. Use proper authentication instead\n"
        recommendation += "4. Ensure sensitive content isn't exposed to specific bots"

        finding = RobotsFinding(
            title="User-Agent Specific Rules in robots.txt",
            severity=RobotsSeverity.INFO,
            description=description,
            poc=poc,
            impact=impact,
            recommendation=recommendation,
            cwe_id="CWE-200",
            category="user_agent",
            raw_data={'user_agents': list(self.user_agents)}
        )

        self.findings.append(finding)

    def _create_info_disclosure_finding(self):
        """Create overall information disclosure finding."""
        high_value_paths = []
        for path_obj in self.disallowed_paths:
            path_lower = path_obj.path.lower()
            if any(keyword in path_lower for keyword in self.HIGH_VALUE_KEYWORDS):
                high_value_paths.append(path_obj.path)

        if not high_value_paths:
            return

        description = f"robots.txt discloses {len(high_value_paths)} potentially sensitive path(s) "
        description += "containing high-value keywords (admin, backup, config, etc.)."

        poc = f"# Access robots.txt\ncurl '{self.base_url}/robots.txt'\n\n"
        poc += "# High-value paths disclosed:\n"
        for path in high_value_paths[:15]:
            full_url = urllib.parse.urljoin(self.base_url, path)
            poc += f"# {full_url}\n"

        impact = "An attacker can:\n"
        impact += "- Systematically enumerate sensitive paths\n"
        impact += "- Prioritize high-value targets for exploitation\n"
        impact += "- Map out protected areas of the application\n"
        impact += "- Understand security boundaries"

        recommendation = "1. Minimize sensitive path disclosure in robots.txt\n"
        recommendation += "2. Use allow-lists instead of block-lists\n"
        recommendation += "3. Implement proper access controls\n"
        recommendation += "4. Don't rely on obscurity for security\n"
        recommendation += "5. Regular review robots.txt for information leakage"

        severity = RobotsSeverity.MEDIUM
        if len(high_value_paths) > 20:
            severity = RobotsSeverity.HIGH

        finding = RobotsFinding(
            title="Extensive Information Disclosure via robots.txt",
            severity=severity,
            description=description,
            paths=high_value_paths,
            poc=poc,
            impact=impact,
            recommendation=recommendation,
            cwe_id="CWE-200",
            category="information_disclosure",
            raw_data={'high_value_paths': high_value_paths}
        )

        self.findings.append(finding)

    def _add_no_robots_finding(self):
        """Add finding when no robots.txt exists."""
        finding = RobotsFinding(
            title="No robots.txt File Found",
            severity=RobotsSeverity.INFO,
            description="The target does not have a robots.txt file. This is informational only.",
            poc=f"curl '{self.base_url}/robots.txt'\n# Returns: 404 Not Found",
            impact="No impact. The absence of robots.txt is not a security issue.",
            recommendation="No action required. Consider adding robots.txt for SEO purposes.",
            cwe_id=None,
            category="informational"
        )

        self.findings.append(finding)

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report."""
        return {
            'target': self.base_url,
            'domain': self.domain,
            'scan_date': date.today().isoformat(),
            'robots_txt_exists': bool(self.robots_content),
            'total_disallowed_paths': len(self.disallowed_paths),
            'total_sitemaps': len(self.sitemaps),
            'user_agents': list(self.user_agents),
            'crawl_delays': self.crawl_delays,
            'findings': [f.to_dict() for f in self.findings],
            'disallowed_paths': [p.to_dict() for p in self.disallowed_paths],
            'sitemaps': [s.to_dict() for s in self.sitemaps],
            'raw_robots_txt': self.robots_content
        }


def main():
    """Main execution function."""
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python robots_txt_analyzer.py <target-url>")
        sys.exit(1)

    target = sys.argv[1]

    analyzer = RobotsTxtAnalyzer(target)
    findings = analyzer.analyze()

    report = analyzer.generate_report()

    # Print summary
    print(f"\nRobots.txt Analysis Results")
    print(f"{'='*60}")
    print(f"Target: {analyzer.base_url}")
    print(f"Robots.txt Exists: {bool(analyzer.robots_content)}")
    print(f"Disallowed Paths: {len(analyzer.disallowed_paths)}")
    print(f"Sitemaps: {len(analyzer.sitemaps)}")
    print(f"User Agents: {len(analyzer.user_agents)}")
    print(f"Findings: {len(findings)}")

    # Print findings by severity
    severity_counts = {}
    for finding in findings:
        sev = finding.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\nFindings by Severity:")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if sev in severity_counts:
            print(f"  {sev}: {severity_counts[sev]}")

    # Save report
    output_file = f"robots_analysis_{analyzer.domain.replace('.', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved to {output_file}")


if __name__ == '__main__':
    main()
