"""
Git Repository Security Scanner
Scan git history for secrets, analyze commit patterns, find deleted sensitive files
"""

import subprocess
import re
import os
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from colorama import Fore, Style

from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


@dataclass
class RepoFinding:
    """A security finding in repository history"""
    finding_type: str  # secret_in_history, deleted_sensitive_file, suspicious_commit, exposed_config
    severity: str
    description: str
    commit_hash: str = ''
    commit_message: str = ''
    file_path: str = ''
    evidence: str = ''


# Secret patterns to search in git history
HISTORY_SECRET_PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'(?:aws_secret|AWS_SECRET|secret_key)\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{40})',
    'GitHub Token': r'gh[ps]_[A-Za-z0-9_]{36,}',
    'GitLab Token': r'glpat-[A-Za-z0-9_\-]{20,}',
    'Slack Token': r'xox[baprs]-[0-9A-Za-z\-]{10,}',
    'Slack Webhook': r'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Stripe Key': r'sk_live_[0-9a-zA-Z]{24,}',
    'Stripe Publishable': r'pk_live_[0-9a-zA-Z]{24,}',
    'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'Private Key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    'JWT Token': r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+',
    'Generic Secret': r'(?:secret|password|passwd|token|api_key|apikey|auth)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',
    'Database URL': r'(?:mysql|postgres|mongodb|redis)://[^\s\'"]+:[^\s\'"]+@[^\s\'"]+',
    'Firebase URL': r'https://[a-z0-9-]+\.firebaseio\.com',
    'SendGrid Key': r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
    'Twilio SID': r'AC[0-9a-fA-F]{32}',
    'Mailgun Key': r'key-[0-9a-zA-Z]{32}',
}

# Sensitive file patterns
SENSITIVE_FILES = [
    '.env', '.env.local', '.env.production', '.env.staging',
    'credentials.json', 'credentials.yml', 'secrets.json', 'secrets.yml',
    'config/database.yml', 'config/secrets.yml',
    'id_rsa', 'id_ed25519', 'id_ecdsa',
    '.htpasswd', '.htaccess',
    'wp-config.php',
    'web.config',
    'application.properties', 'application.yml',
    'docker-compose.yml',
    '.npmrc', '.pypirc',
    'terraform.tfvars', 'terraform.tfstate',
    'kubeconfig', '.kube/config',
    'firebase.json', 'serviceAccountKey.json',
]

# Suspicious commit message patterns
SUSPICIOUS_COMMITS = [
    (r'(?:remove|delete|fix)\s+(?:secret|password|credential|key|token)', 'Secret removal attempt'),
    (r'(?:oops|accident|mistake|wrong)', 'Accidental commit'),
    (r'revert.*(?:config|secret|credential)', 'Config/secret revert'),
    (r'(?:hotfix|emergency).*(?:auth|security|vuln)', 'Emergency security fix'),
    (r'(?:disable|remove)\s+(?:auth|security|validation)', 'Security control removal'),
]


class RepoScanner:
    """Scan git repository for security issues in history"""

    def __init__(self, repo_path: str, target: Optional[str] = None):
        self.repo_path = Path(repo_path)
        self.target = target or self.repo_path.name
        self.findings: List[RepoFinding] = []
        self.is_git_repo = (self.repo_path / '.git').exists()

    def scan(self, max_commits: int = 500) -> List[RepoFinding]:
        """Full repository security scan"""
        context = DatabaseHooks.before_test(self.target, 'repo_scanner')
        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            return self.findings

        self.findings = []

        if not self.is_git_repo:
            print(f"{Fore.YELLOW}[WARN] Not a git repository: {self.repo_path}{Style.RESET_ALL}")
            # Still scan current files
            self._scan_current_files()
            return self.findings

        self._scan_git_history(max_commits)
        self._find_deleted_sensitive_files()
        self._analyze_suspicious_commits()
        self._check_gitignore()
        self._scan_current_files()

        db = BountyHoundDB()
        db.record_tool_run(self.target, 'repo_scanner',
                          findings_count=len(self.findings), duration_seconds=0)
        return self.findings

    def clone_and_scan(self, repo_url: str, max_commits: int = 500) -> List[RepoFinding]:
        """Clone a repository and scan it"""
        # Validate URL to prevent injection
        if not re.match(r'^https?://[a-zA-Z0-9._\-/]+$', repo_url):
            print(f"{Fore.RED}[ERROR] Invalid repository URL{Style.RESET_ALL}")
            return []

        clone_dir = self.repo_path / 'cloned_repo'
        try:
            subprocess.run(
                ['git', 'clone', '--depth', str(max_commits), repo_url, str(clone_dir)],
                capture_output=True, text=True, timeout=120
            )
            self.repo_path = clone_dir
            self.is_git_repo = True
            return self.scan(max_commits)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"{Fore.RED}[ERROR] Clone failed: {e}{Style.RESET_ALL}")
            return []

    def _run_git(self, args: List[str], timeout: int = 30) -> str:
        """Run a git command safely"""
        try:
            result = subprocess.run(
                ['git'] + args,
                cwd=str(self.repo_path),
                capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ''

    def _scan_git_history(self, max_commits: int):
        """Search git log for secrets using git log -p"""
        # Get commit list first
        log_output = self._run_git(
            ['log', '--all', f'--max-count={max_commits}', '--pretty=format:%H|%s', '--diff-filter=A'],
            timeout=60
        )

        for pattern_name, pattern in HISTORY_SECRET_PATTERNS.items():
            # Use git log -G for efficient regex search
            matches = self._run_git(
                ['log', '--all', f'--max-count={max_commits}',
                 '-G', pattern, '--pretty=format:%H|%an|%s',
                 '--name-only'],
                timeout=60
            )
            if matches.strip():
                lines = matches.strip().split('\n')
                i = 0
                while i < len(lines):
                    if '|' in lines[i]:
                        parts = lines[i].split('|', 2)
                        commit_hash = parts[0][:8]
                        commit_msg = parts[2] if len(parts) > 2 else ''
                        # Get file paths (lines after commit line until next commit or empty)
                        files = []
                        i += 1
                        while i < len(lines) and lines[i].strip() and '|' not in lines[i]:
                            files.append(lines[i].strip())
                            i += 1
                        self.findings.append(RepoFinding(
                            finding_type='secret_in_history',
                            severity='CRITICAL',
                            description=f'{pattern_name} found in git history',
                            commit_hash=commit_hash,
                            commit_message=commit_msg[:80],
                            file_path=', '.join(files[:3]),
                            evidence=f'Pattern: {pattern_name}',
                        ))
                    else:
                        i += 1

    def _find_deleted_sensitive_files(self):
        """Find sensitive files that were deleted from the repo"""
        deleted = self._run_git(
            ['log', '--all', '--diff-filter=D', '--name-only', '--pretty=format:%H|%s'],
            timeout=30
        )
        for line in deleted.split('\n'):
            line = line.strip()
            if not line or '|' in line:
                continue
            for sensitive in SENSITIVE_FILES:
                if line.endswith(sensitive) or line == sensitive:
                    self.findings.append(RepoFinding(
                        finding_type='deleted_sensitive_file',
                        severity='HIGH',
                        description=f'Sensitive file was deleted but exists in git history: {line}',
                        file_path=line,
                        evidence=f'File still accessible via: git log --all --full-history -- {line}',
                    ))

    def _analyze_suspicious_commits(self):
        """Find commits with suspicious messages"""
        log_output = self._run_git(
            ['log', '--all', '--max-count=500', '--pretty=format:%H|%s'],
            timeout=30
        )
        for line in log_output.split('\n'):
            if '|' not in line:
                continue
            commit_hash, commit_msg = line.split('|', 1)
            for pattern, desc in SUSPICIOUS_COMMITS:
                if re.search(pattern, commit_msg, re.IGNORECASE):
                    self.findings.append(RepoFinding(
                        finding_type='suspicious_commit',
                        severity='MEDIUM',
                        description=f'{desc}: "{commit_msg[:80]}"',
                        commit_hash=commit_hash[:8],
                        commit_message=commit_msg[:80],
                    ))

    def _check_gitignore(self):
        """Analyze .gitignore for missing sensitive patterns"""
        gitignore_path = self.repo_path / '.gitignore'
        if not gitignore_path.exists():
            self.findings.append(RepoFinding(
                finding_type='exposed_config',
                severity='MEDIUM',
                description='No .gitignore file - sensitive files may be tracked',
            ))
            return

        try:
            content = gitignore_path.read_text(encoding='utf-8', errors='ignore')
            should_have = ['.env', '*.pem', '*.key', 'credentials', 'secrets', '*.tfvars', '*.tfstate']
            missing = [p for p in should_have if p not in content]
            if missing:
                self.findings.append(RepoFinding(
                    finding_type='exposed_config',
                    severity='LOW',
                    description=f'.gitignore missing patterns: {", ".join(missing)}',
                    file_path='.gitignore',
                ))
        except Exception:
            pass

    def _scan_current_files(self):
        """Check if sensitive files currently exist in working tree"""
        for sensitive in SENSITIVE_FILES:
            full_path = self.repo_path / sensitive
            if full_path.exists():
                self.findings.append(RepoFinding(
                    finding_type='exposed_config',
                    severity='HIGH',
                    description=f'Sensitive file exists in working tree: {sensitive}',
                    file_path=sensitive,
                ))

    def summary(self) -> Dict:
        return {
            'total_findings': len(self.findings),
            'by_type': {t: sum(1 for f in self.findings if f.finding_type == t)
                       for t in set(f.finding_type for f in self.findings)} if self.findings else {},
            'by_severity': {s: sum(1 for f in self.findings if f.severity == s)
                           for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']},
        }

    def print_report(self):
        severity_colors = {'CRITICAL': Fore.RED, 'HIGH': Fore.YELLOW, 'MEDIUM': Fore.CYAN, 'LOW': Fore.WHITE}
        for f in sorted(self.findings, key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW'].index(x.severity)):
            color = severity_colors.get(f.severity, Fore.WHITE)
            print(f"{color}[{f.severity}] [{f.finding_type}] {f.description}{Style.RESET_ALL}")
            if f.commit_hash:
                print(f"  Commit: {f.commit_hash}")
            if f.file_path:
                print(f"  File: {f.file_path}")
