"""
Source Code Vulnerability Auditor
Deep pattern-based vulnerability detection across multiple languages
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from colorama import Fore, Style

from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB


@dataclass
class CodeFinding:
    """A vulnerability found in source code"""
    file_path: str
    line_number: int
    code_snippet: str
    vuln_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    cwe: str
    language: str
    confidence: str = 'MEDIUM'  # HIGH, MEDIUM, LOW
    fix_suggestion: str = ''


# Vulnerability patterns per language
# Format: {language: {vuln_type: [(pattern_regex, severity, cwe, description, fix)]}}
VULN_PATTERNS = {
    'python': {
        'command_injection': [
            (r'os\.system\s*\(.*[fF][\'""]', 'CRITICAL', 'CWE-78', 'OS command injection via f-string in os.system()', 'Use subprocess.run() with list args'),
            (r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True', 'HIGH', 'CWE-78', 'Shell=True enables command injection', 'Use shell=False with list args'),
            (r'eval\s*\(', 'CRITICAL', 'CWE-95', 'eval() executes arbitrary code', 'Use ast.literal_eval() or safer alternatives'),
            (r'exec\s*\(', 'CRITICAL', 'CWE-95', 'exec() executes arbitrary code', 'Remove or use restricted execution'),
            (r'__import__\s*\(', 'HIGH', 'CWE-95', 'Dynamic import can execute arbitrary modules', 'Use explicit imports'),
        ],
        'sql_injection': [
            (r'(?:execute|cursor\.execute)\s*\(\s*[fF][\'""]', 'CRITICAL', 'CWE-89', 'SQL injection via f-string in execute()', 'Use parameterized queries'),
            (r'(?:execute|cursor\.execute)\s*\(.*%\s', 'CRITICAL', 'CWE-89', 'SQL injection via string formatting', 'Use parameterized queries'),
            (r'(?:execute|cursor\.execute)\s*\(.*\.format\(', 'CRITICAL', 'CWE-89', 'SQL injection via .format()', 'Use parameterized queries'),
            (r'raw\s*\(\s*[fF][\'""].*(?:SELECT|INSERT|UPDATE|DELETE)', 'CRITICAL', 'CWE-89', 'Raw SQL with f-string', 'Use ORM or parameterized queries'),
        ],
        'deserialization': [
            (r'pickle\.loads?\s*\(', 'CRITICAL', 'CWE-502', 'Unsafe deserialization with pickle', 'Use json or safer serialization'),
            (r'yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)', 'HIGH', 'CWE-502', 'Unsafe YAML loading without SafeLoader', 'Use yaml.safe_load() or Loader=SafeLoader'),
            (r'marshal\.loads?\s*\(', 'HIGH', 'CWE-502', 'Unsafe deserialization with marshal', 'Use json or safer serialization'),
        ],
        'path_traversal': [
            (r'open\s*\(.*(?:request|input|argv|args|params)', 'HIGH', 'CWE-22', 'File open with user-controlled path', 'Validate and sanitize file paths'),
            (r'send_file\s*\(.*(?:request|input)', 'HIGH', 'CWE-22', 'send_file with user-controlled path', 'Use safe_join() and validate paths'),
        ],
        'hardcoded_secrets': [
            (r'(?:password|secret|api_key|token)\s*=\s*[\'"][^\'"]{8,}[\'"]', 'HIGH', 'CWE-798', 'Hardcoded credential', 'Use environment variables or secret manager'),
        ],
        'ssrf': [
            (r'requests\.(?:get|post|put|delete|patch)\s*\(.*(?:request|input|args|params)', 'HIGH', 'CWE-918', 'SSRF via user-controlled URL', 'Validate and whitelist URLs'),
        ],
        'xxe': [
            (r'etree\.parse\s*\(', 'MEDIUM', 'CWE-611', 'XML parsing may be vulnerable to XXE', 'Disable external entity processing'),
            (r'xml\.sax\.parse', 'MEDIUM', 'CWE-611', 'SAX parser may allow XXE', 'Configure parser to disable DTDs'),
        ],
        'weak_crypto': [
            (r'(?:md5|MD5)\s*\(', 'MEDIUM', 'CWE-327', 'MD5 is cryptographically broken', 'Use SHA-256 or stronger'),
            (r'(?:sha1|SHA1)\s*\(', 'MEDIUM', 'CWE-327', 'SHA1 is cryptographically weak', 'Use SHA-256 or stronger'),
            (r'DES\b', 'HIGH', 'CWE-327', 'DES is broken', 'Use AES-256'),
        ],
    },
    'javascript': {
        'xss': [
            (r'innerHTML\s*=', 'HIGH', 'CWE-79', 'innerHTML allows XSS', 'Use textContent or DOMPurify'),
            (r'document\.write\s*\(', 'HIGH', 'CWE-79', 'document.write enables XSS', 'Use DOM manipulation methods'),
            (r'\.html\s*\(.*(?:req|input|param|query)', 'HIGH', 'CWE-79', 'jQuery .html() with user input', 'Use .text() or sanitize input'),
            (r'dangerouslySetInnerHTML', 'MEDIUM', 'CWE-79', 'React dangerouslySetInnerHTML', 'Sanitize with DOMPurify before use'),
        ],
        'command_injection': [
            (r'child_process\.exec\s*\(', 'CRITICAL', 'CWE-78', 'exec() allows command injection', 'Use execFile() with array args'),
            (r'eval\s*\(', 'CRITICAL', 'CWE-95', 'eval() executes arbitrary code', 'Use JSON.parse() or safer alternatives'),
            (r'new\s+Function\s*\(', 'HIGH', 'CWE-95', 'Dynamic function creation', 'Use static functions'),
        ],
        'sql_injection': [
            (r'query\s*\(\s*`.*\$\{', 'CRITICAL', 'CWE-89', 'SQL injection via template literal', 'Use parameterized queries'),
            (r'query\s*\(.*\+\s*(?:req|input|param)', 'CRITICAL', 'CWE-89', 'SQL injection via string concatenation', 'Use parameterized queries'),
        ],
        'prototype_pollution': [
            (r'Object\.assign\s*\(\s*\{\}.*(?:req|input|body|params)', 'HIGH', 'CWE-1321', 'Prototype pollution via Object.assign', 'Validate keys, filter __proto__'),
            (r'(?:merge|extend|defaults)\s*\(.*(?:req|input|body)', 'MEDIUM', 'CWE-1321', 'Deep merge with user input may cause prototype pollution', 'Use safe merge library'),
        ],
        'path_traversal': [
            (r'(?:readFile|readFileSync)\s*\(.*(?:req|input|param|query)', 'HIGH', 'CWE-22', 'File read with user-controlled path', 'Use path.resolve() and validate'),
            (r'res\.sendFile\s*\(.*(?:req|param)', 'HIGH', 'CWE-22', 'sendFile with user input', 'Use path.join() with root option'),
        ],
        'ssrf': [
            (r'(?:fetch|axios|request)\s*\(.*(?:req|input|param|query|body)', 'HIGH', 'CWE-918', 'SSRF via user-controlled URL', 'Validate and whitelist URLs'),
        ],
        'insecure_config': [
            (r'cors\s*\(\s*\)', 'MEDIUM', 'CWE-942', 'CORS with default (allow all) config', 'Specify allowed origins'),
            (r'(?:secure|httpOnly)\s*:\s*false', 'MEDIUM', 'CWE-614', 'Cookie security flag disabled', 'Set secure and httpOnly to true'),
        ],
    },
    'java': {
        'sql_injection': [
            (r'Statement.*execute(?:Query|Update)\s*\(.*\+', 'CRITICAL', 'CWE-89', 'SQL injection via string concatenation', 'Use PreparedStatement'),
            (r'createQuery\s*\(.*\+', 'HIGH', 'CWE-89', 'HQL/JPQL injection', 'Use parameterized queries or Criteria API'),
        ],
        'command_injection': [
            (r'Runtime\.getRuntime\(\)\.exec\s*\(', 'CRITICAL', 'CWE-78', 'Runtime.exec() command injection', 'Use ProcessBuilder with array args'),
            (r'ProcessBuilder\s*\(.*\+', 'HIGH', 'CWE-78', 'ProcessBuilder with string concatenation', 'Use list constructor'),
        ],
        'deserialization': [
            (r'ObjectInputStream.*readObject\s*\(', 'CRITICAL', 'CWE-502', 'Unsafe Java deserialization', 'Use ObjectInputFilter or avoid native serialization'),
            (r'XMLDecoder', 'CRITICAL', 'CWE-502', 'XMLDecoder allows arbitrary code execution', 'Use safer XML parsing'),
        ],
        'xxe': [
            (r'DocumentBuilderFactory\.newInstance\(\)', 'MEDIUM', 'CWE-611', 'XML parser without XXE protection', 'Disable external entities and DTDs'),
            (r'SAXParserFactory\.newInstance\(\)', 'MEDIUM', 'CWE-611', 'SAX parser without XXE protection', 'Disable external entities'),
        ],
        'path_traversal': [
            (r'new\s+File\s*\(.*(?:request|getParameter|input)', 'HIGH', 'CWE-22', 'File creation with user input', 'Canonicalize and validate path'),
        ],
        'weak_crypto': [
            (r'Cipher\.getInstance\s*\(\s*"DES', 'HIGH', 'CWE-327', 'DES encryption is broken', 'Use AES/GCM'),
            (r'MessageDigest\.getInstance\s*\(\s*"MD5', 'MEDIUM', 'CWE-327', 'MD5 is broken', 'Use SHA-256'),
            (r'MessageDigest\.getInstance\s*\(\s*"SHA-1', 'MEDIUM', 'CWE-327', 'SHA-1 is weak', 'Use SHA-256'),
        ],
        'hardcoded_secrets': [
            (r'(?:password|secret|apiKey|token)\s*=\s*"[^"]{8,}"', 'HIGH', 'CWE-798', 'Hardcoded credential', 'Use environment variables or vault'),
        ],
    },
    'php': {
        'sql_injection': [
            (r'mysql_query\s*\(.*\$', 'CRITICAL', 'CWE-89', 'SQL injection via variable in mysql_query', 'Use PDO with prepared statements'),
            (r'mysqli_query\s*\(.*\$', 'CRITICAL', 'CWE-89', 'SQL injection in mysqli_query', 'Use prepared statements'),
            (r'\$.*->query\s*\(.*\$', 'HIGH', 'CWE-89', 'SQL injection via object query', 'Use prepared statements'),
        ],
        'command_injection': [
            (r'(?:system|exec|passthru|shell_exec|popen)\s*\(.*\$', 'CRITICAL', 'CWE-78', 'Command injection via user variable', 'Use escapeshellarg() and escapeshellcmd()'),
            (r'`.*\$', 'CRITICAL', 'CWE-78', 'Backtick command injection', 'Use escapeshellarg()'),
        ],
        'xss': [
            (r'echo\s+\$_(GET|POST|REQUEST|COOKIE)', 'HIGH', 'CWE-79', 'Reflected XSS via direct echo', 'Use htmlspecialchars()'),
            (r'print\s+\$_(GET|POST|REQUEST)', 'HIGH', 'CWE-79', 'XSS via print', 'Use htmlspecialchars()'),
        ],
        'file_inclusion': [
            (r'(?:include|require)(?:_once)?\s*\(?\s*\$', 'CRITICAL', 'CWE-98', 'Local/Remote File Inclusion', 'Whitelist allowed files'),
        ],
        'deserialization': [
            (r'unserialize\s*\(.*\$', 'CRITICAL', 'CWE-502', 'Unsafe PHP deserialization', 'Use json_decode() instead'),
        ],
        'path_traversal': [
            (r'(?:file_get_contents|fopen|readfile)\s*\(.*\$', 'HIGH', 'CWE-22', 'File operation with user input', 'Validate and canonicalize paths'),
        ],
    },
    'go': {
        'sql_injection': [
            (r'(?:Query|Exec)\s*\(.*fmt\.Sprintf', 'CRITICAL', 'CWE-89', 'SQL injection via fmt.Sprintf', 'Use parameterized queries with $1 placeholders'),
            (r'(?:Query|Exec)\s*\(.*\+\s*', 'CRITICAL', 'CWE-89', 'SQL injection via concatenation', 'Use parameterized queries'),
        ],
        'command_injection': [
            (r'exec\.Command\s*\(.*\+', 'HIGH', 'CWE-78', 'Command injection via concatenation', 'Use exec.Command with separate args'),
        ],
        'path_traversal': [
            (r'os\.Open\s*\(.*(?:r\.URL|r\.Form|param)', 'HIGH', 'CWE-22', 'File open with user input', 'Use filepath.Clean() and validate'),
            (r'http\.ServeFile\s*\(.*(?:r\.URL|param)', 'HIGH', 'CWE-22', 'ServeFile with user input', 'Use http.FileServer with root'),
        ],
        'ssrf': [
            (r'http\.(?:Get|Post)\s*\(.*(?:r\.Form|param|query)', 'HIGH', 'CWE-918', 'SSRF via user-controlled URL', 'Validate and whitelist URLs'),
        ],
    },
    'ruby': {
        'command_injection': [
            (r'system\s*\(.*(?:params|request|input)', 'CRITICAL', 'CWE-78', 'System command with user input', 'Use array form of system()'),
            (r'`.*#\{.*(?:params|request|input)', 'CRITICAL', 'CWE-78', 'Backtick command injection', 'Use Open3 with array args'),
            (r'IO\.popen\s*\(.*(?:params|request)', 'CRITICAL', 'CWE-78', 'popen command injection', 'Use array args'),
        ],
        'sql_injection': [
            (r'\.where\s*\(.*#\{', 'HIGH', 'CWE-89', 'SQL injection in ActiveRecord where', 'Use hash conditions or ? placeholders'),
            (r'\.find_by_sql\s*\(.*#\{', 'CRITICAL', 'CWE-89', 'SQL injection in find_by_sql', 'Use parameterized queries'),
        ],
        'deserialization': [
            (r'Marshal\.load', 'CRITICAL', 'CWE-502', 'Unsafe Ruby deserialization', 'Use JSON.parse instead'),
            (r'YAML\.load\s*\((?!.*safe)', 'HIGH', 'CWE-502', 'Unsafe YAML loading', 'Use YAML.safe_load'),
        ],
        'xss': [
            (r'\.html_safe', 'MEDIUM', 'CWE-79', 'html_safe bypasses Rails escaping', 'Use sanitize() helper'),
            (r'raw\s*\(.*(?:params|request)', 'HIGH', 'CWE-79', 'raw() with user input', 'Use sanitize() or h()'),
        ],
        'mass_assignment': [
            (r'\.update\s*\(.*params\b(?!\.permit)', 'HIGH', 'CWE-915', 'Mass assignment without strong params', 'Use params.permit(:field1, :field2)'),
        ],
    },
    'c_cpp': {
        'buffer_overflow': [
            (r'\bstrcpy\s*\(', 'CRITICAL', 'CWE-120', 'strcpy has no bounds checking', 'Use strncpy() or strlcpy()'),
            (r'\bstrcat\s*\(', 'CRITICAL', 'CWE-120', 'strcat has no bounds checking', 'Use strncat() or strlcat()'),
            (r'\bsprintf\s*\(', 'HIGH', 'CWE-120', 'sprintf has no bounds checking', 'Use snprintf()'),
            (r'\bgets\s*\(', 'CRITICAL', 'CWE-120', 'gets() is always vulnerable', 'Use fgets()'),
            (r'\bscanf\s*\(\s*"%s"', 'HIGH', 'CWE-120', 'scanf %s has no bounds', 'Use %Ns with max length'),
        ],
        'format_string': [
            (r'printf\s*\(\s*(?!")[a-zA-Z_]', 'CRITICAL', 'CWE-134', 'Format string vulnerability', 'Use printf("%s", var)'),
            (r'fprintf\s*\([^,]+,\s*(?!")[a-zA-Z_]', 'CRITICAL', 'CWE-134', 'Format string vulnerability', 'Always use format specifier'),
        ],
        'integer_overflow': [
            (r'malloc\s*\(.*\*', 'MEDIUM', 'CWE-190', 'Integer overflow in malloc size', 'Check for overflow before malloc'),
        ],
        'use_after_free': [
            (r'free\s*\([^)]+\);\s*\n[^=]*\1', 'HIGH', 'CWE-416', 'Potential use-after-free', 'Set pointer to NULL after free'),
        ],
        'race_condition': [
            (r'(?:access|stat)\s*\(.*\n.*(?:open|fopen)\s*\(', 'MEDIUM', 'CWE-367', 'TOCTOU race condition', 'Use fstat() on file descriptor'),
        ],
    },
}

# Language detection by extension
LANGUAGE_MAP = {
    '.py': 'python', '.pyw': 'python',
    '.js': 'javascript', '.jsx': 'javascript', '.ts': 'javascript', '.tsx': 'javascript', '.mjs': 'javascript',
    '.java': 'java', '.kt': 'java', '.scala': 'java',
    '.php': 'php', '.phtml': 'php',
    '.go': 'go',
    '.rb': 'ruby', '.erb': 'ruby',
    '.c': 'c_cpp', '.cpp': 'c_cpp', '.cc': 'c_cpp', '.cxx': 'c_cpp', '.h': 'c_cpp', '.hpp': 'c_cpp',
}

# Directories to skip
SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv', 'env',
    'vendor', 'dist', 'build', '.next', '.nuxt', 'target', 'bin',
    '.idea', '.vscode', '.gradle', 'coverage', '.tox', '.mypy_cache',
}


class CodeAuditor:
    """Deep source code vulnerability scanner"""

    def __init__(self, repo_path: str, target: Optional[str] = None):
        self.repo_path = Path(repo_path)
        self.target = target or self.repo_path.name
        self.findings: List[CodeFinding] = []
        self.files_scanned = 0
        self.lines_scanned = 0

    def audit(self, languages: Optional[List[str]] = None) -> List[CodeFinding]:
        """Full audit of repository. If languages not specified, auto-detect from files."""
        # Database check
        context = DatabaseHooks.before_test(self.target, 'code_auditor')
        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            return self.findings

        self.findings = []
        self.files_scanned = 0
        self.lines_scanned = 0

        for file_path in self._walk_files():
            lang = self._detect_language(file_path)
            if lang is None:
                continue
            if languages and lang not in languages:
                continue
            self._audit_file(file_path, lang)

        # Record in database
        db = BountyHoundDB()
        db.record_tool_run(self.target, 'code_auditor',
                          findings_count=len(self.findings),
                          duration_seconds=0)

        return self.findings

    def audit_file(self, file_path: str) -> List[CodeFinding]:
        """Audit a single file"""
        path = Path(file_path)
        lang = self._detect_language(path)
        if lang is None:
            return []
        self._audit_file(path, lang)
        return [f for f in self.findings if f.file_path == str(path)]

    def _walk_files(self):
        """Walk repo, yield source files, skip irrelevant dirs"""
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                yield Path(root) / f

    def _detect_language(self, file_path: Path) -> Optional[str]:
        return LANGUAGE_MAP.get(file_path.suffix.lower())

    def _audit_file(self, file_path: Path, language: str):
        """Scan a single file for vulnerabilities"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return

        lines = content.split('\n')
        self.files_scanned += 1
        self.lines_scanned += len(lines)

        patterns = VULN_PATTERNS.get(language, {})
        for vuln_type, rules in patterns.items():
            for pattern, severity, cwe, description, fix in rules:
                for i, line in enumerate(lines, 1):
                    stripped = line.strip()
                    # Skip comments
                    if stripped.startswith(('#', '//', '/*', '*', '<!--')):
                        continue
                    if re.search(pattern, line):
                        # Get context (3 lines before and after)
                        start = max(0, i - 4)
                        end = min(len(lines), i + 3)
                        snippet = '\n'.join(f"{'>' if j == i else ' '} {j}: {lines[j-1]}"
                                          for j in range(start + 1, end + 1))
                        self.findings.append(CodeFinding(
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=snippet,
                            vuln_type=vuln_type,
                            severity=severity,
                            description=description,
                            cwe=cwe,
                            language=language,
                            confidence='HIGH' if severity == 'CRITICAL' else 'MEDIUM',
                            fix_suggestion=fix,
                        ))

    def summary(self) -> Dict:
        """Return audit summary"""
        by_severity = {}
        by_type = {}
        by_language = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
            by_language[f.language] = by_language.get(f.language, 0) + 1

        return {
            'total_findings': len(self.findings),
            'files_scanned': self.files_scanned,
            'lines_scanned': self.lines_scanned,
            'by_severity': by_severity,
            'by_type': by_type,
            'by_language': by_language,
        }

    def print_report(self):
        """Print findings to terminal"""
        severity_colors = {
            'CRITICAL': Fore.RED, 'HIGH': Fore.YELLOW,
            'MEDIUM': Fore.CYAN, 'LOW': Fore.WHITE,
        }
        for f in sorted(self.findings, key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW'].index(x.severity)):
            color = severity_colors.get(f.severity, Fore.WHITE)
            print(f"\n{color}[{f.severity}] {f.vuln_type} - {f.cwe}{Style.RESET_ALL}")
            print(f"  File: {f.file_path}:{f.line_number}")
            print(f"  Description: {f.description}")
            print(f"  Fix: {f.fix_suggestion}")
            print(f"  Code:\n{f.code_snippet}")

        s = self.summary()
        print(f"\n{Fore.GREEN}=== Audit Summary ==={Style.RESET_ALL}")
        print(f"  Files scanned: {s['files_scanned']}")
        print(f"  Lines scanned: {s['lines_scanned']}")
        print(f"  Total findings: {s['total_findings']}")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = s['by_severity'].get(sev, 0)
            if count:
                color = severity_colors.get(sev, Fore.WHITE)
                print(f"  {color}{sev}: {count}{Style.RESET_ALL}")
