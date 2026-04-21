"""
Response Analyzer - Parses error responses to identify SQL dialects, WAF vendors,
framework details, and filter rules, then recommends adapted payloads.

This module closes the feedback loop: test payload -> analyze error -> adapt payload.
Instead of blind retries, each failed attempt teaches the system what's blocked and why.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import re


class SQLDialect(Enum):
    MYSQL = 'mysql'
    POSTGRESQL = 'postgresql'
    MSSQL = 'mssql'
    ORACLE = 'oracle'
    SQLITE = 'sqlite'
    UNKNOWN = 'unknown'


class WAFVendor(Enum):
    CLOUDFLARE = 'cloudflare'
    AWS_WAF = 'aws_waf'
    AKAMAI = 'akamai'
    IMPERVA = 'imperva'
    MODSECURITY = 'modsecurity'
    SUCURI = 'sucuri'
    F5_BIG_IP = 'f5_big_ip'
    BARRACUDA = 'barracuda'
    FORTINET = 'fortinet'
    UNKNOWN = 'unknown'


class BlockReason(Enum):
    WAF_BLOCKED = 'waf_blocked'
    INPUT_VALIDATION = 'input_validation'
    RATE_LIMITED = 'rate_limited'
    AUTH_REQUIRED = 'auth_required'
    PARAMETER_FILTERED = 'parameter_filtered'
    CONTENT_TYPE_REJECTED = 'content_type_rejected'
    SIZE_LIMIT = 'size_limit'
    UNKNOWN = 'unknown'


@dataclass
class ResponseAnalysis:
    """Complete analysis of a response to a test payload."""
    status_code: int
    block_reason: BlockReason
    sql_dialect: SQLDialect = SQLDialect.UNKNOWN
    waf_vendor: WAFVendor = WAFVendor.UNKNOWN
    framework: str = ''
    blocked_patterns: List[str] = field(default_factory=list)
    allowed_patterns: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 0.0
    raw_evidence: str = ''


# SQL dialect fingerprints: {pattern: dialect}
_SQL_FINGERPRINTS: Dict[str, SQLDialect] = {
    r'you have an error in your sql syntax': SQLDialect.MYSQL,
    r'mysql_': SQLDialect.MYSQL,
    r'mariadb': SQLDialect.MYSQL,
    r'warning.*mysql': SQLDialect.MYSQL,
    r'com\.mysql\.jdbc': SQLDialect.MYSQL,
    r'pg_query|pg_exec|pg_connect': SQLDialect.POSTGRESQL,
    r'psycopg2': SQLDialect.POSTGRESQL,
    r'unterminated quoted string': SQLDialect.POSTGRESQL,
    r'org\.postgresql': SQLDialect.POSTGRESQL,
    r'error.*position.*char': SQLDialect.POSTGRESQL,
    r'unclosed quotation mark': SQLDialect.MSSQL,
    r'microsoft.*odbc': SQLDialect.MSSQL,
    r'sql server': SQLDialect.MSSQL,
    r'sqlclient': SQLDialect.MSSQL,
    r'system\.data\.sqlclient': SQLDialect.MSSQL,
    r'ora-\d{5}': SQLDialect.ORACLE,
    r'oracle.*driver': SQLDialect.ORACLE,
    r'plsql': SQLDialect.ORACLE,
    r'oracleexception': SQLDialect.ORACLE,
    r'sqlite3?\.': SQLDialect.SQLITE,
    r'sqlite_error': SQLDialect.SQLITE,
    r'near ".*": syntax error': SQLDialect.SQLITE,
    r'unrecognized token': SQLDialect.SQLITE,
}

# WAF vendor fingerprints: {pattern: (vendor, evidence_field)}
_WAF_FINGERPRINTS: Dict[str, Tuple[WAFVendor, str]] = {
    r'cf-ray': (WAFVendor.CLOUDFLARE, 'header'),
    r'cloudflare': (WAFVendor.CLOUDFLARE, 'body'),
    r'__cfduid': (WAFVendor.CLOUDFLARE, 'cookie'),
    r'attention required.*cloudflare': (WAFVendor.CLOUDFLARE, 'body'),
    r'x-amzn-waf': (WAFVendor.AWS_WAF, 'header'),
    r'awswaf': (WAFVendor.AWS_WAF, 'header'),
    r'x-amzn-requestid': (WAFVendor.AWS_WAF, 'header'),
    r'akamai.*ghost': (WAFVendor.AKAMAI, 'header'),
    r'x-akamai': (WAFVendor.AKAMAI, 'header'),
    r'akamaighost': (WAFVendor.AKAMAI, 'body'),
    r'incapsula': (WAFVendor.IMPERVA, 'body'),
    r'imperva': (WAFVendor.IMPERVA, 'body'),
    r'x-iinfo': (WAFVendor.IMPERVA, 'header'),
    r'visid_incap': (WAFVendor.IMPERVA, 'cookie'),
    r'mod_security': (WAFVendor.MODSECURITY, 'body'),
    r'modsecurity': (WAFVendor.MODSECURITY, 'body'),
    r'noyb': (WAFVendor.MODSECURITY, 'header'),
    r'sucuri': (WAFVendor.SUCURI, 'body'),
    r'x-sucuri': (WAFVendor.SUCURI, 'header'),
    r'sucuri-cache': (WAFVendor.SUCURI, 'header'),
    r'bigipserver': (WAFVendor.F5_BIG_IP, 'header'),
    r'f5-trafficshield': (WAFVendor.F5_BIG_IP, 'header'),
    r'x-cnection': (WAFVendor.F5_BIG_IP, 'header'),
    r'barracuda': (WAFVendor.BARRACUDA, 'body'),
    r'barra_counter_session': (WAFVendor.BARRACUDA, 'cookie'),
    r'fortigate': (WAFVendor.FORTINET, 'body'),
    r'fortiwebserver': (WAFVendor.FORTINET, 'header'),
}

# Framework fingerprints
_FRAMEWORK_FINGERPRINTS: Dict[str, str] = {
    r'x-powered-by.*express': 'express',
    r'x-powered-by.*php': 'php',
    r'x-powered-by.*asp\.net': 'aspnet',
    r'x-powered-by.*django': 'django',
    r'x-powered-by.*rails': 'rails',
    r'server.*nginx': 'nginx',
    r'server.*apache': 'apache',
    r'server.*iis': 'iis',
    r'x-aspnet-version': 'aspnet',
    r'x-drupal': 'drupal',
    r'x-generator.*wordpress': 'wordpress',
    r'x-django': 'django',
    r'_rails_session': 'rails',
    r'phpsessid': 'php',
    r'jsessionid': 'java',
    r'laravel_session': 'laravel',
    r'csrftoken.*django': 'django',
    r'spring.*framework': 'spring',
    r'struts': 'struts',
    r'flask': 'flask',
    r'fastapi': 'fastapi',
}

# Blocked pattern indicators: what the WAF/filter likely matched
_BLOCK_INDICATORS: Dict[str, List[str]] = {
    'script_tags': [r'<script', r'script>', r'javascript:', r'onerror', r'onload'],
    'sql_keywords': [r'\bunion\b', r'\bselect\b', r'\bfrom\b', r'\bwhere\b', r'\binsert\b',
                     r'\bupdate\b', r'\bdelete\b', r'\bdrop\b'],
    'command_injection': [r'\bcat\b', r'\bls\b', r'\bwhoami\b', r'\bcurl\b', r'\bwget\b',
                         r'\bping\b', r'; *\w', r'\| *\w'],
    'traversal': [r'\.\./', r'\.\.\\', r'%2e%2e', r'%252e'],
    'special_chars': [r"'", r'"', r'<', r'>', r'\{', r'\}', r'\|', r';', r'`'],
}


class ResponseAnalyzer:
    """Analyzes HTTP responses to determine what security controls are in place
    and recommends adapted payloads to bypass them."""

    def __init__(self) -> None:
        self._history: List[ResponseAnalysis] = []
        self._known_blocks: Set[str] = set()

    def analyze(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        payload_sent: str = '',
        cookies: Optional[Dict[str, str]] = None,
    ) -> ResponseAnalysis:
        """Analyze a response and return structured findings with recommendations."""
        cookies = cookies or {}
        combined_text = self._build_combined_text(headers, body, cookies)

        analysis = ResponseAnalysis(
            status_code=status_code,
            block_reason=self._detect_block_reason(status_code, body, headers),
        )

        # Detect SQL dialect
        analysis.sql_dialect = self._detect_sql_dialect(combined_text)

        # Detect WAF vendor
        analysis.waf_vendor = self._detect_waf(headers, body, cookies)

        # Detect framework
        analysis.framework = self._detect_framework(combined_text)

        # Identify what was blocked
        if payload_sent and analysis.block_reason != BlockReason.UNKNOWN:
            analysis.blocked_patterns = self._identify_blocked_patterns(
                payload_sent, body
            )

        # Generate recommendations
        analysis.recommendations = self._generate_recommendations(analysis, payload_sent)

        # Calculate confidence
        analysis.confidence = self._calculate_confidence(analysis)

        # Store evidence
        evidence_parts = []
        if analysis.waf_vendor != WAFVendor.UNKNOWN:
            evidence_parts.append(f'WAF: {analysis.waf_vendor.value}')
        if analysis.sql_dialect != SQLDialect.UNKNOWN:
            evidence_parts.append(f'SQL: {analysis.sql_dialect.value}')
        if analysis.framework:
            evidence_parts.append(f'Framework: {analysis.framework}')
        if analysis.blocked_patterns:
            evidence_parts.append(f'Blocked: {", ".join(analysis.blocked_patterns[:3])}')
        analysis.raw_evidence = ' | '.join(evidence_parts)

        self._history.append(analysis)
        return analysis

    def get_bypass_strategy(self, analysis: ResponseAnalysis) -> Dict[str, Any]:
        """Return a structured bypass strategy based on analysis."""
        strategy: Dict[str, Any] = {
            'waf_bypass': [],
            'encoding_alternatives': [],
            'payload_transforms': [],
            'timing_adjustments': [],
        }

        if analysis.waf_vendor == WAFVendor.CLOUDFLARE:
            strategy['waf_bypass'] = [
                'Use Unicode normalization (fullwidth chars)',
                'Try chunked transfer encoding',
                'Use HTTP/2 with CRLF in headers',
                'Obfuscate with HTML entities in attributes',
            ]
        elif analysis.waf_vendor == WAFVendor.AWS_WAF:
            strategy['waf_bypass'] = [
                'URL-encode payload twice',
                'Use JSON content-type with payload in values',
                'Split payload across multiple parameters',
                'Use multipart/form-data encoding',
            ]
        elif analysis.waf_vendor == WAFVendor.AKAMAI:
            strategy['waf_bypass'] = [
                'Use HPP (HTTP Parameter Pollution)',
                'Try path-based payload (/;payload)',
                'Use tab/null bytes between keywords',
                'Vary case of SQL keywords randomly',
            ]
        elif analysis.waf_vendor == WAFVendor.IMPERVA:
            strategy['waf_bypass'] = [
                'Use HTTP verb tampering (override with X-HTTP-Method)',
                'Payload in custom headers that get reflected',
                'Use newline injection to split suspicious tokens',
                'Try WebSocket upgrade to bypass WAF inspection',
            ]
        elif analysis.waf_vendor == WAFVendor.MODSECURITY:
            strategy['waf_bypass'] = [
                'Check paranoia level with incremental payloads',
                'Use comment injection in SQL (/*!50000 SELECT*/)',
                'Try payload in less common parameters',
                'Use HTTP/0.9 request to bypass rules',
            ]

        # Encoding alternatives based on blocked patterns
        for pattern in analysis.blocked_patterns:
            if pattern == 'script_tags':
                strategy['encoding_alternatives'].extend([
                    '<svg/onload=...>', '<img src=x onerror=...>',
                    '<details/open/ontoggle=...>', '"><svg onload=...>',
                ])
            elif pattern == 'sql_keywords':
                strategy['encoding_alternatives'].extend([
                    'Use /*!UNION*/ /*!SELECT*/ (MySQL comments)',
                    'Use CASE WHEN for conditional blind',
                    'Replace UNION SELECT with stacked queries',
                    'Use hex encoding for string literals',
                ])
            elif pattern == 'special_chars':
                strategy['encoding_alternatives'].extend([
                    'URL-encode: %27 %22 %3C %3E',
                    'Double-encode: %2527 %2522',
                    'Unicode: %u0027 %u0022',
                    'HTML entities: &#39; &#34;',
                ])

        # SQL dialect-specific transforms
        if analysis.sql_dialect == SQLDialect.MYSQL:
            strategy['payload_transforms'].extend([
                'Use /*!50000 comment syntax*/ for version-conditional execution',
                'Replace spaces with /**/ or %0a',
                'Use GROUP_CONCAT() for data exfil',
                'Try LOAD_FILE() and INTO OUTFILE for file ops',
            ])
        elif analysis.sql_dialect == SQLDialect.POSTGRESQL:
            strategy['payload_transforms'].extend([
                'Use $$ dollar quoting for strings',
                'Use string_agg() for concatenation',
                'Try COPY ... TO/FROM for file operations',
                'Use pg_sleep() for timing confirmation',
            ])
        elif analysis.sql_dialect == SQLDialect.MSSQL:
            strategy['payload_transforms'].extend([
                'Use xp_cmdshell for command execution',
                'Use WAITFOR DELAY for timing confirmation',
                'Try stacked queries (;SELECT ...)',
                'Use fn_xe_file_target_read_file for file read',
            ])

        # Rate limit bypass
        if analysis.block_reason == BlockReason.RATE_LIMITED:
            strategy['timing_adjustments'] = [
                'Add random delay 1-3s between requests',
                'Rotate IP via proxy pool',
                'Add X-Forwarded-For header rotation',
                'Use different HTTP methods (GET vs POST)',
            ]

        return strategy

    def get_accumulated_intelligence(self) -> Dict[str, Any]:
        """Return aggregated intelligence from all analyzed responses."""
        if not self._history:
            return {'total_analyzed': 0}

        wafs = [a.waf_vendor for a in self._history if a.waf_vendor != WAFVendor.UNKNOWN]
        sqls = [a.sql_dialect for a in self._history if a.sql_dialect != SQLDialect.UNKNOWN]
        frameworks = [a.framework for a in self._history if a.framework]
        all_blocks = []
        for a in self._history:
            all_blocks.extend(a.blocked_patterns)

        from collections import Counter
        return {
            'total_analyzed': len(self._history),
            'waf_vendors': dict(Counter(v.value for v in wafs)),
            'sql_dialects': dict(Counter(d.value for d in sqls)),
            'frameworks': dict(Counter(frameworks)),
            'blocked_patterns': dict(Counter(all_blocks)),
            'block_reasons': dict(Counter(a.block_reason.value for a in self._history)),
            'avg_confidence': sum(a.confidence for a in self._history) / len(self._history),
        }

    # ------------------------------------------------------------------
    # Internal detection methods
    # ------------------------------------------------------------------

    @staticmethod
    def _build_combined_text(
        headers: Dict[str, str], body: str, cookies: Dict[str, str],
    ) -> str:
        header_text = ' '.join(f'{k}: {v}' for k, v in headers.items())
        cookie_text = ' '.join(f'{k}={v}' for k, v in cookies.items())
        return f'{header_text} {cookie_text} {body}'.lower()

    @staticmethod
    def _detect_block_reason(
        status: int, body: str, headers: Dict[str, str],
    ) -> BlockReason:
        body_lower = body.lower()
        if status == 429 or 'rate limit' in body_lower or 'too many requests' in body_lower:
            return BlockReason.RATE_LIMITED
        if status == 401 or status == 407:
            return BlockReason.AUTH_REQUIRED
        if status == 403:
            # Distinguish WAF from auth
            waf_indicators = ['blocked', 'forbidden', 'firewall', 'waf', 'security',
                              'access denied', 'not allowed']
            if any(ind in body_lower for ind in waf_indicators):
                return BlockReason.WAF_BLOCKED
            return BlockReason.AUTH_REQUIRED
        if status == 400:
            if 'invalid' in body_lower or 'validation' in body_lower:
                return BlockReason.INPUT_VALIDATION
            if 'content-type' in body_lower or 'unsupported media' in body_lower:
                return BlockReason.CONTENT_TYPE_REJECTED
            return BlockReason.PARAMETER_FILTERED
        if status == 413:
            return BlockReason.SIZE_LIMIT
        if status in (406, 415):
            return BlockReason.CONTENT_TYPE_REJECTED
        return BlockReason.UNKNOWN

    @staticmethod
    def _detect_sql_dialect(text: str) -> SQLDialect:
        text_lower = text.lower()
        for pattern, dialect in _SQL_FINGERPRINTS.items():
            if re.search(pattern, text_lower):
                return dialect
        return SQLDialect.UNKNOWN

    @staticmethod
    def _detect_waf(
        headers: Dict[str, str], body: str, cookies: Dict[str, str],
    ) -> WAFVendor:
        header_text = ' '.join(f'{k}: {v}' for k, v in headers.items()).lower()
        body_lower = body.lower()
        cookie_text = ' '.join(f'{k}={v}' for k, v in cookies.items()).lower()

        for pattern, (vendor, source) in _WAF_FINGERPRINTS.items():
            search_text = {'header': header_text, 'body': body_lower,
                           'cookie': cookie_text}.get(source, body_lower)
            if re.search(pattern, search_text):
                return vendor
        return WAFVendor.UNKNOWN

    @staticmethod
    def _detect_framework(text: str) -> str:
        text_lower = text.lower()
        for pattern, framework in _FRAMEWORK_FINGERPRINTS.items():
            if re.search(pattern, text_lower):
                return framework
        return ''

    @staticmethod
    def _identify_blocked_patterns(payload: str, error_body: str) -> List[str]:
        blocked = []
        payload_lower = payload.lower()
        for category, patterns in _BLOCK_INDICATORS.items():
            for p in patterns:
                if re.search(p, payload_lower):
                    blocked.append(category)
                    break
        return list(set(blocked))

    @staticmethod
    def _generate_recommendations(
        analysis: 'ResponseAnalysis', payload: str,
    ) -> List[str]:
        recs = []
        if analysis.waf_vendor != WAFVendor.UNKNOWN:
            recs.append(f'WAF detected: {analysis.waf_vendor.value} - use vendor-specific bypass')
        if analysis.sql_dialect != SQLDialect.UNKNOWN:
            recs.append(f'SQL dialect: {analysis.sql_dialect.value} - use dialect-specific syntax')
        if analysis.block_reason == BlockReason.WAF_BLOCKED:
            recs.append('Try encoding payload (URL, double-URL, Unicode)')
            recs.append('Try splitting payload across parameters')
        if analysis.block_reason == BlockReason.INPUT_VALIDATION:
            recs.append('Try type confusion (array instead of string)')
            recs.append('Try boundary values (empty, null, max-length)')
        if analysis.block_reason == BlockReason.RATE_LIMITED:
            recs.append('Slow down requests or rotate source IPs')
        if 'script_tags' in analysis.blocked_patterns:
            recs.append('Use event handlers instead of <script> tags')
        if 'sql_keywords' in analysis.blocked_patterns:
            recs.append('Use SQL comment-based obfuscation')
        if 'special_chars' in analysis.blocked_patterns:
            recs.append('Use encoding alternatives for blocked characters')
        if not recs:
            recs.append('No specific blocks detected - try more aggressive payloads')
        return recs

    @staticmethod
    def _calculate_confidence(analysis: 'ResponseAnalysis') -> float:
        score = 0.0
        if analysis.waf_vendor != WAFVendor.UNKNOWN:
            score += 0.3
        if analysis.sql_dialect != SQLDialect.UNKNOWN:
            score += 0.3
        if analysis.framework:
            score += 0.15
        if analysis.blocked_patterns:
            score += 0.15
        if analysis.block_reason != BlockReason.UNKNOWN:
            score += 0.1
        return min(score, 1.0)
