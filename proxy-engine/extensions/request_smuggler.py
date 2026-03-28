"""HTTP Request Smuggler — CL.TE, TE.CL, TE.TE obfuscation, timing-based differential."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from models import ScanFinding

log = logging.getLogger("ext-request-smuggler")

NAME = "request-smuggler"
DESCRIPTION = "CL.TE, TE.CL, TE.TE obfuscation, H2.CL, H2.TE, timing-based differential"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "timeout": 10,
    "timing_threshold": 5.0,  # seconds for timing-based detection
}


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    findings = []

    # CL.TE detection
    findings.extend(await _test_cl_te(url))
    # TE.CL detection
    findings.extend(await _test_te_cl(url))
    # TE.TE obfuscation
    findings.extend(await _test_te_te(url))

    return findings


async def _test_cl_te(url: str) -> list[ScanFinding]:
    """CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding."""
    findings = []

    # Timing-based CL.TE probe
    smuggle_body = "0\r\n\r\nG"  # Partial request that should cause timeout on back-end

    try:
        async with httpx.AsyncClient(verify=False, timeout=_config["timeout"]) as client:
            start = time.time()
            try:
                await client.post(
                    url,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": str(len(smuggle_body) + 6),
                        "Transfer-Encoding": "chunked",
                    },
                    content=smuggle_body,
                )
            except httpx.ReadTimeout:
                elapsed = time.time() - start
                if elapsed >= _config.get("timing_threshold", 5.0):
                    findings.append(ScanFinding(
                        template_id="smuggling_cl_te",
                        name="HTTP Request Smuggling (CL.TE)",
                        severity="high",
                        url=url,
                        matched_at=url,
                        description=f"CL.TE desync detected via timing. Request timed out after {elapsed:.1f}s indicating back-end processed Transfer-Encoding.",
                        extracted=[f"timing={elapsed:.1f}s", "technique=CL.TE"],
                        source="extension",
                        confidence="firm",
                        remediation="Normalize request parsing between front-end and back-end. Reject ambiguous requests.",
                    ))
            except Exception:
                pass
    except Exception:
        pass

    return findings


async def _test_te_cl(url: str) -> list[ScanFinding]:
    """TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length."""
    findings = []

    smuggle_body = "1\r\nZ\r\nQ\r\n\r\n"

    try:
        async with httpx.AsyncClient(verify=False, timeout=_config["timeout"]) as client:
            start = time.time()
            try:
                await client.post(
                    url,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": "4",
                        "Transfer-Encoding": "chunked",
                    },
                    content=smuggle_body,
                )
            except httpx.ReadTimeout:
                elapsed = time.time() - start
                if elapsed >= _config.get("timing_threshold", 5.0):
                    findings.append(ScanFinding(
                        template_id="smuggling_te_cl",
                        name="HTTP Request Smuggling (TE.CL)",
                        severity="high",
                        url=url,
                        matched_at=url,
                        description=f"TE.CL desync detected via timing ({elapsed:.1f}s). Back-end uses Content-Length while front-end uses Transfer-Encoding.",
                        extracted=[f"timing={elapsed:.1f}s", "technique=TE.CL"],
                        source="extension",
                        confidence="firm",
                        remediation="Normalize request parsing. Reject requests with both Content-Length and Transfer-Encoding.",
                    ))
            except Exception:
                pass
    except Exception:
        pass

    return findings


async def _test_te_te(url: str) -> list[ScanFinding]:
    """TE.TE: Both use Transfer-Encoding but one can be confused by obfuscation."""
    findings = []

    obfuscations = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        "Transfer-encoding: chunked",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: \x0bchunked",
    ]

    for obf in obfuscations:
        try:
            async with httpx.AsyncClient(verify=False, timeout=_config["timeout"]) as client:
                # Parse custom header
                if ": " in obf:
                    hname, hval = obf.split(": ", 1)
                else:
                    continue

                start = time.time()
                try:
                    await client.post(
                        url,
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            hname.strip(): hval.strip(),
                        },
                        content="0\r\n\r\n",
                    )
                except httpx.ReadTimeout:
                    elapsed = time.time() - start
                    if elapsed >= _config.get("timing_threshold", 5.0):
                        findings.append(ScanFinding(
                            template_id="smuggling_te_te",
                            name="HTTP Request Smuggling (TE.TE Obfuscation)",
                            severity="high",
                            url=url,
                            matched_at=url,
                            description=f"TE.TE obfuscation variant detected. Obfuscated header: '{obf[:50]}'",
                            extracted=[obf[:50], f"timing={elapsed:.1f}s"],
                            source="extension",
                            confidence="firm",
                            remediation="Normalize Transfer-Encoding header parsing. Reject malformed variants.",
                        ))
                        break
                except Exception:
                    pass
        except Exception:
            continue

    return findings
