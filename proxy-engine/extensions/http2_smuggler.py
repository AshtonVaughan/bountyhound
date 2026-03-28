"""HTTP/2 Smuggler — test H2.CL and H2.TE desync attacks."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from models import ScanFinding

log = logging.getLogger("proxy-engine.ext.http2-smuggler")

NAME = "http2-smuggler"
DESCRIPTION = "Test H2.CL desync (mismatched Content-Length) and H2.TE desync (Transfer-Encoding in H2)"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "timeout": 15.0,
}


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


async def active_check(url: str) -> list[ScanFinding]:
    """Test for HTTP/2 request smuggling via H2.CL and H2.TE desync."""
    findings: list[ScanFinding] = []
    timeout = _config.get("timeout", 15.0)

    # Ensure HTTPS for H2
    parsed = urlparse(url)
    if parsed.scheme == "http":
        h2_url = url.replace("http://", "https://", 1)
    else:
        h2_url = url

    # ── H2.CL Desync ────────────────────────────────────────────────────────
    # Send Content-Length that doesn't match actual body length
    findings.extend(await _test_h2_cl_desync(h2_url, timeout))

    # ── H2.TE Desync ────────────────────────────────────────────────────────
    # Inject Transfer-Encoding header in HTTP/2 request
    findings.extend(await _test_h2_te_desync(h2_url, timeout))

    # ── CL.0 Desync ─────────────────────────────────────────────────────────
    # Send request with body but Content-Length: 0
    findings.extend(await _test_cl0_desync(h2_url, timeout))

    return findings


async def _test_h2_cl_desync(url: str, timeout: float) -> list[ScanFinding]:
    """H2.CL: Content-Length mismatches actual body."""
    findings: list[ScanFinding] = []

    smuggled_body = "0\r\n\r\nGET /h2cl-detect HTTP/1.1\r\nHost: detect\r\n\r\n"
    # Claim body is shorter than it is
    wrong_cl = str(len(smuggled_body) // 2)

    try:
        async with httpx.AsyncClient(
            http2=True, verify=False, timeout=timeout
        ) as client:
            # First, confirm H2 is supported
            baseline = await client.get(url)
            if baseline.http_version not in ("HTTP/2", "h2"):
                log.debug(f"H2 not supported for {url} (got {baseline.http_version})")
                return findings

            # Send mismatched Content-Length
            try:
                resp = await client.post(
                    url,
                    content=smuggled_body.encode(),
                    headers={
                        "Content-Length": wrong_cl,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )

                # Check for desync indicators
                if resp.status_code in (400, 403):
                    # Server may have caught it — check if a second request gets poisoned
                    resp2 = await client.get(url)
                    if resp2.status_code != baseline.status_code:
                        findings.append(ScanFinding(
                            template_id="h2_cl_desync",
                            name="HTTP/2 CL Desync (H2.CL)",
                            severity="high",
                            url=url,
                            matched_at=url,
                            description=(
                                "HTTP/2 connection accepted mismatched Content-Length. "
                                f"Sent CL={wrong_cl} with body length {len(smuggled_body)}. "
                                f"Follow-up request returned different status "
                                f"({resp2.status_code} vs baseline {baseline.status_code}), "
                                "indicating possible request smuggling."
                            ),
                            extracted=[
                                f"Claimed CL: {wrong_cl}",
                                f"Actual body length: {len(smuggled_body)}",
                                f"Baseline status: {baseline.status_code}",
                                f"Post-smuggle status: {resp2.status_code}",
                            ],
                            source="extension",
                            confidence="firm",
                            remediation=(
                                "Ensure front-end and back-end agree on request boundaries. "
                                "Strip Content-Length from H2 requests at the proxy layer."
                            ),
                        ))
                elif resp.status_code != baseline.status_code:
                    findings.append(ScanFinding(
                        template_id="h2_cl_desync_indicator",
                        name="HTTP/2 CL Desync Indicator",
                        severity="medium",
                        url=url,
                        matched_at=url,
                        description=(
                            f"Server responded with {resp.status_code} to H2 request with "
                            f"mismatched Content-Length (claimed {wrong_cl}, actual {len(smuggled_body)}). "
                            "Further manual investigation recommended."
                        ),
                        extracted=[f"CL: {wrong_cl}", f"Status: {resp.status_code}"],
                        source="extension",
                        confidence="tentative",
                        remediation="Investigate request processing pipeline for H2-to-H1 downgrade issues.",
                    ))
            except httpx.RemoteProtocolError as e:
                # Protocol errors can indicate the server tried to process smuggled data
                findings.append(ScanFinding(
                    template_id="h2_cl_desync_protocol_error",
                    name="HTTP/2 CL Desync: Protocol Error",
                    severity="medium",
                    url=url,
                    matched_at=url,
                    description=(
                        f"Server returned protocol error on H2 request with mismatched CL: {e}. "
                        "This may indicate the backend attempted to parse the smuggled request."
                    ),
                    extracted=[str(e)],
                    source="extension",
                    confidence="tentative",
                    remediation="Investigate H2-to-H1 downgrade behaviour on the reverse proxy.",
                ))

    except Exception as e:
        log.debug(f"H2.CL desync test error: {e}")

    return findings


async def _test_h2_te_desync(url: str, timeout: float) -> list[ScanFinding]:
    """H2.TE: Inject Transfer-Encoding in HTTP/2 request."""
    findings: list[ScanFinding] = []

    chunked_body = "1\r\nZ\r\n0\r\n\r\n"

    try:
        async with httpx.AsyncClient(
            http2=True, verify=False, timeout=timeout
        ) as client:
            baseline = await client.get(url)
            if baseline.http_version not in ("HTTP/2", "h2"):
                return findings

            # H2 spec says Transfer-Encoding should not be used, but some
            # front-ends pass it through when downgrading to H1
            te_variants = [
                "chunked",
                "Chunked",
                "chunked\r\nTransfer-Encoding: x",
                " chunked",
                "\tchunked",
            ]

            for te_value in te_variants:
                try:
                    resp = await client.post(
                        url,
                        content=chunked_body.encode(),
                        headers={
                            "Transfer-Encoding": te_value,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                    )

                    if resp.status_code != baseline.status_code:
                        # Check follow-up
                        resp2 = await client.get(url)
                        if resp2.status_code != baseline.status_code:
                            findings.append(ScanFinding(
                                template_id="h2_te_desync",
                                name="HTTP/2 TE Desync (H2.TE)",
                                severity="high",
                                url=url,
                                matched_at=url,
                                description=(
                                    f"Transfer-Encoding '{te_value}' accepted in HTTP/2 request. "
                                    f"Follow-up request returned {resp2.status_code} vs baseline "
                                    f"{baseline.status_code}. Possible H2.TE request smuggling."
                                ),
                                extracted=[
                                    f"TE value: {te_value}",
                                    f"Smuggle status: {resp.status_code}",
                                    f"Follow-up status: {resp2.status_code}",
                                ],
                                source="extension",
                                confidence="firm",
                                remediation=(
                                    "Strip Transfer-Encoding headers from HTTP/2 requests at the "
                                    "front-end proxy. Reject H2 requests containing TE headers."
                                ),
                            ))
                            break

                except Exception:
                    continue

    except Exception as e:
        log.debug(f"H2.TE desync test error: {e}")

    return findings


async def _test_cl0_desync(url: str, timeout: float) -> list[ScanFinding]:
    """CL.0: Send body with Content-Length: 0."""
    findings: list[ScanFinding] = []

    smuggled = "GET /cl0-detect HTTP/1.1\r\nHost: detect\r\n\r\n"

    try:
        async with httpx.AsyncClient(
            http2=True, verify=False, timeout=timeout
        ) as client:
            baseline = await client.get(url)
            if baseline.http_version not in ("HTTP/2", "h2"):
                return findings

            try:
                resp = await client.post(
                    url,
                    content=smuggled.encode(),
                    headers={
                        "Content-Length": "0",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )

                resp2 = await client.get(url)
                if resp2.status_code != baseline.status_code:
                    findings.append(ScanFinding(
                        template_id="cl0_desync",
                        name="CL.0 Request Smuggling",
                        severity="high",
                        url=url,
                        matched_at=url,
                        description=(
                            "Server accepted body content despite Content-Length: 0. "
                            f"Follow-up status changed from {baseline.status_code} to "
                            f"{resp2.status_code}, indicating desync."
                        ),
                        extracted=[
                            f"Body sent: {len(smuggled)} bytes with CL: 0",
                            f"Baseline: {baseline.status_code}",
                            f"Post-smuggle: {resp2.status_code}",
                        ],
                        source="extension",
                        confidence="firm",
                        remediation="Ensure back-end rejects requests where body length exceeds Content-Length.",
                    ))
            except httpx.RemoteProtocolError:
                pass

    except Exception as e:
        log.debug(f"CL.0 desync test error: {e}")

    return findings
