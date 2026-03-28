"""Self-hosted Collaborator server — DNS, HTTP, SMTP OOB interaction detection."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from pathlib import Path

import aiohttp.web

from models import CollaboratorInteraction, CollaboratorConfig, CollaboratorPayload
from state import state

log = logging.getLogger("proxy-engine.collaborator-server")

# ── Internal state ───────────────────────────────────────────────────────────

_payload_registry: dict[str, CollaboratorPayload] = {}  # correlation_id -> payload
_dns_transport: asyncio.DatagramTransport | None = None
_http_runner: aiohttp.web.AppRunner | None = None
_smtp_server = None
_running = False
_sse_queues: list[asyncio.Queue] = []
_tunnel_process = None
_tunnel_public_url: str = ""


# ── Payload generation ───────────────────────────────────────────────────────

def generate_unique_payload(context: str = "") -> CollaboratorPayload:
    """Generate a UUID-based unique collaborator payload."""
    correlation_id = uuid.uuid4().hex[:16]
    cfg = state.collaborator_config
    subdomain = f"{correlation_id}.collab.{cfg.domain}"

    payload = CollaboratorPayload(
        id=str(uuid.uuid4())[:8],
        correlation_id=correlation_id,
        subdomain=subdomain,
        full_dns=subdomain,
        full_url=f"http://{subdomain}:{cfg.http_port}",
        https_url=f"https://{subdomain}",
        smtp_address=f"{correlation_id}@collab.{cfg.domain}",
        context=context,
        created_at=time.time(),
    )

    _payload_registry[correlation_id] = payload
    state.collaborator_payloads[correlation_id] = payload
    return payload


# ── Correlation ──────────────────────────────────────────────────────────────

def correlate_interaction(correlation_id: str, interaction: CollaboratorInteraction) -> None:
    """Auto-link an interaction to the scan/check that generated it."""
    interaction.correlation_id = correlation_id
    state.collaborator_interactions.append(interaction)
    _persist_interaction(interaction)

    # Push to SSE clients
    for q in _sse_queues:
        try:
            q.put_nowait(interaction)
        except asyncio.QueueFull:
            pass


def get_interactions(correlation_id: str | None = None) -> list[CollaboratorInteraction]:
    """Get interactions, optionally filtered by correlation_id."""
    if correlation_id:
        return [i for i in state.collaborator_interactions if i.correlation_id == correlation_id]
    return list(state.collaborator_interactions)


# ── DNS Server ───────────────────────────────────────────────────────────────

class CollaboratorDNSProtocol(asyncio.DatagramProtocol):
    """Catches DNS queries for *.collab.<domain> and logs interactions."""

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        try:
            # Minimal DNS parsing — extract query name
            if len(data) < 12:
                return

            txn_id = data[:2]
            # Skip header (12 bytes), parse question
            pos = 12
            labels = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                pos += 1
                labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
                pos += length

            query_name = ".".join(labels).lower()
            log.info(f"[collaborator-dns] Query: {query_name} from {addr[0]}")

            # Extract correlation ID from subdomain prefix
            correlation_id = _extract_correlation_id(query_name)
            if correlation_id:
                interaction = CollaboratorInteraction(
                    id=str(uuid.uuid4())[:8],
                    protocol="dns",
                    remote_address=addr[0],
                    timestamp=time.time(),
                    dns_query=query_name,
                    context=_payload_registry.get(correlation_id, CollaboratorPayload()).context,
                )
                correlate_interaction(correlation_id, interaction)

            # Read qtype and qclass from the question section
            qtype = 1  # default to A record
            qclass = 1
            if pos + 4 <= len(data):
                qtype = int.from_bytes(data[pos:pos+2], 'big')
                qclass = int.from_bytes(data[pos+2:pos+4], 'big')

            # Build minimal DNS response
            response_ip = state.collaborator_config.response_ip
            ip_parts = [int(p) for p in response_ip.split(".")]

            # DNS response: copy txn_id, flags=0x8180, QDCOUNT=1, ANCOUNT=1
            resp = bytearray(txn_id)
            resp += b"\x81\x80"  # flags: response, no error
            resp += b"\x00\x01"  # QDCOUNT
            resp += b"\x00\x01"  # ANCOUNT
            resp += b"\x00\x00\x00\x00"  # NSCOUNT, ARCOUNT

            # Question section (copy from request)
            resp += data[12:pos + 4]  # question + qtype + qclass

            # Answer section — varies by qtype
            resp += b"\xc0\x0c"  # pointer to name in question
            cfg = state.collaborator_config

            if qtype == 28:  # AAAA
                resp += b"\x00\x1c"  # type AAAA
                resp += b"\x00\x01"  # class IN
                resp += b"\x00\x00\x00\x3c"  # TTL 60
                resp += b"\x00\x10"  # RDLENGTH 16
                # ::1 in 16 bytes
                resp += b"\x00" * 15 + b"\x01"
            elif qtype == 15:  # MX
                # Build the collab domain as DNS name labels
                collab_domain = f"collab.{cfg.domain}"
                mx_rdata = b"\x00\x0a"  # preference = 10
                for label in collab_domain.split("."):
                    mx_rdata += bytes([len(label)]) + label.encode("ascii")
                mx_rdata += b"\x00"  # root terminator
                resp += b"\x00\x0f"  # type MX
                resp += b"\x00\x01"  # class IN
                resp += b"\x00\x00\x00\x3c"  # TTL 60
                resp += len(mx_rdata).to_bytes(2, 'big')  # RDLENGTH
                resp += mx_rdata
            elif qtype == 16:  # TXT
                txt_content = (correlation_id or "no-correlation").encode("ascii")
                # TXT RDATA: 1-byte length prefix + text
                txt_rdata = bytes([len(txt_content)]) + txt_content
                resp += b"\x00\x10"  # type TXT
                resp += b"\x00\x01"  # class IN
                resp += b"\x00\x00\x00\x3c"  # TTL 60
                resp += len(txt_rdata).to_bytes(2, 'big')  # RDLENGTH
                resp += txt_rdata
            elif qtype == 5:  # CNAME
                collab_domain = f"collab.{cfg.domain}"
                cname_rdata = bytearray()
                for label in collab_domain.split("."):
                    cname_rdata += bytes([len(label)]) + label.encode("ascii")
                cname_rdata += b"\x00"
                resp += b"\x00\x05"  # type CNAME
                resp += b"\x00\x01"  # class IN
                resp += b"\x00\x00\x00\x3c"  # TTL 60
                resp += len(cname_rdata).to_bytes(2, 'big')  # RDLENGTH
                resp += bytes(cname_rdata)
            else:  # Type 1 (A) and any other type — default A record
                resp += b"\x00\x01"  # type A
                resp += b"\x00\x01"  # class IN
                resp += b"\x00\x00\x00\x3c"  # TTL 60
                resp += b"\x00\x04"  # RDLENGTH
                resp += bytes(ip_parts)

            self.transport.sendto(bytes(resp), addr)

        except Exception as e:
            log.debug(f"[collaborator-dns] Parse error: {e}")


# ── HTTP Callback Server ────────────────────────────────────────────────────

async def _http_callback_handler(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Capture HTTP callback interactions."""
    host = request.host.split(":")[0]
    path = request.path

    log.info(f"[collaborator-http] {request.method} {host}{path} from {request.remote}")

    correlation_id = _extract_correlation_id(host) or _extract_correlation_id(path.strip("/"))

    body = ""
    try:
        body = await request.text()
    except Exception:
        pass

    if correlation_id:
        raw_req = f"{request.method} {path} HTTP/1.1\nHost: {host}\n"
        for k, v in request.headers.items():
            raw_req += f"{k}: {v}\n"
        if body:
            raw_req += f"\n{body}"

        interaction = CollaboratorInteraction(
            id=str(uuid.uuid4())[:8],
            protocol="http",
            remote_address=request.remote or "",
            timestamp=time.time(),
            raw_request=raw_req,
            http_method=request.method,
            http_path=path,
            context=_payload_registry.get(correlation_id, CollaboratorPayload()).context,
        )
        correlate_interaction(correlation_id, interaction)

    return aiohttp.web.Response(text="ok", status=200)


# ── SMTP Listener ───────────────────────────────────────────────────────────

class CollaboratorSMTPHandler:
    """aiosmtpd handler that captures email OOB interactions."""

    async def handle_DATA(self, server, session, envelope) -> str:
        mail_from = envelope.mail_from or ""
        rcpt_tos = envelope.rcpt_tos or []
        data = envelope.content.decode("utf-8", errors="replace") if envelope.content else ""

        log.info(f"[collaborator-smtp] From: {mail_from} To: {rcpt_tos} ({len(data)} bytes)")

        for rcpt in rcpt_tos:
            correlation_id = _extract_correlation_id(rcpt.split("@")[0])
            if correlation_id:
                interaction = CollaboratorInteraction(
                    id=str(uuid.uuid4())[:8],
                    protocol="smtp",
                    remote_address=session.peer[0] if session.peer else "",
                    timestamp=time.time(),
                    smtp_from=mail_from,
                    smtp_to=rcpt,
                    smtp_data=data[:5000],
                    context=_payload_registry.get(correlation_id, CollaboratorPayload()).context,
                )
                correlate_interaction(correlation_id, interaction)

        return "250 OK"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_correlation_id(text: str) -> str | None:
    """Extract 16-char hex correlation ID from text."""
    text = text.lower()
    # Look for the ID as a prefix before .collab or directly
    parts = text.split(".")
    for part in parts:
        part = part.strip()
        if len(part) == 16 and all(c in "0123456789abcdef" for c in part):
            if part in _payload_registry:
                return part
    return None


# ── HTTPS cert generation ────────────────────────────────────────────────────

def _create_self_signed_cert(domain: str) -> tuple[str, str]:
    """Generate a self-signed certificate for HTTPS callback server."""
    import tempfile, subprocess
    cert_dir = tempfile.mkdtemp(prefix="collab_cert_")
    cert_path = os.path.join(cert_dir, "cert.pem")
    key_path = os.path.join(cert_dir, "key.pem")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
        "-out", cert_path, "-days", "365", "-nodes",
        "-subj", f"/CN=*.{domain}"
    ], check=True, capture_output=True)
    return cert_path, key_path


# ── Tunnel integration ──────────────────────────────────────────────────────

async def start_tunnel(port: int, provider: str = "auto") -> str:
    """Start ngrok or cloudflared tunnel for public reachability."""
    global _tunnel_process, _tunnel_public_url
    import shutil, subprocess

    # Try cloudflared first, then ngrok
    if provider == "auto":
        if shutil.which("cloudflared"):
            provider = "cloudflared"
        elif shutil.which("ngrok"):
            provider = "ngrok"
        else:
            log.warning("[collaborator] No tunnel binary found (ngrok/cloudflared)")
            return ""

    if provider == "cloudflared":
        _tunnel_process = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        # Parse URL from stderr output
        import re as _re
        for _ in range(30):  # Wait up to 30 seconds
            line = _tunnel_process.stderr.readline().decode()
            if "trycloudflare.com" in line or ".cloudflare" in line:
                match = _re.search(r'https?://[^\s]+', line)
                if match:
                    _tunnel_public_url = match.group(0)
                    log.info(f"[collaborator] Tunnel URL: {_tunnel_public_url}")
                    return _tunnel_public_url
            await asyncio.sleep(1)
    elif provider == "ngrok":
        _tunnel_process = subprocess.Popen(
            ["ngrok", "http", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        await asyncio.sleep(3)
        # Get URL from ngrok API
        try:
            import httpx
            async with httpx.AsyncClient() as c:
                r = await c.get("http://127.0.0.1:4040/api/tunnels")
                tunnels = r.json().get("tunnels", [])
                if tunnels:
                    _tunnel_public_url = tunnels[0].get("public_url", "")
                    log.info(f"[collaborator] Tunnel URL: {_tunnel_public_url}")
                    return _tunnel_public_url
        except Exception:
            pass

    return ""


def get_tunnel_url() -> str:
    """Return the current tunnel public URL, if any."""
    return _tunnel_public_url


async def stop_tunnel():
    """Terminate tunnel subprocess and clear URL."""
    global _tunnel_process, _tunnel_public_url
    if _tunnel_process:
        _tunnel_process.terminate()
        _tunnel_process = None
    _tunnel_public_url = ""


# ── Server lifecycle ─────────────────────────────────────────────────────────

async def start_servers(
    domain: str | None = None,
    dns_port: int | None = None,
    http_port: int | None = None,
    smtp_port: int | None = None,
) -> dict:
    """Start all collaborator servers."""
    global _dns_transport, _http_runner, _smtp_server, _running

    if _running:
        return {"status": "already_running"}

    cfg = state.collaborator_config
    if domain:
        cfg.domain = domain
    if dns_port:
        cfg.dns_port = dns_port
    if http_port:
        cfg.http_port = http_port
    if smtp_port:
        cfg.smtp_port = smtp_port
    cfg.enabled = True

    started = []

    # Start DNS server
    try:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            CollaboratorDNSProtocol,
            local_addr=("0.0.0.0", cfg.dns_port),
        )
        _dns_transport = transport
        started.append(f"dns:{cfg.dns_port}")
        log.info(f"[collaborator] DNS server on port {cfg.dns_port}")
    except Exception as e:
        log.warning(f"[collaborator] DNS server failed: {e}")

    # Start HTTP callback server
    try:
        app = aiohttp.web.Application()
        app.router.add_route("*", "/{path_info:.*}", _http_callback_handler)
        _http_runner = aiohttp.web.AppRunner(app)
        await _http_runner.setup()
        site = aiohttp.web.TCPSite(_http_runner, "0.0.0.0", cfg.http_port)
        await site.start()
        started.append(f"http:{cfg.http_port}")
        log.info(f"[collaborator] HTTP callback server on port {cfg.http_port}")
    except Exception as e:
        log.warning(f"[collaborator] HTTP server failed: {e}")

    # Start HTTPS callback server (HTTP port + 1)
    try:
        import ssl as _ssl
        cert_path, key_path = _create_self_signed_cert(cfg.domain)
        ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(cert_path, key_path)
        https_site = aiohttp.web.TCPSite(_http_runner, "0.0.0.0", cfg.http_port + 1, ssl_context=ssl_ctx)
        await https_site.start()
        started.append(f"https:{cfg.http_port + 1}")
        log.info(f"[collaborator] HTTPS callback server on port {cfg.http_port + 1}")
    except Exception as e:
        log.warning(f"[collaborator] HTTPS server failed: {e}")

    # Start SMTP listener
    try:
        from aiosmtpd.controller import Controller
        handler = CollaboratorSMTPHandler()
        _smtp_server = Controller(handler, hostname="0.0.0.0", port=cfg.smtp_port)
        _smtp_server.start()
        started.append(f"smtp:{cfg.smtp_port}")
        log.info(f"[collaborator] SMTP listener on port {cfg.smtp_port}")
    except ImportError:
        log.warning("[collaborator] aiosmtpd not installed, SMTP disabled")
    except Exception as e:
        log.warning(f"[collaborator] SMTP server failed: {e}")

    _running = True
    _load_interactions()

    return {"status": "started", "servers": started, "domain": cfg.domain}


async def stop_servers() -> dict:
    """Stop all collaborator servers."""
    global _dns_transport, _http_runner, _smtp_server, _running

    stopped = []

    if _dns_transport:
        _dns_transport.close()
        _dns_transport = None
        stopped.append("dns")

    if _http_runner:
        await _http_runner.cleanup()
        _http_runner = None
        stopped.append("http")

    if _smtp_server:
        _smtp_server.stop()
        _smtp_server = None
        stopped.append("smtp")

    # Stop tunnel if running
    await stop_tunnel()

    _running = False
    state.collaborator_config.enabled = False

    return {"status": "stopped", "servers": stopped}


# ── Persistence ──────────────────────────────────────────────────────────────

def _persist_interaction(interaction: CollaboratorInteraction) -> None:
    """Append interaction to JSONL file."""
    try:
        path = Path(state.collaborator_config.persist_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(interaction.model_dump(), default=str) + "\n")
    except Exception as e:
        log.debug(f"[collaborator] Persist error: {e}")


def _load_interactions() -> None:
    """Load interactions from JSONL file."""
    try:
        path = Path(state.collaborator_config.persist_path)
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                data = json.loads(line)
                interaction = CollaboratorInteraction(**data)
                if interaction not in state.collaborator_interactions:
                    state.collaborator_interactions.append(interaction)
        log.info(f"[collaborator] Loaded {len(state.collaborator_interactions)} interactions")
    except Exception as e:
        log.debug(f"[collaborator] Load error: {e}")


# ── SSE push ─────────────────────────────────────────────────────────────────

async def sse_interactions():
    """Generator for SSE real-time interaction notifications."""
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _sse_queues.append(q)
    try:
        while True:
            interaction = await q.get()
            yield json.dumps(interaction.model_dump(), default=str)
    finally:
        _sse_queues.remove(q)
