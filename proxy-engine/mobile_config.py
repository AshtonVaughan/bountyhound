"""Mobile proxy configuration — PAC file, QR code, iOS mobileconfig generation."""

from __future__ import annotations

import base64
import logging
from pathlib import Path

log = logging.getLogger("proxy-engine.mobile-config")


def generate_pac_file(proxy_host: str = "127.0.0.1", proxy_port: int = 8080) -> str:
    """Generate a PAC (Proxy Auto-Config) file."""
    return f"""function FindProxyForURL(url, host) {{
    // Direct connections for local addresses
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {{
        return "DIRECT";
    }}
    return "PROXY {proxy_host}:{proxy_port}";
}}
"""


def generate_qr_data(proxy_host: str = "127.0.0.1", proxy_port: int = 8080) -> str:
    """Generate a QR code PNG as base64 for mobile proxy setup."""
    try:
        import qrcode
        from io import BytesIO

        config_url = f"http://{proxy_host}:{proxy_port}"
        wifi_config = f"PROXY:{proxy_host}:{proxy_port}"

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(wifi_config)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode("ascii")

    except ImportError:
        log.warning("[mobile-config] qrcode library not installed")
        return ""


def generate_mobileconfig(
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
    ca_cert_path: str | None = None,
) -> str:
    """Generate an iOS mobileconfig profile XML for proxy + CA cert installation."""
    import uuid

    profile_uuid = str(uuid.uuid4()).upper()
    proxy_uuid = str(uuid.uuid4()).upper()
    cert_uuid = str(uuid.uuid4()).upper()

    cert_payload = ""
    if ca_cert_path:
        cert_path = Path(ca_cert_path)
        if cert_path.exists():
            cert_data = base64.b64encode(cert_path.read_bytes()).decode("ascii")
            cert_payload = f"""
        <dict>
            <key>PayloadContent</key>
            <data>{cert_data}</data>
            <key>PayloadDescription</key>
            <string>Proxy Engine CA Certificate</string>
            <key>PayloadDisplayName</key>
            <string>Proxy Engine CA</string>
            <key>PayloadIdentifier</key>
            <string>com.proxy-engine.cert.{cert_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>{cert_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>"""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDescription</key>
            <string>Configures HTTP proxy for traffic interception</string>
            <key>PayloadDisplayName</key>
            <string>Proxy Engine HTTP Proxy</string>
            <key>PayloadIdentifier</key>
            <string>com.proxy-engine.proxy.{proxy_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.proxy.http.global</string>
            <key>PayloadUUID</key>
            <string>{proxy_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ProxyCaptiveLoginAllowed</key>
            <true/>
            <key>HTTPEnable</key>
            <integer>1</integer>
            <key>HTTPProxy</key>
            <string>{proxy_host}</string>
            <key>HTTPPort</key>
            <integer>{proxy_port}</integer>
            <key>HTTPSEnable</key>
            <integer>1</integer>
            <key>HTTPSProxy</key>
            <string>{proxy_host}</string>
            <key>HTTPSPort</key>
            <integer>{proxy_port}</integer>
        </dict>{cert_payload}
    </array>
    <key>PayloadDescription</key>
    <string>Proxy Engine mobile configuration for HTTP/HTTPS traffic interception</string>
    <key>PayloadDisplayName</key>
    <string>Proxy Engine</string>
    <key>PayloadIdentifier</key>
    <string>com.proxy-engine.profile.{profile_uuid}</string>
    <key>PayloadOrganization</key>
    <string>Proxy Engine</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>"""
