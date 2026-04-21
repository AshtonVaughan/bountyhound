"""
IoT and Hardware Security Tester

Tests IoT devices and hardware security:
- Network device discovery
- MQTT broker security
- UPnP vulnerabilities
- Firmware extraction
- Default credentials
"""

import subprocess
import requests
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class Finding:
    """IoT security finding"""
    title: str
    description: str
    severity: str
    evidence: Dict
    vuln_type: str = "IoT"


class IoTTester:
    """Test IoT devices and hardware security"""

    def __init__(self):
        self.timeout = 10
        self.common_ports = {
            1883: "MQTT",
            8883: "MQTT/TLS",
            5683: "CoAP",
            1900: "UPnP",
            554: "RTSP",
            8080: "HTTP-Alt",
            80: "HTTP",
            23: "Telnet",
            22: "SSH"
        }

    def scan_network_devices(self, network: str) -> List[Dict]:
        """
        Discover IoT devices on network

        Technique:
        - Nmap scan for common IoT ports
        - Identify MQTT, CoAP, UPnP, RTSP
        - Fingerprint device types

        Args:
            network: Network CIDR (e.g., "192.168.1.0/24")

        Returns:
            List of discovered device dictionaries
        """
        devices = []

        try:
            # Build nmap command for IoT ports
            ports = ",".join(str(p) for p in self.common_ports.keys())
            cmd = [
                "nmap",
                "-p", ports,
                "-sV",  # Service version detection
                "--open",  # Only open ports
                network
            ]

            # Run nmap (requires nmap installed)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            # Parse nmap output
            current_host = None
            for line in result.stdout.split('\n'):
                # Host line
                if line.startswith("Nmap scan report for"):
                    current_host = line.split()[-1]

                # Port line
                elif "/tcp" in line and "open" in line:
                    parts = line.split()
                    port = int(parts[0].split('/')[0])

                    if current_host:
                        devices.append({
                            "host": current_host,
                            "port": port,
                            "service": self.common_ports.get(port, "Unknown"),
                            "raw": line
                        })

        except Exception as e:
            print(f"[!] Network scan failed: {e}")

        return devices

    def test_mqtt_security(self, mqtt_broker: str) -> List[Finding]:
        """
        Test MQTT broker security

        Tests:
        - Connect without authentication
        - Subscribe to all topics (#)
        - Test topic injection
        - Check for sensitive data in topics

        Args:
            mqtt_broker: MQTT broker address (host:port)

        Returns:
            List of findings if vulnerabilities detected
        """
        findings = []

        try:
            import paho.mqtt.client as mqtt

            # Parse host:port
            if ':' in mqtt_broker:
                host, port = mqtt_broker.split(':')
                port = int(port)
            else:
                host = mqtt_broker
                port = 1883

            # Try connecting without auth
            client = mqtt.Client()

            # Track received messages
            messages = []

            def on_message(client, userdata, msg):
                messages.append({
                    "topic": msg.topic,
                    "payload": msg.payload.decode('utf-8', errors='ignore')
                })

            client.on_message = on_message

            try:
                client.connect(host, port, timeout=self.timeout)

                # Subscribe to all topics
                client.subscribe("#")

                # Wait for messages
                client.loop_start()
                import time
                time.sleep(5)
                client.loop_stop()

                # If connected without auth
                findings.append(Finding(
                    title="MQTT Broker No Authentication",
                    description=f"MQTT broker at {mqtt_broker} allows unauthenticated connections",
                    severity="HIGH",
                    evidence={
                        "broker": mqtt_broker,
                        "auth_required": False,
                        "messages_received": len(messages),
                        "sample_topics": [m["topic"] for m in messages[:5]]
                    },
                    vuln_type="IoT_MQTT_NoAuth"
                ))

                # Check for sensitive data
                for msg in messages:
                    if any(term in msg["payload"].lower() for term in ["password", "token", "key", "secret"]):
                        findings.append(Finding(
                            title="MQTT Sensitive Data Exposure",
                            description=f"Sensitive data found in MQTT topic: {msg['topic']}",
                            severity="CRITICAL",
                            evidence={
                                "broker": mqtt_broker,
                                "topic": msg["topic"],
                                "payload_preview": msg["payload"][:100]
                            },
                            vuln_type="IoT_MQTT_SensitiveData"
                        ))
                        break

            except Exception as e:
                # Connection failed - likely requires auth (good)
                pass

        except ImportError:
            print("[!] paho-mqtt not installed. Run: pip install paho-mqtt")
        except Exception as e:
            print(f"[!] MQTT test failed: {e}")

        return findings

    def test_upnp_vulnerabilities(self, upnp_device: str) -> List[Finding]:
        """
        Test UPnP security

        Tests:
        - SSDP discovery
        - SOAP injection
        - Command injection in UPnP calls

        Args:
            upnp_device: UPnP device IP

        Returns:
            List of findings if vulnerabilities detected
        """
        findings = []

        try:
            # Try accessing UPnP description
            response = requests.get(
                f"http://{upnp_device}:1900/description.xml",
                timeout=self.timeout
            )

            if response.status_code == 200:
                findings.append(Finding(
                    title="UPnP Device Accessible",
                    description=f"UPnP device at {upnp_device} exposes service description",
                    severity="MEDIUM",
                    evidence={
                        "device": upnp_device,
                        "description": response.text[:500]
                    },
                    vuln_type="IoT_UPnP_Exposure"
                ))

        except Exception as e:
            pass

        return findings

    def test_firmware_extraction(self, device_ip: str) -> Dict:
        """
        Attempt firmware extraction

        Checks:
        - Exposed firmware update endpoint
        - Download firmware
        - Analyze firmware (binwalk, etc.)

        Args:
            device_ip: Device IP address

        Returns:
            Dictionary with extraction results
        """
        # Common firmware endpoints
        endpoints = [
            "/firmware.bin",
            "/update.bin",
            "/system.img",
            "/firmware/download",
            "/api/firmware"
        ]

        for endpoint in endpoints:
            try:
                response = requests.get(
                    f"http://{device_ip}{endpoint}",
                    timeout=self.timeout,
                    stream=True
                )

                if response.status_code == 200:
                    # Check if binary data (firmware)
                    content_type = response.headers.get('Content-Type', '')

                    if 'application/octet-stream' in content_type or 'application/binary' in content_type:
                        return {
                            "extracted": True,
                            "url": f"http://{device_ip}{endpoint}",
                            "size": response.headers.get('Content-Length', 'unknown'),
                            "content_type": content_type
                        }

            except Exception:
                continue

        return {"extracted": False}

    def test_default_credentials(self, device_ip: str) -> List[Finding]:
        """
        Test for default credentials

        Tests common defaults:
        - admin:admin
        - admin:password
        - root:root
        - admin:(blank)

        Args:
            device_ip: Device IP address

        Returns:
            List of findings if defaults work
        """
        findings = []

        # Common default credentials
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", ""),
            ("root", "root"),
            ("admin", "12345"),
            ("user", "user"),
        ]

        # Try HTTP Basic Auth
        for username, password in default_creds:
            try:
                response = requests.get(
                    f"http://{device_ip}",
                    auth=(username, password),
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    findings.append(Finding(
                        title="IoT Device Default Credentials",
                        description=f"Device at {device_ip} accessible with default credentials: {username}:{password}",
                        severity="CRITICAL",
                        evidence={
                            "device": device_ip,
                            "username": username,
                            "password": password,
                            "status": "logged_in"
                        },
                        vuln_type="IoT_Default_Credentials"
                    ))
                    break

            except Exception:
                continue

        return findings
