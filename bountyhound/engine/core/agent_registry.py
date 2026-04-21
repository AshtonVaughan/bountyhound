"""
Agent Registry - Catalog of all BountyHound agents with metadata.

Maps every Python agent module to:
- module path + class name (for dynamic import)
- phase (when it runs in the pipeline)
- trigger conditions (what must be true for it to run)
- priority (higher = runs first within a phase)
- category (web, api, mobile, reversing, sast, cloud, etc.)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set


@dataclass
class AgentEntry:
    """Registry entry for a single agent."""
    name: str
    module: str
    class_name: str
    phase: str  # '1', '1.5', '2', '3A', '3B', '3C', '3D', '5', '6'
    category: str  # web, api, auth, injection, mobile, reversing, sast, cloud, hardware, discovery, understanding
    triggers: List[str] = field(default_factory=list)  # conditions that must be true
    priority: int = 50  # 0-100, higher = earlier in phase
    needs_auth: bool = False
    needs_target_url: bool = True
    description: str = ''
    run_method: str = 'run_all_tests'  # default method to call


# All registered agents
AGENT_REGISTRY: List[AgentEntry] = [
    # ================================================================
    # PHASE 1: DISCOVERY
    # ================================================================
    AgentEntry(
        name='js_analyzer', module='engine.discovery.js_analyzer',
        class_name='JsAnalyzer', phase='1', category='discovery',
        triggers=['has_web'], priority=90,
        description='Extract secrets, endpoints, API keys from JavaScript files',
        run_method='analyze_all',
    ),
    AgentEntry(
        name='content_discovery', module='engine.discovery.content_discovery',
        class_name='ContentDiscovery', phase='1', category='discovery',
        triggers=['has_web'], priority=85,
        description='Brute-force directory/file discovery',
        run_method='discover',
    ),
    AgentEntry(
        name='wayback_miner', module='engine.discovery.wayback_miner',
        class_name='WaybackMiner', phase='1', category='discovery',
        triggers=['has_web'], priority=80,
        description='Mine Wayback Machine for historical endpoints',
        run_method='find_interesting',
    ),
    AgentEntry(
        name='github_osint', module='engine.discovery.github_osint',
        class_name='GitHubOSINT', phase='1', category='discovery',
        triggers=['has_web'], priority=75,
        description='Search GitHub for leaked secrets',
        run_method='find_secrets',
    ),
    AgentEntry(
        name='tech_fingerprinter', module='engine.understanding.tech_fingerprinter',
        class_name='TechFingerprinter', phase='1', category='discovery',
        triggers=['has_web'], priority=95,
        description='Identify technologies, frameworks, WAF',
        run_method='fingerprint',
    ),
    AgentEntry(
        name='api_doc_scanner', module='engine.agents.api_documentation_scanner',
        class_name='APIDocumentationScanner', phase='1', category='discovery',
        triggers=['has_web'], priority=70,
        description='Find Swagger/OpenAPI/RAML documentation',
        run_method='scan_all',
    ),
    AgentEntry(
        name='dns_analyzer', module='engine.agents.dns_record_analyzer',
        class_name='DNSRecordAnalyzer', phase='1', category='discovery',
        triggers=['has_web'], priority=65,
        description='Analyze DNS records for misconfigurations',
        run_method='analyze_all',
    ),
    AgentEntry(
        name='robots_analyzer', module='engine.agents.robots_txt_analyzer',
        class_name='RobotsTxtAnalyzer', phase='1', category='discovery',
        triggers=['has_web'], priority=60,
        description='Analyze robots.txt for hidden paths',
        run_method='analyze',
    ),
    AgentEntry(
        name='katana_crawler', module='engine.agents.katana_crawler',
        class_name='KatanaCrawlerAgent', phase='1', category='discovery',
        triggers=['has_web'], priority=88,
        description='Fast JS-aware web crawl — discovers API endpoints, forms, hidden routes',
        run_method='run',
    ),
    AgentEntry(
        name='gau_urls', module='engine.agents.gau_urls',
        class_name='GAUUrlsAgent', phase='1', category='discovery',
        triggers=['has_web'], priority=82,
        description='Fetch historical URLs from Wayback, CommonCrawl, OTX, URLScan',
        run_method='run',
    ),
    AgentEntry(
        name='ffuf_fuzzer', module='engine.agents.ffuf_fuzzer',
        class_name='FfufFuzzerAgent', phase='1', category='discovery',
        triggers=['has_web'], priority=83,
        description='Fast directory/parameter/vhost fuzzing',
        run_method='run',
    ),
    AgentEntry(
        name='feroxbuster_discovery', module='engine.agents.feroxbuster_discovery',
        class_name='FeroxbusterDiscoveryAgent', phase='1', category='discovery',
        triggers=['has_web'], priority=84,
        description='Recursive content and directory discovery',
        run_method='run',
    ),
    AgentEntry(
        name='trufflehog_secrets', module='engine.agents.trufflehog_secrets',
        class_name='TrufflehogSecretsAgent', phase='1', category='discovery',
        triggers=['has_web'], priority=86,
        description='Scan JS files and git repos for leaked secrets and API keys',
        run_method='run',
    ),
    AgentEntry(
        name='dnsx_resolver', module='engine.agents.dnsx_resolver',
        class_name='DNSXResolverAgent', phase='1', category='discovery',
        triggers=['has_subdomains'], priority=87,
        description='Bulk DNS resolution and subdomain takeover fingerprinting',
        run_method='run',
    ),

    # ================================================================
    # PHASE 1.5: HYPOTHESIS GENERATION
    # ================================================================
    AgentEntry(
        name='discovery_engine', module='engine.agents.discovery_engine',
        class_name='DiscoveryEngine', phase='1.5', category='discovery',
        triggers=['has_web'], priority=90,
        description='LLM-powered hypothesis generation',
        run_method='generate_hypotheses',
    ),

    # ================================================================
    # PHASE 2: AUTHORIZATION TESTING
    # ================================================================
    AgentEntry(
        name='auth_bypass', module='engine.agents.authentication_bypass_tester',
        class_name='AuthenticationBypassTester', phase='2', category='auth',
        triggers=['has_web', 'has_auth'], priority=95, needs_auth=True,
        description='2FA bypass, OAuth bypass, JWT bypass, session management',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='oauth_tester', module='engine.agents.oauth_flow_tester',
        class_name='OAuthFlowTester', phase='2', category='auth',
        triggers=['has_oauth'], priority=90, needs_auth=True,
        description='OAuth flow vulnerabilities',
        run_method='run_comprehensive_test',
    ),
    AgentEntry(
        name='jwt_analyzer', module='engine.agents.jwt_analyzer',
        class_name='JWTAnalyzer', phase='2', category='auth',
        triggers=['has_jwt'], priority=90,
        description='JWT token attacks (none alg, key confusion, etc.)',
        run_method='analyze_token',
    ),
    AgentEntry(
        name='mfa_bypass', module='engine.agents.mfa_bypass_tester',
        class_name='MFABypassTester', phase='2', category='auth',
        triggers=['has_mfa'], priority=85, needs_auth=True,
        description='MFA bypass techniques',
        run_method='test_response_manipulation',
    ),
    AgentEntry(
        name='api_auth_chain', module='engine.agents.api_authentication_chain_tester',
        class_name='APIAuthenticationChainTester', phase='2', category='auth',
        triggers=['has_api'], priority=80, needs_auth=True,
        description='API authentication chain testing',
        run_method='run_comprehensive_test',
    ),

    # ================================================================
    # PHASE 3A: CLI SCANNING (background)
    # ================================================================
    # This is handled by `bountyhound scan` CLI, not a Python agent

    # ================================================================
    # PHASE 3B: BROWSER TESTING (foreground)
    # ================================================================
    # This is manual browser interaction, not auto-dispatched

    # ================================================================
    # PHASE 3C: SOURCE CODE / BINARY / MOBILE ANALYSIS
    # ================================================================
    AgentEntry(
        name='code_auditor', module='engine.sast.analyzers.code_auditor',
        class_name='CodeAuditor', phase='3C', category='sast',
        triggers=['has_source_code'], priority=95, needs_target_url=False,
        description='Deep vulnerability patterns across 7 languages',
        run_method='audit',
    ),
    AgentEntry(
        name='dependency_auditor', module='engine.sast.analyzers.dependency_auditor',
        class_name='DependencyAuditor', phase='3C', category='sast',
        triggers=['has_source_code'], priority=90, needs_target_url=False,
        description='Dependency CVE scanning',
        run_method='audit',
    ),
    AgentEntry(
        name='repo_scanner', module='engine.sast.analyzers.repo_scanner',
        class_name='RepoScanner', phase='3C', category='sast',
        triggers=['has_source_code'], priority=85, needs_target_url=False,
        description='Git history secret scanning',
        run_method='scan',
    ),
    AgentEntry(
        name='secrets_scanner', module='engine.sast.analyzers.secrets_scanner',
        class_name='SecretsScanner', phase='3C', category='sast',
        triggers=['has_source_code'], priority=88, needs_target_url=False,
        description='Regex-based secret detection',
        run_method='scan',
    ),
    AgentEntry(
        name='semgrep_runner', module='engine.sast.analyzers.semgrep_runner',
        class_name='SemgrepRunner', phase='3C', category='sast',
        triggers=['has_source_code', 'has_semgrep'], priority=80, needs_target_url=False,
        description='Semgrep SAST scanning',
        run_method='scan',
    ),
    AgentEntry(
        name='binary_analyzer', module='engine.reversing.binary_analyzer',
        class_name='BinaryAnalyzer', phase='3C', category='reversing',
        triggers=['has_binary'], priority=95, needs_target_url=False,
        description='PE/ELF/Mach-O binary analysis',
        run_method='analyze',
    ),
    AgentEntry(
        name='decompiler', module='engine.reversing.decompiler',
        class_name='Decompiler', phase='3C', category='reversing',
        triggers=['has_binary'], priority=90, needs_target_url=False,
        description='Binary decompilation and function analysis',
        run_method='full_analysis',
    ),
    AgentEntry(
        name='apk_analyzer', module='engine.mobile.android.apk_analyzer',
        class_name='APKAnalyzer', phase='3C', category='mobile',
        triggers=['has_apk'], priority=95, needs_target_url=False,
        description='Android APK security analysis',
        run_method='analyze',
    ),
    AgentEntry(
        name='ipa_analyzer', module='engine.mobile.ios.ipa_analyzer',
        class_name='IPAAnalyzer', phase='3C', category='mobile',
        triggers=['has_ipa'], priority=95, needs_target_url=False,
        description='iOS IPA security analysis',
        run_method='analyze',
    ),
    AgentEntry(
        name='firmware_analyzer', module='engine.hardware.firmware.analyzer',
        class_name='FirmwareAnalyzer', phase='3C', category='hardware',
        triggers=['has_firmware'], priority=90, needs_target_url=False,
        description='Firmware binary analysis',
        run_method='comprehensive_analysis',
    ),
    AgentEntry(
        name='desktop_tester', module='engine.omnihack.desktop_tester',
        class_name='DesktopTester', phase='3C', category='desktop',
        triggers=['has_desktop_app'], priority=85, needs_target_url=False,
        description='Desktop application security testing',
        run_method='scan_for_secrets',
    ),

    # ================================================================
    # PHASE 3D: DEEP WEB TESTING
    # ================================================================
    AgentEntry(
        name='interactsh_oast', module='engine.agents.interactsh_oast',
        class_name='InteractshOASTAgent', phase='3D', category='injection',
        triggers=['has_web'], priority=92,
        description='OOB interaction server — generates payloads for blind SSRF, XXE, Log4j, blind XSS',
        run_method='run',
    ),
    AgentEntry(
        name='arjun_params', module='engine.agents.arjun_params',
        class_name='ArjunParamsAgent', phase='3D', category='api',
        triggers=['has_web', 'has_params'], priority=88,
        description='Discover hidden HTTP parameters via response-size analysis',
        run_method='run',
    ),
    AgentEntry(
        name='dalfox_xss', module='engine.agents.dalfox_xss',
        class_name='DalfoxXSSAgent', phase='3D', category='injection',
        triggers=['has_web', 'has_params'], priority=87,
        description='Context-aware XSS scanning with blind XSS callback support',
        run_method='run',
    ),
    AgentEntry(
        name='sqlmap_injection', module='engine.agents.sqlmap_injection',
        class_name='SQLMapInjectionAgent', phase='3D', category='injection',
        triggers=['has_web', 'has_params'], priority=83,
        description='SQL injection detection across all techniques (detection-only mode)',
        run_method='run',
    ),
    AgentEntry(
        name='timing_injection', module='engine.testing.timing_injection',
        class_name='TimingInjection', phase='3D', category='injection',
        triggers=['has_web', 'has_params'], priority=85,
        description='Blind SQLi/NoSQLi/CMDi via timing',
        run_method='test_all',
    ),
    AgentEntry(
        name='subdomain_takeover', module='engine.testing.subdomain_takeover',
        class_name='SubdomainTakeover', phase='3D', category='web',
        triggers=['has_subdomains'], priority=90,
        description='Dangling CNAME subdomain takeover',
        run_method='bulk_check',
    ),
    AgentEntry(
        name='xss_tester', module='engine.agents.cors_tester',
        class_name='CORSTester', phase='3D', category='web',
        triggers=['has_web'], priority=80,
        description='CORS misconfiguration testing',
        run_method='test_wildcard_with_credentials',
    ),
    AgentEntry(
        name='csrf_tester', module='engine.agents.csrf_tester',
        class_name='CSRFTester', phase='3D', category='web',
        triggers=['has_web', 'has_forms'], priority=75, needs_auth=True,
        description='CSRF vulnerability testing',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='sqli_tester', module='engine.agents.nosql_injection_tester',
        class_name='NoSQLInjectionTester', phase='3D', category='injection',
        triggers=['has_web', 'has_params'], priority=85,
        description='NoSQL injection testing',
        run_method='test_all',
    ),
    AgentEntry(
        name='cmd_injection', module='engine.agents.os_command_injection_tester',
        class_name='CommandInjectionTester', phase='3D', category='injection',
        triggers=['has_web', 'has_params'], priority=80,
        description='OS command injection testing',
        run_method='test_endpoint',
    ),
    AgentEntry(
        name='ssti_tester', module='engine.agents.server_side_template_injection_tester',
        class_name='SSTITester', phase='3D', category='injection',
        triggers=['has_web', 'has_params'], priority=80,
        description='Server-side template injection',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='ssrf_tester', module='engine.agents.ssrf_tester',
        class_name='SSRFTester', phase='3D', category='injection',
        triggers=['has_web', 'has_url_params'], priority=85,
        description='SSRF testing',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='xxe_tester', module='engine.agents.xxe_tester',
        class_name='XXETester', phase='3D', category='injection',
        triggers=['has_web', 'has_xml'], priority=80,
        description='XML External Entity testing',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='path_traversal', module='engine.agents.path_traversal_tester',
        class_name='PathTraversalTester', phase='3D', category='injection',
        triggers=['has_web', 'has_file_params'], priority=80,
        description='Path traversal testing',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='open_redirect', module='engine.agents.open_redirect_tester',
        class_name='OpenRedirectTester', phase='3D', category='web',
        triggers=['has_web', 'has_url_params'], priority=70,
        description='Open redirect testing',
        run_method='test_url',
    ),
    AgentEntry(
        name='http_smuggling', module='engine.agents.http_request_smuggling_tester',
        class_name='HTTPRequestSmugglingTester', phase='3D', category='web',
        triggers=['has_web', 'has_proxy'], priority=75,
        description='HTTP request smuggling (CL.TE/TE.CL)',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='race_condition', module='engine.agents.race_condition_tester',
        class_name='RaceConditionTester', phase='3D', category='web',
        triggers=['has_web', 'has_state_changing'], priority=70,
        description='Race condition testing',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='file_upload', module='engine.agents.file_upload_security',
        class_name='FileUploadSecurityTester', phase='3D', category='web',
        triggers=['has_upload'], priority=80,
        description='File upload security testing',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='cache_poisoning', module='engine.agents.cache_poisoning_tester',
        class_name='CachePoisoningTester', phase='3D', category='web',
        triggers=['has_web', 'has_cdn'], priority=75,
        description='Web cache poisoning and deception',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='deserialization', module='engine.agents.deserialization_tester',
        class_name='DeserializationTester', phase='3D', category='injection',
        triggers=['has_web', 'has_serialized_data'], priority=80,
        description='Insecure deserialization testing',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='host_header', module='engine.agents.host_header_injection_tester',
        class_name='HostHeaderInjectionTester', phase='3D', category='web',
        triggers=['has_web'], priority=65,
        description='Host header injection and password reset poisoning',
        run_method='run_full_scan',
    ),
    AgentEntry(
        name='ldap_injection', module='engine.agents.ldap_injection_tester',
        class_name='LDAPInjectionTester', phase='3D', category='injection',
        triggers=['has_web', 'has_ldap'], priority=70,
        description='LDAP injection testing',
        run_method='test_all',
    ),
    AgentEntry(
        name='mass_assignment', module='engine.agents.mass_assignment_tester',
        class_name='MassAssignmentTester', phase='3D', category='api',
        triggers=['has_api', 'has_json_body'], priority=75, needs_auth=True,
        description='Mass assignment / parameter pollution',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='prototype_pollution', module='engine.agents.prototype_pollution_tester',
        class_name='PrototypePollutionTester', phase='3D', category='web',
        triggers=['has_web', 'has_js_frontend'], priority=70,
        description='JavaScript prototype pollution',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='websocket_tester', module='engine.agents.websocket_tester',
        class_name='WebSocketTester', phase='3D', category='web',
        triggers=['has_websocket'], priority=80,
        description='WebSocket security testing',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='cookie_analyzer', module='engine.agents.cookie_security_analyzer',
        class_name='CookieSecurityAnalyzer', phase='3D', category='web',
        triggers=['has_web', 'has_cookies'], priority=60,
        description='Cookie security flag analysis',
        run_method='collect_cookies',
    ),

    # ================================================================
    # PHASE 3D: API-SPECIFIC TESTING
    # ================================================================
    AgentEntry(
        name='graphql_tester', module='engine.agents.graphql_advanced_tester',
        class_name='GraphQLAdvancedTester', phase='3D', category='api',
        triggers=['has_graphql'], priority=95,
        description='GraphQL deep testing (batching, DoS, directives)',
        run_method='test_graphql_endpoint',
    ),
    AgentEntry(
        name='graphql_enumerator', module='engine.agents.graphql_enumerator',
        class_name='GraphQLEnumerator', phase='3D', category='api',
        triggers=['has_graphql'], priority=90,
        description='GraphQL schema enumeration',
        run_method='enumerate_complete',
    ),
    AgentEntry(
        name='api_fuzzer', module='engine.agents.api_fuzzer',
        class_name='APIFuzzer', phase='3D', category='api',
        triggers=['has_api'], priority=70,
        description='API parameter fuzzing',
        run_method='test_parameter_discovery',
    ),
    AgentEntry(
        name='api_gateway_bypass', module='engine.agents.api_gateway_bypass_tester',
        class_name='APIGatewayBypassTester', phase='3D', category='api',
        triggers=['has_api', 'has_gateway'], priority=85,
        description='API gateway bypass techniques',
        run_method='run_comprehensive_test',
    ),
    AgentEntry(
        name='api_rate_limit', module='engine.agents.api_rate_limit_tester',
        class_name='ApiRateLimitTester', phase='3D', category='api',
        triggers=['has_api'], priority=60,
        description='Rate limit bypass testing',
        run_method='run_full_scan',
    ),
    AgentEntry(
        name='api_versioning', module='engine.agents.api_versioning_tester',
        class_name='APIVersioningTester', phase='3D', category='api',
        triggers=['has_api'], priority=55,
        description='API version discovery and testing',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='param_miner', module='engine.agents.api_endpoint_parameter_miner',
        class_name='APIParameterMiner', phase='3D', category='api',
        triggers=['has_api'], priority=65,
        description='Hidden parameter discovery',
        run_method='mine_parameters',
    ),
    AgentEntry(
        name='grpc_tester', module='engine.agents.grpc_security_tester',
        class_name='GrpcSecurityTester', phase='3D', category='api',
        triggers=['has_grpc'], priority=85,
        description='gRPC security testing',
        run_method='run_comprehensive_test',
    ),
    AgentEntry(
        name='business_logic', module='engine.agents.business_logic_tester',
        class_name='BusinessLogicTester', phase='3D', category='web',
        triggers=['has_web', 'has_auth'], priority=85, needs_auth=True,
        description='Business logic flaw testing',
        run_method='test_workflow_bypass',
    ),
    AgentEntry(
        name='priv_escalation', module='engine.agents.privilege_escalation_chain_builder',
        class_name='PrivilegeEscalationChainBuilder', phase='3D', category='auth',
        triggers=['has_web', 'has_auth', 'has_roles'], priority=90, needs_auth=True,
        description='Privilege escalation chain discovery',
        run_method='discover_and_exploit',
    ),

    # ================================================================
    # PHASE 3D: CLOUD-SPECIFIC TESTING
    # ================================================================
    AgentEntry(
        name='s3_enumerator', module='engine.cloud.aws.s3_enumerator',
        class_name='S3Enumerator', phase='3D', category='cloud',
        triggers=['has_aws', 'has_s3'], priority=90,
        description='AWS S3 bucket enumeration and testing',
        run_method='enumerate_and_test',
    ),
    AgentEntry(
        name='azure_tester', module='engine.cloud.azure_tester',
        class_name='AzureBlobTester', phase='3D', category='cloud',
        triggers=['has_azure'], priority=85,
        description='Azure blob storage testing',
        run_method='test_all',
    ),
    AgentEntry(
        name='gcs_scanner', module='engine.cloud.gcp.gcs_scanner',
        class_name='GCSScanner', phase='3D', category='cloud',
        triggers=['has_gcp'], priority=85,
        description='GCP cloud storage testing',
        run_method='scan_all',
    ),
    AgentEntry(
        name='metadata_ssrf', module='engine.cloud.aws.metadata_ssrf',
        class_name='MetadataSSRF', phase='3D', category='cloud',
        triggers=['has_aws', 'has_ssrf_candidate'], priority=95,
        description='Cloud metadata SSRF (169.254.169.254)',
        run_method='test_all',
    ),

    # ================================================================
    # PHASE 5: ANALYSIS & CHAINING
    # ================================================================
    AgentEntry(
        name='flow_mapper', module='engine.understanding.flow_mapper',
        class_name='FlowMapper', phase='5', category='understanding',
        triggers=['has_web'], priority=85,
        description='Map auth/payment/registration flows, find bypass points',
        run_method='map_all_flows',
    ),
    AgentEntry(
        name='permission_mapper', module='engine.understanding.permission_mapper',
        class_name='PermissionMapper', phase='5', category='understanding',
        triggers=['has_web', 'has_auth'], priority=90, needs_auth=True,
        description='RBAC permission matrix mapping',
        run_method='map_permissions',
    ),
    AgentEntry(
        name='api_response_analyzer', module='engine.agents.api_response_analyzer',
        class_name='APIResponseAnalyzer', phase='5', category='api',
        triggers=['has_api'], priority=70,
        description='Analyze API response patterns for info leaks',
        run_method='run_comprehensive_analysis',
    ),
    AgentEntry(
        name='api_schema_analyzer', module='engine.agents.api_schema_analyzer',
        class_name='APISchemaAnalyzer', phase='5', category='api',
        triggers=['has_api'], priority=65,
        description='API schema analysis for security issues',
        run_method='analyze',
    ),

    # ================================================================
    # PHASE 6: VALIDATION & REPORTING
    # ================================================================
    AgentEntry(
        name='poc_validator', module='engine.agents.poc_validator',
        class_name='POCValidator', phase='6', category='validation',
        triggers=[], priority=95,
        description='Validate findings with curl POC',
        run_method='validate',
    ),
    AgentEntry(
        name='reporter', module='engine.agents.reporter_agent',
        class_name='ReporterAgent', phase='6', category='reporting',
        triggers=[], priority=90,
        description='Generate first-try reproduction reports',
        run_method='generate_first_try_report',
    ),
    AgentEntry(
        name='submission_optimizer', module='engine.agents.submission_optimizer',
        class_name='SubmissionOptimizer', phase='6', category='reporting',
        triggers=[], priority=80,
        description='Optimize report for maximum payout',
        run_method='generate_submission_plan',
    ),

    # ================================================================
    # PHASE 3D: SECURITY HEADERS (lower priority)
    # ================================================================
    AgentEntry(
        name='security_headers', module='engine.agents.http_security_headers_scanner',
        class_name='HTTPHeaderSecurityAnalyzer', phase='3D', category='web',
        triggers=['has_web'], priority=30,
        description='HTTP security header analysis',
        run_method='analyze',
    ),
    AgentEntry(
        name='tls_tester', module='engine.agents.tls_ssl_configuration_tester',
        class_name='TLSSSLConfigurationTester', phase='3D', category='web',
        triggers=['has_web'], priority=25,
        description='TLS/SSL configuration testing',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='hsts_analyzer', module='engine.agents.hsts_analyzer',
        class_name='HSTSAnalyzer', phase='3D', category='web',
        triggers=['has_web'], priority=25,
        description='HSTS configuration analysis',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='csp_tester', module='engine.agents.content_security_policy_tester',
        class_name='ContentSecurityPolicyTester', phase='3D', category='web',
        triggers=['has_web'], priority=25,
        description='Content Security Policy analysis',
        run_method='run_all_tests',
    ),
    AgentEntry(
        name='security_txt', module='engine.agents.security_txt_validator',
        class_name='SecurityTxtValidator', phase='3D', category='web',
        triggers=['has_web'], priority=20,
        description='security.txt validation',
        run_method='validate',
    ),
]


class AgentRegistry:
    """Query and filter the agent registry."""

    def __init__(self):
        self._agents = {a.name: a for a in AGENT_REGISTRY}

    @property
    def all_agents(self) -> List[AgentEntry]:
        return AGENT_REGISTRY

    def get(self, name: str) -> Optional[AgentEntry]:
        return self._agents.get(name)

    def by_phase(self, phase: str) -> List[AgentEntry]:
        """Get agents for a specific phase, sorted by priority (highest first)."""
        return sorted(
            [a for a in AGENT_REGISTRY if a.phase == phase],
            key=lambda a: a.priority, reverse=True
        )

    def by_category(self, category: str) -> List[AgentEntry]:
        return [a for a in AGENT_REGISTRY if a.category == category]

    def by_triggers(self, active_triggers: Set[str]) -> List[AgentEntry]:
        """Get all agents whose trigger conditions are met."""
        result = []
        for agent in AGENT_REGISTRY:
            if not agent.triggers:  # No triggers = always runs (e.g., validation)
                result.append(agent)
            elif all(t in active_triggers for t in agent.triggers):
                result.append(agent)
        return result

    def for_phase(self, phase: str, active_triggers: Set[str]) -> List[AgentEntry]:
        """Get agents for a phase whose triggers are met, sorted by priority."""
        phase_agents = self.by_phase(phase)
        result = []
        for agent in phase_agents:
            if not agent.triggers or all(t in active_triggers for t in agent.triggers):
                result.append(agent)
        return result

    def summary(self) -> Dict:
        """Registry statistics."""
        phases = {}
        categories = {}
        for a in AGENT_REGISTRY:
            phases[a.phase] = phases.get(a.phase, 0) + 1
            categories[a.category] = categories.get(a.category, 0) + 1
        return {
            'total_agents': len(AGENT_REGISTRY),
            'by_phase': phases,
            'by_category': categories,
        }
