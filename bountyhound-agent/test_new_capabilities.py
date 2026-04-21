"""Smoke tests for all 9 web modules + 6 non-web modules + import verification for 7 existing ones.

Run: python test_new_capabilities.py
"""

import sys
import os
import traceback

# Add the bountyhound-agent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0
RESULTS = []


def test(name, fn):
    """Run a test and track results."""
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        RESULTS.append(('PASS', name))
        print(f"  PASS  {name}")
    except Exception as e:
        FAIL += 1
        RESULTS.append(('FAIL', name, str(e)))
        print(f"  FAIL  {name}: {e}")


# ============================================================
# Test 1: JsAnalyzer - parse sample JS, extract endpoints
# ============================================================
def test_js_analyzer():
    from engine.discovery.js_analyzer import JsAnalyzer, JsFinding, PATTERNS

    # Verify class instantiation
    analyzer = JsAnalyzer('test.com')
    assert analyzer.target == 'test.com'

    # Test endpoint extraction
    sample_js = '''
    fetch('/api/v1/users')
    axios.get('/api/v2/orders/123')
    const baseURL = 'https://internal.test.com/api'
    '''
    endpoints = analyzer.extract_endpoints(sample_js)
    assert len(endpoints) > 0, "Should extract at least one endpoint"
    assert any('/api/' in e['value'] for e in endpoints), "Should find /api/ endpoint"

    # Test secret extraction
    secret_js = '''
    const key = 'AKIAIOSFODNN7EXAMPLE'
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123'
    const firebase_key = 'AIzaSyA1234567890abcdefghijklmnop12345'
    '''
    secrets = analyzer.extract_secrets(secret_js)
    assert len(secrets) > 0, "Should extract at least one secret"

    # Test summary
    summary = analyzer.summary()
    assert 'total' in summary
    assert 'by_type' in summary

    # Test patterns exist
    assert len(PATTERNS) >= 7, "Should have 7+ pattern categories"


# ============================================================
# Test 2: ContentDiscovery - init, check wordlists exist
# ============================================================
def test_content_discovery():
    from engine.discovery.content_discovery import ContentDiscovery, COMMON_WORDLIST, CMS_WORDLIST, CLOUD_WORDLIST

    disc = ContentDiscovery('test.com')
    assert disc.target == 'test.com'
    assert disc.max_workers == 10

    # Verify wordlists have content
    total_common = sum(len(v) for v in COMMON_WORDLIST.values())
    assert total_common >= 80, f"COMMON wordlist should have 80+ paths, got {total_common}"

    total_cms = sum(len(v) for v in CMS_WORDLIST.values())
    assert total_cms >= 10, f"CMS wordlist should have 10+ paths, got {total_cms}"

    total_cloud = sum(len(v) for v in CLOUD_WORDLIST.values())
    assert total_cloud >= 5, f"CLOUD wordlist should have 5+ paths, got {total_cloud}"

    # Verify categories exist
    assert 'admin' in COMMON_WORDLIST
    assert 'api' in COMMON_WORDLIST
    assert 'config' in COMMON_WORDLIST
    assert 'backup' in COMMON_WORDLIST


# ============================================================
# Test 3: WaybackMiner - init, verify CDX URL builder
# ============================================================
def test_wayback_miner():
    from engine.discovery.wayback_miner import WaybackMiner, CDX_API, INTERESTING_PATTERNS

    miner = WaybackMiner('test.com')
    assert miner.target == 'test.com'

    # Verify CDX API URL
    assert 'web.archive.org' in CDX_API

    # Verify interesting patterns
    assert len(INTERESTING_PATTERNS) >= 7, "Should have 7+ pattern categories"
    assert 'api' in INTERESTING_PATTERNS
    assert 'admin' in INTERESTING_PATTERNS
    assert 'config' in INTERESTING_PATTERNS

    # Verify summary works on empty state
    summary = miner.summary()
    assert summary['total_urls'] == 0


# ============================================================
# Test 4: GitHubOSINT - init, verify search query builder
# ============================================================
def test_github_osint():
    from engine.discovery.github_osint import GitHubOSINT, SECRET_SEARCH_QUERIES, SECRET_FILE_EXTENSIONS

    osint = GitHubOSINT('test.com')
    assert osint.target == 'test.com'

    # Verify search queries
    assert len(SECRET_SEARCH_QUERIES) >= 10, f"Should have 10+ search queries, got {len(SECRET_SEARCH_QUERIES)}"

    # Verify domain replacement works
    for q in SECRET_SEARCH_QUERIES:
        replaced = q.replace('{domain}', 'example.com')
        assert 'example.com' in replaced, f"Query should contain domain: {replaced}"

    # Verify file extensions
    assert len(SECRET_FILE_EXTENSIONS) >= 10
    assert 'env' in SECRET_FILE_EXTENSIONS
    assert 'json' in SECRET_FILE_EXTENSIONS


# ============================================================
# Test 5: FlowMapper - init, verify flow pattern matching
# ============================================================
def test_flow_mapper():
    from engine.understanding.flow_mapper import FlowMapper, Flow, FlowStep, FLOW_PATTERNS

    mapper = FlowMapper('test.com')
    assert mapper.target == 'test.com'

    # Verify flow patterns
    assert len(FLOW_PATTERNS) >= 4, "Should have 4+ flow types"
    assert 'auth' in FLOW_PATTERNS
    assert 'payment' in FLOW_PATTERNS
    assert 'registration' in FLOW_PATTERNS

    # Test flow classification
    assert mapper._classify_request('https://test.com/login') == 'auth'
    assert mapper._classify_request('https://test.com/checkout') == 'payment'
    assert mapper._classify_request('https://test.com/register') == 'registration'
    assert mapper._classify_request('https://test.com/about') is None

    # Test bypass point detection
    flow = Flow(name='test_auth', flow_type='auth')
    flow.steps = [
        FlowStep(url='/login', method='POST', status_code=200),
        FlowStep(url='/verify-mfa', method='POST', status_code=200),
        FlowStep(url='/dashboard', method='GET', status_code=200),
    ]
    bypasses = mapper.find_bypass_points(flow)
    assert len(bypasses) > 0, "Should detect bypass point at verify-mfa step"


# ============================================================
# Test 6: PermissionMapper - init, verify matrix builder
# ============================================================
def test_permission_mapper():
    from engine.understanding.permission_mapper import PermissionMapper, PermissionEntry, EscalationPath, DEFAULT_ROLE_HIERARCHY

    mapper = PermissionMapper('test.com')
    assert mapper.target == 'test.com'

    # Verify role hierarchy
    assert len(DEFAULT_ROLE_HIERARCHY) >= 4
    assert 'unauthenticated' in DEFAULT_ROLE_HIERARCHY
    assert 'admin' in DEFAULT_ROLE_HIERARCHY

    # Test escalation detection with mock data
    mapper.matrix = {
        '/api/admin/users': {
            'user': PermissionEntry(
                endpoint='/api/admin/users', role='user',
                status_code=200, has_data=True,
                response_keys=['users', 'total'], data_count=50,
            ),
            'admin': PermissionEntry(
                endpoint='/api/admin/users', role='admin',
                status_code=200, has_data=True,
                response_keys=['users', 'total'], data_count=50,
            ),
        },
    }
    escalations = mapper.find_escalation_paths()
    assert len(escalations) > 0, "Should detect escalation: user gets admin data"


# ============================================================
# Test 7: TechFingerprinter - init, verify fingerprint patterns
# ============================================================
def test_tech_fingerprinter():
    from engine.understanding.tech_fingerprinter import (
        TechFingerprinter, COOKIE_FINGERPRINTS, HEADER_FINGERPRINTS,
        WAF_SIGNATURES, HTML_PATTERNS,
    )

    fp = TechFingerprinter('test.com')
    assert fp.target == 'test.com'

    # Verify fingerprint databases
    assert len(COOKIE_FINGERPRINTS) >= 15, f"Should have 15+ cookie fingerprints, got {len(COOKIE_FINGERPRINTS)}"
    assert len(WAF_SIGNATURES) >= 8, f"Should have 8+ WAF signatures, got {len(WAF_SIGNATURES)}"
    assert len(HTML_PATTERNS) >= 10, f"Should have 10+ HTML patterns, got {len(HTML_PATTERNS)}"

    # Verify known cookies
    assert 'PHPSESSID' in COOKIE_FINGERPRINTS
    assert 'JSESSIONID' in COOKIE_FINGERPRINTS
    assert 'csrftoken' in COOKIE_FINGERPRINTS

    # Verify known WAFs
    assert 'Cloudflare' in WAF_SIGNATURES
    assert 'AWS WAF' in WAF_SIGNATURES
    assert 'Akamai' in WAF_SIGNATURES


# ============================================================
# Test 8: TimingInjection - init, verify payload lists
# ============================================================
def test_timing_injection():
    from engine.testing.timing_injection import (
        TimingInjection, SQLI_PAYLOADS, NOSQLI_PAYLOADS, CMDI_PAYLOADS,
        DELAY_THRESHOLD, BASELINE_SAMPLES, MAX_ROUNDS,
    )

    ti = TimingInjection('test.com')
    assert ti.target == 'test.com'

    # Verify payload lists
    assert len(SQLI_PAYLOADS) >= 10, f"Should have 10+ SQLi payloads, got {len(SQLI_PAYLOADS)}"
    assert len(NOSQLI_PAYLOADS) >= 3, f"Should have 3+ NoSQLi payloads, got {len(NOSQLI_PAYLOADS)}"
    assert len(CMDI_PAYLOADS) >= 8, f"Should have 8+ CMDi payloads, got {len(CMDI_PAYLOADS)}"

    # Verify settings
    assert DELAY_THRESHOLD == 4.0
    assert BASELINE_SAMPLES == 5
    assert MAX_ROUNDS == 3

    # Verify payloads contain sleep/delay patterns
    assert any('SLEEP' in p for p in SQLI_PAYLOADS)
    assert any('pg_sleep' in p for p in SQLI_PAYLOADS)
    assert any('WAITFOR' in p for p in SQLI_PAYLOADS)
    assert any('sleep' in p for p in CMDI_PAYLOADS)


# ============================================================
# Test 9: SubdomainTakeover - init, verify fingerprint DB
# ============================================================
def test_subdomain_takeover():
    from engine.testing.subdomain_takeover import SubdomainTakeover, FINGERPRINT_DB, TakeoverResult

    st = SubdomainTakeover('test.com')
    assert st.target == 'test.com'
    assert st.max_workers == 10

    # Verify fingerprint database
    assert len(FINGERPRINT_DB) >= 30, f"Should have 30+ service fingerprints, got {len(FINGERPRINT_DB)}"

    # Verify known services
    assert 'github.io' in FINGERPRINT_DB
    assert 'herokuapp.com' in FINGERPRINT_DB
    assert 's3.amazonaws.com' in FINGERPRINT_DB
    assert 'azurewebsites.net' in FINGERPRINT_DB
    assert 'myshopify.com' in FINGERPRINT_DB

    # Verify fingerprint structure
    for cname, (service, fingerprint, can_takeover) in FINGERPRINT_DB.items():
        assert isinstance(service, str)
        assert isinstance(fingerprint, str)
        assert isinstance(can_takeover, bool)


# ============================================================
# Tests 10-16: Import checks for existing agent modules
# ============================================================
def test_import_race_condition():
    from engine.agents.race_condition_tester import RaceConditionTester
    assert RaceConditionTester is not None

def test_import_jwt_analyzer():
    from engine.agents.jwt_analyzer import JWTAnalyzer
    assert JWTAnalyzer is not None

def test_import_file_upload():
    from engine.agents.file_upload_security import FileUploadSecurityTester
    assert FileUploadSecurityTester is not None

def test_import_http_smuggling():
    from engine.agents.http_request_smuggling_tester import HTTPRequestSmugglingTester
    assert HTTPRequestSmugglingTester is not None

def test_import_graphql_advanced():
    from engine.agents.graphql_advanced_tester import GraphQLAdvancedTester
    assert GraphQLAdvancedTester is not None

def test_import_param_miner():
    from engine.agents.api_endpoint_parameter_miner import APIParameterMiner
    assert APIParameterMiner is not None

def test_import_api_docs():
    from engine.agents.api_documentation_scanner import APIDocumentationScanner
    assert APIDocumentationScanner is not None


# ============================================================
# Test 17: BinaryAnalyzer - init, verify analysis methods
# ============================================================
def test_binary_analyzer():
    from engine.reversing.binary_analyzer import BinaryAnalyzer, BinaryInfo
    import tempfile, os

    # Create a minimal test binary (PE-like header)
    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        # Write MZ header + some test data
        f.write(b'MZ' + b'\x00' * 58 + b'\x80\x00\x00\x00')  # DOS header with PE offset at 0x80
        f.write(b'\x00' * 64)  # padding
        f.write(b'PE\x00\x00')  # PE signature at offset 0x80
        f.write(b'\x4c\x01')  # Machine: i386
        f.write(b'\x00' * 200)  # rest of headers
        f.write(b'strcpy\x00sprintf\x00LoadLibraryA\x00')  # some strings
        f.write(b'password=secret123\x00')
        f.write(b'https://internal.api.com/v1\x00')
        f.write(b'AKIA1234567890ABCDEF\x00')
        test_path = f.name

    try:
        analyzer = BinaryAnalyzer(test_path)
        assert str(analyzer.binary_path) == test_path

        # Test file type detection
        ft = analyzer.get_file_type()
        assert ft == 'PE', f"Expected PE, got {ft}"

        # Test string extraction
        strings = analyzer.extract_strings(min_length=4)
        assert len(strings) > 0, "Should extract strings"

        # Test interesting strings
        interesting = analyzer.find_interesting_strings()
        assert isinstance(interesting, dict)
        assert 'urls' in interesting
        assert 'api_keys' in interesting

        # Test entropy
        entropy = analyzer.calculate_entropy()
        assert 0.0 <= entropy <= 8.0, f"Entropy should be 0-8, got {entropy}"

        # Test vulnerability detection
        vulns = analyzer.find_vulnerabilities()
        assert isinstance(vulns, list)

        # Test full analysis
        analysis = analyzer.analyze()
        assert 'file_type' in analysis
        assert 'interesting_strings' in analysis
        assert 'entropy' in analysis

        # Test BinaryInfo dataclass
        info = BinaryInfo(
            path=test_path, file_type='PE', architecture='x86',
            size=500, md5='abc', sha256='def', entropy=4.5,
            is_packed=False, sections_count=0, imports_count=0, exports_count=0
        )
        assert info.file_type == 'PE'
    finally:
        os.unlink(test_path)


# ============================================================
# Test 18: Decompiler - init, verify tool detection
# ============================================================
def test_decompiler():
    from engine.reversing.decompiler import Decompiler, FunctionInfo
    import tempfile, os

    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(b'\x00' * 100)
        test_path = f.name

    try:
        decomp = Decompiler(test_path)
        assert str(decomp.binary_path) == test_path

        # Verify tool detection runs without error
        tools = decomp.available_tools
        assert isinstance(tools, dict)

        # Test FunctionInfo dataclass
        fi = FunctionInfo(name='main', address='0x401000', size=100, category='entry')
        assert fi.name == 'main'

        # Test crypto function patterns
        crypto = decomp.find_crypto_functions()
        assert isinstance(crypto, list)

        # Test auth function patterns
        auth = decomp.find_auth_functions()
        assert isinstance(auth, list)
    finally:
        os.unlink(test_path)


# ============================================================
# Test 19: BinaryPatcher - init, verify patching
# ============================================================
def test_binary_patcher():
    from engine.reversing.patcher import BinaryPatcher, Patch
    import tempfile, os

    # Create test binary with known content
    test_data = b'\x90' * 20 + b'\x74\x05' + b'\x90' * 10 + b'Hello World\x00' + b'\x90' * 20
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(test_data)
        test_path = f.name

    try:
        patcher = BinaryPatcher(test_path)
        assert len(patcher.data) == len(test_data)

        # Test patch_bytes
        result = patcher.patch_bytes(0, b'\xCC\xCC')
        assert result is True
        assert patcher.data[0] == 0xCC
        assert patcher.data[1] == 0xCC

        # Test nop_region
        result = patcher.nop_region(5, 3)
        assert result is True
        assert patcher.data[5:8] == bytearray([0x90, 0x90, 0x90])

        # Test patch_string
        count = patcher.patch_string('Hello World', 'Bye World!!')
        assert count >= 1

        # Test find_pattern
        offsets = patcher.find_pattern(b'\x90\x90\x90')
        assert len(offsets) > 0

        # Test patch_jump (offset 20 has JZ 0x74)
        result = patcher.patch_jump(20, 'always')
        assert result is True
        assert patcher.data[20] == 0xEB  # JMP short

        # Test get_diff
        diff = patcher.get_diff()
        assert len(diff) >= 3

        # Test undo_last
        patcher.undo_last()
        assert patcher.data[20] == 0x74  # Restored JZ

        # Test save
        output = patcher.save()
        assert os.path.exists(output)
        os.unlink(output)

        # Test Patch dataclass
        p = Patch(offset=0, original=b'\x90', patched=b'\xCC', description='test')
        assert p.offset == 0
    finally:
        os.unlink(test_path)


# ============================================================
# Test 20: CodeAuditor - scan sample code for vulns
# ============================================================
def test_code_auditor():
    from engine.sast.analyzers.code_auditor import CodeAuditor, CodeFinding, VULN_PATTERNS, LANGUAGE_MAP
    import tempfile, os

    # Verify pattern coverage
    assert len(VULN_PATTERNS) >= 7, f"Should have 7+ languages, got {len(VULN_PATTERNS)}"
    assert 'python' in VULN_PATTERNS
    assert 'javascript' in VULN_PATTERNS
    assert 'java' in VULN_PATTERNS
    assert 'php' in VULN_PATTERNS
    assert 'go' in VULN_PATTERNS
    assert 'ruby' in VULN_PATTERNS
    assert 'c_cpp' in VULN_PATTERNS

    # Verify language map
    assert LANGUAGE_MAP['.py'] == 'python'
    assert LANGUAGE_MAP['.js'] == 'javascript'
    assert LANGUAGE_MAP['.java'] == 'java'

    # Create temp directory with vulnerable files
    tmpdir = tempfile.mkdtemp()
    try:
        # Python file with vulns
        with open(os.path.join(tmpdir, 'vuln.py'), 'w') as f:
            f.write('import os\nos.system(f"rm {user_input}")\n')
            f.write('cursor.execute(f"SELECT * FROM users WHERE id={uid}")\n')

        import uuid
        auditor = CodeAuditor(tmpdir, target=f'test-code-{uuid.uuid4().hex[:8]}')
        findings = auditor.audit()
        assert len(findings) >= 2, f"Should find 2+ vulns in sample, got {len(findings)}"

        # Verify finding structure
        for f in findings:
            assert isinstance(f, CodeFinding)
            assert f.severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
            assert f.cwe.startswith('CWE-')

        summary = auditor.summary()
        assert summary['total_findings'] >= 2
        assert summary['files_scanned'] >= 1
    finally:
        import shutil
        shutil.rmtree(tmpdir)


# ============================================================
# Test 21: DependencyAuditor - parse manifests, check CVEs
# ============================================================
def test_dependency_auditor():
    from engine.sast.analyzers.dependency_auditor import DependencyAuditor, DependencyFinding, KNOWN_VULNS, MANIFEST_FILES
    import tempfile, os, json

    # Verify known vulns coverage
    assert len(KNOWN_VULNS) >= 4, f"Should have 4+ ecosystems, got {len(KNOWN_VULNS)}"
    assert 'npm' in KNOWN_VULNS
    assert 'pip' in KNOWN_VULNS
    assert 'maven' in KNOWN_VULNS

    # Verify manifest file detection
    assert 'package.json' in MANIFEST_FILES
    assert 'requirements.txt' in MANIFEST_FILES

    # Create temp directory with vulnerable package.json
    tmpdir = tempfile.mkdtemp()
    try:
        pkg = {
            'dependencies': {
                'lodash': '^4.17.15',  # Vulnerable
                'express': '4.16.0',   # Vulnerable
            }
        }
        with open(os.path.join(tmpdir, 'package.json'), 'w') as f:
            json.dump(pkg, f)

        import uuid
        auditor = DependencyAuditor(tmpdir, target=f'test-dep-{uuid.uuid4().hex[:8]}')
        # Just test manifest parsing (skip npm audit which needs npm installed)
        auditor._discover_manifests()
        assert len(auditor.manifests_found) >= 1

        for m in auditor.manifests_found:
            auditor._parse_manifest(m)
        assert 'npm' in auditor.dependencies
        assert 'lodash' in auditor.dependencies['npm']

        auditor._check_known_vulns()
        assert len(auditor.findings) >= 1, "Should find lodash CVE"

        summary = auditor.summary()
        assert summary['total_findings'] >= 1
    finally:
        import shutil
        shutil.rmtree(tmpdir)


# ============================================================
# Test 22: RepoScanner - init, verify patterns
# ============================================================
def test_repo_scanner():
    from engine.sast.analyzers.repo_scanner import RepoScanner, RepoFinding, HISTORY_SECRET_PATTERNS, SENSITIVE_FILES
    import tempfile

    # Verify pattern coverage
    assert len(HISTORY_SECRET_PATTERNS) >= 15, f"Should have 15+ secret patterns, got {len(HISTORY_SECRET_PATTERNS)}"
    assert 'AWS Access Key' in HISTORY_SECRET_PATTERNS
    assert 'GitHub Token' in HISTORY_SECRET_PATTERNS
    assert 'Private Key' in HISTORY_SECRET_PATTERNS
    assert 'JWT Token' in HISTORY_SECRET_PATTERNS

    # Verify sensitive files
    assert len(SENSITIVE_FILES) >= 20
    assert '.env' in SENSITIVE_FILES

    # Test on non-git directory
    tmpdir = tempfile.mkdtemp()
    scanner = RepoScanner(tmpdir, target='test')
    assert scanner.is_git_repo is False

    summary = scanner.summary()
    assert summary['total_findings'] == 0

    # Verify RepoFinding dataclass
    finding = RepoFinding(
        finding_type='secret_in_history', severity='CRITICAL',
        description='Test', commit_hash='abc123'
    )
    assert finding.finding_type == 'secret_in_history'

    import shutil
    shutil.rmtree(tmpdir)


# ============================================================
# ============================================================
# Auto-Dispatch System Tests (23-28)
# ============================================================

def test_agent_registry():
    from engine.core.agent_registry import AgentRegistry, AgentEntry
    r = AgentRegistry()
    s = r.summary()
    assert s['total_agents'] >= 65, f"Expected 65+ agents, got {s['total_agents']}"
    assert '1' in s['by_phase'], "Missing phase 1"
    assert '3D' in s['by_phase'], "Missing phase 3D"
    assert '6' in s['by_phase'], "Missing phase 6"
    # Test get
    a = r.get('graphql_tester')
    assert a is not None, "graphql_tester not found"
    assert a.phase == '3D'
    assert 'has_graphql' in a.triggers
    # Test by_phase
    phase1 = r.by_phase('1')
    assert len(phase1) >= 5, f"Expected 5+ phase 1 agents, got {len(phase1)}"
    # Test trigger filtering
    web_agents = r.by_triggers({'has_web'})
    assert len(web_agents) >= 20, f"Expected 20+ web-triggered agents, got {len(web_agents)}"


def test_target_profile():
    from engine.core.target_profiler import TargetProfile
    # Test basic profile
    p = TargetProfile(target='test.com')
    assert len(p.triggers) == 0, "Fresh profile should have no triggers"
    # Set some triggers
    p.has_web = True
    p.has_graphql = True
    p.has_api = True
    triggers = p.triggers
    assert 'has_web' in triggers
    assert 'has_graphql' in triggers
    assert 'has_api' in triggers
    assert len(triggers) == 3
    # Test set_trigger
    p.set_trigger('has_jwt', True)
    assert 'has_jwt' in p.triggers
    # Test summary
    s = p.summary()
    assert 'test.com' in s
    assert 'has_web' in s


def test_auto_dispatcher():
    from engine.core.auto_dispatcher import AutoDispatcher, AgentResult
    from engine.core.agent_registry import AgentRegistry
    from engine.core.target_profiler import TargetProfile
    r = AgentRegistry()
    p = TargetProfile(target='test.com', has_web=True, has_graphql=True, has_api=True)
    d = AutoDispatcher(r, p, max_workers=2)
    # Check agent selection
    phase1 = d.get_agents_for_phase('1')
    assert len(phase1) >= 5
    phase3d = d.get_agents_for_phase('3D')
    # Should include graphql agents since has_graphql is True
    gql_agents = [a for a in phase3d if 'graphql' in a.name]
    assert len(gql_agents) >= 1, "GraphQL agents should be selected for has_graphql target"
    # AgentResult dataclass
    result = AgentResult(agent_name='test', phase='1', success=True, findings=[{'title': 'XSS'}])
    assert result.success
    assert len(result.findings) == 1


def test_hunt_executor_import():
    from engine.core.hunt_executor import HuntExecutor, HuntReport
    # Verify class exists and has expected attributes
    assert hasattr(HuntExecutor, 'FINDINGS_DIR')
    assert hasattr(HuntExecutor, 'hunt')
    assert hasattr(HuntExecutor, 'execute')
    # Test HuntReport
    report = HuntReport(target='test.com', started_at='2026-01-01')
    assert report.target == 'test.com'
    assert len(report.findings) == 0
    s = report.summary()
    assert 'test.com' in s
    d = report.to_dict()
    assert d['target'] == 'test.com'
    assert d['findings_count'] == 0


def test_dispatch_routing():
    """Verify correct agent routing for different target types."""
    from engine.core.auto_dispatcher import AutoDispatcher
    from engine.core.agent_registry import AgentRegistry
    from engine.core.target_profiler import TargetProfile
    r = AgentRegistry()

    # Source code target should only get SAST agents in 3C
    p_src = TargetProfile(target='/code', has_source_code=True)
    d_src = AutoDispatcher(r, p_src)
    src_3c = d_src.get_agents_for_phase('3C')
    src_names = [a.name for a in src_3c]
    assert 'code_auditor' in src_names, "code_auditor missing for source target"
    assert 'dependency_auditor' in src_names, "dependency_auditor missing for source target"
    # Should NOT get web agents in 3D
    src_3d = d_src.get_agents_for_phase('3D')
    assert len(src_3d) == 0, f"Source target should not dispatch web agents, got {len(src_3d)}"

    # Binary target
    p_bin = TargetProfile(target='app.exe', has_binary=True)
    d_bin = AutoDispatcher(r, p_bin)
    bin_3c = d_bin.get_agents_for_phase('3C')
    bin_names = [a.name for a in bin_3c]
    assert 'binary_analyzer' in bin_names
    assert 'decompiler' in bin_names

    # Mobile target
    p_mob = TargetProfile(target='app.apk', has_apk=True)
    d_mob = AutoDispatcher(r, p_mob)
    mob_3c = d_mob.get_agents_for_phase('3C')
    assert any(a.name == 'apk_analyzer' for a in mob_3c)

    # Phase 6 always dispatches (no triggers)
    p_empty = TargetProfile(target='nothing')
    d_empty = AutoDispatcher(r, p_empty)
    phase6 = d_empty.get_agents_for_phase('6')
    assert len(phase6) >= 3, f"Phase 6 should always have 3+ agents, got {len(phase6)}"


def test_profile_triggers_update():
    """Test dynamic profile updating from discovery results."""
    from engine.core.target_profiler import TargetProfiler, TargetProfile
    profiler = TargetProfiler('test.com')
    profiler.profile = TargetProfile(target='test.com', has_web=True)
    assert 'has_graphql' not in profiler.profile.triggers
    # Simulate discovery finding GraphQL
    profiler.update_from_discovery('graphql_endpoint', True)
    assert 'has_graphql' in profiler.profile.triggers
    # Simulate finding JWT
    profiler.update_from_discovery('jwt_token', True)
    assert 'has_jwt' in profiler.profile.triggers
    # Simulate finding S3
    profiler.update_from_discovery('s3_bucket', True)
    assert 'has_s3' in profiler.profile.triggers


# Run all tests
# ============================================================
if __name__ == '__main__':
    print("=" * 60)
    print("BountyHound 28 Capabilities - Smoke Tests")
    print("=" * 60)

    print("\n--- Web Discovery Modules ---")
    test("1. JsAnalyzer", test_js_analyzer)
    test("2. ContentDiscovery", test_content_discovery)
    test("3. WaybackMiner", test_wayback_miner)
    test("4. GitHubOSINT", test_github_osint)

    print("\n--- Web Understanding Modules ---")
    test("5. FlowMapper", test_flow_mapper)
    test("6. PermissionMapper", test_permission_mapper)
    test("7. TechFingerprinter", test_tech_fingerprinter)

    print("\n--- Web Testing Modules ---")
    test("8. TimingInjection", test_timing_injection)
    test("9. SubdomainTakeover", test_subdomain_takeover)

    print("\n--- Existing Agent Import Checks ---")
    test("10. RaceConditionTester import", test_import_race_condition)
    test("11. JWTAnalyzer import", test_import_jwt_analyzer)
    test("12. FileUploadSecurityTester import", test_import_file_upload)
    test("13. HTTPRequestSmugglingTester import", test_import_http_smuggling)
    test("14. GraphQLAdvancedTester import", test_import_graphql_advanced)
    test("15. APIEndpointParameterMiner import", test_import_param_miner)
    test("16. APIDocumentationScanner import", test_import_api_docs)

    print("\n--- Reverse Engineering Modules ---")
    test("17. BinaryAnalyzer", test_binary_analyzer)
    test("18. Decompiler", test_decompiler)
    test("19. BinaryPatcher", test_binary_patcher)

    print("\n--- Deep SAST Modules ---")
    test("20. CodeAuditor", test_code_auditor)
    test("21. DependencyAuditor", test_dependency_auditor)
    test("22. RepoScanner", test_repo_scanner)

    print("\n--- Auto-Dispatch System ---")
    test("23. AgentRegistry", test_agent_registry)
    test("24. TargetProfile", test_target_profile)
    test("25. AutoDispatcher", test_auto_dispatcher)
    test("26. HuntExecutor import", test_hunt_executor_import)
    test("27. Dispatch routing", test_dispatch_routing)
    test("28. Profile triggers update", test_profile_triggers_update)

    print("\n" + "=" * 60)
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
    print("=" * 60)

    if FAIL > 0:
        print("\nFailed tests:")
        for r in RESULTS:
            if r[0] == 'FAIL':
                print(f"  {r[1]}: {r[2]}")

    sys.exit(0 if FAIL == 0 else 1)
