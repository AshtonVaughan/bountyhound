"""End-to-end smoke test for all 16 new BountyHound modules."""
import os
import sys
import tempfile

# Use temp DB for testing - unique name to avoid stale file locks
import uuid
test_db = os.path.join(tempfile.gettempdir(), f'bh_test_e2e_{uuid.uuid4().hex[:8]}.db')

# Monkey-patch config to use test DB before any imports
from engine.core import config as _cfg
_cfg.BountyHoundConfig.DB_PATH = test_db

# Clear singleton cache so we get a fresh DB connection
from engine.core.database import BountyHoundDB
BountyHoundDB._instances = {}

print('=== E2E SMOKE TEST ===')
print()

# 1. Database migration creates all tables
print('1. Database + Migration...')
from engine.core.database import BountyHoundDB
db = BountyHoundDB(db_path=test_db)
with db._get_connection() as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [r[0] for r in cursor.fetchall()]
    print(f'   Tables: {len(tables)}')
    expected_tables = ['request_log', 'hunt_snapshots', 'fp_patterns',
                       'agent_metrics', 'payload_attempts', 'recon_cache_v2']
    for t in expected_tables:
        assert t in tables, f'Missing table: {t}'
    print('   All 6 new tables present: OK')

    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    indexes = [r[0] for r in cursor.fetchall()]
    print(f'   Indexes: {len(indexes)}')

print()

# 2. RequestLogger
print('2. RequestLogger...')
from engine.core.request_logger import RequestLogger
logger = RequestLogger(db=db)
logger.log_request(target='test-target', method='GET', url='https://test.com/api',
                   status_code=200, resp_body='{"ok":true}')
reqs = logger.get_requests(target='test-target', limit=5)
assert len(reqs) >= 1, 'No requests logged'
print('   Logged and retrieved 1 request: OK')

print()

# 3. EvidenceVault
print('3. EvidenceVault...')
from engine.core.evidence_vault import EvidenceVault
vault = EvidenceVault('test-target')
vault.save_raw('test-evidence', 'This is test evidence content')
evidence = vault.list_evidence()
print(f'   Saved and listed evidence ({len(evidence)} categories): OK')

print()

# 4. ExploitNotebook
print('4. ExploitNotebook...')
from engine.core.exploit_notebook import ExploitNotebook
nb = ExploitNotebook('test-target')
nb.add_entry('General', 'Test Entry', 'Testing the notebook system')
contents = nb.get_contents()
assert 'Test Entry' in contents, 'Notebook entry not found'
print('   Entry added and read back: OK')

print()

# 5. Quality gates
print('5. Quality Gates...')
from engine.core.quality_gates import run_all_gates
finding = {
    'title': 'IDOR in user API',
    'severity': 'HIGH',
    'vuln_type': 'IDOR',
    'verified': True,
    'state_change_confirmed': True,
    'endpoint': '/api/users/123',
    'curl_command': 'curl -H "Auth: token" https://test.com/api/users/123',
    'impact': 'Access other user data'
}
result = run_all_gates(finding)
print(f'   Verdict: {result["final_verdict"]}')
print(f'   Confidence: {result["confidence"]["grade"]} ({result["confidence"]["score"]:.2f})')
print('   Quality gates: OK')

print()

# 6. HuntState
print('6. HuntState...')
from engine.core.hunt_state import HuntState
hs = HuntState('test-target')
hs.update_phase('phase_0', 'completed')
hs.add_endpoint('https://test.com/api', 'GET')
hs.add_finding('Test Finding', 'HIGH', 'IDOR')
hs.save_snapshot()
progress = hs.get_progress()
assert progress['endpoints_discovered'] == 1, 'Endpoint not tracked'
print('   State saved, 1 endpoint tracked: OK')

print()

# 7. ReconCache
print('7. ReconCache...')
from engine.core.recon_cache import ReconCache
rc = ReconCache('test-target')
rc.store('subdomain', 'sub1.test.com', source='subfinder', ttl_days=2)
rc.store('subdomain', 'sub2.test.com', source='subfinder', ttl_days=2)
cached = rc.get('subdomain')
assert len(cached) >= 2, f'Expected 2 cached items, got {len(cached)}'
assert rc.is_fresh('subdomain'), 'Should be fresh'
print(f'   Cached and retrieved {len(cached)} subdomains: OK')

print()

# 8. PayloadTracker
print('8. PayloadTracker...')
from engine.core.payload_tracker import PayloadTracker
pt = PayloadTracker('test-target')
pt.record_attempt('/api/users', '<script>alert(1)</script>', 'xss', status_code=200, success=False)
assert pt.was_tried('/api/users', '<script>alert(1)</script>'), 'Should be marked as tried'
print('   Payload tracked and dedup works: OK')

print()

# 9. ResponseDiff
print('9. ResponseDiff...')
from engine.core.response_diff import ResponseDiff
rd = ResponseDiff()

# Use the base diff_responses method (takes two response dicts)
diff = rd.diff_responses(
    {'status_code': 200, 'body': '{"user":"alice","email":"alice@test.com"}', 'headers': {}},
    {'status_code': 200, 'body': '{"user":"bob","email":"bob@test.com"}', 'headers': {}}
)
print(f'   Body similarity: {diff.get("body_similarity", 0):.1%}')
print('   ResponseDiff: OK')

print()

# 10. FalsePositiveDB
print('10. FalsePositiveDB...')
from engine.core.fp_patterns import FalsePositiveDB
fpdb = FalsePositiveDB()
fp_check = fpdb.check_finding({
    'title': 'CORS misconfiguration',
    'response_body': 'Access-Control-Allow-Origin: *',
    'vuln_type': 'CORS'
})
print(f'    FP check: is_fp={fp_check["is_false_positive"]}')
print('    FP patterns: OK')

print()

# 11. AgentMetrics
print('11. AgentMetrics...')
from engine.core.agent_metrics import AgentMetrics
# Use test DB instance explicitly
am = AgentMetrics.__new__(AgentMetrics)
am._db = db
am.record_finding('e2e-test-agent', 'test-target', confirmed=True)
am.record_finding('e2e-test-agent', 'test-target', confirmed=False)
stats = am.get_agent_stats('e2e-test-agent')
assert stats['total_findings'] == 2, f'Should have 2 findings, got {stats["total_findings"]}'
print(f'    Agent stats: {stats["total_findings"]} produced, precision={stats["precision"]:.1%}: OK')

print()

# 12. BountyEstimator
print('12. BountyEstimator...')
from engine.core.bounty_estimator import BountyEstimator
be = BountyEstimator('test-target')
be.add_finding('IDOR in user API', 'HIGH', 'IDOR', verified=True, state_change_proven=True)
total = be.get_running_total()
print(f'    Estimated: ${total["total_typical"]:.0f} (range: ${total["total_min"]:.0f}-${total["total_max"]:.0f}): OK')

print()

# 13. ChainValidator
print('13. ChainValidator...')
from engine.core.chain_validator import ChainValidator
steps = [
    {'description': 'Info disclosure reveals user IDs', 'verified': True,
     'evidence': 'curl output shows user IDs', 'severity': 'LOW',
     'requires_auth': False, 'requires_interaction': False},
    {'description': 'IDOR to access other user data', 'verified': True,
     'evidence': 'curl confirms cross-account access', 'severity': 'HIGH',
     'requires_auth': True, 'requires_interaction': False}
]
validation = ChainValidator.validate_chain(steps)
impact = ChainValidator.assess_chain_impact(steps, 'Full account data access')
print(f'    Chain valid={validation["valid"]}, severity={impact["chain_severity"]}: OK')

print()

# 14. ScopePrioritizer
print('14. ScopePrioritizer...')
from engine.core.scope_prioritizer import ScopePrioritizer
sp = ScopePrioritizer()
endpoints = [
    {'url': 'https://test.com/api/admin/users', 'method': 'POST'},
    {'url': 'https://test.com/static/logo.png', 'method': 'GET'},
    {'url': 'https://test.com/api/auth/login', 'method': 'POST'},
]
prioritized = sp.prioritize_endpoints(endpoints)
assert prioritized[0]['url'] != 'https://test.com/static/logo.png', 'Static should not be first'
print(f'    Prioritized {len(prioritized)} endpoints (top: {prioritized[0]["url"]}): OK')

print()

# 15. AttackPath
print('15. AttackPath...')
from engine.core.attack_path import AttackPath
path_result = AttackPath.validate({
    'entry_point': 'Unauthenticated API endpoint /api/users',
    'steps': ['Enumerate user IDs', 'Access /api/users/123 with User B token'],
    'impact': 'Read other user personal data',
    'requires_auth': True,
    'requires_interaction': False,
    'verified_steps': [True, True]
})
print(f'    Path valid={path_result["valid"]}, completeness={path_result["completeness"]:.0%}: OK')

print()

# 16. HttpClient + RequestLogger integration
print('16. HttpClient + RequestLogger integration...')
from engine.core.http_client import HttpClient
client = HttpClient(target='test-target')
assert client._logger is not None, 'Logger should be initialized'
print('    HttpClient created with logger: OK')

print()
print('=' * 40)
print('=== ALL 16 E2E TESTS PASSED ===')
print('=' * 40)

# Cleanup (best-effort - Windows may hold file lock from singleton)
try:
    os.remove(test_db)
except OSError:
    pass  # Will be cleaned up on next run
