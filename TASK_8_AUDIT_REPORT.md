# Task 8: Engine/Core Directory Audit Report

## Status: ANALYSIS COMPLETE - DELETION DEFERRED TO POST-TASK-9

## Summary

The `bountyhound-agent/engine/` directory (which contains 69 files across 14 subdirectories) has **135 active external imports** across 45 files. Therefore, it **cannot be safely deleted at this time**.

However, these imports are only used by:
- Old CLI and script files
- Example files
- Test files for the old architecture

All of these are **scheduled for deletion in Task 9** ("Delete 138 unused agents").

## Detailed Findings

### Import Analysis

**Total external imports from engine/: 135**

Breakdown by consuming file type:
- 13 CLI/Script files (db_commands.py, main.py, build_disclosed_cache.py, etc.)
- 8 Example files (ai_hunt_example.py, monitoring_example.py, etc.)
- 24 Test files (test_ai_hunter.py, test_cloud_integration.py, etc.)
- Plus verify_* scripts and test runners

### Modules Imported

**engine.agents.*** (17 modules)
- api_documentation_scanner
- api_endpoint_parameter_miner
- api_rate_limit_tester
- content_security_policy_tester
- deserialization_tester
- file_upload_security
- graphql_advanced_tester
- http_request_smuggling_tester
- jwt_analyzer
- mass_assignment_tester
- nosql_injection_tester
- open_redirect_tester
- os_command_injection_tester
- phased_hunter
- race_condition_tester
- rejection_filter
- smuggling_tester

**engine.cloud.*** (5 modules)
- firestore_tester
- functions_tester
- gcs_scanner
- iam_tester
- secret_manager

**engine.core.*** (25 modules) - MOST CRITICAL
- agent_metrics, agent_registry, ai_hunter, attack_path, auto_dispatcher
- bounty_estimator, chain_validator, command_router
- database (BountyHoundDB), db_hooks, evidence_vault, exploit_notebook
- fp_patterns, h1_disclosed_checker, http_client
- hunt_executor, hunt_state, monitor, payload_hooks, payload_learner, payload_tracker
- proxy_config, quality_gates, recon_cache, request_logger, response_diff, scheduler
- scope_prioritizer, state_verifier, target_profiler, tool_checker

**engine.discovery.*** (4 modules)
- content_discovery, github_osint, js_analyzer, wayback_miner

**engine.hardware.*** (5 modules)
- bluetooth_scanner, firmware analyzer, jtag_tester, serial_scanner, usb_analyzer

**engine.intel.*** (4 modules)
- changelog_fetcher, cve_fetcher, h1_fetcher, target_brief

**engine.reversing.*** (3 modules)
- binary_analyzer, decompiler, patcher

**engine.sast.*** (3 modules)
- code_auditor, dependency_auditor, repo_scanner

**engine.testing.*** (2 modules)
- subdomain_takeover, timing_injection

**engine.understanding.*** (3 modules)
- flow_mapper, permission_mapper, tech_fingerprinter

**engine.verification.*** (1 module)
**engine.scoring** (1 module)

### New Architecture Status

The worktree/redesign (`feature/bountyhound-redesign`) contains:
- `bountyhound-agent/data/db.py` - New unified database interface
- No imports from engine/
- No cli/, examples/, scripts/, or agents/ directories
- Clean slate for new architecture

## Deletion Plan

**Cannot delete now** because:
1. Old code still uses engine/ (135 imports)
2. Old files are not yet removed

**Can delete after Task 9** because:
1. Task 9 deletes 138 old agent files + cli + examples + scripts
2. Deletion of Task 9 targets eliminates all 135 imports
3. After Task 9: engine/ becomes orphaned with zero callers
4. Safe cleanup: Delete engine/ as follow-up task after Task 9 completes

## Recommendation

✅ **Create follow-up task**: "Task 9.5: Delete orphaned engine/ directory"
- Should run immediately after Task 9 completes
- At that point: `rm -rf bountyhound-agent/engine/` will be safe

## Test Plan For Later

Once Task 9 is complete, verify deletion safety:
```bash
# Verify zero imports remain
grep -r "from engine\|import engine" bountyhound-agent/ --include="*.py" \
  --exclude-dir="engine" 2>/dev/null
# Expected output: (nothing)

# Delete
rm -rf bountyhound-agent/engine/

# Run tests
python -m pytest bountyhound-agent/tests/ -v
```

---
**Task 8 Status**: ✅ COMPLETE - Analysis performed, decision documented
**Follow-up**: Task 9 (delete agents) must complete first
