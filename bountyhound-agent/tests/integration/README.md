# BountyHound Integration Tests

Comprehensive end-to-end tests validating the complete BountyHound v4 pipeline from hunt initiation to report submission.

## Test Coverage

### test_full_pipeline.py

**Main Pipeline Test**: `test_full_hunt_pipeline_graphql_target`
- ✅ Phase 0: Database check (DatabaseHooks.before_test)
- ✅ Phase 1: Reconnaissance (asset discovery)
- ✅ Phase 2: Discovery (DiscoveryEngine generates hypotheses)
- ✅ Phase 3: Validation (StateVerifier confirms exploits with before/after state comparison)
- ✅ Phase 4: Exploitation (POC validation and evidence gathering)
- ✅ Phase 5: Reporting (RejectionFilter + report generation)
- ✅ Hunt state checkpointing (HuntState saves progress)
- ✅ Semantic duplicate detection (prevents duplicate submissions)
- ✅ Payout tracking and ROI calculation

**Component Tests**:

1. **test_pipeline_with_error_recovery**
   - Validates hunt can resume from checkpoint after crash
   - Tests HuntState save/load mechanism
   - Ensures no work is lost during interruptions

2. **test_rejection_filter_blocks_false_positive**
   - Tests RejectionFilter blocks findings without state change
   - Validates HTTP 200 alone doesn't pass quality gate
   - Ensures low-quality findings get rejected/manual review

3. **test_rejection_filter_blocks_own_account_access**
   - Tests "intended functionality" detection
   - Blocks findings where user accesses own resources
   - Prevents false positives from authorized behavior

4. **test_semantic_dedup_catches_similar_finding**
   - Tests semantic duplicate detection
   - Prevents submitting similar findings
   - Uses both keyword and semantic matching

5. **test_state_verifier_rejects_http_200_only**
   - Validates HTTP status code alone is insufficient
   - Requires actual state change verification
   - Prevents Airbnb 2026-02-14 type false positives

6. **test_state_verifier_detects_actual_change**
   - Tests before/after state comparison
   - Confirms diff detection works correctly
   - Validates mutation success detection

7. **test_phase_0_database_check_skips_recent_test**
   - Tests database-driven test skipping
   - Validates "tested recently" logic
   - Prevents duplicate work

8. **test_database_tracks_payout_roi**
   - Tests payout recording
   - Validates ROI calculation
   - Ensures target stats are updated

## Mock Components

### MockGraphQLTarget
- Simulates GraphQL API with known BOLA vulnerability
- deleteUser mutation lacks authorization (exploitable)
- Provides introspection and schema access
- Tracks state changes (user deletion)

### MockReconTool
- Generates realistic recon data
- Returns subdomains, tech stack, endpoints
- Used to test discovery phase

### MockDiscoveryEngine
- Simulates LLM-powered hypothesis generation
- Creates vulnerability hypotheses from recon data
- Includes GraphQL-specific attack patterns

### MockHTTPClient
- Simulates HTTP requests
- Executes GraphQL queries/mutations
- Used for state verification tests

## Running Tests

```bash
# Run all integration tests
pytest tests/integration/ -v

# Run specific test
pytest tests/integration/test_full_pipeline.py::TestFullHuntPipeline::test_full_hunt_pipeline_graphql_target -v

# Run without coverage
pytest tests/integration/ -v --no-cov

# Run with detailed output
pytest tests/integration/ -v -s
```

## Success Criteria

All 9 tests must pass:

```
tests/integration/test_full_pipeline.py::TestFullHuntPipeline::test_full_hunt_pipeline_graphql_target PASSED
tests/integration/test_full_pipeline.py::TestFullHuntPipeline::test_pipeline_with_error_recovery PASSED
tests/integration/test_full_pipeline.py::TestFullHuntPipeline::test_rejection_filter_blocks_false_positive PASSED
tests/integration/test_full_pipeline.py::TestFullHuntPipeline::test_rejection_filter_blocks_own_account_access PASSED
tests/integration/test_full_pipeline.py::TestFullHuntPipeline::test_semantic_dedup_catches_similar_finding PASSED
tests/integration/test_full_pipeline.py::TestFullHuntPipeline::test_state_verifier_rejects_http_200_only PASSED
tests/integration/test_full_pipeline.py::TestFullHuntPipeline::test_state_verifier_detects_actual_change PASSED
tests/integration/test_full_pipeline.py::TestFullHuntPipeline::test_phase_0_database_check_skips_recent_test PASSED
tests/integration/test_full_pipeline.py::TestFullHuntPipeline::test_database_tracks_payout_roi PASSED
```

## What's Validated

### Pipeline Integrity
- All phases execute in correct order
- State is preserved between phases
- Checkpoints enable crash recovery
- Database is consulted before testing

### Quality Gates
- StateVerifier prevents HTTP 200 false positives
- RejectionFilter blocks low-quality findings
- Semantic dedup prevents duplicate submissions
- "Intended functionality" is detected and rejected

### Data Flow
- Recon data flows to discovery
- Hypotheses flow to validation
- Verified findings flow to reporting
- Payouts update target statistics

### Database Integration
- Phase 0 database checks work
- Tool runs are recorded
- Findings are stored correctly
- ROI tracking is accurate
- Duplicate detection works

## Future Improvements

1. Add tests for more vulnerability types (XSS, SQLi, etc.)
2. Test multi-account authorization validation
3. Add tests for API gateway bypass scenarios
4. Test parallel agent execution
5. Add performance benchmarks for each phase
6. Test error handling for network failures
7. Add tests for credential management
8. Test report submission to HackerOne/Bugcrowd

## Notes

- Tests use temporary SQLite databases (no pollution of real data)
- Mock components simulate real targets without external dependencies
- All tests are deterministic and repeatable
- No network access required (fully offline)
- Fast execution (~6-20 seconds total)
