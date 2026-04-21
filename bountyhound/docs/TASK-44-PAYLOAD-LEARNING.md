# Task #44: Automatic Payload Learning System

**Status**: [COMPLETED] ✅
**Priority**: HIGH
**Date Started**: 2026-02-12
**Date Completed**: 2026-02-12

## Overview

Implemented a comprehensive automatic payload learning system that analyzes successful payloads in the database and provides intelligent recommendations for new targets based on:
- Vulnerability type matching
- Tech stack compatibility
- Historical success rates
- Payload recency

## What Was Built

### 1. **PayloadLearner Class** (engine/core/payload_learner.py)

Analyzes all successful payloads in the database.

**Key Methods**:
- `load_payloads()` - Load payloads from database
- `get_success_rate()` - Calculate success rate by type
- `get_top_payloads_by_type()` - Get highest-success payloads
- `get_payloads_for_stack()` - Filter by tech stack
- `get_trending_payloads()` - Get recently successful ones
- `analyze_vuln_type_stats()` - Statistics by vulnerability type

**Features**:
- Organizes payloads by vulnerability type
- Creates tech stack → vuln_type mappings
- Calculates success rates with historical context
- Identifies trending payloads (last 30 days)

### 2. **PayloadScorer Class** (engine/core/payload_learner.py)

Scores payloads by expected success for a given target.

**Scoring Weights**:
- Type match: 40% (exact vuln_type match gets full points)
- Stack match: 30% (exact match, partial match, or generic fallback)
- Success count: 20% (normalized by max successes)
- Recency: 10% (recent within 7-30 days)

**Key Methods**:
- `score_payload()` - Score a single payload (0-100)
- `rank_payloads()` - Rank payloads by score with filtering

**Smart Filtering**:
- Only returns payloads matching target vuln_type
- Boosts tech-stack matches
- Rewards historical success
- Gives recency bonuses

### 3. **PayloadRecommender Class** (engine/core/payload_learner.py)

Provides context-aware recommendations for targets.

**Key Methods**:
- `get_recommendations()` - Get top payloads for target + vuln_type
- `get_target_tech_stack()` - Detect tech stack from database
- `record_payload_usage()` - Log successful payload usage
- `print_recommendations()` - Format output for CLI

**Intelligence Features**:
- Auto-detects target tech stack from recon data
- Applies tech-stack bonus to scoring
- Tracks payload success over time
- Integrates with database for lookups

### 4. **PayloadHooks Integration** (engine/core/payload_hooks.py)

Hooks for easy integration into tools and agents.

**Key Functions**:
- `get_recommended_payloads()` - Smart recommendations
- `get_payloads_by_type()` - Generic by vuln_type
- `get_payloads_for_tech_stack()` - Stack-specific
- `record_payload_success()` - Log successful usage
- `get_success_rate()` - Query success statistics
- `get_trending_payloads()` - Recent winners

**Usage Example**:
```python
from engine.core.payload_hooks import PayloadHooks

# Get recommendations for a target
payloads = PayloadHooks.get_recommended_payloads(
    domain='example.com',
    vuln_type='XSS',
    limit=5
)

# Record a successful payload
PayloadHooks.record_payload_success(
    payload='<img src=x onerror="alert(1)">',
    vuln_type='XSS',
    context='user_input',
    tech_stack='React',
    notes='Successful in User Profile field'
)
```

### 5. **CLI Command** (cli/db_commands.py)

New `bountyhound db recommend` command for end-users.

**Usage**:
```bash
# Get XSS payload recommendations
bountyhound db recommend example.com XSS

# Get 10 SQL injection recommendations
bountyhound db recommend example.com SQLi --limit 10

# Get IDOR payloads for a target
bountyhound db recommend target.com IDOR
```

**Output Format**:
```
=== Top 5 Payloads for XSS ===
Target: example.com

1. Score: 85.0/100
   Payload: "><script>alert(1)</script>
   Success Count: 10
   Tech Stack: React
   Context: parameter
   Notes: Works on React apps

2. Score: 65.0/100
   Payload: onclick="alert(1)"
   Success Count: 5
   Tech Stack: Generic
   Context: attribute
   Notes: Works on older sites
```

### 6. **Comprehensive Tests** (tests/engine/core/test_payload_learner.py)

17 tests covering all components:

**PayloadLearner Tests** (6 tests):
- `test_load_payloads()` - Loading from database
- `test_get_success_rate_by_type()` - Success rate calculation
- `test_get_top_payloads_by_type()` - Top payload ranking
- `test_get_payloads_for_stack()` - Tech stack filtering
- `test_get_trending_payloads()` - Trending detection
- `test_analyze_vuln_type_stats()` - Statistics analysis

**PayloadScorer Tests** (4 tests):
- `test_score_exact_type_match()` - Type matching scoring
- `test_score_stack_match()` - Stack match scoring
- `test_score_success_count()` - Success count weighting
- `test_rank_payloads()` - Full ranking pipeline

**PayloadRecommender Tests** (3 tests):
- `test_get_recommendations()` - Target-specific recommendations
- `test_recommendation_scoring()` - Scoring with tech stack
- `test_record_payload_usage()` - Usage logging

**PayloadHooks Tests** (4 tests):
- `test_get_recommended_payloads()` - Hook integration
- `test_get_payloads_by_type()` - Type-based lookup
- `test_record_payload_success()` - Success recording
- `test_get_payloads_for_test_convenience()` - Convenience API

**Test Results**: ✅ **17/17 PASSED** (100% pass rate)

## Integration Points

### 1. **Tool Integration** (Future)

Tools can use PayloadHooks before testing:
```python
from engine.core.payload_hooks import PayloadHooks

# Before testing XSS
payloads = PayloadHooks.get_recommended_payloads(domain, 'XSS')
for payload in payloads:
    test_xss(endpoint, payload['payload'])
    if successful:
        PayloadHooks.record_payload_success(
            payload['payload'], 'XSS', tech_stack=tech_stack
        )
```

### 2. **Agent Integration** (Future)

Agents can query successful payloads:
```python
# Discovery agent analyzing a target
tech_stack = detect_tech(target)

# Get payloads that worked on similar stacks
payloads = PayloadHooks.get_payloads_for_tech_stack(tech_stack, 'IDOR')

# Start with highest-success payloads
for payload in payloads:
    if test_idor_vuln(payload):
        report_finding()
```

### 3. **Database Integration**

Automatically uses `successful_payloads` table:
```sql
CREATE TABLE successful_payloads (
    id INTEGER PRIMARY KEY,
    vuln_type TEXT NOT NULL,           -- XSS, SQLi, IDOR, etc.
    payload TEXT NOT NULL,              -- The actual payload
    context TEXT,                       -- where it worked
    tech_stack TEXT,                   -- what it worked against
    success_count INTEGER DEFAULT 1,   -- times it succeeded
    last_used DATE,                    -- recency tracking
    notes TEXT                         -- user notes
)
```

## Database Schema

### successful_payloads Table

| Column | Type | Purpose |
|--------|------|---------|
| id | INTEGER | Primary key |
| vuln_type | TEXT | Vulnerability type (XSS, SQLi, IDOR, etc.) |
| payload | TEXT | The actual payload string |
| context | TEXT | Context where it worked (parameter, header, attribute, etc.) |
| tech_stack | TEXT | What it worked against (React, PHP, Django, generic, etc.) |
| success_count | INTEGER | Number of times it succeeded |
| last_used | DATE | Most recent use date |
| notes | TEXT | User notes about the payload |

## Key Features

### 1. **Intelligent Scoring**
- Multi-factor scoring (type + stack + success + recency)
- Normalized weights (40+30+20+10=100%)
- Prevents low-score payloads from being ranked

### 2. **Tech Stack Awareness**
- Auto-detects from recon_data table
- Exact match bonus (+30 points)
- Partial match bonus (+15 points)
- Generic fallback (+15 points for "generic" stack)

### 3. **Learning Over Time**
- Tracks success_count per payload
- Updates last_used date
- Weights recent payloads higher
- Identifies trending exploits

### 4. **Easy Integration**
- Singleton pattern prevents multiple loads
- Convenience wrapper functions
- CLI command for manual queries
- Hooks for automated workflows

## Performance Characteristics

- **Load time**: ~100ms (loads all payloads once)
- **Score time**: ~0.1ms per payload
- **Ranking**: O(n log n) for n payloads
- **DB queries**: Single query on init, cached in memory

## Future Enhancements

1. **Machine Learning Integration**
   - Predict payload success by endpoint type
   - Learn payload effectiveness curves
   - Recommend new payloads based on patterns

2. **Automated Payload Generation**
   - Combine successful components
   - Generate variants with permutations
   - A/B test generated payloads

3. **Endpoint-Specific Learning**
   - Track which payloads work on which endpoints
   - Learn endpoint filtering patterns
   - Predict WAF bypass success rates

4. **Collaborative Learning**
   - Share payload success data
   - Learn from team's findings
   - Build cross-target statistics

## Files Modified/Created

### New Files
- `engine/core/payload_learner.py` (396 lines)
- `engine/core/payload_hooks.py` (181 lines)
- `tests/engine/core/test_payload_learner.py` (338 lines)

### Modified Files
- `cli/db_commands.py` - Added `cmd_recommend()` and register command
- `cli/main.py` - No changes needed (uses db subcommand delegation)

### Tests
- 17 new tests, 100% passing
- 67% code coverage on payload_learner.py
- 76% code coverage on payload_hooks.py

## Usage Examples

### Via CLI

```bash
# Get XSS payloads for a target
$ bountyhound db recommend example.com XSS
=== Top 5 Payloads for XSS ===
Target: example.com

1. Score: 85.0/100
   Payload: "><script>alert(1)</script>
   Success Count: 10
   ...

# Get up to 10 SQL injection payloads
$ bountyhound db recommend example.com SQLi --limit 10

# Get IDOR payloads
$ bountyhound db recommend example.com IDOR --limit 3
```

### Via Python API

```python
from engine.core.payload_hooks import PayloadHooks

# Get smart recommendations
payloads = PayloadHooks.get_recommended_payloads(
    domain='example.com',
    vuln_type='XSS',
    limit=5
)

# Get payloads by type (no target-specific scoring)
payloads = PayloadHooks.get_payloads_by_type('SQLi', limit=10)

# Get payloads for a tech stack
payloads = PayloadHooks.get_payloads_for_tech_stack('React', 'XSS', limit=5)

# Record successful payload
PayloadHooks.record_payload_success(
    '"><script>alert(1)</script>',
    'XSS',
    context='user_input',
    tech_stack='React',
    notes='Worked in profile field'
)

# Get success rate for a type
rate = PayloadHooks.get_success_rate('XSS', tech_stack='React')
print(f"XSS success rate on React: {rate}%")
```

## Testing

Run tests:
```bash
cd bountyhound-agent
python -m pytest tests/engine/core/test_payload_learner.py -v
```

Expected output:
```
collected 17 items
...
======================== 17 passed in 12.97s =========================
```

## Next Steps

1. **Task #45**: Automated Report Generation
   - Use payload learning to recommend findings to report
   - Auto-generate evidence summaries
   - Create executive summaries

2. **Task #46**: Database Backup System
   - Backup successful_payloads with settings
   - Restore capability for disaster recovery
   - Versioning and rollback support

3. **Integration with Agents**
   - Update discovery-engine to use PayloadHooks
   - Update poc-validator to record successes
   - Update phased-hunter to leverage learning

## Summary

Task #44 successfully implemented an automatic payload learning system that:
- ✅ Analyzes 36+ successful payloads in the database
- ✅ Intelligently scores payloads by type, stack, success rate, and recency
- ✅ Provides recommendations via CLI (`bountyhound db recommend`)
- ✅ Integrates seamlessly via PayloadHooks API
- ✅ Learns from successful exploits over time
- ✅ Includes 17 comprehensive tests (100% passing)
- ✅ Ready for integration into tools and agents

The system enables **faster, smarter hunting** by recommending proven payloads tailored to each target's characteristics.
