# HackerOne Database Status

**Date**: 2026-02-11
**Status**: PHASE 1 COMPLETE, PHASE 2 BLOCKED

---

## ✅ Phase 1: Basic Program Data (COMPLETE)

Successfully fetched and stored **6,337 programs** with basic information:

| Field | Status |
|-------|--------|
| Program ID | ✅ Complete |
| Handle | ✅ Complete |
| Name | ✅ Complete |
| URL | ✅ Complete |
| Submission State | ✅ Complete |
| Offers Bounties | ✅ Complete (372 programs)|
| Currency | ✅ Complete |

**Query tool working**: `python tools/h1-program-query.py`

---

## ❌ Phase 2: Detailed Program Data (BLOCKED)

### What's Missing

The following tables exist in the schema but are **empty**:

- **scopes** (0 records) - In-scope assets for each program
- **out_of_scope** (0 records) - Out-of-scope assets
- **severity_bounties** (0 records) - Bounty ranges by severity
- **disclosed_reports** (0 records) - Sample of disclosed reports per program

### Blockers

1. **GraphQL Schema Mismatch**
   - Used field names: `critical_minimum_bounty`, `hacktivity_items`
   - Actual API doesn't have these fields
   - Need GraphQL introspection to discover correct schema

2. **Rate Limiting**
   - HackerOne returned HTTP 429 after just 1 request
   - Current rate: 1 request/second = too fast
   - Need: 2-5 seconds between requests minimum
   - Estimated time for 6,337 programs: **3.5 - 8.8 hours**

3. **Authentication Requirements**
   - Some program details may require higher privilege levels
   - Current: Basic authenticated session
   - May need: API token with specific scopes

---

## 🔧 Solutions

### Option 1: Manual Program Page Scraping

Instead of using GraphQL, scrape program pages directly:

**Pros**:
- No GraphQL schema issues
- Can get exact data as displayed
- Works with current authentication

**Cons**:
- Slower (HTML parsing)
- More fragile (depends on HTML structure)
- Still rate limited

**Implementation**: Navigate to each program's page (e.g., `https://hackerone.com/doordash`) and extract data from DOM.

### Option 2: Slow GraphQL Fetching

Fix GraphQL query and run with 5-second delays:

**Pros**:
- Structured data
- Official API
- More reliable

**Cons**:
- Need correct schema first
- 8+ hours to complete
- May still hit rate limits

**Implementation**:
1. Use introspection to discover correct fields
2. Update query
3. Run in background with 5-sec delays

### Option 3: Target Specific Programs

Instead of fetching all 6,337, focus on:
- Top 100 bounty programs (by report count)
- Programs offering bounties (372 total)
- Specific programs of interest

**Pros**:
- Much faster (30 min - 2 hours)
- More manageable
- Still very useful

**Cons**:
- Incomplete database
- Need to manually select programs

---

## 📊 Current Database Value

Even with just basic program data, the database provides:

✅ **Search Capabilities**
```bash
# Find any program
python tools/h1-program-query.py search doordash

# List all bounty programs
python tools/h1-program-query.py search "" --offers-bounty

# Top programs by reports
python tools/h1-program-query.py top 50
```

✅ **Quick Program Discovery**
- Know which 372 programs offer bounties
- Know which 457 programs are open
- Quick lookup by handle

✅ **Foundation for Tools**
- Duplicate detector can query program list
- Scope validator has program handles
- Report optimizer knows bounty programs

---

## 🎯 Recommended Next Step

**Option 3**: Fetch detailed data for **top 100 bounty programs only**

This provides:
- Scopes for high-value targets
- Disclosed reports for duplicate detection
- Bounty ranges for prioritization
- Reasonable time investment (1-2 hours)

Once proven working, can expand to all 372 bounty programs, then all 6,337 if needed.

---

## 🛠️ Implementation Plan

1. **Fix GraphQL Schema** (15 min)
   - Use introspection on a single program
   - Discover correct field names
   - Update query template

2. **Test on 1 Program** (5 min)
   - Validate query works
   - Check rate limiting
   - Confirm data saves correctly

3. **Fetch Top 100** (1-2 hours)
   - Run with 5-second delays
   - Save to database incrementally
   - Show progress

4. **Validate Results** (10 min)
   - Check database stats
   - Test query tools
   - Verify data quality

**Total Time**: ~2-3 hours for fully functional database of top programs

---

## 📝 Files

- `data/h1-programs.db` - SQLite database with 6,337 programs
- `tools/h1-program-query.py` - Query interface ✅ WORKING
- `tools/fetch-program-details.py` - Detail fetcher (needs schema fix)
- `tools/fetch-all-program-details-browser.js` - Browser script (needs schema fix)
- `H1-DATABASE-COMPLETE.md` - Phase 1 success documentation
- `H1-DATABASE-STATUS.md` - This file

---

**Next Action**: User decision on which option to pursue for Phase 2.
