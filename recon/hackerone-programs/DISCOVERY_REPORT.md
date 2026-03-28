# HackerOne BBP Discovery Report

## Summary
- **Target**: All public Bug Bounty Programs on HackerOne
- **Discovered**: 24 programs (via browser automation)
- **Available**: 236 total BBPs (per HackerOne UI)
- **Status**: Phase 1 (Discovery) - Partial completion

## Discovery Method
- URL: `https://hackerone.com/opportunities/all/search?bbp=true`
- Technique: Browser automation with CSS selector extraction + JavaScript scrolling
- Implementation: Claude Code Chrome browser automation

## Challenges Encountered

### 1. Infinite Scroll Limitation
HackerOne uses infinite scroll pagination. The browser automation approach:
- Successfully loaded initial 24 programs
- Triggered multiple scroll events
- Did not trigger lazy loading of additional programs

**Root cause**: The page's JavaScript lazy-loading mechanism may require:
- Specific viewport events not triggered by `window.scrollBy()`
- Intersection Observer API requirements
- Dynamic rendering of list items on-demand

### 2. Why Only 24 Programs Loaded
- Initial page renders ~24 programs in DOM
- Additional programs load dynamically as user scrolls
- Browser automation scrolling didn't consistently trigger lazy load events
- Page may have intentional rate limiting for programmatic access

## Programs Discovered (24 Total)

1. Anduril Industries
2. Audible
3. Banco Plata
4. Braze Inc
5. CLEAR
6. DoorDash
7. Dyson
8. Flipkart
9. HubSpot
10. Kong
11. Meesho
12. M-Pesa
13. Neon BBP
14. NetScaler Public Program
15. Notion Labs
16. Ripio
17. Robinhood
18. Stripchat
19. Syfe
20. Twilio
21. Unico IDtech
22. Vercel Open Source
23. Wallet on Telegram
24. Zooplus

## Alternative Approaches for Complete Discovery

### Option A: HackerOne API
- Check if HackerOne provides an API for program listings
- Docs: https://docs.hackerone.com
- Advantage: Direct data access, no browser automation needed
- Status: **NOT YET EXPLORED**

### Option B: Extended Browser Automation
- Use Selenium/Puppeteer with longer delays
- Simulate more realistic user behavior (slow scrolling, waits)
- May increase load time significantly (hours)
- Status: **FEASIBLE BUT TIME-CONSUMING**

### Option C: Manual Pagination
- Navigate through page sorting/filtering UI
- Use pagination controls if available
- Extract programs from each page manually
- Status: **SLOW, NOT AUTOMATED**

### Option D: Headless Browser with Event Listeners
- Implement IntersectionObserver in-page listener
- Detect when new items load and trigger extractions
- More reliable lazy-load detection
- Status: **REQUIRES CODE INJECTION**

## Next Steps

### Recommended
1. **Investigate HackerOne API** - Check docs for bulk program export
2. **Scrape Program Details** - Start detailed scraping on these 24 to validate pipeline
3. **Assess Remaining Coverage** - Decide if 24 programs sufficient for initial analysis

### If Complete Coverage Required
1. Try extended browser automation with more aggressive timing
2. Implement headless browser with JavaScript event listeners
3. Consider alternative data sources (GitHub, public databases)

## File Outputs
- `programs_index.json` - 24 discovered programs
- `programs/` - Directory for detailed program JSON files (to be populated)
- `scrape_log.txt` - Log of scraping operations
- `summary.json` - Aggregated statistics (to be generated)

---
**Generated**: 2026-03-09
**Status**: Ready for Phase 2 (Detailed Scraping)
