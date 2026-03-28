#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Import programs from browser result to database"""

import sys
import os
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import json
import sqlite3
from datetime import datetime

# Read the result file
result_file = r"C:\Users\vaugh\.claude\projects\C--Users-vaugh\f7f7c8e4-d2e7-43c2-b885-1c7c953e5fdb\tool-results\mcp-playwright-browser_evaluate-1770788752394.txt"

print("Loading programs data...")
with open(result_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Extract just the JSON object
import re
match = re.search(r'### Result\n(\{.*?\})\n### Ran Playwright', content, re.DOTALL)
if not match:
    # Try without the ending marker
    match = re.search(r'### Result\n(\{.*)', content, re.DOTALL)

if match:
    result_json = match.group(1)
    # Find the end of the JSON object by counting braces
    brace_count = 0
    end_pos = 0
    for i, char in enumerate(result_json):
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                end_pos = i + 1
                break

    result_json = result_json[:end_pos]
    programs_data = json.loads(result_json)
else:
    print("✗ Could not extract result from file")
    sys.exit(1)

programs = programs_data['programs']
print(f"✓ Loaded {len(programs)} programs")

# Connect to database
db_path = "C:/Users/vaugh/Projects/bountyhound-agent/data/h1-programs.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Save programs
saved = 0
skipped = 0

for prog in programs:
    try:
        c.execute('''INSERT OR REPLACE INTO programs (
            id, handle, name, url, submission_state, offers_bounties,
            currency, scraped_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (
            prog['id'],
            prog['handle'],
            prog.get('name', ''),
            prog.get('url', ''),
            prog.get('submission_state', ''),
            1 if prog.get('offers_bounties') else 0,
            prog.get('currency', 'usd'),
            datetime.now().isoformat()
        ))
        saved += 1

        if saved % 500 == 0:
            print(f"  Saved {saved}/{len(programs)}...")
            conn.commit()

    except Exception as e:
        print(f"✗ Error saving {prog.get('handle', 'unknown')}: {e}")
        skipped += 1

conn.commit()
conn.close()

print(f"\n✓ Import complete!")
print(f"  Saved: {saved}")
print(f"  Skipped: {skipped}")
print(f"  Total: {len(programs)}")

# Print stats
conn = sqlite3.connect(db_path)
c = conn.cursor()

c.execute("SELECT COUNT(*) FROM programs")
total = c.fetchone()[0]

c.execute("SELECT COUNT(*) FROM programs WHERE offers_bounties = 1")
bounty = c.fetchone()[0]

c.execute("SELECT COUNT(*) FROM programs WHERE submission_state = 'open'")
open_programs = c.fetchone()[0]

conn.close()

print(f"\n📊 Database Statistics:")
print(f"  Total Programs: {total:,}")
print(f"  Bounty Programs: {bounty:,}")
print(f"  Open Programs: {open_programs:,}")
print(f"\n📁 Database: {db_path}")
