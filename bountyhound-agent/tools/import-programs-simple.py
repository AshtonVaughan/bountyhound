#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple import - extract JSON and save to database"""

import sys
import os
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import json
import sqlite3
from datetime import datetime

# Read file and extract JSON
result_file = r"C:\Users\vaugh\.claude\projects\C--Users-vaugh\f7f7c8e4-d2e7-43c2-b885-1c7c953e5fdb\tool-results\mcp-playwright-browser_evaluate-1770788752394.txt"

print("Reading file...")
with open(result_file, 'r', encoding='utf-8') as f:
    wrapper = json.load(f)

# Extract the text field
text_content = wrapper[0]['text']

# Find the JSON object after "### Result\n"
start_marker = '### Result\n'
start_idx = text_content.find(start_marker)
if start_idx == -1:
    print("✗ Could not find result marker")
    sys.exit(1)

json_start = start_idx + len(start_marker)
json_content = text_content[json_start:]

# Find the end of the JSON by counting braces
brace_count = 0
end_idx = 0
for i, char in enumerate(json_content):
    if char == '{':
        brace_count += 1
    elif char == '}':
        brace_count -= 1
        if brace_count == 0:
            end_idx = i + 1
            break

json_str = json_content[:end_idx]

print("Parsing JSON...")
try:
    data = json.loads(json_str)
    programs = data['programs']
    print(f"✓ Loaded {len(programs)} programs")
except Exception as e:
    print(f"✗ JSON parse error: {e}")
    print(f"  First 500 chars: {json_str[:500]}")
    sys.exit(1)

# Save to database
db_path = "C:/Users/vaugh/Projects/bountyhound-agent/data/h1-programs.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

print(f"\nSaving to database...")
saved = 0

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

        if saved % 1000 == 0:
            print(f"  Saved {saved}/{len(programs)}...")
            conn.commit()

    except Exception as e:
        print(f"✗ Error saving {prog.get('handle', 'unknown')}: {e}")

conn.commit()

# Print stats
c.execute("SELECT COUNT(*) FROM programs")
total = c.fetchone()[0]

c.execute("SELECT COUNT(*) FROM programs WHERE offers_bounties = 1")
bounty = c.fetchone()[0]

c.execute("SELECT COUNT(*) FROM programs WHERE submission_state = 'open'")
open_programs = c.fetchone()[0]

conn.close()

print(f"\n✓ Import complete!")
print(f"\n📊 Database Statistics:")
print(f"  Total Programs: {total:,}")
print(f"  Bounty Programs: {bounty:,}")
print(f"  Open Programs: {open_programs:,}")
print(f"\n📁 Database: {db_path}")
