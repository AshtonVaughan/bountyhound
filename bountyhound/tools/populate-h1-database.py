#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Populate HackerOne Database from Browser-Fetched Data
Takes JSON data fetched via browser and saves to SQLite
"""

import sys
import os
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import sqlite3
import json
from datetime import datetime

def save_programs_batch(db_path, programs):
    """Save a batch of programs to database"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    saved = 0
    for prog in programs:
        try:
            c.execute('''INSERT OR REPLACE INTO programs (
                id, handle, name, url, submission_state, offers_bounties,
                currency, managed_program, scraped_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                prog['id'],
                prog['handle'],
                prog.get('name', ''),
                prog.get('url', ''),
                prog.get('submission_state', ''),
                prog.get('offers_bounties', False),
                prog.get('currency', 'usd'),
                False,  # Will update this later with detailed data
                datetime.now().isoformat()
            ))
            saved += 1
        except Exception as e:
            print(f"✗ Error saving {prog.get('handle', 'unknown')}: {e}")

    conn.commit()
    conn.close()
    return saved

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python populate-h1-database.py <programs.json>")
        sys.exit(1)

    json_file = sys.argv[1]
    db_path = "C:/Users/vaugh/Projects/bountyhound-agent/data/h1-programs.db"

    with open(json_file, 'r') as f:
        data = json.load(f)

    programs = data.get('programs', [])
    saved = save_programs_batch(db_path, programs)

    print(f"✓ Saved {saved}/{len(programs)} programs to database")
