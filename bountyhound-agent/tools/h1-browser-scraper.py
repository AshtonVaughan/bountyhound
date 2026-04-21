#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HackerOne Browser-Based Scraper
Uses Playwright to scrape program data from authenticated session
"""

import sys
import os
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import sqlite3
import json
import time
from datetime import datetime

def init_database(db_path):
    """Create database schema"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS programs (
        id TEXT PRIMARY KEY,
        handle TEXT UNIQUE NOT NULL,
        name TEXT,
        url TEXT,
        offers_bounties BOOLEAN,
        min_bounty INTEGER,
        max_bounty INTEGER,
        currency TEXT,
        submission_state TEXT,
        managed_program BOOLEAN,
        scoped_assets TEXT,
        out_of_scope TEXT,
        policy TEXT,
        scraped_at TEXT
    )''')

    c.execute('CREATE INDEX IF NOT EXISTS idx_handle ON programs(handle)')

    conn.commit()
    conn.close()
    print("✓ Database initialized")

def extract_program_data_from_page():
    """
    Extract program data using browser automation
    This script is meant to be run WITH browser automation
    """
    print("This scraper requires Playwright browser automation.")
    print("Use the main scraper with Playwright integration instead.")

def save_program(db_path, program):
    """Save program to database"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute('''INSERT OR REPLACE INTO programs VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )''', (
        program.get('id', ''),
        program['handle'],
        program.get('name', ''),
        program.get('url', ''),
        program.get('offers_bounties', False),
        program.get('min_bounty'),
        program.get('max_bounty'),
        program.get('currency', 'USD'),
        program.get('submission_state', ''),
        program.get('managed_program', False),
        json.dumps(program.get('scoped_assets', [])),
        json.dumps(program.get('out_of_scope', [])),
        program.get('policy', ''),
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    db_path = "C:/Users/vaugh/Projects/bountyhound-agent/data/h1-programs.db"
    init_database(db_path)

    print("\n⚠️  This scraper requires browser automation.")
    print("Please use Claude Code with Playwright to run the full scraping process.")
    print("\nThe database has been initialized at:")
    print(f"  {db_path}")
