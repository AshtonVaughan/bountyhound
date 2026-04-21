#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 2: Fetch detailed program data for all programs
Saves scopes, out-of-scope, and bounty tables
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

DB_PATH = "C:/Users/vaugh/Projects/bountyhound-agent/data/h1-programs.db"
OUTPUT_FILE = "C:/Users/vaugh/bounty-findings/h1-phase2-results.jsonl"

def get_program_handles(limit=None):
    """Get all program handles from database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if limit:
        # Get top programs by report count
        c.execute("SELECT handle FROM programs WHERE offers_bounties = 1 ORDER BY resolved_report_count DESC LIMIT ?", (limit,))
    else:
        # Get all programs
        c.execute("SELECT handle FROM programs ORDER BY resolved_report_count DESC")

    handles = [row[0] for row in c.fetchall()]
    conn.close()
    return handles

def save_program_data(program_data):
    """Save program data to database"""
    if 'error' in program_data or 'errors' in program_data:
        return {'scopes': 0, 'out_of_scope': 0, 'bounties': 0, 'error': True}

    team = program_data.get('data', {}).get('team')
    if not team:
        return {'scopes': 0, 'out_of_scope': 0, 'bounties': 0, 'error': True}

    program_id = team['id']

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    stats = {'scopes': 0, 'out_of_scope': 0, 'bounties': 0, 'error': False}

    try:
        # Save in-scope assets
        scopes = team.get('in_scope', {}).get('edges', [])
        for edge in scopes:
            scope = edge['node']
            c.execute('''INSERT OR REPLACE INTO scopes (
                id, program_id, asset_type, asset_identifier, instruction,
                max_severity, eligible_for_bounty, eligible_for_submission
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (
                scope['id'],
                program_id,
                scope.get('asset_type', ''),
                scope.get('asset_identifier', ''),
                scope.get('instruction') or '',
                scope.get('max_severity', ''),
                1 if scope.get('eligible_for_bounty') else 0,
                1 if scope.get('eligible_for_submission') else 0
            ))
            stats['scopes'] += 1

        # Save out-of-scope assets
        out_of_scope = team.get('out_of_scope', {}).get('edges', [])
        for edge in out_of_scope:
            oos = edge['node']
            c.execute('''INSERT OR REPLACE INTO out_of_scope (
                id, program_id, asset_type, asset_identifier, instruction
            ) VALUES (?, ?, ?, ?, ?)''', (
                oos['id'],
                program_id,
                oos.get('asset_type', ''),
                oos.get('asset_identifier', ''),
                oos.get('instruction') or ''
            ))
            stats['out_of_scope'] += 1

        # Save bounty table
        bounty_table = team.get('bounty_table')
        if bounty_table:
            rows = bounty_table.get('bounty_table_rows', {}).get('edges', [])
            for edge in rows:
                row = edge['node']
                severities = [
                    ('critical', row.get('critical'), row.get('critical_minimum')),
                    ('high', row.get('high'), row.get('high_minimum')),
                    ('medium', row.get('medium'), row.get('medium_minimum')),
                    ('low', row.get('low'), row.get('low_minimum'))
                ]
                for severity, max_bounty, min_bounty in severities:
                    if max_bounty is not None or min_bounty is not None:
                        c.execute('''INSERT OR REPLACE INTO severity_bounties (
                            program_id, severity, min_bounty, max_bounty
                        ) VALUES (?, ?, ?, ?)''', (
                            program_id,
                            severity,
                            min_bounty,
                            max_bounty
                        ))
                        stats['bounties'] += 1

        conn.commit()

    except Exception as e:
        print(f"  ✗ Error saving: {e}")
        stats['error'] = True
    finally:
        conn.close()

    return stats

def main():
    # Get all program handles
    print("📥 Loading program handles...")
    all_handles = get_program_handles()
    print(f"Found {len(all_handles)} programs")

    # Check which programs already have data
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT DISTINCT program_id FROM scopes")
    completed_ids = set(row[0] for row in c.fetchall())
    conn.close()

    # Get handles for programs that need data
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if completed_ids:
        placeholders = ','.join('?' * len(completed_ids))
        c.execute(f"SELECT handle FROM programs WHERE id NOT IN ({placeholders}) ORDER BY resolved_report_count DESC", list(completed_ids))
    else:
        c.execute("SELECT handle FROM programs ORDER BY resolved_report_count DESC")
    remaining_handles = [row[0] for row in c.fetchall()]
    conn.close()

    print(f"Already completed: {len(completed_ids)}")
    print(f"Remaining: {len(remaining_handles)}")
    print(f"\nThis will take approximately {len(remaining_handles) * 5 / 3600:.1f} hours with 5-second delays")
    print("Results will be saved incrementally to database")
    print("\nStarting fetch...\n")

    # Output file for raw JSON (for debugging)
    with open(OUTPUT_FILE, 'w') as f:
        f.write('')  # Clear file

    # Process in batches of 10 for progress tracking
    batch_size = 10
    total_stats = {'scopes': 0, 'out_of_scope': 0, 'bounties': 0, 'errors': 0}

    for i in range(0, len(remaining_handles), batch_size):
        batch = remaining_handles[i:i+batch_size]
        print(f"Batch {i//batch_size + 1}/{(len(remaining_handles) + batch_size - 1)//batch_size} ({len(batch)} programs)")
        print(f"Handles: {', '.join(batch[:5])}{'...' if len(batch) > 5 else ''}")

        # This will be filled by browser script
        print(f"\nReady for browser to fetch batch {i//batch_size + 1}")
        print(f"Handles: {json.dumps(batch)}")
        print("---")

        # Note: Actual fetching will be done via Playwright browser script
        # This Python script is just for orchestration and saving
        break  # Stop here - actual fetch will be done via browser

    print("\nNext step: Use browser automation to fetch these batches")

if __name__ == "__main__":
    main()
