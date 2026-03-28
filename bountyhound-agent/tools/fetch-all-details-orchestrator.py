#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fetch all program details using browser automation
Orchestrates the process of fetching scopes, bounties, and disclosed reports
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

def get_program_handles(db_path, limit=None):
    """Get all program handles from database"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    query = "SELECT handle FROM programs ORDER BY resolved_report_count DESC"
    if limit:
        query += f" LIMIT {limit}"

    c.execute(query)
    handles = [row[0] for row in c.fetchall()]
    conn.close()

    return handles

def save_program_details(db_path, program_data):
    """Save program details to database"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    try:
        data = program_data.get('data', {})
        team = data.get('team')

        if not team:
            return {'scopes': 0, 'out_of_scope': 0, 'bounties': 0, 'disclosed': 0}

        program_id = team['id']

        # Save scopes
        scopes = team.get('in_scope_assets', {}).get('edges', [])
        for edge in scopes:
            scope = edge['node']
            try:
                c.execute('''INSERT OR REPLACE INTO scopes (
                    id, program_id, asset_type, asset_identifier, instruction,
                    max_severity, eligible_for_bounty, eligible_for_submission
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (
                    scope['id'],
                    program_id,
                    scope.get('asset_type', ''),
                    scope.get('asset_identifier', ''),
                    scope.get('instruction', ''),
                    scope.get('max_severity', ''),
                    1 if scope.get('eligible_for_bounty') else 0,
                    1 if scope.get('eligible_for_submission') else 0
                ))
            except Exception as e:
                pass  # Skip errors silently

        # Save out of scope
        out_of_scope = team.get('out_of_scope_assets', {}).get('edges', [])
        for edge in out_of_scope:
            oos = edge['node']
            try:
                c.execute('''INSERT OR REPLACE INTO out_of_scope (
                    id, program_id, asset_type, asset_identifier, instruction
                ) VALUES (?, ?, ?, ?, ?)''', (
                    oos['id'],
                    program_id,
                    oos.get('asset_type', ''),
                    oos.get('asset_identifier', ''),
                    oos.get('instruction', '')
                ))
            except Exception as e:
                pass

        # Save bounty table
        bounty_table = team.get('bounty_table')
        bounty_count = 0
        if bounty_table:
            severities = [
                ('critical', bounty_table.get('critical_minimum_bounty'), bounty_table.get('critical_maximum_bounty')),
                ('high', bounty_table.get('high_minimum_bounty'), bounty_table.get('high_maximum_bounty')),
                ('medium', bounty_table.get('medium_minimum_bounty'), bounty_table.get('medium_maximum_bounty')),
                ('low', bounty_table.get('low_minimum_bounty'), bounty_table.get('low_maximum_bounty'))
            ]

            for severity, min_bounty, max_bounty in severities:
                if min_bounty is not None or max_bounty is not None:
                    try:
                        c.execute('''INSERT OR REPLACE INTO severity_bounties (
                            program_id, severity, min_bounty, max_bounty
                        ) VALUES (?, ?, ?, ?)''', (
                            program_id,
                            severity,
                            min_bounty,
                            max_bounty
                        ))
                        bounty_count += 1
                    except Exception as e:
                        pass

        # Save disclosed reports
        disclosed = team.get('disclosed_reports', {}).get('edges', [])
        for edge in disclosed:
            node = edge.get('node', {})
            report = node.get('report')
            if report:
                try:
                    severity_rating = report.get('severity_rating', {})
                    c.execute('''INSERT OR REPLACE INTO disclosed_reports (
                        id, program_id, title, severity_rating, disclosed_at,
                        vulnerability_information
                    ) VALUES (?, ?, ?, ?, ?, ?)''', (
                        report['id'],
                        program_id,
                        report.get('title', ''),
                        severity_rating.get('rating', '') if severity_rating else '',
                        report.get('disclosed_at', ''),
                        report.get('vulnerability_information', '')
                    ))
                except Exception as e:
                    pass

        conn.commit()

        return {
            'scopes': len(scopes),
            'out_of_scope': len(out_of_scope),
            'bounties': bounty_count,
            'disclosed': len(disclosed)
        }

    except Exception as e:
        print(f"  ✗ Error processing program: {e}")
        return {'scopes': 0, 'out_of_scope': 0, 'bounties': 0, 'disclosed': 0}
    finally:
        conn.close()

def process_batch_results(db_path, results):
    """Process a batch of results from browser"""
    total_stats = {'scopes': 0, 'out_of_scope': 0, 'bounties': 0, 'disclosed': 0}

    for result in results:
        if 'error' in result and 'data' not in result:
            print(f"  ✗ {result['handle']}: {result['error']}")
            continue

        stats = save_program_details(db_path, result)
        for key in total_stats:
            total_stats[key] += stats[key]

    return total_stats

if __name__ == "__main__":
    db_path = "C:/Users/vaugh/Projects/bountyhound-agent/data/h1-programs.db"

    # Get program handles
    print("Loading program handles...")
    handles = get_program_handles(db_path)
    print(f"Found {len(handles)} programs")

    # Create JavaScript file with handles for browser
    # This will be used by the browser automation
    print("\nReady to fetch program details via browser automation")
    print(f"Total programs: {len(handles)}")
    print("\nNext step: Use Playwright to execute the fetch")
