#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fetch detailed program information from HackerOne
This script fetches scopes, out-of-scopes, bounties, and disclosed reports
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

# GraphQL query for detailed program information
PROGRAM_DETAILS_QUERY = '''
query ProgramDetails($handle: String!) {
  team(handle: $handle) {
    id
    handle
    name

    # Scopes
    in_scope_assets: structured_scopes(
      first: 100
      archived: false
    ) {
      edges {
        node {
          id
          asset_type
          asset_identifier
          instruction
          max_severity
          eligible_for_bounty
          eligible_for_submission
        }
      }
    }

    # Out of scope
    out_of_scope_assets: structured_scopes(
      first: 100
      archived: false
      eligible_for_submission: false
    ) {
      edges {
        node {
          id
          asset_type
          asset_identifier
          instruction
        }
      }
    }

    # Bounty table
    bounty_table {
      id
      critical_minimum_bounty
      critical_maximum_bounty
      high_minimum_bounty
      high_maximum_bounty
      medium_minimum_bounty
      medium_maximum_bounty
      low_minimum_bounty
      low_maximum_bounty
    }

    # Disclosed reports (sample)
    disclosed_reports: hacktivity_items(
      first: 20
      type: HACKTIVITY_TYPE_HACKTIVITY
    ) {
      edges {
        node {
          ... on Disclosed {
            id
            report {
              id
              title
              substate
              severity_rating: severity {
                rating
              }
              disclosed_at
              vulnerability_information
            }
          }
        }
      }
    }
  }
}
'''

def save_program_details(db_path, handle, details):
    """Save detailed program information to database"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    try:
        team = details['data']['team']
        if not team:
            print(f"  ⚠ Program {handle} not found or private")
            return False

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
                    scope.get('eligible_for_bounty', False),
                    scope.get('eligible_for_submission', True)
                ))
            except Exception as e:
                print(f"  ✗ Error saving scope: {e}")

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
                print(f"  ✗ Error saving out-of-scope: {e}")

        # Save bounty table
        bounty_table = team.get('bounty_table')
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
                    except Exception as e:
                        print(f"  ✗ Error saving bounty: {e}")

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
                    print(f"  ✗ Error saving disclosed report: {e}")

        conn.commit()

        # Return counts
        scope_count = len(scopes)
        oos_count = len(out_of_scope)
        bounty_count = 4 if bounty_table else 0
        disclosed_count = len(disclosed)

        return {
            'scopes': scope_count,
            'out_of_scope': oos_count,
            'bounties': bounty_count,
            'disclosed': disclosed_count
        }

    except Exception as e:
        print(f"  ✗ Error processing {handle}: {e}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    # This script is designed to be called with program handles
    # It will be integrated with browser automation to fetch data
    print("This script is designed to be used with browser automation")
    print("Use fetch-all-program-details.py to fetch all program data")
