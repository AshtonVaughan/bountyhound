#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HackerOne Program Database Scraper
Fetches ALL active HackerOne programs and stores complete details in SQLite
"""

import sys
import os

# Fix Windows encoding
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import sqlite3
import requests
import json
import time
import os
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class H1ProgramScraper:
    def __init__(self, db_path="h1-programs.db"):
        self.db_path = db_path
        self.session = requests.Session()

        # Get API token from environment
        api_token = os.getenv('H1_API_TOKEN')
        if not api_token:
            raise ValueError("H1_API_TOKEN not found in environment. Please set it in .env file")

        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_token}'
        })
        self.api_url = "https://hackerone.com/graphql"
        self.init_database()

    def init_database(self):
        """Create database schema"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Programs table
        c.execute('''CREATE TABLE IF NOT EXISTS programs (
            id TEXT PRIMARY KEY,
            handle TEXT UNIQUE NOT NULL,
            name TEXT,
            url TEXT,
            state TEXT,
            submission_state TEXT,
            triage_active BOOLEAN,
            publicly_launched_at TEXT,
            created_at TEXT,
            updated_at TEXT,

            -- Offerings
            offers_bounties BOOLEAN,
            offers_swag BOOLEAN,
            currency TEXT,
            min_bounty INTEGER,
            max_bounty INTEGER,
            average_bounty INTEGER,

            -- Stats
            resolved_report_count INTEGER,
            reports_resolved_count INTEGER,
            average_time_to_bounty_awarded TEXT,
            average_time_to_first_program_response TEXT,
            average_time_to_resolution TEXT,

            -- Program details
            policy TEXT,
            policy_html TEXT,

            -- Metadata
            allows_disclosure BOOLEAN,
            managed_program BOOLEAN,

            scraped_at TEXT
        )''')

        # Scopes table (in-scope assets)
        c.execute('''CREATE TABLE IF NOT EXISTS scopes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id TEXT,
            asset_type TEXT,
            asset_identifier TEXT,
            eligible_for_bounty BOOLEAN,
            eligible_for_submission BOOLEAN,
            instruction TEXT,
            max_severity TEXT,
            created_at TEXT,

            FOREIGN KEY (program_id) REFERENCES programs(id)
        )''')

        # Out of scope table
        c.execute('''CREATE TABLE IF NOT EXISTS out_of_scope (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id TEXT,
            asset_type TEXT,
            asset_identifier TEXT,
            description TEXT,

            FOREIGN KEY (program_id) REFERENCES programs(id)
        )''')

        # Severity table (bounty ranges)
        c.execute('''CREATE TABLE IF NOT EXISTS severity_bounties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id TEXT,
            severity TEXT,
            min_bounty INTEGER,
            max_bounty INTEGER,

            FOREIGN KEY (program_id) REFERENCES programs(id)
        )''')

        # Campaigns table (active bonuses)
        c.execute('''CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY,
            program_id TEXT,
            name TEXT,
            description TEXT,
            start_date TEXT,
            end_date TEXT,
            bonus_percentage FLOAT,

            FOREIGN KEY (program_id) REFERENCES programs(id)
        )''')

        # Disclosed reports table
        c.execute('''CREATE TABLE IF NOT EXISTS disclosed_reports (
            id TEXT PRIMARY KEY,
            program_id TEXT,
            title TEXT,
            vulnerability_information TEXT,
            severity_rating TEXT,
            state TEXT,
            disclosed_at TEXT,
            created_at TEXT,

            FOREIGN KEY (program_id) REFERENCES programs(id)
        )''')

        # Create indexes
        c.execute('CREATE INDEX IF NOT EXISTS idx_program_handle ON programs(handle)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_scope_program ON scopes(program_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_oos_program ON out_of_scope(program_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_disclosed_program ON disclosed_reports(program_id)')

        conn.commit()
        conn.close()
        print(f"✓ Database initialized: {self.db_path}")

    def graphql_query(self, query, variables=None):
        """Execute GraphQL query against HackerOne"""
        try:
            response = self.session.post(
                self.api_url,
                json={'query': query, 'variables': variables or {}},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"✗ GraphQL error: {e}")
            return None

    def fetch_all_programs(self):
        """Fetch all active programs using HackerOne directory"""
        programs = []
        page = 1

        query = '''
        query DirectoryQuery($cursor: String, $where: FiltersTeamFilterInput) {
          teams(first: 100, after: $cursor, where: $where) {
            pageInfo {
              hasNextPage
              endCursor
            }
            edges {
              node {
                id
                handle
                name
                url
                state
                submissionState: submission_state
                triageActive: triage_active
                currency

                offers_bounties
                offers_swag

                resolved_report_count

                publicly_launched_at

                managed_program
              }
            }
          }
        }
        '''

        cursor = None
        while True:
            print(f"📥 Fetching page {page}...")

            variables = {
                'cursor': cursor,
                'where': {
                    '_and': [
                        {'submission_state': {'_eq': 'open'}},
                        {'state': {'_eq': 'public_mode'}}
                    ]
                }
            }

            result = self.graphql_query(query, variables)
            if not result or 'data' not in result:
                break

            edges = result['data']['teams']['edges']
            programs.extend([edge['node'] for edge in edges])

            page_info = result['data']['teams']['pageInfo']
            if not page_info['hasNextPage']:
                break

            cursor = page_info['endCursor']
            page += 1
            time.sleep(1)  # Rate limiting

        print(f"✓ Found {len(programs)} active programs")
        return programs

    def fetch_program_details(self, handle):
        """Fetch complete program details including scope, policy, etc."""
        query = '''
        query TeamQuery($handle: String!) {
          team(handle: $handle) {
            id
            handle
            name
            url
            state
            submission_state
            triage_active
            currency

            offers_bounties
            offers_swag

            resolved_report_count
            reports_resolved_count

            average_time_to_bounty_awarded
            average_time_to_first_program_response
            average_time_to_resolution

            publicly_launched_at
            created_at
            updated_at

            allows_disclosure
            managed_program

            policy
            policy_html

            structured_scopes(first: 100) {
              edges {
                node {
                  id
                  asset_type
                  asset_identifier
                  eligible_for_bounty
                  eligible_for_submission
                  instruction
                  max_severity
                  created_at
                }
              }
            }

            bounty_table {
              critical {
                min
                max
              }
              high {
                min
                max
              }
              medium {
                min
                max
              }
              low {
                min
                max
              }
              none {
                min
                max
              }
            }
          }
        }
        '''

        result = self.graphql_query(query, {'handle': handle})
        if result and 'data' in result and result['data']['team']:
            return result['data']['team']
        return None

    def fetch_disclosed_reports(self, handle, limit=50):
        """Fetch disclosed reports for duplicate detection"""
        query = '''
        query HacktivityQuery($handle: String!, $first: Int) {
          team(handle: $handle) {
            hacktivity_items(first: $first, type: "disclosed") {
              edges {
                node {
                  ... on HacktivityItemReport {
                    id
                    title
                    vulnerability_information
                    severity_rating
                    state
                    disclosed_at
                    created_at
                  }
                }
              }
            }
          }
        }
        '''

        result = self.graphql_query(query, {'handle': handle, 'first': limit})
        if result and 'data' in result and result['data']['team']:
            edges = result['data']['team']['hacktivity_items']['edges']
            return [edge['node'] for edge in edges]
        return []

    def save_program(self, program_data):
        """Save program and all related data to database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        program_id = program_data['id']

        # Insert program
        c.execute('''INSERT OR REPLACE INTO programs VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?,
            ?, ?,
            ?
        )''', (
            program_id,
            program_data['handle'],
            program_data.get('name'),
            program_data.get('url'),
            program_data.get('state'),
            program_data.get('submission_state'),
            program_data.get('triage_active'),
            program_data.get('publicly_launched_at'),
            program_data.get('created_at'),
            program_data.get('updated_at'),

            program_data.get('offers_bounties'),
            program_data.get('offers_swag'),
            program_data.get('currency'),
            None, None, None,  # Will calculate from bounty_table

            program_data.get('resolved_report_count'),
            program_data.get('reports_resolved_count'),
            program_data.get('average_time_to_bounty_awarded'),
            program_data.get('average_time_to_first_program_response'),
            program_data.get('average_time_to_resolution'),

            program_data.get('policy'),
            program_data.get('policy_html'),

            program_data.get('allows_disclosure'),
            program_data.get('managed_program'),

            datetime.now().isoformat()
        ))

        # Insert scopes
        if 'structured_scopes' in program_data:
            for edge in program_data['structured_scopes']['edges']:
                scope = edge['node']
                c.execute('''INSERT INTO scopes VALUES (
                    NULL, ?, ?, ?, ?, ?, ?, ?, ?
                )''', (
                    program_id,
                    scope.get('asset_type'),
                    scope.get('asset_identifier'),
                    scope.get('eligible_for_bounty'),
                    scope.get('eligible_for_submission'),
                    scope.get('instruction'),
                    scope.get('max_severity'),
                    scope.get('created_at')
                ))

        # Insert severity bounties
        if 'bounty_table' in program_data and program_data['bounty_table']:
            for severity, bounty in program_data['bounty_table'].items():
                if bounty:
                    c.execute('''INSERT INTO severity_bounties VALUES (
                        NULL, ?, ?, ?, ?
                    )''', (
                        program_id,
                        severity,
                        bounty.get('min'),
                        bounty.get('max')
                    ))

        conn.commit()
        conn.close()

    def save_disclosed_reports(self, program_id, reports):
        """Save disclosed reports for duplicate detection"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        for report in reports:
            c.execute('''INSERT OR REPLACE INTO disclosed_reports VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?
            )''', (
                report['id'],
                program_id,
                report.get('title'),
                report.get('vulnerability_information'),
                report.get('severity_rating'),
                report.get('state'),
                report.get('disclosed_at'),
                report.get('created_at')
            ))

        conn.commit()
        conn.close()

    def scrape_all(self):
        """Main scraping function"""
        print("🚀 Starting HackerOne program scraper...")
        print("=" * 70)

        # Fetch all programs
        programs = self.fetch_all_programs()

        # Fetch details for each program
        for i, program in enumerate(programs, 1):
            handle = program['handle']
            print(f"\n[{i}/{len(programs)}] Processing: {handle}")

            # Fetch full details
            details = self.fetch_program_details(handle)
            if details:
                self.save_program(details)
                print(f"  ✓ Saved program details")

                # Fetch disclosed reports
                disclosed = self.fetch_disclosed_reports(handle)
                if disclosed:
                    self.save_disclosed_reports(details['id'], disclosed)
                    print(f"  ✓ Saved {len(disclosed)} disclosed reports")
            else:
                print(f"  ✗ Failed to fetch details")

            # Rate limiting
            time.sleep(2)

        print("\n" + "=" * 70)
        print("✓ Scraping complete!")
        self.print_stats()

    def print_stats(self):
        """Print database statistics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM programs")
        program_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM scopes")
        scope_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM disclosed_reports")
        report_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM programs WHERE offers_bounties = 1")
        bounty_count = c.fetchone()[0]

        conn.close()

        print(f"\n📊 Database Statistics:")
        print(f"  Programs: {program_count}")
        print(f"  Bounty Programs: {bounty_count}")
        print(f"  In-Scope Assets: {scope_count}")
        print(f"  Disclosed Reports: {report_count}")
        print(f"\n📁 Database: {self.db_path}")
        print(f"  Size: {Path(self.db_path).stat().st_size / 1024 / 1024:.2f} MB")

if __name__ == "__main__":
    scraper = H1ProgramScraper("C:/Users/vaugh/Projects/bountyhound-agent/data/h1-programs.db")
    scraper.scrape_all()
