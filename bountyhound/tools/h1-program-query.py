#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HackerOne Program Query Tool
Query and analyze the H1 programs database
"""

import sys
import os
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import sqlite3
from datetime import datetime
from tabulate import tabulate

class H1ProgramQuery:
    def __init__(self, db_path="C:/Users/vaugh/Projects/bountyhound-agent/data/h1-programs.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row

    def __del__(self):
        if hasattr(self, 'conn'):
            self.conn.close()

    def search_programs(self, keyword=None, offers_bounty=None, min_bounty=None):
        """Search programs by keyword"""
        query = "SELECT * FROM programs WHERE 1=1"
        params = []

        if keyword:
            query += " AND (handle LIKE ? OR name LIKE ? OR policy LIKE ?)"
            params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])

        if offers_bounty is not None:
            query += " AND offers_bounties = ?"
            params.append(1 if offers_bounty else 0)

        if min_bounty:
            query += " AND min_bounty >= ?"
            params.append(min_bounty)

        query += " ORDER BY resolved_report_count DESC"

        cursor = self.conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_program_scope(self, handle):
        """Get all in-scope assets for a program"""
        query = '''
        SELECT s.* FROM scopes s
        JOIN programs p ON s.program_id = p.id
        WHERE p.handle = ?
        ORDER BY s.eligible_for_bounty DESC, s.asset_type
        '''
        cursor = self.conn.execute(query, (handle,))
        return [dict(row) for row in cursor.fetchall()]

    def get_program_out_of_scope(self, handle):
        """Get out-of-scope items for a program"""
        query = '''
        SELECT o.* FROM out_of_scope o
        JOIN programs p ON o.program_id = p.id
        WHERE p.handle = ?
        '''
        cursor = self.conn.execute(query, (handle,))
        return [dict(row) for row in cursor.fetchall()]

    def get_program_bounties(self, handle):
        """Get bounty ranges by severity"""
        query = '''
        SELECT sb.* FROM severity_bounties sb
        JOIN programs p ON sb.program_id = p.id
        WHERE p.handle = ?
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
        '''
        cursor = self.conn.execute(query, (handle,))
        return [dict(row) for row in cursor.fetchall()]

    def get_disclosed_reports(self, handle, limit=50):
        """Get disclosed reports for a program"""
        query = '''
        SELECT dr.* FROM disclosed_reports dr
        JOIN programs p ON dr.program_id = p.id
        WHERE p.handle = ?
        ORDER BY dr.disclosed_at DESC
        LIMIT ?
        '''
        cursor = self.conn.execute(query, (handle, limit))
        return [dict(row) for row in cursor.fetchall()]

    def check_duplicate(self, title, vulnerability_info):
        """Check if a vulnerability might be a duplicate"""
        query = '''
        SELECT
            p.handle,
            dr.title,
            dr.severity_rating,
            dr.disclosed_at,
            -- Simple similarity score
            (
                CASE WHEN dr.title LIKE ? THEN 50 ELSE 0 END +
                CASE WHEN dr.vulnerability_information LIKE ? THEN 50 ELSE 0 END
            ) as similarity_score
        FROM disclosed_reports dr
        JOIN programs p ON dr.program_id = p.id
        WHERE similarity_score > 50
        ORDER BY similarity_score DESC, dr.disclosed_at DESC
        LIMIT 10
        '''

        cursor = self.conn.execute(query, (f"%{title}%", f"%{vulnerability_info}%"))
        return [dict(row) for row in cursor.fetchall()]

    def get_top_programs(self, limit=20, sort_by='resolved_report_count'):
        """Get top programs by various metrics"""
        query = f'''
        SELECT
            handle,
            name,
            offers_bounties,
            currency,
            resolved_report_count,
            average_time_to_bounty_awarded,
            average_time_to_first_program_response
        FROM programs
        WHERE state = 'public_mode'
            AND submission_state = 'open'
        ORDER BY {sort_by} DESC
        LIMIT ?
        '''
        cursor = self.conn.execute(query, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def find_by_technology(self, tech):
        """Find programs using specific technology (from scopes)"""
        query = '''
        SELECT DISTINCT
            p.handle,
            p.name,
            p.offers_bounties,
            COUNT(s.id) as scope_count
        FROM programs p
        JOIN scopes s ON p.id = s.program_id
        WHERE s.asset_identifier LIKE ?
           OR s.instruction LIKE ?
           OR p.policy LIKE ?
        GROUP BY p.id
        ORDER BY scope_count DESC
        '''
        pattern = f"%{tech}%"
        cursor = self.conn.execute(query, (pattern, pattern, pattern))
        return [dict(row) for row in cursor.fetchall()]

    def get_stats(self):
        """Get database statistics"""
        stats = {}

        cursor = self.conn.execute("SELECT COUNT(*) FROM programs")
        stats['total_programs'] = cursor.fetchone()[0]

        cursor = self.conn.execute("SELECT COUNT(*) FROM programs WHERE offers_bounties = 1")
        stats['bounty_programs'] = cursor.fetchone()[0]

        cursor = self.conn.execute("SELECT COUNT(*) FROM scopes")
        stats['total_scopes'] = cursor.fetchone()[0]

        cursor = self.conn.execute("SELECT COUNT(*) FROM disclosed_reports")
        stats['disclosed_reports'] = cursor.fetchone()[0]

        cursor = self.conn.execute("SELECT AVG(resolved_report_count) FROM programs WHERE resolved_report_count > 0")
        avg_val = cursor.fetchone()[0]
        stats['avg_reports_per_program'] = avg_val if avg_val is not None else 0.0

        return stats

    def export_program_full(self, handle, output_file=None):
        """Export complete program details"""
        # Get program
        cursor = self.conn.execute("SELECT * FROM programs WHERE handle = ?", (handle,))
        program = dict(cursor.fetchone())

        # Get scopes
        scopes = self.get_program_scope(handle)

        # Get bounties
        bounties = self.get_program_bounties(handle)

        # Get disclosed reports
        disclosed = self.get_disclosed_reports(handle, limit=100)

        data = {
            'program': program,
            'scopes': scopes,
            'bounties': bounties,
            'disclosed_reports': disclosed
        }

        if output_file:
            import json
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"✓ Exported to {output_file}")

        return data

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python h1-program-query.py search <keyword>")
        print("  python h1-program-query.py scope <handle>")
        print("  python h1-program-query.py bounties <handle>")
        print("  python h1-program-query.py disclosed <handle>")
        print("  python h1-program-query.py duplicate <title>")
        print("  python h1-program-query.py top [limit]")
        print("  python h1-program-query.py tech <technology>")
        print("  python h1-program-query.py export <handle> [output.json]")
        print("  python h1-program-query.py stats")
        return

    query = H1ProgramQuery()
    command = sys.argv[1]

    if command == "search":
        keyword = sys.argv[2] if len(sys.argv) > 2 else None
        results = query.search_programs(keyword)

        if results:
            table = [[
                r['handle'],
                r['name'][:40] if r['name'] else '',
                '✓' if r['offers_bounties'] else '✗',
                r['currency'] or '',
                r['resolved_report_count'] or 0
            ] for r in results]

            print(tabulate(table,
                headers=['Handle', 'Name', 'Bounty', 'Currency', 'Reports'],
                tablefmt='grid'))
        else:
            print("No programs found")

    elif command == "scope":
        handle = sys.argv[2]
        scopes = query.get_program_scope(handle)

        if scopes:
            table = [[
                s['asset_type'],
                s['asset_identifier'][:50],
                '✓' if s['eligible_for_bounty'] else '✗',
                s['max_severity'] or ''
            ] for s in scopes]

            print(f"\n{handle} - In Scope Assets:\n")
            print(tabulate(table,
                headers=['Type', 'Asset', 'Bounty', 'Max Severity'],
                tablefmt='grid'))
        else:
            print("No scopes found")

    elif command == "bounties":
        handle = sys.argv[2]
        bounties = query.get_program_bounties(handle)

        if bounties:
            table = [[
                b['severity'].upper(),
                f"${b['min_bounty']:,}" if b['min_bounty'] else 'N/A',
                f"${b['max_bounty']:,}" if b['max_bounty'] else 'N/A'
            ] for b in bounties]

            print(f"\n{handle} - Bounty Ranges:\n")
            print(tabulate(table,
                headers=['Severity', 'Min', 'Max'],
                tablefmt='grid'))
        else:
            print("No bounty information found")

    elif command == "disclosed":
        handle = sys.argv[2]
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 50
        reports = query.get_disclosed_reports(handle, limit)

        if reports:
            table = [[
                r['title'][:60],
                r['severity_rating'] or '',
                r['disclosed_at'][:10] if r['disclosed_at'] else ''
            ] for r in reports]

            print(f"\n{handle} - Disclosed Reports (last {limit}):\n")
            print(tabulate(table,
                headers=['Title', 'Severity', 'Disclosed'],
                tablefmt='grid'))
        else:
            print("No disclosed reports found")

    elif command == "duplicate":
        title = " ".join(sys.argv[2:])
        results = query.check_duplicate(title, title)

        if results:
            table = [[
                r['handle'],
                r['title'][:50],
                r['severity_rating'] or '',
                r['similarity_score']
            ] for r in results]

            print(f"\nPotential Duplicates for: '{title}'\n")
            print(tabulate(table,
                headers=['Program', 'Title', 'Severity', 'Score'],
                tablefmt='grid'))
        else:
            print("No potential duplicates found")

    elif command == "top":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        results = query.get_top_programs(limit)

        table = [[
            r['handle'],
            r['name'][:40] if r['name'] else '',
            '✓' if r['offers_bounties'] else '✗',
            r['resolved_report_count'] or 0
        ] for r in results]

        print(f"\nTop {limit} Programs:\n")
        print(tabulate(table,
            headers=['Handle', 'Name', 'Bounty', 'Reports'],
            tablefmt='grid'))

    elif command == "tech":
        tech = sys.argv[2]
        results = query.find_by_technology(tech)

        if results:
            table = [[
                r['handle'],
                r['name'][:40] if r['name'] else '',
                '✓' if r['offers_bounties'] else '✗',
                r['scope_count']
            ] for r in results]

            print(f"\nPrograms using '{tech}':\n")
            print(tabulate(table,
                headers=['Handle', 'Name', 'Bounty', 'Scopes'],
                tablefmt='grid'))
        else:
            print(f"No programs found using '{tech}'")

    elif command == "export":
        handle = sys.argv[2]
        output = sys.argv[3] if len(sys.argv) > 3 else f"{handle}-export.json"
        query.export_program_full(handle, output)

    elif command == "stats":
        stats = query.get_stats()
        print("\n📊 Database Statistics:\n")
        print(f"  Total Programs: {stats['total_programs']:,}")
        print(f"  Bounty Programs: {stats['bounty_programs']:,}")
        print(f"  Total Scopes: {stats['total_scopes']:,}")
        print(f"  Disclosed Reports: {stats['disclosed_reports']:,}")
        print(f"  Avg Reports/Program: {stats['avg_reports_per_program']:.1f}")

if __name__ == "__main__":
    main()
