"""
Database Hooks for Automatic Testing Context

Provides automatic database checks before any testing action to prevent
duplicate work and enable data-driven decisions.
"""

from datetime import datetime, date
from typing import Dict, List, Any, Optional
from engine.core.database import BountyHoundDB
from engine.core.semantic_dedup import SemanticDuplicateDetector
from engine.core.h1_disclosed_checker import H1DisclosedChecker


class DatabaseHooks:
    """Automatic database checks before testing."""

    @staticmethod
    def before_test(target: str, tool: str, db: Optional[BountyHoundDB] = None) -> Dict[str, Any]:
        """
        Called before any test. Returns context from database.

        Args:
            target: Domain or target identifier
            tool: Tool name (s3_enumerator, apk_analyzer, etc.)
            db: Optional database instance (for testing)

        Returns:
            dict with:
              - should_skip: bool - whether to skip this test
              - reason: str - explanation
              - previous_findings: list - past findings from this target
              - recommendations: list - suggested actions
              - last_tested_days: int - days since last test (or None)
        """
        if db is None:
            db = BountyHoundDB.get_instance()

        # Get target info
        target_info = db.get_target_stats(target)

        if not target_info:
            return {
                'should_skip': False,
                'reason': 'Never tested before',
                'previous_findings': [],
                'recommendations': ['Full test recommended', 'New target - explore thoroughly'],
                'last_tested_days': None
            }

        # Check recent testing
        last_tested = target_info['last_tested']
        days_since_test = (date.today() - last_tested).days

        # Get recent findings
        recent_findings = db.get_recent_findings(target, limit=5)

        # Decision logic based on recency
        if days_since_test < 7:
            return {
                'should_skip': True,
                'reason': f'Tested {days_since_test} day(s) ago (too recent)',
                'previous_findings': recent_findings,
                'recommendations': [
                    'Skip this target',
                    'Focus on targets not tested recently',
                    f'Last test found {target_info["total_findings"]} issues'
                ],
                'last_tested_days': days_since_test,
                'target_stats': target_info
            }

        # Check tool-specific history
        last_tool_run = db.get_last_tool_run(target, tool)

        if last_tool_run:
            tool_days = (date.today() - last_tool_run['run_date']).days

            if tool_days < 14:
                return {
                    'should_skip': True,
                    'reason': f'{tool} was run {tool_days} day(s) ago (too recent)',
                    'previous_findings': db.get_findings_by_tool(target, tool),
                    'recommendations': [
                        f'Skip {tool} for this target',
                        f'Last run found {last_tool_run["findings_count"]} findings',
                        'Try a different tool or target'
                    ],
                    'last_tested_days': days_since_test,
                    'last_tool_run': last_tool_run
                }

        # Determine recommendation based on time elapsed
        if days_since_test >= 30:
            recommendation = 'Full retest recommended'
            reason_detail = 'sufficient time elapsed'
        else:
            recommendation = 'Selective retest recommended'
            reason_detail = 'moderate time elapsed'

        return {
            'should_skip': False,
            'reason': f'Last tested {days_since_test} day(s) ago ({reason_detail})',
            'previous_findings': recent_findings,
            'recommendations': [
                recommendation,
                f'Previously found {target_info["total_findings"]} issues',
                f'ROI: ${target_info["total_payouts"]:.2f} from {target_info["accepted_findings"]} accepted'
            ],
            'last_tested_days': days_since_test,
            'target_stats': target_info,
            'last_tool_run': last_tool_run
        }

    @staticmethod
    def check_duplicate(target: str, vuln_type: str, keywords: List[str],
                       title: str = "", description: str = "",
                       program: str = "",
                       semantic_threshold: float = 0.75,
                       db: Optional[BountyHoundDB] = None) -> Dict[str, Any]:
        """
        Check if a similar finding already exists using keyword, semantic, and H1 disclosed report matching.

        Args:
            target: Domain
            vuln_type: Vulnerability type (IDOR, XSS, etc.)
            keywords: Keywords to search for
            title: Finding title (optional, for semantic matching)
            description: Finding description (optional, for semantic matching)
            program: HackerOne program handle (optional, e.g., "shopify", "github")
            semantic_threshold: Minimum similarity score for semantic duplicates (0.0-1.0)
            db: Optional database instance (for testing)

        Returns:
            dict with:
              - is_duplicate: bool
              - match_type: str - 'keyword', 'semantic', 'disclosed_report', or None
              - matches: list - matching findings (sorted by relevance)
              - recommendation: str
        """
        if db is None:
            db = BountyHoundDB.get_instance()

        # 1. Original keyword-based check
        keyword_match = db.find_similar_findings(target, vuln_type, keywords)

        if keyword_match:
            return {
                'is_duplicate': True,
                'match_type': 'keyword',
                'matches': [keyword_match],
                'recommendation': f'REJECT - keyword duplicate: {keyword_match["title"]} ({keyword_match["status"]})'
            }

        # 2. Semantic similarity check (if title/description provided)
        if title or description:
            detector = SemanticDuplicateDetector()
            new_finding = {"title": title, "description": description}

            # Get findings filtered by vuln_type at SQL level (avoids loading 100 then filtering)
            existing_same_type = db.get_recent_findings_by_type(target, vuln_type, limit=100)

            semantic_matches = detector.find_duplicates(
                new_finding,
                existing_same_type,
                threshold=semantic_threshold
            )

            if semantic_matches:
                top_match = semantic_matches[0]
                similarity_pct = top_match['similarity_score'] * 100

                return {
                    'is_duplicate': True,
                    'match_type': 'semantic',
                    'matches': semantic_matches,
                    'recommendation': (
                        f'REJECT - {similarity_pct:.0f}% similar to existing finding: '
                        f'{top_match["title"]} ({top_match.get("status", "unknown")})'
                    )
                }

        # 3. NEW: Check against HackerOne disclosed reports
        if program and (title or description):
            checker = H1DisclosedChecker()
            finding = {"title": title, "description": description}
            disclosed_check = checker.check_against_disclosed(finding, program, use_cache=True)

            if disclosed_check['is_duplicate']:
                return {
                    'is_duplicate': True,
                    'match_type': 'disclosed_report',
                    'matches': disclosed_check['matches'],
                    'recommendation': disclosed_check['recommendation']
                }

        return {
            'is_duplicate': False,
            'match_type': None,
            'matches': [],
            'recommendation': 'PROCEED - no duplicates found (keyword, semantic, or disclosed)'
        }

    @staticmethod
    def get_successful_payloads(vuln_type: str, tech_stack: Optional[str] = None,
                                 context: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get payloads that have worked in the past.

        Args:
            vuln_type: Type of vulnerability (XSS, SQLi, etc.)
            tech_stack: Optional tech stack filter (React, PHP, etc.)
            context: Optional context filter (parameter, header, etc.)
            limit: Maximum number of payloads to return

        Returns:
            List of successful payload dictionaries
        """
        db = BountyHoundDB.get_instance()

        with db._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT payload, context, tech_stack, success_count, last_used, notes
                FROM successful_payloads
                WHERE vuln_type = ?
            """
            params = [vuln_type]

            if tech_stack:
                query += " AND tech_stack = ?"
                params.append(tech_stack)

            if context:
                query += " AND context = ?"
                params.append(context)

            query += " ORDER BY success_count DESC, last_used DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
