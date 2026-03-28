"""
Automatic Payload Learning System

Analyzes successful payloads in the database and provides intelligent recommendations
for new targets based on vulnerability type, tech stack, and historical success rates.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import json
from datetime import datetime, date, timedelta
from typing import List, Dict, Optional, Tuple
from collections import defaultdict, Counter
from colorama import Fore, Style
from engine.core.database import BountyHoundDB



class PayloadLearner:
    """Learn patterns from successful payloads in the database."""

    def __init__(self):
        """Initialize payload learner."""
        self.db = BountyHoundDB()
        self.payloads = []
        self.patterns = defaultdict(list)  # vuln_type -> payloads
        self.tech_patterns = defaultdict(lambda: defaultdict(list))  # tech_stack -> vuln_type -> payloads

    def load_payloads(self):
        """Load all successful payloads from database."""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, vuln_type, payload, context, tech_stack, success_count, last_used, notes
                FROM successful_payloads
                ORDER BY success_count DESC
            """)

            self.payloads = [dict(row) for row in cursor.fetchall()]

        # Organize by pattern
        for payload_record in self.payloads:
            vuln_type = payload_record['vuln_type']
            tech_stack = payload_record.get('tech_stack') or 'generic'

            self.patterns[vuln_type].append(payload_record)
            self.tech_patterns[tech_stack][vuln_type].append(payload_record)

    def get_success_rate(self, vuln_type: str, tech_stack: Optional[str] = None) -> float:
        """
        Calculate success rate for a vulnerability type.

        Args:
            vuln_type: Vulnerability type (XSS, SQLi, etc.)
            tech_stack: Optional tech stack to narrow search

        Returns:
            Success rate as percentage (0-100)
        """
        if tech_stack:
            payloads = self.tech_patterns.get(tech_stack, {}).get(vuln_type, [])
        else:
            payloads = self.patterns.get(vuln_type, [])

        if not payloads:
            return 0.0

        total_successes = sum(p['success_count'] for p in payloads)
        total_attempts = len(payloads) * 5  # Estimate: ~5 attempts per payload

        return (total_successes / total_attempts * 100) if total_attempts > 0 else 0.0

    def get_top_payloads_by_type(self, vuln_type: str, limit: int = 5) -> List[Dict]:
        """Get top payloads for a vulnerability type."""
        payloads = self.patterns.get(vuln_type, [])
        return sorted(payloads, key=lambda p: p['success_count'], reverse=True)[:limit]

    def get_payloads_for_stack(self, tech_stack: str, vuln_type: Optional[str] = None,
                              limit: int = 5) -> List[Dict]:
        """Get top payloads for a specific tech stack."""
        if vuln_type:
            payloads = self.tech_patterns.get(tech_stack, {}).get(vuln_type, [])
        else:
            # Get all payloads for this tech stack
            payloads = []
            for vuln_payloads in self.tech_patterns.get(tech_stack, {}).values():
                payloads.extend(vuln_payloads)

        return sorted(payloads, key=lambda p: p['success_count'], reverse=True)[:limit]

    def get_trending_payloads(self, days: int = 30, limit: int = 10) -> List[Dict]:
        """Get recently successful payloads."""
        cutoff_date = date.today() - timedelta(days=days)

        recent = []
        for payload in self.payloads:
            last_used = payload.get('last_used')
            if last_used:
                last_used_date = datetime.strptime(last_used, '%Y-%m-%d').date()
                if last_used_date >= cutoff_date:
                    recent.append(payload)

        return sorted(recent, key=lambda p: p['success_count'], reverse=True)[:limit]

    def analyze_vuln_type_stats(self) -> Dict[str, Dict]:
        """Get statistics for each vulnerability type."""
        stats = {}

        for vuln_type, payloads in self.patterns.items():
            if not payloads:
                continue

            total_success = sum(p['success_count'] for p in payloads)
            avg_success = total_success / len(payloads) if payloads else 0

            stats[vuln_type] = {
                'payload_count': len(payloads),
                'total_successes': total_success,
                'avg_success_per_payload': round(avg_success, 2),
                'success_rate': round(self.get_success_rate(vuln_type), 1),
                'most_successful': payloads[0] if payloads else None
            }

        return stats

    def print_summary(self):
        """Print payload learning summary."""
        print(f"\n{Fore.CYAN}=== PAYLOAD LEARNING ANALYSIS ==={Style.RESET_ALL}")
        print(f"Total payloads: {len(self.payloads)}")
        print(f"Vulnerability types: {len(self.patterns)}")

        stats = self.analyze_vuln_type_stats()

        if stats:
            print(f"\n{Fore.YELLOW}By Vulnerability Type:{Style.RESET_ALL}")
            for vuln_type, data in sorted(stats.items(), key=lambda x: x[1]['success_rate'], reverse=True):
                success_rate = data['success_rate']
                color = Fore.GREEN if success_rate >= 50 else Fore.YELLOW if success_rate >= 25 else Fore.RED
                print(f"  {color}{vuln_type:15} {data['payload_count']:3} payloads | "
                      f"{success_rate:5.1f}% success | "
                      f"{data['total_successes']:4} total wins{Style.RESET_ALL}")


class PayloadScorer:
    """Score payloads by expected success for a given target."""

    def __init__(self, learner: PayloadLearner):
        """
        Initialize scorer.

        Args:
            learner: PayloadLearner instance with loaded payloads
        """
        self.learner = learner
        self.weights = {
            'type_match': 0.4,      # Vulnerability type match
            'stack_match': 0.3,     # Tech stack match
            'success_count': 0.2,   # Historical success
            'recency': 0.1          # Recently used
        }

    def score_payload(self, payload: Dict, vuln_type: str, tech_stack: Optional[str] = None,
                     days_old: Optional[int] = None) -> float:
        """
        Score a single payload.

        Args:
            payload: Payload record from database
            vuln_type: Target vulnerability type
            tech_stack: Target tech stack
            days_old: Age of payload in days (for recency)

        Returns:
            Score from 0-100
        """
        score = 0.0

        # Type match (40%)
        if payload['vuln_type'].lower() == vuln_type.lower():
            score += 40
        else:
            # No score for mismatched type (this payload shouldn't be ranked high)
            return 0.0

        # Stack match (30%)
        if tech_stack and payload.get('tech_stack'):
            payload_stack = payload['tech_stack'].lower()
            target_stack = tech_stack.lower()

            if payload_stack == target_stack:
                score += 30
            elif target_stack in payload_stack or payload_stack in target_stack:
                score += 15  # Partial match (e.g., "React" in "React+Node")
        elif not tech_stack:
            # If no target tech stack, "generic" gets partial points
            if payload.get('tech_stack', '').lower() == 'generic':
                score += 15

        # Success count (20%)
        # Normalize success count to 0-20
        max_success = 100
        success_ratio = min(payload['success_count'] / max_success, 1.0)
        score += success_ratio * 20

        # Recency (10%)
        if days_old is not None:
            if days_old <= 7:
                score += 10
            elif days_old <= 30:
                score += 5
            # else: 0 points for old payloads

        return score

    def rank_payloads(self, vuln_type: str, tech_stack: Optional[str] = None,
                     limit: int = 10) -> List[Tuple[Dict, float]]:
        """
        Rank payloads by score for a target.

        Args:
            vuln_type: Target vulnerability type
            tech_stack: Target tech stack (optional)
            limit: Number of payloads to return

        Returns:
            List of (payload, score) tuples sorted by score descending
        """
        scored = []

        for payload in self.learner.payloads:
            # Calculate days old
            last_used = payload.get('last_used')
            if last_used:
                last_used_date = datetime.strptime(last_used, '%Y-%m-%d').date()
                days_old = (date.today() - last_used_date).days
            else:
                days_old = 999

            score = self.score_payload(payload, vuln_type, tech_stack, days_old)
            if score > 0:  # Only include payloads with positive scores
                scored.append((payload, score))

        # Sort by score descending
        scored.sort(key=lambda x: x[1], reverse=True)

        return scored[:limit]


class PayloadRecommender:
    """Recommend payloads for a target based on its characteristics."""

    def __init__(self, db: Optional[BountyHoundDB] = None):
        """
        Initialize recommender.

        Args:
            db: BountyHoundDB instance (optional, creates new if not provided)
        """
        self.db = db or BountyHoundDB()
        self.learner = PayloadLearner()
        self.scorer = PayloadScorer(self.learner)

        # Load payloads
        self.learner.load_payloads()

    def get_target_tech_stack(self, domain: str) -> Optional[str]:
        """Get detected tech stack for a target."""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            target_id = None

            cursor.execute("SELECT id FROM targets WHERE domain = ?", (domain,))
            row = cursor.fetchone()
            if row:
                target_id = row['id']

            if target_id:
                cursor.execute("""
                    SELECT data_value FROM recon_data
                    WHERE target_id = ? AND data_type = 'tech_stack'
                    LIMIT 1
                """, (target_id,))
                row = cursor.fetchone()
                if row:
                    return row['data_value']

        return None

    def get_recommendations(self, domain: str, vuln_type: str, limit: int = 5) -> List[Dict]:
        """
        Get payload recommendations for a target.

        Args:
            domain: Target domain
            vuln_type: Vulnerability type to test
            limit: Number of payloads to recommend

        Returns:
            List of recommended payloads with scores and metadata
        """
        # Get tech stack if available
        tech_stack = self.get_target_tech_stack(domain)

        # Rank payloads
        ranked = self.scorer.rank_payloads(vuln_type, tech_stack, limit)

        recommendations = []
        for payload, score in ranked:
            recommendations.append({
                'payload': payload['payload'],
                'vuln_type': payload['vuln_type'],
                'tech_stack': payload.get('tech_stack'),
                'context': payload.get('context'),
                'score': round(score, 1),
                'success_count': payload['success_count'],
                'notes': payload.get('notes')
            })

        return recommendations

    def record_payload_usage(self, payload_id: int, successful: bool = True):
        """Record that a payload was used."""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            if successful:
                # Increment success count
                cursor.execute("""
                    UPDATE successful_payloads
                    SET success_count = success_count + 1,
                        last_used = ?
                    WHERE id = ?
                """, (date.today().isoformat(), payload_id))

    def print_recommendations(self, domain: str, vuln_type: str, limit: int = 5):
        """Print formatted recommendations."""
        recommendations = self.get_recommendations(domain, vuln_type, limit)

        if not recommendations:
            print(f"{Fore.YELLOW}No payloads found for {vuln_type}{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}[+] Top {min(len(recommendations), limit)} payloads for {vuln_type}:{Style.RESET_ALL}")

        for i, rec in enumerate(recommendations, 1):
            score_color = Fore.GREEN if rec['score'] >= 70 else Fore.YELLOW if rec['score'] >= 50 else Fore.RED
            print(f"\n  {score_color}{i}. Score: {rec['score']}/100{Style.RESET_ALL}")
            print(f"     Payload: {rec['payload'][:80]}{'...' if len(rec['payload']) > 80 else ''}")
            print(f"     Success Count: {rec['success_count']}")
            if rec['tech_stack']:
                print(f"     Tech Stack: {rec['tech_stack']}")
            if rec['context']:
                print(f"     Context: {rec['context']}")
            if rec['notes']:
                print(f"     Notes: {rec['notes']}")


def main():
    """CLI interface for payload learning."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python payload_learner.py <command> [args...]")
        print("\nCommands:")
        print("  analyze              Show payload learning analysis")
        print("  recommend <domain> <vuln_type>  Get recommendations")
        print("  stats                Show vulnerability type statistics")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'analyze':
        learner = PayloadLearner()
        learner.load_payloads()
        learner.print_summary()

    elif command == 'recommend' and len(sys.argv) >= 4:
        domain = sys.argv[2]
        vuln_type = sys.argv[3]
        limit = int(sys.argv[4]) if len(sys.argv) > 4 else 5

        recommender = PayloadRecommender()
        recommender.print_recommendations(domain, vuln_type, limit)

    elif command == 'stats':
        learner = PayloadLearner()
        learner.load_payloads()
        stats = learner.analyze_vuln_type_stats()

        print(f"\n{Fore.CYAN}=== VULNERABILITY TYPE STATISTICS ==={Style.RESET_ALL}")
        for vuln_type, data in sorted(stats.items(), key=lambda x: x[1]['success_rate'], reverse=True):
            print(f"\n{Fore.YELLOW}{vuln_type}{Style.RESET_ALL}")
            print(f"  Payloads: {data['payload_count']}")
            print(f"  Total Successes: {data['total_successes']}")
            print(f"  Avg per Payload: {data['avg_success_per_payload']}")
            print(f"  Success Rate: {data['success_rate']}%")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == '__main__':
    main()
