"""
BountyHound Cross-Hunt Analytics

Generates reports and insights from the BountyHound database to guide
target selection and technique optimization.

Usage:
    from engine.core.database import BountyHoundDB
    from engine.core.analytics import HuntAnalytics, DashboardReport

    db = BountyHoundDB()
    analytics = HuntAnalytics(db)

    # Get target ROI rankings
    roi = analytics.roi_by_target(limit=10)

    # Generate full dashboard
    report = DashboardReport(analytics)
    print(report.generate_text_report())
    data = report.generate_json_report()
"""

import json
import sqlite3
from datetime import datetime, date, timedelta
from typing import Optional, Dict, List, Any, Tuple
from engine.core.database import BountyHoundDB
from engine.core.config import BountyHoundConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DB_PATH = BountyHoundConfig.DB_PATH


def _safe_query(conn, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Execute a query and return rows as dicts, returning [] on any error."""
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    except (sqlite3.OperationalError, sqlite3.DatabaseError):
        # Table or column doesn't exist yet -- schema evolves over time
        return []


def _safe_scalar(conn, query: str, params: tuple = (), default=None):
    """Execute a query that returns a single scalar value."""
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        row = cursor.fetchone()
        if row is None:
            return default
        val = row[0] if not isinstance(row, dict) else list(row.values())[0]
        return val if val is not None else default
    except (sqlite3.OperationalError, sqlite3.DatabaseError):
        return default


def _fmt_currency(amount: float, currency: str = "USD") -> str:
    """Format a monetary amount."""
    if currency == "USD":
        return f"${amount:,.2f}"
    return f"{amount:,.2f} {currency}"


def _fmt_duration(minutes: float) -> str:
    """Format minutes into a human-readable string."""
    if minutes < 60:
        return f"{minutes:.0f}m"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f}h"
    days = hours / 24
    return f"{days:.1f}d"


def _pad(text: str, width: int, align: str = "left") -> str:
    """Pad text to a fixed width."""
    text = str(text)[:width]
    if align == "right":
        return text.rjust(width)
    if align == "center":
        return text.center(width)
    return text.ljust(width)


# ---------------------------------------------------------------------------
# HuntAnalytics
# ---------------------------------------------------------------------------

class HuntAnalytics:
    """Cross-hunt analytics engine backed by the BountyHound SQLite database."""

    def __init__(self, db: BountyHoundDB):
        self.db = db

    # -- private helpers ----------------------------------------------------

    def _query(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        with self.db._get_connection() as conn:
            return _safe_query(conn, query, params)

    def _scalar(self, query: str, params: tuple = (), default=None):
        with self.db._get_connection() as conn:
            return _safe_scalar(conn, query, params, default)

    # -- public analytics ---------------------------------------------------

    def roi_by_target(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Targets ranked by ROI (total payout / total time invested).

        Time invested is approximated from testing_sessions.duration_minutes.
        Falls back to automation_runs.duration_seconds if no sessions exist.

        Returns list of dicts:
            domain, total_payouts, total_hours, roi_per_hour,
            total_findings, accepted_findings, acceptance_rate
        """
        query = """
            WITH time_per_target AS (
                SELECT
                    t.id AS target_id,
                    COALESCE(
                        (SELECT SUM(ts.duration_minutes)
                         FROM testing_sessions ts WHERE ts.target_id = t.id),
                        (SELECT SUM(ar.duration_seconds) / 60.0
                         FROM automation_runs ar WHERE ar.target_id = t.id),
                        0
                    ) AS total_minutes
                FROM targets t
                WHERE t.total_payouts > 0 OR t.total_findings > 0
            )
            SELECT
                t.domain,
                t.total_payouts,
                t.total_findings,
                t.accepted_findings,
                ROUND(t.accepted_findings * 1.0 / NULLIF(t.total_findings, 0), 4) AS acceptance_rate,
                tpt.total_minutes
            FROM targets t
            JOIN time_per_target tpt ON tpt.target_id = t.id
            ORDER BY
                CASE WHEN tpt.total_minutes > 0
                     THEN t.total_payouts / tpt.total_minutes
                     ELSE t.total_payouts
                END DESC
            LIMIT ?
        """
        rows = self._query(query, (limit,))
        results = []
        for r in rows:
            total_hours = r["total_minutes"] / 60.0 if r["total_minutes"] else 0
            roi = r["total_payouts"] / total_hours if total_hours > 0 else None
            results.append({
                "domain": r["domain"],
                "total_payouts": r["total_payouts"],
                "total_hours": round(total_hours, 2),
                "roi_per_hour": round(roi, 2) if roi is not None else None,
                "total_findings": r["total_findings"],
                "accepted_findings": r["accepted_findings"],
                "acceptance_rate": round(r["acceptance_rate"] * 100, 1) if r["acceptance_rate"] else 0.0,
            })
        return results

    def roi_by_vuln_type(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Vulnerability types ranked by acceptance rate and average payout.

        Returns list of dicts:
            vuln_type, total, accepted, acceptance_rate, avg_payout,
            total_payout, max_payout
        """
        query = """
            SELECT
                f.vuln_type,
                COUNT(*) AS total,
                SUM(CASE WHEN f.status = 'accepted' THEN 1 ELSE 0 END) AS accepted,
                ROUND(
                    SUM(CASE WHEN f.status = 'accepted' THEN 1 ELSE 0 END) * 100.0
                    / COUNT(*), 1
                ) AS acceptance_rate,
                ROUND(AVG(CASE WHEN f.payout > 0 THEN f.payout END), 2) AS avg_payout,
                ROUND(SUM(f.payout), 2) AS total_payout,
                ROUND(MAX(f.payout), 2) AS max_payout
            FROM findings f
            GROUP BY f.vuln_type
            ORDER BY acceptance_rate DESC, avg_payout DESC
            LIMIT ?
        """
        return self._query(query, (limit,))

    def success_rate_by_tool(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Tools ranked by findings-per-run.

        Returns list of dicts:
            tool_name, total_runs, total_findings, findings_per_run,
            success_runs, success_rate
        """
        query = """
            SELECT
                ar.tool_name,
                COUNT(*) AS total_runs,
                SUM(ar.findings_count) AS total_findings,
                ROUND(SUM(ar.findings_count) * 1.0 / COUNT(*), 2) AS findings_per_run,
                SUM(CASE WHEN ar.success = 1 THEN 1 ELSE 0 END) AS success_runs,
                ROUND(
                    SUM(CASE WHEN ar.success = 1 THEN 1 ELSE 0 END) * 100.0
                    / COUNT(*), 1
                ) AS success_rate
            FROM automation_runs ar
            GROUP BY ar.tool_name
            ORDER BY findings_per_run DESC
            LIMIT ?
        """
        return self._query(query, (limit,))

    def time_to_triage(self, program: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Average days from discovered_date to status change (proxy for triage).

        Since the schema does not track triage_date explicitly, this computes
        the age of pending findings vs accepted findings as a proxy.

        If *program* is given, filter to that platform_handle.

        Returns list of dicts:
            program_name, platform, avg_days_pending, avg_days_accepted,
            pending_count, accepted_count
        """
        where = ""
        params: tuple = ()
        if program:
            where = "AND t.platform_handle = ?"
            params = (program,)

        query = f"""
            SELECT
                COALESCE(t.program_name, t.domain) AS program_name,
                t.platform,
                ROUND(AVG(
                    CASE WHEN f.status = 'pending'
                    THEN julianday('now') - julianday(f.discovered_date)
                    END
                ), 1) AS avg_days_pending,
                ROUND(AVG(
                    CASE WHEN f.status = 'accepted'
                    THEN julianday('now') - julianday(f.discovered_date)
                    END
                ), 1) AS avg_days_accepted,
                SUM(CASE WHEN f.status = 'pending' THEN 1 ELSE 0 END) AS pending_count,
                SUM(CASE WHEN f.status = 'accepted' THEN 1 ELSE 0 END) AS accepted_count
            FROM findings f
            JOIN targets t ON f.target_id = t.id
            WHERE 1=1 {where}
            GROUP BY t.id
            HAVING pending_count > 0 OR accepted_count > 0
            ORDER BY avg_days_pending DESC
        """
        return self._query(query, params)

    def monthly_earnings(self, months: int = 12) -> List[Dict[str, Any]]:
        """
        Monthly earnings over the past N months.

        Returns list of dicts:
            month (YYYY-MM), earnings, findings_count, accepted_count
        """
        cutoff = (date.today() - timedelta(days=months * 31)).isoformat()
        query = """
            SELECT
                strftime('%Y-%m', f.discovered_date) AS month,
                ROUND(SUM(f.payout), 2) AS earnings,
                COUNT(*) AS findings_count,
                SUM(CASE WHEN f.status = 'accepted' THEN 1 ELSE 0 END) AS accepted_count
            FROM findings f
            WHERE f.discovered_date >= ?
            GROUP BY month
            ORDER BY month ASC
        """
        return self._query(query, (cutoff,))

    def top_techniques(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Most successful payloads/techniques from the successful_payloads table.

        Returns list of dicts:
            vuln_type, payload (truncated), context, tech_stack,
            success_count, last_used
        """
        query = """
            SELECT
                sp.vuln_type,
                CASE WHEN LENGTH(sp.payload) > 80
                     THEN SUBSTR(sp.payload, 1, 77) || '...'
                     ELSE sp.payload
                END AS payload,
                sp.context,
                sp.tech_stack,
                sp.success_count,
                sp.last_used
            FROM successful_payloads sp
            ORDER BY sp.success_count DESC
            LIMIT ?
        """
        return self._query(query, (limit,))

    def target_recommendations(self) -> List[Dict[str, Any]]:
        """
        Suggest which targets to re-test based on:
          - Time since last test (stale targets get priority)
          - Past acceptance rate (high success targets get priority)
          - Payout history (high payout targets get priority)

        Returns list of dicts sorted by composite score:
            domain, last_tested, days_since_test, acceptance_rate,
            avg_payout, total_payouts, score, recommendation
        """
        query = """
            SELECT
                t.domain,
                t.last_tested,
                t.total_findings,
                t.accepted_findings,
                t.total_payouts,
                t.avg_payout,
                ROUND(t.accepted_findings * 1.0 / NULLIF(t.total_findings, 0), 4)
                    AS acceptance_rate,
                CAST(julianday('now') - julianday(COALESCE(t.last_tested, t.added_date))
                     AS INTEGER) AS days_since_test
            FROM targets t
            WHERE t.total_findings > 0
        """
        rows = self._query(query)
        if not rows:
            return []

        # Normalise scores to [0, 1] for each dimension
        max_days = max(r["days_since_test"] or 1 for r in rows) or 1
        max_payout = max(r["total_payouts"] or 0 for r in rows) or 1

        results = []
        for r in rows:
            days = r["days_since_test"] or 0
            acc_rate = r["acceptance_rate"] or 0
            payout_norm = (r["total_payouts"] or 0) / max_payout
            staleness = days / max_days

            # Weighted composite: staleness 40%, acceptance 35%, payout 25%
            score = round(staleness * 0.40 + acc_rate * 0.35 + payout_norm * 0.25, 4)

            if days >= 30:
                rec = "FULL RETEST - stale target, high priority"
            elif days >= 14:
                rec = "SELECTIVE RETEST - moderate staleness"
            elif days >= 7:
                rec = "LIGHT CHECK - recently tested"
            else:
                rec = "SKIP - tested within the last week"

            results.append({
                "domain": r["domain"],
                "last_tested": r["last_tested"],
                "days_since_test": days,
                "acceptance_rate": round(acc_rate * 100, 1),
                "avg_payout": r["avg_payout"] or 0,
                "total_payouts": r["total_payouts"] or 0,
                "score": score,
                "recommendation": rec,
            })

        results.sort(key=lambda x: x["score"], reverse=True)
        return results

    def hunt_efficiency(self, hunt_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Time spent per testing session and findings-per-hour.

        If *hunt_id* is given, return data for that session only.
        Otherwise return all sessions ordered by efficiency.

        Returns list of dicts:
            session_id, domain, start_time, duration_minutes,
            findings_count, findings_per_hour, tools_used
        """
        where = ""
        params: tuple = ()
        if hunt_id is not None:
            where = "AND ts.id = ?"
            params = (hunt_id,)

        query = f"""
            SELECT
                ts.id AS session_id,
                t.domain,
                ts.start_time,
                ts.duration_minutes,
                ts.findings_count,
                ROUND(
                    ts.findings_count * 60.0 / NULLIF(ts.duration_minutes, 0), 2
                ) AS findings_per_hour,
                ts.tools_used
            FROM testing_sessions ts
            JOIN targets t ON ts.target_id = t.id
            WHERE ts.duration_minutes > 0 {where}
            ORDER BY findings_per_hour DESC
        """
        return self._query(query, params)

    def payout_forecast(self, months: int = 3) -> Dict[str, Any]:
        """
        Simple linear projection of future earnings based on the last 6
        months of historical data.

        Returns dict:
            historical_monthly_avg, trend_direction, projected_months (list),
            projected_total, confidence_note
        """
        history = self.monthly_earnings(months=6)
        if not history:
            return {
                "historical_monthly_avg": 0,
                "trend_direction": "unknown",
                "projected_months": [],
                "projected_total": 0,
                "confidence_note": "No historical data available.",
            }

        amounts = [h["earnings"] or 0 for h in history]
        avg = sum(amounts) / len(amounts) if amounts else 0

        # Simple linear trend: compare first half vs second half
        mid = len(amounts) // 2 or 1
        first_half_avg = sum(amounts[:mid]) / mid if mid > 0 else 0
        second_half_avg = sum(amounts[mid:]) / (len(amounts) - mid) if (len(amounts) - mid) > 0 else 0

        if second_half_avg > first_half_avg * 1.1:
            trend = "increasing"
            growth = (second_half_avg - first_half_avg) / first_half_avg if first_half_avg > 0 else 0
        elif second_half_avg < first_half_avg * 0.9:
            trend = "decreasing"
            growth = (second_half_avg - first_half_avg) / first_half_avg if first_half_avg > 0 else 0
        else:
            trend = "stable"
            growth = 0

        # Project forward
        projected = []
        current = second_half_avg if second_half_avg > 0 else avg
        today = date.today()
        for i in range(1, months + 1):
            projected_month = today + timedelta(days=30 * i)
            month_label = projected_month.strftime("%Y-%m")
            projected_amount = round(current * (1 + growth), 2)
            current = projected_amount
            projected.append({
                "month": month_label,
                "projected_earnings": projected_amount,
            })

        return {
            "historical_monthly_avg": round(avg, 2),
            "trend_direction": trend,
            "projected_months": projected,
            "projected_total": round(sum(p["projected_earnings"] for p in projected), 2),
            "confidence_note": (
                "Based on simple linear extrapolation from the last 6 months. "
                "Actual results depend on target availability, program changes, "
                "and time invested."
            ),
        }

    # -- summary helpers used by DashboardReport ----------------------------

    def overview(self) -> Dict[str, Any]:
        """High-level summary stats."""
        total_earnings = self._scalar(
            "SELECT COALESCE(SUM(payout), 0) FROM findings WHERE status = 'accepted'",
            default=0,
        )
        total_findings = self._scalar(
            "SELECT COUNT(*) FROM findings", default=0
        )
        accepted_findings = self._scalar(
            "SELECT COUNT(*) FROM findings WHERE status = 'accepted'", default=0
        )
        pending_findings = self._scalar(
            "SELECT COUNT(*) FROM findings WHERE status = 'pending'", default=0
        )
        total_targets = self._scalar(
            "SELECT COUNT(*) FROM targets", default=0
        )
        active_targets = self._scalar(
            "SELECT COUNT(*) FROM targets WHERE last_tested >= date('now', '-30 days')",
            default=0,
        )
        total_sessions = self._scalar(
            "SELECT COUNT(*) FROM testing_sessions", default=0
        )
        total_hours = self._scalar(
            "SELECT COALESCE(SUM(duration_minutes), 0) / 60.0 FROM testing_sessions",
            default=0,
        )

        return {
            "total_earnings": round(total_earnings, 2),
            "total_findings": total_findings,
            "accepted_findings": accepted_findings,
            "pending_findings": pending_findings,
            "total_targets": total_targets,
            "active_targets": active_targets,
            "total_sessions": total_sessions,
            "total_hours": round(total_hours, 1),
            "overall_acceptance_rate": round(
                accepted_findings * 100.0 / total_findings, 1
            ) if total_findings else 0,
        }


# ---------------------------------------------------------------------------
# DashboardReport
# ---------------------------------------------------------------------------

class DashboardReport:
    """Generates formatted analytics reports from HuntAnalytics data."""

    def __init__(self, analytics: HuntAnalytics):
        self.analytics = analytics

    # -- text report --------------------------------------------------------

    def generate_text_report(self) -> str:
        """
        Generates a formatted text dashboard with ASCII tables.

        Sections:
            1. Overview
            2. Top Targets by ROI
            3. Top Vulnerability Types
            4. Tool Effectiveness
            5. Monthly Earnings Trend
            6. Payout Forecast
            7. Target Recommendations
        """
        sections: List[str] = []
        sep = "=" * 72

        # Header
        sections.append(sep)
        sections.append("  BOUNTYHOUND ANALYTICS DASHBOARD")
        sections.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        sections.append(sep)

        # 1. Overview
        ov = self.analytics.overview()
        sections.append("")
        sections.append("  OVERVIEW")
        sections.append("  " + "-" * 40)
        sections.append(f"  Total Earnings:       {_fmt_currency(ov['total_earnings'])}")
        sections.append(f"  Total Findings:       {ov['total_findings']}")
        sections.append(f"  Accepted:             {ov['accepted_findings']}")
        sections.append(f"  Pending:              {ov['pending_findings']}")
        sections.append(f"  Acceptance Rate:      {ov['overall_acceptance_rate']}%")
        sections.append(f"  Targets Tracked:      {ov['total_targets']}")
        sections.append(f"  Active (30d):         {ov['active_targets']}")
        sections.append(f"  Testing Sessions:     {ov['total_sessions']}")
        sections.append(f"  Total Hours:          {ov['total_hours']}h")

        # 2. Top Targets by ROI
        roi = self.analytics.roi_by_target(limit=10)
        if roi:
            sections.append("")
            sections.append("  TOP TARGETS BY ROI")
            sections.append("  " + "-" * 68)
            header = (
                f"  {_pad('Domain', 30)} "
                f"{_pad('Payouts', 12, 'right')} "
                f"{_pad('Hours', 8, 'right')} "
                f"{_pad('$/hr', 10, 'right')} "
                f"{_pad('Accept%', 8, 'right')}"
            )
            sections.append(header)
            sections.append("  " + "-" * 68)
            for r in roi:
                roi_str = _fmt_currency(r["roi_per_hour"]) if r["roi_per_hour"] is not None else "N/A"
                sections.append(
                    f"  {_pad(r['domain'], 30)} "
                    f"{_pad(_fmt_currency(r['total_payouts']), 12, 'right')} "
                    f"{_pad(str(r['total_hours']), 8, 'right')} "
                    f"{_pad(roi_str, 10, 'right')} "
                    f"{_pad(str(r['acceptance_rate']) + '%', 8, 'right')}"
                )

        # 3. Top Vulnerability Types
        vuln = self.analytics.roi_by_vuln_type(limit=10)
        if vuln:
            sections.append("")
            sections.append("  TOP VULNERABILITY TYPES")
            sections.append("  " + "-" * 68)
            header = (
                f"  {_pad('Vuln Type', 20)} "
                f"{_pad('Total', 6, 'right')} "
                f"{_pad('Accept', 7, 'right')} "
                f"{_pad('Rate', 7, 'right')} "
                f"{_pad('Avg Pay', 12, 'right')} "
                f"{_pad('Total Pay', 12, 'right')}"
            )
            sections.append(header)
            sections.append("  " + "-" * 68)
            for v in vuln:
                avg_pay = _fmt_currency(v["avg_payout"]) if v["avg_payout"] else "$0.00"
                total_pay = _fmt_currency(v["total_payout"]) if v["total_payout"] else "$0.00"
                sections.append(
                    f"  {_pad(v['vuln_type'], 20)} "
                    f"{_pad(str(v['total']), 6, 'right')} "
                    f"{_pad(str(v['accepted']), 7, 'right')} "
                    f"{_pad(str(v['acceptance_rate']) + '%', 7, 'right')} "
                    f"{_pad(avg_pay, 12, 'right')} "
                    f"{_pad(total_pay, 12, 'right')}"
                )

        # 4. Tool Effectiveness
        tools = self.analytics.success_rate_by_tool(limit=10)
        if tools:
            sections.append("")
            sections.append("  TOOL EFFECTIVENESS")
            sections.append("  " + "-" * 60)
            header = (
                f"  {_pad('Tool', 25)} "
                f"{_pad('Runs', 6, 'right')} "
                f"{_pad('Finds', 7, 'right')} "
                f"{_pad('Per Run', 8, 'right')} "
                f"{_pad('OK%', 7, 'right')}"
            )
            sections.append(header)
            sections.append("  " + "-" * 60)
            for t in tools:
                sections.append(
                    f"  {_pad(t['tool_name'], 25)} "
                    f"{_pad(str(t['total_runs']), 6, 'right')} "
                    f"{_pad(str(t['total_findings']), 7, 'right')} "
                    f"{_pad(str(t['findings_per_run']), 8, 'right')} "
                    f"{_pad(str(t['success_rate']) + '%', 7, 'right')}"
                )

        # 5. Monthly Earnings Trend
        monthly = self.analytics.monthly_earnings(months=12)
        if monthly:
            sections.append("")
            sections.append("  MONTHLY EARNINGS (LAST 12 MONTHS)")
            sections.append("  " + "-" * 50)
            max_earn = max(m["earnings"] or 0 for m in monthly) or 1
            bar_max = 30
            for m in monthly:
                earn = m["earnings"] or 0
                bar_len = int((earn / max_earn) * bar_max) if max_earn > 0 else 0
                bar = "#" * bar_len
                sections.append(
                    f"  {m['month']}  {_pad(_fmt_currency(earn), 12, 'right')}  "
                    f"[{bar}] ({m['findings_count']} findings)"
                )

        # 6. Payout Forecast
        forecast = self.analytics.payout_forecast(months=3)
        if forecast["projected_months"]:
            sections.append("")
            sections.append("  PAYOUT FORECAST (NEXT 3 MONTHS)")
            sections.append("  " + "-" * 50)
            sections.append(f"  Historical Avg:   {_fmt_currency(forecast['historical_monthly_avg'])}/month")
            sections.append(f"  Trend:            {forecast['trend_direction'].upper()}")
            for p in forecast["projected_months"]:
                sections.append(
                    f"  {p['month']}  ~{_fmt_currency(p['projected_earnings'])}"
                )
            sections.append(f"  Projected Total:  ~{_fmt_currency(forecast['projected_total'])}")
            sections.append(f"  Note: {forecast['confidence_note']}")

        # 7. Target Recommendations
        recs = self.analytics.target_recommendations()
        if recs:
            top_recs = [r for r in recs if r["recommendation"] != "SKIP - tested within the last week"][:10]
            if top_recs:
                sections.append("")
                sections.append("  TARGET RECOMMENDATIONS")
                sections.append("  " + "-" * 68)
                header = (
                    f"  {_pad('Domain', 28)} "
                    f"{_pad('Days', 5, 'right')} "
                    f"{_pad('Accept%', 8, 'right')} "
                    f"{_pad('Payouts', 12, 'right')} "
                    f"{_pad('Action', 15)}"
                )
                sections.append(header)
                sections.append("  " + "-" * 68)
                for r in top_recs:
                    action = r["recommendation"].split(" - ")[0]
                    sections.append(
                        f"  {_pad(r['domain'], 28)} "
                        f"{_pad(str(r['days_since_test']), 5, 'right')} "
                        f"{_pad(str(r['acceptance_rate']) + '%', 8, 'right')} "
                        f"{_pad(_fmt_currency(r['total_payouts']), 12, 'right')} "
                        f"{_pad(action, 15)}"
                    )

        # Footer
        sections.append("")
        sections.append(sep)
        sections.append(f"  Database: {DB_PATH}")
        sections.append(sep)

        return "\n".join(sections)

    # -- JSON report --------------------------------------------------------

    def generate_json_report(self) -> Dict[str, Any]:
        """
        Returns all analytics as a JSON-serializable dictionary for
        consumption by external tools or dashboards.

        Structure:
            generated_at, overview, top_targets, top_vuln_types,
            tool_effectiveness, monthly_earnings, payout_forecast,
            target_recommendations, hunt_efficiency, top_techniques,
            time_to_triage
        """
        return {
            "generated_at": datetime.now().isoformat(),
            "database_path": DB_PATH,
            "overview": self.analytics.overview(),
            "top_targets": self.analytics.roi_by_target(limit=20),
            "top_vuln_types": self.analytics.roi_by_vuln_type(limit=20),
            "tool_effectiveness": self.analytics.success_rate_by_tool(limit=20),
            "monthly_earnings": self.analytics.monthly_earnings(months=12),
            "payout_forecast": self.analytics.payout_forecast(months=3),
            "target_recommendations": self.analytics.target_recommendations(),
            "hunt_efficiency": self.analytics.hunt_efficiency(),
            "top_techniques": self.analytics.top_techniques(limit=10),
            "time_to_triage": self.analytics.time_to_triage(),
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    """Quick CLI entry point: python -m engine.core.analytics"""
    db = BountyHoundDB.get_instance(DB_PATH)
    analytics = HuntAnalytics(db)
    report = DashboardReport(analytics)
    print(report.generate_text_report())


if __name__ == "__main__":
    main()
