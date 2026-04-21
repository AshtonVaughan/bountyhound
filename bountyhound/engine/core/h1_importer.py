"""
HackerOne API payout importer

Fetches real bounty payout data from HackerOne API to replace placeholder data
and enable accurate ROI calculations.
"""
import os
import requests
from typing import List, Dict, Optional
from datetime import datetime


class HackerOneImporter:
    """Import payout data from HackerOne API"""

    def __init__(self):
        self.api_token = os.environ.get("H1_API_TOKEN", "")
        self.username = os.environ.get("H1_USERNAME", "")
        self.base_url = "https://api.hackerone.com/v1"

    def fetch_payouts(self) -> List[Dict]:
        """
        Fetch all bounty awards from HackerOne

        Returns:
            List of payout dictionaries with report_id, title, amount, currency, awarded_at
        """
        if not self.api_token or not self.username:
            return []

        headers = {"Accept": "application/json"}
        auth = (self.username, self.api_token)

        # Fetch reports with bounty awards
        try:
            response = requests.get(
                f"{self.base_url}/reports",
                headers=headers,
                auth=auth,
                params={"filter[bounty_awarded_at]": "present"},
                timeout=30
            )

            if response.status_code != 200:
                return []

            reports = response.json().get("data", [])
            payouts = []

            for report in reports:
                attrs = report.get("attributes", {})
                bounty = attrs.get("bounty_amount")

                if bounty:
                    payouts.append({
                        "report_id": report["id"],
                        "title": attrs.get("title", ""),
                        "amount": float(bounty),
                        "currency": attrs.get("currency", "USD"),
                        "awarded_at": attrs.get("bounty_awarded_at", "")
                    })

            return payouts

        except Exception as e:
            # Log error but don't crash - return empty list
            print(f"Error fetching HackerOne payouts: {e}")
            return []

    def sync_to_database(self, db, payouts: List[Dict]):
        """
        Sync HackerOne payouts to database

        Args:
            db: Database instance
            payouts: List of payout dictionaries from fetch_payouts()
        """
        for payout in payouts:
            # Check if finding exists
            existing = db.get_finding_by_id(payout["report_id"])

            if existing:
                # Update payout amount
                db.update_finding_payout(
                    payout["report_id"],
                    payout["amount"],
                    payout["currency"]
                )
            else:
                # Create new finding record
                db.insert_finding(
                    target="hackerone",
                    vuln_type="imported",
                    title=payout["title"],
                    severity="INFO",  # Default severity for imported findings
                    payout=payout["amount"],
                    currency=payout["currency"],
                    report_id=payout["report_id"]
                )

    def import_all(self, db) -> Dict:
        """
        Complete import workflow: fetch from API and sync to database

        Args:
            db: Database instance

        Returns:
            Dictionary with import statistics
        """
        payouts = self.fetch_payouts()

        if not payouts:
            return {
                "success": False,
                "imported": 0,
                "updated": 0,
                "total_amount": 0.0
            }

        # Count updates vs new imports
        updated = 0
        imported = 0

        for payout in payouts:
            if db.get_finding_by_id(payout["report_id"]):
                updated += 1
            else:
                imported += 1

        # Sync to database
        self.sync_to_database(db, payouts)

        # Calculate total amount
        total_amount = sum(p["amount"] for p in payouts)

        return {
            "success": True,
            "imported": imported,
            "updated": updated,
            "total_amount": total_amount,
            "count": len(payouts)
        }
