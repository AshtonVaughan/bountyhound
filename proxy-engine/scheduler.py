"""Enhanced scan scheduler with cron expression support.

Lightweight cron parser (5-field: minute hour day month weekday).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from typing import Any

import httpx

log = logging.getLogger("scheduler")


# ── Cron Parser ──────────────────────────────────────────────────────────────

def _cron_matches(expr: str, dt: datetime) -> bool:
    """Check if a cron expression matches a datetime.

    5-field format: minute hour day_of_month month day_of_week
    Supports: * (any), */N (step), N-M (range), N,M (list)
    """
    fields = expr.strip().split()
    if len(fields) != 5:
        return False

    values = [dt.minute, dt.hour, dt.day, dt.month, dt.isoweekday() % 7]
    ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]

    for field, value, (low, high) in zip(fields, values, ranges):
        if not _field_matches(field, value, low, high):
            return False
    return True


def _field_matches(field: str, value: int, low: int, high: int) -> bool:
    """Check if a single cron field matches a value."""
    if field == "*":
        return True

    for part in field.split(","):
        # Step: */N or N-M/S
        if "/" in part:
            range_part, step_str = part.split("/", 1)
            try:
                step = int(step_str)
            except ValueError:
                continue

            if range_part == "*":
                if value % step == 0:
                    return True
            elif "-" in range_part:
                try:
                    start, end = range_part.split("-", 1)
                    if int(start) <= value <= int(end) and (value - int(start)) % step == 0:
                        return True
                except ValueError:
                    continue
            continue

        # Range: N-M
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                if int(start) <= value <= int(end):
                    return True
            except ValueError:
                continue
            continue

        # Exact: N
        try:
            if int(part) == value:
                return True
        except ValueError:
            continue

    return False


def next_cron_time(expr: str, after: datetime | None = None) -> datetime | None:
    """Find the next datetime matching a cron expression (within 48 hours)."""
    if after is None:
        after = datetime.now()

    # Check every minute for the next 48 hours
    dt = after.replace(second=0, microsecond=0)
    from datetime import timedelta
    for _ in range(48 * 60):
        dt += timedelta(minutes=1)
        if _cron_matches(expr, dt):
            return dt
    return None


# ── Scheduler Loop ───────────────────────────────────────────────────────────

async def run_scheduler() -> None:
    """Main scheduler loop — checks every 30s for matching cron expressions."""
    while True:
        await asyncio.sleep(30)
        try:
            from state import state
            from models import ScanRequest
            from scanner import start_scan

            now = datetime.now()
            current_time = time.time()

            for scan in state.scheduled_scans:
                if not scan.enabled:
                    continue

                # Cron-based scheduling
                cron_expr = getattr(scan, "cron_expr", "")
                if cron_expr:
                    if _cron_matches(cron_expr, now):
                        # Don't re-trigger within same minute
                        if current_time - scan.last_run < 60:
                            continue

                        log.info(f"[scheduler] Cron trigger: {scan.name} ({cron_expr})")
                        req = ScanRequest(
                            urls=scan.urls,
                            profile=scan.profile or None,
                        )
                        job = await start_scan(req)
                        scan.last_run = current_time
                        scan.last_scan_id = job.scan_id

                        # Webhook notification
                        webhook_url = getattr(scan, "webhook_url", "")
                        if webhook_url:
                            asyncio.ensure_future(_send_webhook(webhook_url, job.scan_id, scan.name))

                # Interval-based scheduling (existing behavior, as fallback)
                elif scan.interval_minutes > 0:
                    if scan.next_run > 0 and current_time >= scan.next_run:
                        log.info(f"[scheduler] Interval trigger: {scan.name}")
                        req = ScanRequest(
                            urls=scan.urls,
                            profile=scan.profile or None,
                        )
                        job = await start_scan(req)
                        scan.last_run = current_time
                        scan.last_scan_id = job.scan_id
                        scan.next_run = current_time + scan.interval_minutes * 60

                        webhook_url = getattr(scan, "webhook_url", "")
                        if webhook_url:
                            asyncio.ensure_future(_send_webhook(webhook_url, job.scan_id, scan.name))

        except Exception as e:
            log.debug(f"[scheduler] Error: {e}")


async def _send_webhook(url: str, scan_id: str, scan_name: str) -> None:
    """POST scan results to webhook URL on completion."""
    # Wait for scan to complete (poll every 5s, max 5 min)
    from state import state
    for _ in range(60):
        await asyncio.sleep(5)
        job = state.scanner_jobs.get(scan_id)
        if job and job.status in ("completed", "error"):
            break

    job = state.scanner_jobs.get(scan_id)
    if not job:
        return

    payload = {
        "scan_id": scan_id,
        "scan_name": scan_name,
        "status": job.status,
        "findings_count": len(job.findings),
        "findings": [
            {
                "template_id": f.template_id,
                "name": f.name,
                "severity": f.severity,
                "url": f.url,
                "description": f.description,
            }
            for f in job.findings[:50]  # Cap at 50
        ],
        "timestamp": time.time(),
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            log.info(f"[scheduler] Webhook sent to {url}: {resp.status_code}")
    except Exception as e:
        log.warning(f"[scheduler] Webhook failed: {e}")


# ── SARIF Output ─────────────────────────────────────────────────────────────

def findings_to_sarif(findings: list, tool_name: str = "proxy-engine") -> dict:
    """Convert scan findings to SARIF format for CI/CD integration."""
    results = []
    rules = {}

    for f in findings:
        rule_id = f.template_id

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.name,
                "shortDescription": {"text": f.name},
                "fullDescription": {"text": f.description or f.name},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(f.severity),
                },
            }

        result = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(f.severity),
            "message": {"text": f.description or f.name},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url},
                },
            }],
        }
        if f.remediation:
            result["fixes"] = [{"description": {"text": f.remediation}}]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": "3.0.0",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }


def _severity_to_sarif_level(severity: str) -> str:
    mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    return mapping.get(severity, "note")
