"""
Migrate CODEXDATABASE.db → h1-programs.db

Updates:
  - programs: UPDATE existing (by handle), INSERT new
  - scopes: INSERT OR IGNORE (dedup by program_id + asset_identifier)
  - severity_bounties: INSERT OR IGNORE per severity row
"""

import sqlite3
import json
from datetime import datetime

CODEX_PATH = "CODEXDATABASE.db"
H1_PATH = "h1-programs.db"
SCRAPED_AT = "2026-03-09T13:38:39+00:00"

ASSET_TYPE_MAP = {
    "Domain":              "URL",
    "Url":                 "URL",
    "Wildcard":            "WILDCARD",
    "OtherAsset":          "OTHER",
    "AndroidPlayStore":    "GOOGLE_PLAY_APP_ID",
    "IosAppStore":         "APPLE_STORE_APP_ID",
    "SourceCode":          "SOURCE_CODE",
    "IpAddress":           "IP_ADDRESS",
    "Executable":          "DOWNLOADABLE_EXECUTABLES",
    "Hardware":            "HARDWARE",
    "Cidr":                "CIDR",
    "Api":                 "API",
    "AndroidApk":          "OTHER_APK",
    "SmartContract":       "SMART_CONTRACT",
    "WindowsMicrosoftStore": "WINDOWS_APP_STORE_APP_ID",
    "AiModel":             "AI_MODEL",
    "IosTestflight":       "TESTFLIGHT",
    "IosIpa":              "OTHER_IPA",
}


def migrate():
    src = sqlite3.connect(CODEX_PATH)
    dst = sqlite3.connect(H1_PATH)
    src.row_factory = sqlite3.Row
    dst.row_factory = sqlite3.Row

    sc = src.cursor()
    dc = dst.cursor()

    # ── 1. Build handle → h1_program_id map ──────────────────────────────
    dc.execute("SELECT id, handle FROM programs")
    h1_handle_to_id: dict[str, int] = {r["handle"]: r["id"] for r in dc.fetchall()}

    # ── 2. Programs ───────────────────────────────────────────────────────
    sc.execute("SELECT * FROM programs")
    codex_programs = sc.fetchall()

    updated = inserted = 0
    # track codex_program_id → h1_program_id for scope migration
    codex_id_to_h1_id: dict[int, int] = {}

    for p in codex_programs:
        handle = p["handle"]
        # map fields
        row = {
            "handle":                              handle,
            "name":                                p["name"],
            "url":                                 p["url"],
            "state":                               p["state"],
            "submission_state":                    p["submission_state"],
            "triage_active":                       p["triage_active"],
            "publicly_launched_at":                p["launched_at"],
            "updated_at":                          p["last_updated_at"],
            "offers_bounties":                     p["offers_bounties"],
            "currency":                            p["currency"],
            "min_bounty":                          p["minimum_bounty_table_value"],
            "max_bounty":                          p["maximum_bounty_table_value"],
            "average_bounty":                      p["base_bounty"],
            "resolved_report_count":               p["resolved_report_count"],
            "reports_resolved_count":              p["resolved_report_count"],
            "average_time_to_bounty_awarded":      p["sla_average_time_to_bounty_awarded"],
            "average_time_to_first_program_response": p["sla_average_time_to_first_program_response"],
            "average_time_to_resolution":          p["sla_average_time_to_report_resolved"],
            "policy":                              p["policy"],
            "allows_disclosure":                   p["allows_private_disclosure"],
            "scraped_at":                          SCRAPED_AT,
        }

        if handle in h1_handle_to_id:
            # UPDATE existing
            h1_id = h1_handle_to_id[handle]
            dc.execute("""
                UPDATE programs SET
                    name=:name, url=:url, state=:state,
                    submission_state=:submission_state, triage_active=:triage_active,
                    publicly_launched_at=:publicly_launched_at, updated_at=:updated_at,
                    offers_bounties=:offers_bounties, currency=:currency,
                    min_bounty=:min_bounty, max_bounty=:max_bounty,
                    average_bounty=:average_bounty,
                    resolved_report_count=:resolved_report_count,
                    reports_resolved_count=:reports_resolved_count,
                    average_time_to_bounty_awarded=:average_time_to_bounty_awarded,
                    average_time_to_first_program_response=:average_time_to_first_program_response,
                    average_time_to_resolution=:average_time_to_resolution,
                    policy=:policy, allows_disclosure=:allows_disclosure,
                    scraped_at=:scraped_at
                WHERE handle=:handle
            """, row)
            updated += 1
        else:
            # INSERT new
            dc.execute("""
                INSERT INTO programs
                    (handle, name, url, state, submission_state, triage_active,
                     publicly_launched_at, updated_at, offers_bounties, currency,
                     min_bounty, max_bounty, average_bounty,
                     resolved_report_count, reports_resolved_count,
                     average_time_to_bounty_awarded,
                     average_time_to_first_program_response,
                     average_time_to_resolution, policy, allows_disclosure,
                     scraped_at)
                VALUES
                    (:handle, :name, :url, :state, :submission_state, :triage_active,
                     :publicly_launched_at, :updated_at, :offers_bounties, :currency,
                     :min_bounty, :max_bounty, :average_bounty,
                     :resolved_report_count, :reports_resolved_count,
                     :average_time_to_bounty_awarded,
                     :average_time_to_first_program_response,
                     :average_time_to_resolution, :policy, :allows_disclosure,
                     :scraped_at)
            """, row)
            h1_id = dc.lastrowid
            h1_handle_to_id[handle] = h1_id
            inserted += 1

        codex_id_to_h1_id[p["id"]] = h1_id

    dst.commit()
    print(f"Programs: {updated} updated, {inserted} inserted")

    # ── 3. Scopes ─────────────────────────────────────────────────────────
    # Build existing (h1_program_id, asset_identifier) set to avoid duplicates
    dc.execute("SELECT program_id, asset_identifier FROM scopes")
    existing_scopes: set[tuple[int, str]] = {(r[0], r[1]) for r in dc.fetchall()}

    sc.execute("SELECT * FROM scopes")
    codex_scopes = sc.fetchall()

    scope_inserted = scope_skipped = 0
    for s in codex_scopes:
        h1_pid = codex_id_to_h1_id.get(s["program_id"])
        if h1_pid is None:
            continue

        identifier = s["identifier"] or ""
        if (h1_pid, identifier) in existing_scopes:
            scope_skipped += 1
            continue

        # get max_severity from raw_json cvss_score field
        rj = json.loads(s["raw_json"]) if s["raw_json"] else {}
        max_severity = rj.get("cvss_score")  # e.g. "critical", "high", None

        asset_type = ASSET_TYPE_MAP.get(s["display_name"], "OTHER")

        dc.execute("""
            INSERT INTO scopes
                (program_id, asset_type, asset_identifier, instruction,
                 max_severity, eligible_for_bounty, eligible_for_submission, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            h1_pid,
            asset_type,
            identifier,
            s["instruction"],
            max_severity,
            1 if s["eligible_for_bounty"] else 0,
            1 if s["eligible_for_submission"] else 0,
            s["created_at_remote"],
        ))
        existing_scopes.add((h1_pid, identifier))
        scope_inserted += 1

    dst.commit()
    print(f"Scopes: {scope_inserted} inserted, {scope_skipped} skipped (already exist)")

    # ── 4. Severity bounties ──────────────────────────────────────────────
    # Build existing (program_id, severity) set
    dc.execute("SELECT program_id, severity FROM severity_bounties")
    existing_bounties: set[tuple[int, str]] = {(r[0], r[1]) for r in dc.fetchall()}

    sc.execute("SELECT * FROM bounty_table_rows")
    bounty_rows = sc.fetchall()

    bounty_inserted = bounty_skipped = 0
    severity_cols = [
        ("low",      "low_minimum"),
        ("medium",   "medium_minimum"),
        ("high",     "high_minimum"),
        ("critical", "critical_minimum"),
    ]

    for b in bounty_rows:
        h1_pid = codex_id_to_h1_id.get(b["program_id"])
        if h1_pid is None:
            continue

        for sev, min_col in severity_cols:
            max_val = b[sev]
            min_val = b[min_col]
            if max_val is None:
                continue  # not offered for this severity
            if (h1_pid, sev) in existing_bounties:
                # UPDATE with fresher data
                dc.execute("""
                    UPDATE severity_bounties
                    SET min_bounty=?, max_bounty=?
                    WHERE program_id=? AND severity=?
                """, (min_val, max_val, h1_pid, sev))
                bounty_skipped += 1
            else:
                dc.execute("""
                    INSERT INTO severity_bounties (program_id, severity, min_bounty, max_bounty, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (h1_pid, sev, min_val, max_val, SCRAPED_AT))
                existing_bounties.add((h1_pid, sev))
                bounty_inserted += 1

    dst.commit()
    print(f"Severity bounties: {bounty_inserted} inserted, {bounty_skipped} updated")

    src.close()
    dst.close()
    print("\nMigration complete.")


if __name__ == "__main__":
    migrate()
