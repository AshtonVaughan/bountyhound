#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Import live public HackerOne program data into CODEXDATABASE."""

from __future__ import annotations

import argparse
import io
import json
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import requests


if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = REPO_ROOT / "data" / "CODEXDATABASE.db"
HACKERONE_BASE_URL = "https://hackerone.com"
GRAPHQL_URL = f"{HACKERONE_BASE_URL}/graphql"
PUBLIC_PROGRAM_SOURCE_URL = f"{HACKERONE_BASE_URL}/opportunities/all"
DEFAULT_DELAY_SECONDS = 0.25
DEFAULT_SCOPE_PAGE_SIZE = 100
DEFAULT_MAX_RETRIES = 5
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
EXCLUDED_HANDLES = {"security"}

OPEN_PUBLIC_PROGRAMS_QUERY = """
query OpenPublicPrograms($cursor: String) {
  teams(
    first: 100
    after: $cursor
    where: {
      state: { _eq: public_mode }
      submission_state: { _eq: open }
    }
  ) {
    total_count
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      id
      handle
      name
      url
      type
      state
      submission_state
      offers_bounties
      currency
    }
  }
}
"""

PROGRAM_OVERVIEW_QUERY = """
query ProgramOverview($handle: String!) {
  team(handle: $handle) {
    id
    handle
    name
    url
    type
    state
    submission_state
    offers_bounties
    currency
    profile_picture(size: small)
    about
    policy
    scope_description
    triage_active
    publicly_visible_retesting
    allows_private_disclosure
    allows_bounty_splitting
    launched_at
    last_updated_at
    minimum_bounty_table_value
    maximum_bounty_table_value
    base_bounty
    response_efficiency_percentage
    response_efficiency_indicator
    resolved_report_count
    participants_count
    external_program {
      id
    }
    report_submission_form_intro
    customized_report_template
    cwe_field_hidden
    report_template
    signal_requirements_setting {
      target_signal
    }
    team_display_options {
      id
      show_response_efficiency_indicator
      show_mean_first_response_time
      show_mean_report_triage_time
      show_mean_bounty_time
      show_mean_resolution_time
      show_top_bounties
      show_average_bounty
      show_total_bounties_paid
      show_total_reports_per_asset
    }
    most_recent_sla_snapshot {
      id
      average_time_to_first_program_response
      average_time_to_report_triage
      average_time_to_bounty_awarded
      average_time_to_report_resolved
    }
    declarative_policy {
      has_open_scope
      pays_within_one_month
      protected_by_gold_standard_safe_harbor
      protected_by_ai_safe_harbor
      disclosure_declaration
      introduction
      exemplary_standards_exclusions
      contact_email
      platform_standards_exclusions {
        id
        justification
        platform_standard
      }
      scope_exclusions {
        id
        _id
        category
        details
        created_at
      }
    }
    bounty_table {
      id
      low_label
      medium_label
      high_label
      critical_label
      description
      use_range
      bounty_table_rows(first: 100) {
        edges {
          node {
            id
            _id
            low
            medium
            high
            critical
            low_minimum
            medium_minimum
            high_minimum
            critical_minimum
            structured_scope {
              id
              asset_identifier
            }
          }
        }
      }
    }
  }
}
"""

PROGRAM_SCOPES_QUERY = """
query ProgramScopes($handle: String!, $from: Int!, $size: Int!) {
  team(handle: $handle) {
    id
    handle
    structured_scopes_search(from: $from, size: $size) {
      total_count
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        ... on StructuredScopeDocument {
          id
          identifier
          display_name
          instruction
          cvss_score
          eligible_for_bounty
          eligible_for_submission
          asm_system_tags
          created_at
          updated_at
          total_resolved_reports
          attachments {
            id
            file_name
            file_size
            content_type
            expiring_url
          }
        }
      }
    }
  }
}
"""


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def as_bool_int(value: Any) -> int | None:
    if value is None:
        return None
    return 1 if bool(value) else 0


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def merge_unique_items(existing: Any, incoming: Any) -> list[Any]:
    merged: list[Any] = []
    seen: set[tuple[str, str] | tuple[str, Any]] = set()

    for item in as_list(existing) + as_list(incoming):
        if isinstance(item, dict):
            item_id = item.get("id")
            marker = ("id", item_id) if item_id is not None else ("json", json_dumps(item))
        else:
            marker = ("value", json_dumps(item))
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(item)

    return merged


def merge_scope_documents(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)

    for key, value in incoming.items():
        if key == "attachments":
            merged[key] = merge_unique_items(existing.get(key), value)
            continue

        if key == "asm_system_tags":
            merged[key] = merge_unique_items(existing.get(key), value)
            continue

        existing_value = merged.get(key)
        if existing_value in (None, "", [], {}):
            merged[key] = value
            continue

        if key in {"eligible_for_bounty", "eligible_for_submission"}:
            merged[key] = bool(existing_value) or bool(value)

    return merged


def dedupe_scopes(scopes: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    deduped: list[dict[str, Any]] = []
    index_by_remote_id: dict[str, int] = {}
    duplicate_count = 0

    for scope in scopes:
        remote_id = scope.get("id")
        normalized_scope = dict(scope)
        normalized_scope["attachments"] = list(as_list(scope.get("attachments")))
        normalized_scope["asm_system_tags"] = list(as_list(scope.get("asm_system_tags")))

        if remote_id is not None and remote_id in index_by_remote_id:
            duplicate_count += 1
            existing_index = index_by_remote_id[remote_id]
            deduped[existing_index] = merge_scope_documents(deduped[existing_index], normalized_scope)
            continue

        if remote_id is not None:
            index_by_remote_id[remote_id] = len(deduped)
        deduped.append(normalized_scope)

    return deduped, duplicate_count


def stringify_graphql_errors(errors: list[dict[str, Any]]) -> str:
    messages = []
    for error in errors:
        message = error.get("message", "Unknown GraphQL error")
        path = error.get("path")
        if path:
            message = f"{message} ({'.'.join(str(part) for part in path)})"
        messages.append(message)
    return " | ".join(messages)


@dataclass
class ImportCounts:
    source_scope_count: int = 0
    duplicate_scope_count: int = 0
    scope_total_count: int = 0
    in_scope_count: int = 0
    out_of_scope_count: int = 0
    bounty_eligible_scope_count: int = 0
    bounty_table_row_count: int = 0


class HackerOnePublicClient:
    def __init__(self, delay_seconds: float, max_retries: int) -> None:
        self.delay_seconds = delay_seconds
        self.max_retries = max_retries
        self.last_request_at = 0.0
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/123.0.0.0 Safari/537.36"
                ),
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Origin": HACKERONE_BASE_URL,
                "Referer": PUBLIC_PROGRAM_SOURCE_URL,
                "X-Requested-With": "XMLHttpRequest",
            }
        )
        self.csrf_token: str | None = None
        self.refresh_csrf_token()

    def refresh_csrf_token(self) -> None:
        marker = '<meta name="csrf-token" content="'
        bootstrap_urls = (
            f"{HACKERONE_BASE_URL}/uber",
            PUBLIC_PROGRAM_SOURCE_URL,
        )
        bootstrap_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        for bootstrap_url in bootstrap_urls:
            response = self.session.get(bootstrap_url, headers=bootstrap_headers, timeout=60)
            response.raise_for_status()
            start = response.text.find(marker)
            if start == -1:
                continue
            start += len(marker)
            end = response.text.find('"', start)
            if end == -1:
                continue
            self.csrf_token = response.text[start:end]
            self.session.headers["X-CSRF-Token"] = self.csrf_token
            return

        raise RuntimeError("Could not find HackerOne CSRF token")

    def _respect_rate_limit(self) -> None:
        if self.delay_seconds <= 0:
            return
        elapsed = time.monotonic() - self.last_request_at
        if elapsed < self.delay_seconds:
            time.sleep(self.delay_seconds - elapsed)

    def graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"query": query, "variables": variables or {}}
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                self._respect_rate_limit()
                response = self.session.post(GRAPHQL_URL, json=payload, timeout=90)
                self.last_request_at = time.monotonic()

                if response.status_code in RETRY_STATUS_CODES:
                    raise RuntimeError(f"HTTP {response.status_code}")

                response.raise_for_status()
                parsed = response.json()

                if parsed.get("errors"):
                    raise RuntimeError(stringify_graphql_errors(parsed["errors"]))

                return parsed["data"]
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if attempt == self.max_retries:
                    break
                if isinstance(exc, RuntimeError) and "InvalidAuthenticityToken" in str(exc):
                    self.refresh_csrf_token()
                elif isinstance(exc, requests.HTTPError) and exc.response is not None and exc.response.status_code in {401, 403, 422}:
                    self.refresh_csrf_token()
                time.sleep(min(8.0, attempt * 1.5))

        raise RuntimeError(f"GraphQL request failed after {self.max_retries} attempts: {last_error}")

    def enumerate_open_public_programs(self) -> list[dict[str, Any]]:
        cursor: str | None = None
        all_nodes: list[dict[str, Any]] = []

        while True:
            data = self.graphql(OPEN_PUBLIC_PROGRAMS_QUERY, {"cursor": cursor})
            connection = data["teams"]
            all_nodes.extend(connection["nodes"])
            if not connection["pageInfo"]["hasNextPage"]:
                break
            cursor = connection["pageInfo"]["endCursor"]

        return [node for node in all_nodes if node["handle"] not in EXCLUDED_HANDLES]

    def fetch_program_overview(self, handle: str) -> dict[str, Any]:
        data = self.graphql(PROGRAM_OVERVIEW_QUERY, {"handle": handle})
        team = data.get("team")
        if not team:
            raise RuntimeError(f"No public program returned for handle '{handle}'")
        return team

    def fetch_program_scopes(self, handle: str, page_size: int) -> list[dict[str, Any]]:
        all_scopes: list[dict[str, Any]] = []
        current_from = 0

        while True:
            data = self.graphql(
                PROGRAM_SCOPES_QUERY,
                {"handle": handle, "from": current_from, "size": page_size},
            )
            team = data.get("team")
            if not team:
                raise RuntimeError(f"No public scope data returned for handle '{handle}'")

            search_result = team["structured_scopes_search"]
            nodes = search_result["nodes"]
            all_scopes.extend(nodes)

            current_from += len(nodes)
            total_count = search_result["total_count"]
            if current_from >= total_count or not nodes:
                break

        return all_scopes


class CodeXDatabaseImporter:
    def __init__(self, db_path: Path, delay_seconds: float, scope_page_size: int, max_retries: int) -> None:
        self.db_path = db_path
        self.scope_page_size = scope_page_size
        self.client = HackerOnePublicClient(delay_seconds=delay_seconds, max_retries=max_retries)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(db_path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        self.initialize_schema()

    def close(self) -> None:
        self.connection.close()

    def initialize_schema(self) -> None:
        cursor = self.connection.cursor()

        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS import_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL,
                source_filter TEXT NOT NULL,
                source_declared_count INTEGER,
                source_graphql_count INTEGER,
                imported_count INTEGER NOT NULL DEFAULT 0,
                failed_count INTEGER NOT NULL DEFAULT 0,
                excluded_handles_json TEXT NOT NULL,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS import_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                import_run_id INTEGER NOT NULL,
                handle TEXT NOT NULL,
                error_text TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY (import_run_id) REFERENCES import_runs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS programs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                remote_id TEXT NOT NULL UNIQUE,
                handle TEXT NOT NULL UNIQUE,
                name TEXT,
                url TEXT,
                type TEXT,
                state TEXT,
                submission_state TEXT,
                offers_bounties INTEGER NOT NULL DEFAULT 0,
                currency TEXT,
                profile_picture_url TEXT,
                about TEXT,
                policy TEXT,
                scope_description TEXT,
                triage_active INTEGER,
                publicly_visible_retesting INTEGER,
                allows_private_disclosure INTEGER,
                allows_bounty_splitting INTEGER,
                launched_at TEXT,
                last_updated_at TEXT,
                minimum_bounty_table_value REAL,
                maximum_bounty_table_value REAL,
                base_bounty REAL,
                response_efficiency_percentage REAL,
                response_efficiency_indicator TEXT,
                resolved_report_count INTEGER,
                participants_count INTEGER,
                report_submission_form_intro TEXT,
                customized_report_template INTEGER,
                cwe_field_hidden INTEGER,
                report_template TEXT,
                signal_target REAL,
                has_open_scope INTEGER,
                pays_within_one_month INTEGER,
                protected_by_gold_standard_safe_harbor INTEGER,
                protected_by_ai_safe_harbor INTEGER,
                disclosure_declaration TEXT,
                declarative_introduction TEXT,
                contact_email TEXT,
                display_show_response_efficiency_indicator INTEGER,
                display_show_mean_first_response_time INTEGER,
                display_show_mean_report_triage_time INTEGER,
                display_show_mean_bounty_time INTEGER,
                display_show_mean_resolution_time INTEGER,
                display_show_top_bounties INTEGER,
                display_show_average_bounty INTEGER,
                display_show_total_bounties_paid INTEGER,
                display_show_total_reports_per_asset INTEGER,
                sla_average_time_to_first_program_response REAL,
                sla_average_time_to_report_triage REAL,
                sla_average_time_to_bounty_awarded REAL,
                sla_average_time_to_report_resolved REAL,
                external_program_id TEXT,
                scope_total_count INTEGER NOT NULL DEFAULT 0,
                in_scope_count INTEGER NOT NULL DEFAULT 0,
                out_of_scope_count INTEGER NOT NULL DEFAULT 0,
                bounty_eligible_scope_count INTEGER NOT NULL DEFAULT 0,
                bounty_table_row_count INTEGER NOT NULL DEFAULT 0,
                last_import_run_id INTEGER,
                overview_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (last_import_run_id) REFERENCES import_runs(id)
            );

            CREATE TABLE IF NOT EXISTS program_bounty_tables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL UNIQUE,
                remote_id TEXT,
                description TEXT,
                use_range INTEGER,
                low_label TEXT,
                medium_label TEXT,
                high_label TEXT,
                critical_label TEXT,
                raw_json TEXT NOT NULL,
                FOREIGN KEY (program_id) REFERENCES programs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS bounty_table_rows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL,
                bounty_table_id INTEGER NOT NULL,
                row_remote_id TEXT,
                row_database_id INTEGER,
                structured_scope_remote_id TEXT,
                structured_scope_asset_identifier TEXT,
                low REAL,
                medium REAL,
                high REAL,
                critical REAL,
                low_minimum REAL,
                medium_minimum REAL,
                high_minimum REAL,
                critical_minimum REAL,
                raw_json TEXT NOT NULL,
                FOREIGN KEY (program_id) REFERENCES programs(id) ON DELETE CASCADE,
                FOREIGN KEY (bounty_table_id) REFERENCES program_bounty_tables(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS program_platform_standard_exclusions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL,
                remote_id TEXT,
                platform_standard TEXT,
                justification TEXT,
                raw_json TEXT NOT NULL,
                FOREIGN KEY (program_id) REFERENCES programs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS program_scope_exclusions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL,
                remote_id TEXT,
                remote_database_id INTEGER,
                category TEXT,
                details TEXT,
                created_at_remote TEXT,
                raw_json TEXT NOT NULL,
                FOREIGN KEY (program_id) REFERENCES programs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS program_exemplary_standards_exclusions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL,
                exclusion_text TEXT NOT NULL,
                FOREIGN KEY (program_id) REFERENCES programs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL,
                remote_id TEXT NOT NULL,
                identifier TEXT,
                display_name TEXT,
                instruction TEXT,
                cvss_score REAL,
                eligible_for_bounty INTEGER,
                eligible_for_submission INTEGER,
                asm_system_tags_json TEXT,
                created_at_remote TEXT,
                updated_at_remote TEXT,
                total_resolved_reports INTEGER,
                raw_json TEXT NOT NULL,
                UNIQUE (program_id, remote_id),
                FOREIGN KEY (program_id) REFERENCES programs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scope_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_id INTEGER NOT NULL,
                remote_id TEXT,
                file_name TEXT,
                file_size INTEGER,
                content_type TEXT,
                expiring_url TEXT,
                raw_json TEXT NOT NULL,
                FOREIGN KEY (scope_id) REFERENCES scopes(id) ON DELETE CASCADE
            );

            CREATE VIEW IF NOT EXISTS in_scope_targets AS
            SELECT
                programs.handle,
                programs.name,
                scopes.identifier,
                scopes.display_name,
                scopes.instruction,
                scopes.cvss_score,
                scopes.eligible_for_bounty
            FROM scopes
            JOIN programs ON programs.id = scopes.program_id
            WHERE scopes.eligible_for_submission = 1;

            CREATE VIEW IF NOT EXISTS out_of_scope_targets AS
            SELECT
                programs.handle,
                programs.name,
                scopes.identifier,
                scopes.display_name,
                scopes.instruction
            FROM scopes
            JOIN programs ON programs.id = scopes.program_id
            WHERE scopes.eligible_for_submission = 0;
            """
        )

        cursor.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_programs_handle ON programs(handle);
            CREATE INDEX IF NOT EXISTS idx_programs_type ON programs(type);
            CREATE INDEX IF NOT EXISTS idx_programs_submission_state ON programs(submission_state);
            CREATE INDEX IF NOT EXISTS idx_scopes_program_id ON scopes(program_id);
            CREATE INDEX IF NOT EXISTS idx_scopes_submission ON scopes(eligible_for_submission);
            CREATE INDEX IF NOT EXISTS idx_scopes_bounty ON scopes(eligible_for_bounty);
            CREATE INDEX IF NOT EXISTS idx_bounty_rows_program_id ON bounty_table_rows(program_id);
            CREATE INDEX IF NOT EXISTS idx_scope_attachments_scope_id ON scope_attachments(scope_id);
            CREATE INDEX IF NOT EXISTS idx_import_errors_run_id ON import_errors(import_run_id);
            """
        )

        self.connection.commit()

    def create_import_run(self) -> int:
        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT INTO import_runs (
                started_at,
                status,
                source_filter,
                excluded_handles_json,
                notes
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                now_utc_iso(),
                "running",
                "state=public_mode AND submission_state=open",
                json_dumps(sorted(EXCLUDED_HANDLES)),
                "Excludes HackerOne's own security handle to align with the public 453-program count.",
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def finalize_import_run(
        self,
        import_run_id: int,
        source_graphql_count: int,
        imported_count: int,
        failed_count: int,
    ) -> None:
        self.connection.execute(
            """
            UPDATE import_runs
            SET completed_at = ?,
                status = ?,
                source_declared_count = ?,
                source_graphql_count = ?,
                imported_count = ?,
                failed_count = ?
            WHERE id = ?
            """,
            (
                now_utc_iso(),
                "completed" if failed_count == 0 else "completed_with_errors",
                source_graphql_count,
                source_graphql_count,
                imported_count,
                failed_count,
                import_run_id,
            ),
        )
        self.connection.commit()

    def record_import_error(self, import_run_id: int, handle: str, error_text: str) -> None:
        self.connection.execute(
            """
            INSERT INTO import_errors (import_run_id, handle, error_text, occurred_at)
            VALUES (?, ?, ?, ?)
            """,
            (import_run_id, handle, error_text, now_utc_iso()),
        )
        self.connection.commit()

    def upsert_program(self, import_run_id: int, team: dict[str, Any]) -> int:
        declarative_policy = team.get("declarative_policy") or {}
        display_options = team.get("team_display_options") or {}
        sla = team.get("most_recent_sla_snapshot") or {}
        external_program = team.get("external_program") or {}
        signal_requirements = team.get("signal_requirements_setting") or {}

        self.connection.execute(
            """
            INSERT INTO programs (
                remote_id,
                handle,
                name,
                url,
                type,
                state,
                submission_state,
                offers_bounties,
                currency,
                profile_picture_url,
                about,
                policy,
                scope_description,
                triage_active,
                publicly_visible_retesting,
                allows_private_disclosure,
                allows_bounty_splitting,
                launched_at,
                last_updated_at,
                minimum_bounty_table_value,
                maximum_bounty_table_value,
                base_bounty,
                response_efficiency_percentage,
                response_efficiency_indicator,
                resolved_report_count,
                participants_count,
                report_submission_form_intro,
                customized_report_template,
                cwe_field_hidden,
                report_template,
                signal_target,
                has_open_scope,
                pays_within_one_month,
                protected_by_gold_standard_safe_harbor,
                protected_by_ai_safe_harbor,
                disclosure_declaration,
                declarative_introduction,
                contact_email,
                display_show_response_efficiency_indicator,
                display_show_mean_first_response_time,
                display_show_mean_report_triage_time,
                display_show_mean_bounty_time,
                display_show_mean_resolution_time,
                display_show_top_bounties,
                display_show_average_bounty,
                display_show_total_bounties_paid,
                display_show_total_reports_per_asset,
                sla_average_time_to_first_program_response,
                sla_average_time_to_report_triage,
                sla_average_time_to_bounty_awarded,
                sla_average_time_to_report_resolved,
                external_program_id,
                last_import_run_id,
                overview_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(handle) DO UPDATE SET
                remote_id = excluded.remote_id,
                name = excluded.name,
                url = excluded.url,
                type = excluded.type,
                state = excluded.state,
                submission_state = excluded.submission_state,
                offers_bounties = excluded.offers_bounties,
                currency = excluded.currency,
                profile_picture_url = excluded.profile_picture_url,
                about = excluded.about,
                policy = excluded.policy,
                scope_description = excluded.scope_description,
                triage_active = excluded.triage_active,
                publicly_visible_retesting = excluded.publicly_visible_retesting,
                allows_private_disclosure = excluded.allows_private_disclosure,
                allows_bounty_splitting = excluded.allows_bounty_splitting,
                launched_at = excluded.launched_at,
                last_updated_at = excluded.last_updated_at,
                minimum_bounty_table_value = excluded.minimum_bounty_table_value,
                maximum_bounty_table_value = excluded.maximum_bounty_table_value,
                base_bounty = excluded.base_bounty,
                response_efficiency_percentage = excluded.response_efficiency_percentage,
                response_efficiency_indicator = excluded.response_efficiency_indicator,
                resolved_report_count = excluded.resolved_report_count,
                participants_count = excluded.participants_count,
                report_submission_form_intro = excluded.report_submission_form_intro,
                customized_report_template = excluded.customized_report_template,
                cwe_field_hidden = excluded.cwe_field_hidden,
                report_template = excluded.report_template,
                signal_target = excluded.signal_target,
                has_open_scope = excluded.has_open_scope,
                pays_within_one_month = excluded.pays_within_one_month,
                protected_by_gold_standard_safe_harbor = excluded.protected_by_gold_standard_safe_harbor,
                protected_by_ai_safe_harbor = excluded.protected_by_ai_safe_harbor,
                disclosure_declaration = excluded.disclosure_declaration,
                declarative_introduction = excluded.declarative_introduction,
                contact_email = excluded.contact_email,
                display_show_response_efficiency_indicator = excluded.display_show_response_efficiency_indicator,
                display_show_mean_first_response_time = excluded.display_show_mean_first_response_time,
                display_show_mean_report_triage_time = excluded.display_show_mean_report_triage_time,
                display_show_mean_bounty_time = excluded.display_show_mean_bounty_time,
                display_show_mean_resolution_time = excluded.display_show_mean_resolution_time,
                display_show_top_bounties = excluded.display_show_top_bounties,
                display_show_average_bounty = excluded.display_show_average_bounty,
                display_show_total_bounties_paid = excluded.display_show_total_bounties_paid,
                display_show_total_reports_per_asset = excluded.display_show_total_reports_per_asset,
                sla_average_time_to_first_program_response = excluded.sla_average_time_to_first_program_response,
                sla_average_time_to_report_triage = excluded.sla_average_time_to_report_triage,
                sla_average_time_to_bounty_awarded = excluded.sla_average_time_to_bounty_awarded,
                sla_average_time_to_report_resolved = excluded.sla_average_time_to_report_resolved,
                external_program_id = excluded.external_program_id,
                last_import_run_id = excluded.last_import_run_id,
                overview_json = excluded.overview_json,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                team["id"],
                team["handle"],
                team.get("name"),
                team.get("url"),
                team.get("type"),
                team.get("state"),
                team.get("submission_state"),
                as_bool_int(team.get("offers_bounties")) or 0,
                team.get("currency"),
                team.get("profile_picture"),
                team.get("about"),
                team.get("policy"),
                team.get("scope_description"),
                as_bool_int(team.get("triage_active")),
                as_bool_int(team.get("publicly_visible_retesting")),
                as_bool_int(team.get("allows_private_disclosure")),
                as_bool_int(team.get("allows_bounty_splitting")),
                team.get("launched_at"),
                team.get("last_updated_at"),
                team.get("minimum_bounty_table_value"),
                team.get("maximum_bounty_table_value"),
                team.get("base_bounty"),
                team.get("response_efficiency_percentage"),
                team.get("response_efficiency_indicator"),
                team.get("resolved_report_count"),
                team.get("participants_count"),
                team.get("report_submission_form_intro"),
                as_bool_int(team.get("customized_report_template")),
                as_bool_int(team.get("cwe_field_hidden")),
                team.get("report_template"),
                signal_requirements.get("target_signal"),
                as_bool_int(declarative_policy.get("has_open_scope")),
                as_bool_int(declarative_policy.get("pays_within_one_month")),
                as_bool_int(declarative_policy.get("protected_by_gold_standard_safe_harbor")),
                as_bool_int(declarative_policy.get("protected_by_ai_safe_harbor")),
                declarative_policy.get("disclosure_declaration"),
                declarative_policy.get("introduction"),
                declarative_policy.get("contact_email"),
                as_bool_int(display_options.get("show_response_efficiency_indicator")),
                as_bool_int(display_options.get("show_mean_first_response_time")),
                as_bool_int(display_options.get("show_mean_report_triage_time")),
                as_bool_int(display_options.get("show_mean_bounty_time")),
                as_bool_int(display_options.get("show_mean_resolution_time")),
                as_bool_int(display_options.get("show_top_bounties")),
                as_bool_int(display_options.get("show_average_bounty")),
                as_bool_int(display_options.get("show_total_bounties_paid")),
                as_bool_int(display_options.get("show_total_reports_per_asset")),
                sla.get("average_time_to_first_program_response"),
                sla.get("average_time_to_report_triage"),
                sla.get("average_time_to_bounty_awarded"),
                sla.get("average_time_to_report_resolved"),
                external_program.get("id"),
                import_run_id,
                json_dumps(team),
            ),
        )

        row = self.connection.execute(
            "SELECT id FROM programs WHERE handle = ?",
            (team["handle"],),
        ).fetchone()
        if row is None:
            raise RuntimeError(f"Failed to persist program '{team['handle']}'")
        return int(row[0])

    def replace_program_children(
        self,
        program_id: int,
        team: dict[str, Any],
        scopes: list[dict[str, Any]],
    ) -> ImportCounts:
        counts = ImportCounts()
        counts.scope_total_count = len(scopes)
        counts.in_scope_count = sum(1 for scope in scopes if scope.get("eligible_for_submission"))
        counts.out_of_scope_count = sum(1 for scope in scopes if not scope.get("eligible_for_submission"))
        counts.bounty_eligible_scope_count = sum(1 for scope in scopes if scope.get("eligible_for_bounty"))

        self.connection.execute("DELETE FROM program_bounty_tables WHERE program_id = ?", (program_id,))
        self.connection.execute("DELETE FROM program_platform_standard_exclusions WHERE program_id = ?", (program_id,))
        self.connection.execute("DELETE FROM program_scope_exclusions WHERE program_id = ?", (program_id,))
        self.connection.execute("DELETE FROM program_exemplary_standards_exclusions WHERE program_id = ?", (program_id,))
        self.connection.execute("DELETE FROM scopes WHERE program_id = ?", (program_id,))

        self.insert_declarative_policy_children(program_id, team.get("declarative_policy") or {})
        counts.bounty_table_row_count = self.insert_bounty_table(program_id, team.get("bounty_table"))
        self.insert_scopes(program_id, scopes)

        self.connection.execute(
            """
            UPDATE programs
            SET scope_total_count = ?,
                in_scope_count = ?,
                out_of_scope_count = ?,
                bounty_eligible_scope_count = ?,
                bounty_table_row_count = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                counts.scope_total_count,
                counts.in_scope_count,
                counts.out_of_scope_count,
                counts.bounty_eligible_scope_count,
                counts.bounty_table_row_count,
                program_id,
            ),
        )

        return counts

    def insert_declarative_policy_children(self, program_id: int, declarative_policy: dict[str, Any]) -> None:
        for exclusion in as_list(declarative_policy.get("platform_standards_exclusions")):
            self.connection.execute(
                """
                INSERT INTO program_platform_standard_exclusions (
                    program_id,
                    remote_id,
                    platform_standard,
                    justification,
                    raw_json
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    program_id,
                    exclusion.get("id"),
                    exclusion.get("platform_standard"),
                    exclusion.get("justification"),
                    json_dumps(exclusion),
                ),
            )

        for exclusion in as_list(declarative_policy.get("scope_exclusions")):
            self.connection.execute(
                """
                INSERT INTO program_scope_exclusions (
                    program_id,
                    remote_id,
                    remote_database_id,
                    category,
                    details,
                    created_at_remote,
                    raw_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    program_id,
                    exclusion.get("id"),
                    exclusion.get("_id"),
                    exclusion.get("category"),
                    exclusion.get("details"),
                    exclusion.get("created_at"),
                    json_dumps(exclusion),
                ),
            )

        for exclusion_text in as_list(declarative_policy.get("exemplary_standards_exclusions")):
            self.connection.execute(
                """
                INSERT INTO program_exemplary_standards_exclusions (
                    program_id,
                    exclusion_text
                )
                VALUES (?, ?)
                """,
                (program_id, exclusion_text),
            )

    def insert_bounty_table(self, program_id: int, bounty_table: dict[str, Any] | None) -> int:
        if not bounty_table:
            return 0

        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT INTO program_bounty_tables (
                program_id,
                remote_id,
                description,
                use_range,
                low_label,
                medium_label,
                high_label,
                critical_label,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                bounty_table.get("id"),
                bounty_table.get("description"),
                as_bool_int(bounty_table.get("use_range")),
                bounty_table.get("low_label"),
                bounty_table.get("medium_label"),
                bounty_table.get("high_label"),
                bounty_table.get("critical_label"),
                json_dumps(bounty_table),
            ),
        )
        bounty_table_id = int(cursor.lastrowid)

        row_count = 0
        for edge in as_list((bounty_table.get("bounty_table_rows") or {}).get("edges")):
            row = edge.get("node") or {}
            cursor.execute(
                """
                INSERT INTO bounty_table_rows (
                    program_id,
                    bounty_table_id,
                    row_remote_id,
                    row_database_id,
                    structured_scope_remote_id,
                    structured_scope_asset_identifier,
                    low,
                    medium,
                    high,
                    critical,
                    low_minimum,
                    medium_minimum,
                    high_minimum,
                    critical_minimum,
                    raw_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    program_id,
                    bounty_table_id,
                    row.get("id"),
                    row.get("_id"),
                    (row.get("structured_scope") or {}).get("id"),
                    (row.get("structured_scope") or {}).get("asset_identifier"),
                    row.get("low"),
                    row.get("medium"),
                    row.get("high"),
                    row.get("critical"),
                    row.get("low_minimum"),
                    row.get("medium_minimum"),
                    row.get("high_minimum"),
                    row.get("critical_minimum"),
                    json_dumps(row),
                ),
            )
            row_count += 1

        return row_count

    def insert_scopes(self, program_id: int, scopes: list[dict[str, Any]]) -> None:
        cursor = self.connection.cursor()

        for scope in scopes:
            cursor.execute(
                """
                INSERT INTO scopes (
                    program_id,
                    remote_id,
                    identifier,
                    display_name,
                    instruction,
                    cvss_score,
                    eligible_for_bounty,
                    eligible_for_submission,
                    asm_system_tags_json,
                    created_at_remote,
                    updated_at_remote,
                    total_resolved_reports,
                    raw_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    program_id,
                    scope.get("id"),
                    scope.get("identifier"),
                    scope.get("display_name"),
                    scope.get("instruction"),
                    scope.get("cvss_score"),
                    as_bool_int(scope.get("eligible_for_bounty")),
                    as_bool_int(scope.get("eligible_for_submission")),
                    json_dumps(scope.get("asm_system_tags")),
                    scope.get("created_at"),
                    scope.get("updated_at"),
                    scope.get("total_resolved_reports"),
                    json_dumps(scope),
                ),
            )
            scope_id = int(cursor.lastrowid)

            for attachment in as_list(scope.get("attachments")):
                cursor.execute(
                    """
                    INSERT INTO scope_attachments (
                        scope_id,
                        remote_id,
                        file_name,
                        file_size,
                        content_type,
                        expiring_url,
                        raw_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scope_id,
                        attachment.get("id"),
                        attachment.get("file_name"),
                        attachment.get("file_size"),
                        attachment.get("content_type"),
                        attachment.get("expiring_url"),
                        json_dumps(attachment),
                    ),
                )

    def import_program(self, import_run_id: int, handle: str) -> ImportCounts:
        team = self.client.fetch_program_overview(handle)
        scopes = self.client.fetch_program_scopes(handle, self.scope_page_size)
        source_scope_count = len(scopes)
        scopes, duplicate_scope_count = dedupe_scopes(scopes)
        program_id = self.upsert_program(import_run_id, team)
        counts = self.replace_program_children(program_id, team, scopes)
        counts.source_scope_count = source_scope_count
        counts.duplicate_scope_count = duplicate_scope_count
        self.connection.commit()
        return counts

    def import_programs(self, handles: Iterable[str] | None = None, limit: int | None = None) -> None:
        import_run_id = self.create_import_run()
        failed_count = 0
        imported_count = 0

        if handles:
            enumerated = [{"handle": handle} for handle in sorted(set(handles))]
            source_graphql_count = len(enumerated)
        else:
            enumerated = self.client.enumerate_open_public_programs()
            source_graphql_count = len(enumerated)

        if limit is not None:
            enumerated = enumerated[:limit]

        print(f"Import run {import_run_id} started")
        print(f"Target programs: {len(enumerated)}")
        print(f"Database: {self.db_path}")

        for index, program in enumerate(enumerated, start=1):
            handle = program["handle"]
            print(f"[{index}/{len(enumerated)}] Importing {handle} ...")
            try:
                counts = self.import_program(import_run_id, handle)
                imported_count += 1
                print(
                    "  scopes={scope_total_count} raw_scopes={source_scope_count} "
                    "duplicates={duplicate_scope_count} in_scope={in_scope_count} "
                    "out_of_scope={out_of_scope_count} bounty_rows={bounty_table_row_count}".format(
                        **counts.__dict__
                    )
                )
            except Exception as exc:  # noqa: BLE001
                failed_count += 1
                self.connection.rollback()
                self.record_import_error(import_run_id, handle, str(exc))
                print(f"  failed: {exc}")

        self.finalize_import_run(
            import_run_id=import_run_id,
            source_graphql_count=source_graphql_count,
            imported_count=imported_count,
            failed_count=failed_count,
        )

        print("\nImport complete")
        print(f"Imported: {imported_count}")
        print(f"Failed: {failed_count}")
        print(f"Source count: {source_graphql_count}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import live public HackerOne program data into CODEXDATABASE.",
    )
    parser.add_argument(
        "--db-path",
        default=str(DEFAULT_DB_PATH),
        help=f"Path to the SQLite database. Default: {DEFAULT_DB_PATH}",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY_SECONDS,
        help=f"Minimum delay between GraphQL requests in seconds. Default: {DEFAULT_DELAY_SECONDS}",
    )
    parser.add_argument(
        "--scope-page-size",
        type=int,
        default=DEFAULT_SCOPE_PAGE_SIZE,
        help=f"Scope page size for structured_scopes_search pagination. Default: {DEFAULT_SCOPE_PAGE_SIZE}",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help=f"Maximum retries per GraphQL request. Default: {DEFAULT_MAX_RETRIES}",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit the number of programs imported after enumeration.",
    )
    parser.add_argument(
        "--handles",
        nargs="+",
        default=None,
        help="Import only the specified HackerOne handles.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    importer = CodeXDatabaseImporter(
        db_path=Path(args.db_path),
        delay_seconds=args.delay,
        scope_page_size=args.scope_page_size,
        max_retries=args.max_retries,
    )
    try:
        importer.import_programs(handles=args.handles, limit=args.limit)
        return 0
    finally:
        importer.close()


if __name__ == "__main__":
    raise SystemExit(main())
