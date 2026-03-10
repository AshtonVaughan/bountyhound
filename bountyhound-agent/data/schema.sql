-- bountyhound-agent/data/schema.sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS programs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    handle          TEXT    NOT NULL UNIQUE,
    name            TEXT,
    platform        TEXT    NOT NULL DEFAULT 'hackerone',
    url             TEXT,
    offers_bounties INTEGER NOT NULL DEFAULT 0,
    min_bounty      REAL,
    max_bounty      REAL,
    scope_json      TEXT,
    out_of_scope_json TEXT,
    policy_url      TEXT,
    last_updated    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cves (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                  TEXT    UNIQUE,
    description             TEXT,
    cvss_score              REAL,
    cvss_vector             TEXT,
    affected_products_json  TEXT,
    exploit_available       INTEGER NOT NULL DEFAULT 0,
    exploit_url             TEXT,
    published_date          TEXT,
    last_modified           TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id      INTEGER NOT NULL REFERENCES programs(id),
    domain          TEXT    NOT NULL,
    model_json      TEXT,
    source_available INTEGER NOT NULL DEFAULT 0,
    auth_tested     INTEGER NOT NULL DEFAULT 0,
    last_updated    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program_id, domain)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    url             TEXT    NOT NULL,
    method          TEXT,
    auth_required   INTEGER NOT NULL DEFAULT 0,
    params_json     TEXT,
    discovered_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id                  TEXT    PRIMARY KEY,
    target_id           INTEGER NOT NULL REFERENCES targets(id),
    title               TEXT    NOT NULL,
    attack_surface      TEXT,
    technique           TEXT,
    track               INTEGER NOT NULL DEFAULT 2,
    novelty_score       REAL,
    exploitability_score REAL,
    impact_score        REAL,
    effort_score        REAL,
    total_score         REAL,
    status              TEXT    NOT NULL DEFAULT 'pending',
    outcome             TEXT,
    tested_at           TIMESTAMP,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hypothesis_id   TEXT    REFERENCES hypotheses(id),
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    title           TEXT    NOT NULL,
    severity        TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    status          TEXT    NOT NULL DEFAULT 'draft',
    report_path     TEXT,
    payout          REAL,
    submitted_at    TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER NOT NULL REFERENCES findings(id),
    evidence_type   TEXT    NOT NULL,
    file_path       TEXT,
    description     TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hunt_sessions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id           INTEGER NOT NULL REFERENCES targets(id),
    started_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at        TIMESTAMP,
    hypotheses_tested   INTEGER NOT NULL DEFAULT 0,
    findings_count      INTEGER NOT NULL DEFAULT 0,
    notes               TEXT
);

CREATE INDEX IF NOT EXISTS idx_cves_products ON cves(affected_products_json);
CREATE INDEX IF NOT EXISTS idx_hypotheses_target ON hypotheses(target_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id, status);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
