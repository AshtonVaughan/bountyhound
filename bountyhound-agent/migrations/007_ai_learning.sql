-- AI Learning Tables Migration
-- Created: 2026-02-16
-- Purpose: Add tables for AI-powered continuous learning

-- Create learned patterns table
CREATE TABLE IF NOT EXISTS learned_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    tech JSON NOT NULL,
    indicators JSON,
    exploit_template TEXT,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    success_rate REAL GENERATED ALWAYS AS (
        CAST(success_count AS REAL) / NULLIF(success_count + failure_count, 0)
    ) VIRTUAL,
    targets_succeeded JSON,
    targets_failed JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create hypothesis tracking table
CREATE TABLE IF NOT EXISTS hypothesis_tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    hypothesis_title TEXT NOT NULL,
    hypothesis_test TEXT NOT NULL,
    rationale TEXT,
    confidence TEXT,
    result TEXT, -- 'success', 'failure', 'error'
    finding_id INTEGER,
    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

-- Create exploit chains table
CREATE TABLE IF NOT EXISTS exploit_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    chain_title TEXT NOT NULL,
    steps JSON NOT NULL,
    findings_used JSON NOT NULL,
    impact TEXT,
    verified BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index for faster pattern lookups
CREATE INDEX IF NOT EXISTS idx_learned_patterns_tech ON learned_patterns(tech);
CREATE INDEX IF NOT EXISTS idx_learned_patterns_success_rate ON learned_patterns(success_rate);
CREATE INDEX IF NOT EXISTS idx_hypothesis_tests_target ON hypothesis_tests(target);
CREATE INDEX IF NOT EXISTS idx_hypothesis_tests_result ON hypothesis_tests(result);
CREATE INDEX IF NOT EXISTS idx_exploit_chains_target ON exploit_chains(target);
