-- Automated Anti-Forensics Detection System
-- SQLite Database Schema (Phase 1)

PRAGMA foreign_keys = ON;

-- ============================================================================
-- Table: scans
-- Stores high-level scan execution sessions and metadata
-- ============================================================================
CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    target_type     TEXT NOT NULL,          -- 'filesystem', 'memory', 'live_system', 'event_log', 'demo_simulation'
    target_path     TEXT,                   -- Target folder, memory dump path, or hostname
    start_time      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    end_time        TIMESTAMP,
    status          TEXT NOT NULL DEFAULT 'IN_PROGRESS', -- 'IN_PROGRESS', 'COMPLETED', 'FAILED'
    total_artifacts INTEGER DEFAULT 0,
    total_findings  INTEGER DEFAULT 0,
    risk_score      REAL DEFAULT 0.0,       -- Aggregated Threat / Anomaly score (0.0 - 100.0)
    summary_json    TEXT                    -- JSON-encoded dictionary of summary metrics
);

-- ============================================================================
-- Table: findings
-- Stores discrete forensic anomalies and anti-forensics indicators detected
-- ============================================================================
CREATE TABLE IF NOT EXISTS findings (
    finding_id      TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    category        TEXT NOT NULL,          -- 'timestamp', 'log', 'hidden_file', 'memory', 'yara', 'registry'
    severity        TEXT NOT NULL,          -- 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    title           TEXT NOT NULL,
    description     TEXT,
    artifact_path   TEXT,                   -- File path, event record ID, PID, or registry key
    evidence_json   TEXT,                   -- Structured evidence, timestamps, hex offsets, rule names
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

-- ============================================================================
-- Table: features
-- Stores normalized flat feature vectors extracted per scan for downstream ML models
-- ============================================================================
CREATE TABLE IF NOT EXISTS features (
    feature_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL,
    feature_name    TEXT NOT NULL,
    feature_value   REAL NOT NULL,
    feature_type    TEXT NOT NULL DEFAULT 'numeric', -- 'numeric', 'boolean', 'ratio'
    extracted_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    UNIQUE(scan_id, feature_name)
);

-- ============================================================================
-- Indexes for fast querying & reporting
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_features_scan_id ON features(scan_id);
CREATE INDEX IF NOT EXISTS idx_features_name ON features(feature_name);
CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time);
