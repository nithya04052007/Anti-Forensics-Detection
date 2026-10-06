-- Automated Anti-Forensics Detection System
-- SQLite Database Schema (Phase 1 & Phase 2 Persistent Storage)

PRAGMA foreign_keys = ON;

-- ============================================================================
-- Table: users
-- Stores investigator & analyst authentication credentials and roles
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name       TEXT,
    username        TEXT UNIQUE NOT NULL,
    email           TEXT UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'analyst', -- 'admin', 'analyst', 'investigator'
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login      TIMESTAMP
);

-- ============================================================================
-- Table: scans
-- Stores high-level persistent scan execution sessions and metadata
-- ============================================================================
CREATE TABLE IF NOT EXISTS scans (
    scan_id                 TEXT PRIMARY KEY,
    user_id                 INTEGER,                                -- Owner user ID (for user isolation)
    target_type             TEXT NOT NULL,                          -- 'single_file', 'filesystem', 'memory', 'live_system', 'demo_simulation'
    target_path             TEXT,                                   -- Target folder, file path, memory dump path, or hostname
    filename                TEXT,                                   -- Base evidence file / target name
    file_size               INTEGER DEFAULT 0,                      -- Evidence file size in bytes
    file_type               TEXT,                                   -- File extension or claimed signature
    sha256_hash             TEXT,                                   -- Cryptographic SHA-256 hash of evidence
    start_time              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    end_time                TIMESTAMP,
    duration_seconds        REAL DEFAULT 0.0,                       -- Scan duration in seconds
    status                  TEXT NOT NULL DEFAULT 'IN_PROGRESS',    -- 'IN_PROGRESS', 'COMPLETED', 'FAILED'
    risk_score              REAL DEFAULT 0.0,                       -- Threat / Anomaly score (0.0 - 100.0)
    risk_level              TEXT DEFAULT 'LOW',                     -- 'CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    total_artifacts         INTEGER DEFAULT 0,
    total_findings          INTEGER DEFAULT 0,
    critical_count          INTEGER DEFAULT 0,
    high_count              INTEGER DEFAULT 0,
    evasion_findings_count  INTEGER DEFAULT 0,
    ml_prediction           TEXT,                                   -- 'Normal', 'Suspicious'
    ml_probability          REAL DEFAULT 0.0,                       -- Probability of anti-forensics evasion
    ml_confidence           REAL DEFAULT 0.0,                       -- Model confidence percent (e.g. 96.7)
    report_path             TEXT,                                   -- Path or reference to generated report
    detector_version        TEXT DEFAULT 'DFIR-Engine-v2.0',        -- Detector & model version for forensic provenance
    summary_json            TEXT,                                   -- JSON-encoded summary metrics
    result_json             TEXT,                                   -- Full structured scan result for immutable historical reproduction
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ============================================================================
-- Table: findings
-- Stores discrete forensic anomalies and anti-forensics indicators detected
-- ============================================================================
CREATE TABLE IF NOT EXISTS findings (
    finding_id      TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    category        TEXT NOT NULL,          -- 'timestamp', 'log', 'hidden_file', 'memory', 'yara', 'registry', 'extension_tampering', 'covert_storage'
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
-- Indexes for fast querying, filtering, user isolation & reporting
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_user_start_time ON scans(user_id, start_time DESC);
CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time DESC);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);
CREATE INDEX IF NOT EXISTS idx_scans_filename ON scans(filename);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_features_scan_id ON features(scan_id);
CREATE INDEX IF NOT EXISTS idx_features_name ON features(feature_name);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);


