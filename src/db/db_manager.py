"""
Database Manager for Anti-Forensics Detection System
Handles SQLite schema creation, CRUD operations, transactions, user-isolated persistent scan history, and feature matrix export.
"""

import sqlite3
import json
import os
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash

from ..collection.models import Finding, ScanResult


class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        # Support DB path from argument, environment variable, or default
        env_db = os.environ.get("DATABASE_PATH") or os.environ.get("DB_PATH") or os.environ.get("SQLITE_DB_PATH")
        self.db_path = db_path or env_db or "anti_forensics.db"
        if os.path.dirname(self.db_path):
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._ensure_schema()
        self.seed_default_admin()

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a configured SQLite connection with foreign keys enabled."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _ensure_schema(self) -> None:
        """Initialize SQLite database schema and run non-destructive migrations."""
        # Run table definitions and migrations
        self._create_inline_schema()
        self._run_migrations()


    def _create_inline_schema(self) -> None:
        """Inline schema fallback in case schema.sql is not found."""
        with self.get_connection() as conn:
            conn.executescript("""
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name       TEXT,
                username        TEXT UNIQUE NOT NULL,
                email           TEXT UNIQUE,
                password_hash   TEXT NOT NULL,
                role            TEXT NOT NULL DEFAULT 'analyst',
                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_login      TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scans (
                scan_id                 TEXT PRIMARY KEY,
                user_id                 INTEGER,
                target_type             TEXT NOT NULL,
                target_path             TEXT,
                filename                TEXT,
                file_size               INTEGER DEFAULT 0,
                file_type               TEXT,
                sha256_hash             TEXT,
                start_time              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                end_time                TIMESTAMP,
                duration_seconds        REAL DEFAULT 0.0,
                status                  TEXT NOT NULL DEFAULT 'IN_PROGRESS',
                risk_score              REAL DEFAULT 0.0,
                risk_level              TEXT DEFAULT 'LOW',
                total_artifacts         INTEGER DEFAULT 0,
                total_findings          INTEGER DEFAULT 0,
                critical_count          INTEGER DEFAULT 0,
                high_count              INTEGER DEFAULT 0,
                evasion_findings_count  INTEGER DEFAULT 0,
                ml_prediction           TEXT,
                ml_probability          REAL DEFAULT 0.0,
                ml_confidence           REAL DEFAULT 0.0,
                report_path             TEXT,
                detector_version        TEXT DEFAULT 'DFIR-Engine-v2.0',
                summary_json            TEXT,
                result_json             TEXT,
                created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                finding_id      TEXT PRIMARY KEY,
                scan_id         TEXT NOT NULL,
                category        TEXT NOT NULL,
                severity        TEXT NOT NULL,
                title           TEXT NOT NULL,
                description     TEXT,
                artifact_path   TEXT,
                evidence_json   TEXT,
                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS features (
                feature_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT NOT NULL,
                feature_name    TEXT NOT NULL,
                feature_value   REAL NOT NULL,
                feature_type    TEXT NOT NULL DEFAULT 'numeric',
                extracted_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
                UNIQUE(scan_id, feature_name)
            );
            """)

    def _run_migrations(self) -> None:
        """Run non-destructive column additions and index creation on existing tables."""
        with self.get_connection() as conn:
            # 1. Users table migrations
            try:
                cursor = conn.execute("PRAGMA table_info(users)")
                u_cols = {row["name"] for row in cursor.fetchall()}
                if "full_name" not in u_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
            except Exception:
                pass

            # 2. Scans table migrations
            try:
                cursor = conn.execute("PRAGMA table_info(scans)")
                s_cols = {row["name"] for row in cursor.fetchall()}

                new_columns = [
                    ("user_id", "INTEGER"),
                    ("filename", "TEXT"),
                    ("file_size", "INTEGER DEFAULT 0"),
                    ("file_type", "TEXT"),
                    ("sha256_hash", "TEXT"),
                    ("duration_seconds", "REAL DEFAULT 0.0"),
                    ("risk_level", "TEXT DEFAULT 'LOW'"),
                    ("critical_count", "INTEGER DEFAULT 0"),
                    ("high_count", "INTEGER DEFAULT 0"),
                    ("evasion_findings_count", "INTEGER DEFAULT 0"),
                    ("ml_prediction", "TEXT"),
                    ("ml_probability", "REAL DEFAULT 0.0"),
                    ("ml_confidence", "REAL DEFAULT 0.0"),
                    ("report_path", "TEXT"),
                    ("detector_version", "TEXT DEFAULT 'DFIR-Engine-v2.0'"),
                    ("result_json", "TEXT"),
                    ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
                    ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                ]

                for col_name, col_type in new_columns:
                    if col_name not in s_cols:
                        conn.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")

                # Populate filename/risk_level for older records if blank
                conn.execute("""
                    UPDATE scans 
                    SET filename = CASE 
                        WHEN target_path IS NOT NULL AND target_path != '' THEN REPLACE(REPLACE(target_path, '\\', '/'), RTRIM(target_path, REPLACE(target_path, '\\', '/')), '')
                        ELSE target_type 
                    END
                    WHERE filename IS NULL OR filename = ''
                """)

                conn.execute("""
                    UPDATE scans 
                    SET risk_level = CASE 
                        WHEN risk_score >= 80.0 THEN 'CRITICAL'
                        WHEN risk_score >= 61.0 THEN 'HIGH'
                        WHEN risk_score >= 31.0 THEN 'MEDIUM'
                        WHEN risk_score > 0.0 THEN 'LOW'
                        ELSE 'CLEAN'
                    END
                    WHERE risk_level IS NULL OR risk_level = ''
                """)

                # If there are orphaned scans without user_id, associate them with admin (user_id=1)
                conn.execute("UPDATE scans SET user_id = 1 WHERE user_id IS NULL AND (SELECT COUNT(*) FROM users WHERE user_id = 1) > 0")

            except Exception:
                pass

            # 3. Create all indexes safely after columns are guaranteed to exist
            try:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_start_time ON scans(user_id, start_time DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_filename ON scans(filename)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_features_scan_id ON features(scan_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_features_name ON features(feature_name)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            except Exception:
                pass

    # =========================================================================
    # Scan Management & Persistent History
    # =========================================================================

    def create_scan(
        self,
        scan_id: str,
        target_type: str,
        target_path: str = "",
        user_id: Optional[int] = None,
        filename: Optional[str] = None,
        file_size: int = 0,
        file_type: Optional[str] = None,
        sha256_hash: Optional[str] = None,
        detector_version: str = "DFIR-Engine-v2.0"
    ) -> None:
        """Record the initiation of a new persistent scan session linked to an authenticated user."""
        now_iso = datetime.now(timezone.utc).isoformat()
        display_name = filename or (os.path.basename(target_path) if target_path else target_type)
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, user_id, target_type, target_path, filename, file_size,
                    file_type, sha256_hash, start_time, status, detector_version,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'IN_PROGRESS', ?, ?, ?)
                """,
                (
                    scan_id, user_id, target_type, target_path, display_name, file_size,
                    file_type, sha256_hash, now_iso, detector_version, now_iso, now_iso
                )
            )

    def complete_scan(
        self,
        scan_id: str,
        total_artifacts: int,
        total_findings: int,
        risk_score: float,
        summary: Optional[Dict[str, Any]] = None,
        status: str = "COMPLETED",
        risk_level: Optional[str] = None,
        critical_count: int = 0,
        high_count: int = 0,
        evasion_findings_count: int = 0,
        ml_prediction: Optional[str] = None,
        ml_probability: float = 0.0,
        ml_confidence: float = 0.0,
        report_path: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        result_json: Optional[Dict[str, Any]] = None,
        sha256_hash: Optional[str] = None,
        filename: Optional[str] = None,
        file_size: Optional[int] = None,
        file_type: Optional[str] = None
    ) -> None:
        """Update scan metadata upon completion with full persistent summary and snapshot."""
        now_iso = datetime.now(timezone.utc).isoformat()
        summary = summary or {}
        
        # Derive risk level if not explicitly provided
        effective_risk_level = risk_level or summary.get("risk_level")
        if not effective_risk_level:
            if risk_score >= 80.0:
                effective_risk_level = "CRITICAL"
            elif risk_score >= 61.0:
                effective_risk_level = "HIGH"
            elif risk_score >= 31.0:
                effective_risk_level = "MEDIUM"
            elif risk_score > 0.0:
                effective_risk_level = "LOW"
            else:
                effective_risk_level = "CLEAN"

        eff_critical = critical_count or summary.get("critical_count", 0)
        eff_high = high_count or summary.get("high_count", 0)
        eff_evasion = evasion_findings_count or summary.get("suspicious_indicators", total_findings)
        eff_ml_pred = ml_prediction or summary.get("ml_prediction", "Normal")
        eff_ml_prob = ml_probability or summary.get("ml_probability", 0.0)
        eff_ml_conf = ml_confidence or summary.get("ml_confidence_percent", 96.7)
        eff_filename = filename or summary.get("file_name")
        eff_size = file_size if file_size is not None else summary.get("file_size", 0)
        eff_ext = file_type or summary.get("extension")
        eff_hash = sha256_hash or summary.get("sha256") or summary.get("sha256_hash")

        with self.get_connection() as conn:
            # Check existing start_time to calculate duration if duration_seconds is not provided
            if duration_seconds is None:
                row = conn.execute("SELECT start_time FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
                if row and row["start_time"]:
                    try:
                        start_dt = datetime.fromisoformat(row["start_time"])
                        duration_seconds = max(0.0, round((datetime.now(timezone.utc) - start_dt).total_seconds(), 2))
                    except Exception:
                        duration_seconds = 0.0
                else:
                    duration_seconds = 0.0

            conn.execute(
                """
                UPDATE scans
                SET end_time = ?,
                    duration_seconds = ?,
                    status = ?,
                    total_artifacts = ?,
                    total_findings = ?,
                    risk_score = ?,
                    risk_level = ?,
                    critical_count = ?,
                    high_count = ?,
                    evasion_findings_count = ?,
                    ml_prediction = ?,
                    ml_probability = ?,
                    ml_confidence = ?,
                    report_path = COALESCE(?, report_path),
                    filename = COALESCE(?, filename),
                    file_size = CASE WHEN ? > 0 THEN ? ELSE file_size END,
                    file_type = COALESCE(?, file_type),
                    sha256_hash = COALESCE(?, sha256_hash),
                    summary_json = ?,
                    result_json = ?,
                    updated_at = ?
                WHERE scan_id = ?
                """,
                (
                    now_iso,
                    duration_seconds,
                    status,
                    total_artifacts,
                    total_findings,
                    round(risk_score, 2),
                    effective_risk_level,
                    eff_critical,
                    eff_high,
                    eff_evasion,
                    eff_ml_pred,
                    eff_ml_prob,
                    eff_ml_conf,
                    report_path,
                    eff_filename,
                    eff_size, eff_size,
                    eff_ext,
                    eff_hash,
                    json.dumps(summary) if summary else None,
                    json.dumps(result_json) if result_json else None,
                    now_iso,
                    scan_id
                )
            )

    def fail_scan(self, scan_id: str, error_message: str, user_id: Optional[int] = None) -> None:
        """Mark a scan session as failed with error details recorded."""
        now_iso = datetime.now(timezone.utc).isoformat()
        err_summary = {"error": error_message, "failed_at": now_iso}
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE scans
                SET end_time = ?, status = 'FAILED', summary_json = ?, updated_at = ?
                WHERE scan_id = ?
                """,
                (now_iso, json.dumps(err_summary), now_iso, scan_id)
            )

    def get_scan(self, scan_id: str, user_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieve scan record by scan_id with optional user_id isolation check.
        Returns None if not found or if user does not have permission.
        """
        query = "SELECT * FROM scans WHERE scan_id = ?"
        params = [scan_id]
        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)

        with self.get_connection() as conn:
            row = conn.execute(query, params).fetchone()
            if row:
                d = dict(row)
                if d.get("summary_json"):
                    try:
                        d["summary"] = json.loads(d["summary_json"])
                    except Exception:
                        d["summary"] = {}
                else:
                    d["summary"] = {}

                if d.get("result_json"):
                    try:
                        d["result"] = json.loads(d["result_json"])
                    except Exception:
                        d["result"] = None
                else:
                    d["result"] = None
                return d
            return None

    def list_scans(
        self,
        user_id: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        risk_level: Optional[str] = None,
        status: Optional[str] = None,
        sort_by: str = "newest"
    ) -> List[Dict[str, Any]]:
        """
        List historical scan executions with user data isolation, search, filtering, and sorting.
        """
        query = "SELECT * FROM scans WHERE 1=1"
        params: List[Any] = []

        # User data isolation (strict user_id equality)
        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)

        # Search filter (filename, target_path, scan_id, sha256_hash)
        if search and search.strip():
            clean_search = f"%{search.strip()}%"
            query += " AND (filename LIKE ? OR target_path LIKE ? OR scan_id LIKE ? OR sha256_hash LIKE ?)"
            params.extend([clean_search, clean_search, clean_search, clean_search])

        # Risk level filter
        if risk_level and risk_level.upper() != "ALL":
            query += " AND UPPER(risk_level) = ?"
            params.append(risk_level.strip().upper())

        # Status filter
        if status and status.upper() != "ALL":
            query += " AND UPPER(status) = ?"
            params.append(status.strip().upper())

        # Sorting
        if sort_by == "oldest":
            query += " ORDER BY start_time ASC"
        elif sort_by == "highest_risk":
            query += " ORDER BY risk_score DESC, start_time DESC"
        elif sort_by == "lowest_risk":
            query += " ORDER BY risk_score ASC, start_time DESC"
        else:  # default newest
            query += " ORDER BY start_time DESC"

        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                if d.get("summary_json"):
                    try:
                        d["summary"] = json.loads(d["summary_json"])
                    except Exception:
                        d["summary"] = {}
                else:
                    d["summary"] = {}

                if d.get("result_json"):
                    try:
                        d["result"] = json.loads(d["result_json"])
                    except Exception:
                        d["result"] = None
                else:
                    d["result"] = None
                results.append(d)
            return results

    def count_scans(
        self,
        user_id: Optional[int] = None,
        search: Optional[str] = None,
        risk_level: Optional[str] = None,
        status: Optional[str] = None
    ) -> int:
        """Count total matching scans for pagination."""
        query = "SELECT COUNT(*) as total FROM scans WHERE 1=1"
        params: List[Any] = []

        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)

        if search and search.strip():
            clean_search = f"%{search.strip()}%"
            query += " AND (filename LIKE ? OR target_path LIKE ? OR scan_id LIKE ? OR sha256_hash LIKE ?)"
            params.extend([clean_search, clean_search, clean_search, clean_search])

        if risk_level and risk_level.upper() != "ALL":
            query += " AND UPPER(risk_level) = ?"
            params.append(risk_level.strip().upper())

        if status and status.upper() != "ALL":
            query += " AND UPPER(status) = ?"
            params.append(status.strip().upper())

        with self.get_connection() as conn:
            row = conn.execute(query, params).fetchone()
            return row["total"] if row else 0

    def delete_scan(self, scan_id: str, user_id: Optional[int] = None) -> bool:
        """
        Safely delete a scan record and its cascaded findings & features with user verification.
        Returns True if deleted, False if not found or unauthorized.
        """
        with self.get_connection() as conn:
            if user_id is not None:
                conn.execute(
                    "DELETE FROM features WHERE scan_id IN (SELECT scan_id FROM scans WHERE scan_id = ? AND user_id = ?)",
                    (scan_id, user_id)
                )
                conn.execute(
                    "DELETE FROM findings WHERE scan_id IN (SELECT scan_id FROM scans WHERE scan_id = ? AND user_id = ?)",
                    (scan_id, user_id)
                )
                cursor = conn.execute("DELETE FROM scans WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
            else:
                conn.execute("DELETE FROM features WHERE scan_id = ?", (scan_id,))
                conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            return cursor.rowcount > 0

    def get_user_scan_stats(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """Compute aggregated metrics specifically for the authenticated user."""
        query = """
        SELECT 
            COUNT(*) as total_scans,
            COALESCE(SUM(total_findings), 0) as total_findings,
            COALESCE(SUM(CASE WHEN risk_level IN ('HIGH', 'CRITICAL') OR risk_score >= 61.0 THEN 1 ELSE 0 END), 0) as critical_findings,
            COALESCE(AVG(risk_score), 0.0) as avg_risk_score
        FROM scans
        WHERE 1=1
        """
        params: List[Any] = []
        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)

        with self.get_connection() as conn:
            row = conn.execute(query, params).fetchone()
            if row:
                return {
                    "total_scans": row["total_scans"],
                    "total_findings": row["total_findings"],
                    "critical_findings": row["critical_findings"],
                    "high_risk_scans": row["critical_findings"],
                    "avg_risk_score": round(row["avg_risk_score"], 1)
                }
            return {"total_scans": 0, "total_findings": 0, "critical_findings": 0, "high_risk_scans": 0, "avg_risk_score": 0.0}

    # =========================================================================
    # Findings Management
    # =========================================================================

    def insert_finding(self, scan_id: str, finding: Finding) -> None:
        """Insert a single finding into the database."""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings (
                    finding_id, scan_id, category, severity, title, description,
                    artifact_path, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.finding_id,
                    scan_id,
                    finding.category,
                    finding.severity,
                    finding.title,
                    finding.description,
                    finding.artifact_path,
                    json.dumps(finding.evidence),
                    finding.created_at
                )
            )

    def insert_findings_batch(self, scan_id: str, findings: List[Finding]) -> None:
        """Insert a list of findings in a single atomic transaction."""
        if not findings:
            return
        with self.get_connection() as conn:
            data = [
                (
                    f.finding_id,
                    scan_id,
                    f.category,
                    f.severity,
                    f.title,
                    f.description,
                    f.artifact_path,
                    json.dumps(f.evidence),
                    f.created_at
                )
                for f in findings
            ]
            conn.executemany(
                """
                INSERT OR REPLACE INTO findings (
                    finding_id, scan_id, category, severity, title, description,
                    artifact_path, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                data
            )

    def get_findings(
        self,
        scan_id: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve findings for a scan with optional category, severity, and user_id filtering."""
        if user_id is not None:
            query = """
            SELECT f.* FROM findings f
            JOIN scans s ON f.scan_id = s.scan_id
            WHERE f.scan_id = ? AND s.user_id = ?
            """
            params: List[Any] = [scan_id, user_id]
        else:
            query = "SELECT * FROM findings WHERE scan_id = ?"
            params = [scan_id]

        if category:
            query += " AND f.category = ?" if user_id is not None else " AND category = ?"
            params.append(category)
        if severity:
            query += " AND f.severity = ?" if user_id is not None else " AND severity = ?"
            params.append(severity)

        query += " ORDER BY f.created_at ASC" if user_id is not None else " ORDER BY created_at ASC"

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                if d.get("evidence_json"):
                    try:
                        d["evidence"] = json.loads(d["evidence_json"])
                    except Exception:
                        d["evidence"] = {}
                results.append(d)
            return results

    # =========================================================================
    # Features Management (ML-Ready)
    # =========================================================================

    def insert_features(self, scan_id: str, features: Dict[str, Any]) -> None:
        """Insert or update extracted feature vector for a scan."""
        if not features:
            return

        with self.get_connection() as conn:
            data = []
            for name, value in features.items():
                if isinstance(value, bool):
                    f_val = 1.0 if value else 0.0
                    f_type = "boolean"
                elif isinstance(value, (int, float)):
                    f_val = float(value)
                    f_type = "ratio" if ("ratio" in name or "density" in name) else "numeric"
                else:
                    try:
                        f_val = float(value)
                        f_type = "numeric"
                    except (ValueError, TypeError):
                        continue

                data.append((scan_id, name, f_val, f_type))

            conn.executemany(
                """
                INSERT INTO features (scan_id, feature_name, feature_value, feature_type)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(scan_id, feature_name) DO UPDATE SET
                    feature_value = excluded.feature_value,
                    feature_type = excluded.feature_type,
                    extracted_at = CURRENT_TIMESTAMP
                """,
                data
            )

    def get_features(self, scan_id: str, user_id: Optional[int] = None) -> Dict[str, float]:
        """Retrieve features for a single scan as a dictionary with user verification."""
        with self.get_connection() as conn:
            if user_id is not None:
                query = """
                SELECT f.feature_name, f.feature_value
                FROM features f
                JOIN scans s ON f.scan_id = s.scan_id
                WHERE f.scan_id = ? AND s.user_id = ?
                """
                params = (scan_id, user_id)
            else:
                query = "SELECT feature_name, feature_value FROM features WHERE scan_id = ?"
                params = (scan_id,)

            rows = conn.execute(query, params).fetchall()
            return {row["feature_name"]: row["feature_value"] for row in rows}

    def get_features_dataframe(self, scan_id: Optional[str] = None, user_id: Optional[int] = None) -> pd.DataFrame:
        """
        Pivot the features table into a wide pandas DataFrame (1 row per scan_id, columns as features).
        Ideal for training or inference with ML classifiers (Random Forest, XGBoost, etc.).
        """
        query = """
        SELECT f.scan_id, s.target_type, s.risk_score, f.feature_name, f.feature_value
        FROM features f
        JOIN scans s ON f.scan_id = s.scan_id
        WHERE 1=1
        """
        params = []
        if scan_id:
            query += " AND f.scan_id = ?"
            params.append(scan_id)
        if user_id is not None:
            query += " AND s.user_id = ?"
            params.append(user_id)

        with self.get_connection() as conn:
            df = pd.read_sql_query(query, conn, params=params)

        if df.empty:
            return pd.DataFrame()

        # Pivot long table to wide ML feature table
        pivot_df = df.pivot_table(
            index=["scan_id", "target_type", "risk_score"],
            columns="feature_name",
            values="feature_value",
            aggfunc="first"
        ).reset_index()

        pivot_df.columns.name = None
        return pivot_df

    # =========================================================================
    # User Management & Authentication
    # =========================================================================

    def create_user(
        self,
        username: str,
        password: str,
        email: Optional[str] = None,
        full_name: Optional[str] = None,
        role: str = "analyst"
    ) -> Optional[int]:
        """
        Create a new user with securely hashed password.
        Returns user_id if successful, or None if username/email already exists.
        """
        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO users (username, email, full_name, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        username.strip().lower(),
                        email.strip().lower() if email else None,
                        full_name.strip() if full_name else None,
                        password_hash,
                        role,
                        datetime.now(timezone.utc).isoformat()
                    )
                )
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None

    def get_user_by_username_or_email(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Retrieve user record by username or email (case-insensitive)."""
        clean_identifier = identifier.strip().lower()
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM users
                WHERE LOWER(username) = ? OR LOWER(email) = ?
                """,
                (clean_identifier, clean_identifier)
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieve user record by email address (case-insensitive)."""
        clean_email = email.strip().lower()
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE LOWER(email) = ?",
                (clean_email,)
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve user record by user_id."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
            return dict(row) if row else None

    def verify_user(self, identifier: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Verify user credentials against stored password hash.
        If valid, updates last_login timestamp and returns user dict (excluding password_hash).
        """
        user = self.get_user_by_username_or_email(identifier)
        if not user:
            return None

        if check_password_hash(user["password_hash"], password):
            now_iso = datetime.now(timezone.utc).isoformat()
            with self.get_connection() as conn:
                conn.execute(
                    "UPDATE users SET last_login = ? WHERE user_id = ?",
                    (now_iso, user["user_id"])
                )
            user_info = {
                "user_id": user["user_id"],
                "username": user["username"],
                "email": user["email"],
                "full_name": user.get("full_name") or user["username"],
                "role": user["role"],
                "last_login": now_iso
            }
            return user_info
        return None

    def list_users(self) -> List[Dict[str, Any]]:
        """List all users without password hashes."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT user_id, full_name, username, email, role, created_at, last_login FROM users ORDER BY created_at ASC"
            ).fetchall()
            return [dict(row) for row in rows]

    def seed_default_admin(
        self,
        default_username: str = "admin",
        default_password: str = "admin123",
        default_email: str = "admin@antiforensics.local"
    ) -> None:
        """Seed a default administrator account if no users currently exist."""
        try:
            with self.get_connection() as conn:
                count = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
                if count == 0:
                    self.create_user(
                        username=default_username,
                        password=default_password,
                        email=default_email,
                        full_name="System Administrator",
                        role="admin"
                    )
        except Exception:
            pass


