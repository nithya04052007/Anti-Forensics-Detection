"""
Database Manager for Anti-Forensics Detection System
Handles SQLite schema creation, CRUD operations, transactions, and feature matrix export.
"""

import sqlite3
import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash

from ..collection.models import Finding, ScanResult


class DatabaseManager:
    def __init__(self, db_path: str = "anti_forensics.db"):
        self.db_path = db_path
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
        """Initialize SQLite database schema if tables do not exist."""
        schema_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "schema.sql")
        if not os.path.exists(schema_path):
            # Fallback to local directory if relative path differs
            schema_path = "schema.sql"

        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as f:
                schema_sql = f.read()
            with self.get_connection() as conn:
                conn.executescript(schema_sql)
        else:
            self._create_inline_schema()

        # Graceful migration: ensure full_name column exists
        try:
            with self.get_connection() as conn:
                cursor = conn.execute("PRAGMA table_info(users)")
                columns = [row["name"] for row in cursor.fetchall()]
                if columns and "full_name" not in columns:
                    conn.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
        except Exception:
            pass

    def _create_inline_schema(self) -> None:
        """Inline schema fallback in case schema.sql is not found."""
        with self.get_connection() as conn:
            conn.executescript("""
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS scans (
                scan_id         TEXT PRIMARY KEY,
                target_type     TEXT NOT NULL,
                target_path     TEXT,
                start_time      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                end_time        TIMESTAMP,
                status          TEXT NOT NULL DEFAULT 'IN_PROGRESS',
                total_artifacts INTEGER DEFAULT 0,
                total_findings  INTEGER DEFAULT 0,
                risk_score      REAL DEFAULT 0.0,
                summary_json    TEXT
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

            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            """)



    # =========================================================================
    # Scan Management
    # =========================================================================

    def create_scan(self, scan_id: str, target_type: str, target_path: str = "") -> None:
        """Record the initiation of a new scan session."""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (scan_id, target_type, target_path, start_time, status)
                VALUES (?, ?, ?, ?, 'IN_PROGRESS')
                """,
                (scan_id, target_type, target_path, datetime.now(timezone.utc).isoformat())
            )

    def complete_scan(
        self,
        scan_id: str,
        total_artifacts: int,
        total_findings: int,
        risk_score: float,
        summary: Dict[str, Any],
        status: str = "COMPLETED"
    ) -> None:
        """Update scan metadata upon completion."""
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE scans
                SET end_time = ?, status = ?, total_artifacts = ?,
                    total_findings = ?, risk_score = ?, summary_json = ?
                WHERE scan_id = ?
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    status,
                    total_artifacts,
                    total_findings,
                    round(risk_score, 2),
                    json.dumps(summary),
                    scan_id
                )
            )

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve scan record by scan_id."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if row:
                d = dict(row)
                if d.get("summary_json"):
                    try:
                        d["summary"] = json.loads(d["summary_json"])
                    except Exception:
                        d["summary"] = {}
                return d
            return None

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List historical scan executions."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY start_time DESC LIMIT ?", (limit,)
            ).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                if d.get("summary_json"):
                    try:
                        d["summary"] = json.loads(d["summary_json"])
                    except Exception:
                        d["summary"] = {}
                results.append(d)
            return results

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
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve findings for a scan with optional category and severity filtering."""
        query = "SELECT * FROM findings WHERE scan_id = ?"
        params = [scan_id]

        if category:
            query += " AND category = ?"
            params.append(category)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY created_at ASC"

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

    def get_features(self, scan_id: str) -> Dict[str, float]:
        """Retrieve features for a single scan as a dictionary."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT feature_name, feature_value FROM features WHERE scan_id = ?",
                (scan_id,)
            ).fetchall()
            return {row["feature_name"]: row["feature_value"] for row in rows}

    def get_features_dataframe(self, scan_id: Optional[str] = None) -> pd.DataFrame:
        """
        Pivot the features table into a wide pandas DataFrame (1 row per scan_id, columns as features).
        Ideal for training or inference with ML classifiers (Random Forest, XGBoost, etc.).
        """
        query = """
        SELECT f.scan_id, s.target_type, s.risk_score, f.feature_name, f.feature_value
        FROM features f
        JOIN scans s ON f.scan_id = s.scan_id
        """
        params = []
        if scan_id:
            query += " WHERE f.scan_id = ?"
            params.append(scan_id)

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


