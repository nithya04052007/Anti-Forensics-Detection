"""
Unit tests for Database Manager & SQLite schema operations
"""

import unittest
import tempfile
import os
import uuid

from src.db.db_manager import DatabaseManager
from src.collection.models import Finding


class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.db = DatabaseManager(db_path=self.temp_file.name)

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def test_scan_lifecycle(self):
        scan_id = str(uuid.uuid4())
        self.db.create_scan(scan_id, target_type="demo_simulation", target_path="C:\\Temp")

        scan = self.db.get_scan(scan_id)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["status"], "IN_PROGRESS")

        self.db.complete_scan(
            scan_id=scan_id,
            total_artifacts=10,
            total_findings=3,
            risk_score=75.5,
            summary={"tested": True}
        )

        completed_scan = self.db.get_scan(scan_id)
        self.assertEqual(completed_scan["status"], "COMPLETED")
        self.assertEqual(completed_scan["risk_score"], 75.5)
        self.assertEqual(completed_scan["total_findings"], 3)
        self.assertEqual(completed_scan["summary"]["tested"], True)

    def test_insert_and_query_findings(self):
        scan_id = str(uuid.uuid4())
        self.db.create_scan(scan_id, target_type="filesystem")

        findings = [
            Finding(
                scan_id=scan_id,
                category="timestamp",
                severity="HIGH",
                title="Timestomp Anomaly",
                description="Sub-second nanosecond zeroing",
                artifact_path="C:\\test.exe",
                evidence={"zeroed": True}
            ),
            Finding(
                scan_id=scan_id,
                category="log",
                severity="CRITICAL",
                title="Audit Log Cleared",
                description="Event 1102",
                artifact_path="Security",
                evidence={"event_id": 1102}
            )
        ]

        self.db.insert_findings_batch(scan_id, findings)

        retrieved_all = self.db.get_findings(scan_id)
        self.assertEqual(len(retrieved_all), 2)

        retrieved_crit = self.db.get_findings(scan_id, severity="CRITICAL")
        self.assertEqual(len(retrieved_crit), 1)
        self.assertEqual(retrieved_crit[0]["category"], "log")

    def test_insert_features_and_export_dataframe(self):
        scan_id = str(uuid.uuid4())
        self.db.create_scan(scan_id, target_type="filesystem")

        features = {
            "total_files_scanned": 15.0,
            "timestomp_detected_count": 2.0,
            "has_timestomp_anomaly": 1.0,
            "anti_forensics_risk_score": 65.0
        }

        self.db.insert_features(scan_id, features)
        retrieved_features = self.db.get_features(scan_id)
        self.assertEqual(retrieved_features["total_files_scanned"], 15.0)
        self.assertEqual(retrieved_features["anti_forensics_risk_score"], 65.0)

        df = self.db.get_features_dataframe(scan_id)
        self.assertFalse(df.empty)
        self.assertIn("total_files_scanned", df.columns)
        self.assertEqual(df["total_files_scanned"].iloc[0], 15.0)


if __name__ == "__main__":
    unittest.main()
