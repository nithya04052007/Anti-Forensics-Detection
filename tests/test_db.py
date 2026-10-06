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
        if hasattr(self, 'temp_file') and os.path.exists(self.temp_file.name):
            try:
                os.remove(self.temp_file.name)
            except Exception:
                pass

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


    def test_user_isolated_scan_history_and_search(self):
        user_a = self.db.create_user(username="user_a", email="usera@test.com", password="Password123!", full_name="User A")
        user_b = self.db.create_user(username="user_b", email="userb@test.com", password="Password123!", full_name="User B")
        self.assertIsNotNone(user_a)
        self.assertIsNotNone(user_b)

        # Create 3 scans for User A
        for i, fname in enumerate(["sample_evidence.exe", "suspicious_log.evtx", "normal_doc.pdf"]):
            s_id = f"userA-scan-{i}"
            self.db.create_scan(
                scan_id=s_id,
                target_type="file",
                target_path=f"C:\\evidence\\{fname}",
                user_id=user_a,
                filename=fname,
                file_size=1024 * (i + 1),
                file_type=fname.split(".")[-1],
                sha256_hash=f"hash-{i}"
            )
            risk = "HIGH" if i == 0 else ("CRITICAL" if i == 1 else "LOW")
            self.db.complete_scan(
                scan_id=s_id,
                total_artifacts=1,
                total_findings=i * 2,
                risk_score=90.0 if i == 1 else 30.0,
                risk_level=risk,
                critical_count=1 if risk == "CRITICAL" else 0,
                high_count=1 if risk == "HIGH" else 0,
                duration_seconds=1.5,
                result_json={"filename": fname, "risk_level": risk}
            )

        # Create 1 scan for User B
        self.db.create_scan(
            scan_id="userB-scan-0",
            target_type="file",
            target_path="C:\\evidence\\userb.bin",
            user_id=user_b,
            filename="userb.bin",
            file_size=5000,
            file_type="bin",
            sha256_hash="hash-userb"
        )
        self.db.complete_scan(
            scan_id="userB-scan-0",
            total_artifacts=1,
            total_findings=5,
            risk_score=85.0,
            risk_level="HIGH"
        )

        # 1. User isolation - User A cannot see User B's scans
        scans_a = self.db.list_scans(user_id=user_a)
        self.assertEqual(len(scans_a), 3)
        self.assertTrue(all(s["user_id"] == user_a for s in scans_a))

        scans_b = self.db.list_scans(user_id=user_b)
        self.assertEqual(len(scans_b), 1)
        self.assertEqual(scans_b[0]["filename"], "userb.bin")

        # 2. Search by filename
        searched = self.db.list_scans(user_id=user_a, search="suspicious")
        self.assertEqual(len(searched), 1)
        self.assertEqual(searched[0]["filename"], "suspicious_log.evtx")

        # 3. Filter by risk level
        high_scans = self.db.list_scans(user_id=user_a, risk_level="HIGH")
        self.assertEqual(len(high_scans), 1)
        self.assertEqual(high_scans[0]["filename"], "sample_evidence.exe")

        # 4. Pagination
        page_1 = self.db.list_scans(user_id=user_a, limit=2, offset=0)
        self.assertEqual(len(page_1), 2)
        total_a = self.db.count_scans(user_id=user_a)
        self.assertEqual(total_a, 3)

        # 5. User Stats
        stats_a = self.db.get_user_scan_stats(user_id=user_a)
        self.assertEqual(stats_a["total_scans"], 3)
        self.assertEqual(stats_a["high_risk_scans"], 2) # HIGH + CRITICAL

        # 6. Deletion with user isolation
        # User B trying to delete User A's scan should fail
        del_fail = self.db.delete_scan("userA-scan-0", user_id=user_b)
        self.assertFalse(del_fail)
        self.assertIsNotNone(self.db.get_scan("userA-scan-0", user_id=user_a))

        # User A deleting User A's scan should succeed
        del_success = self.db.delete_scan("userA-scan-0", user_id=user_a)
        self.assertTrue(del_success)
        self.assertIsNone(self.db.get_scan("userA-scan-0", user_id=user_a))
        self.assertEqual(self.db.count_scans(user_id=user_a), 2)


if __name__ == "__main__":
    unittest.main()

