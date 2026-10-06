"""
Integration and security tests for persistent scan history API, user data isolation,
report regeneration from database snapshots, and deletion authorization.
"""

import os
import tempfile
import unittest
import json
import io
from werkzeug.security import generate_password_hash

import app as app_module
from app import app
from src.db.db_manager import DatabaseManager


class TestScanHistoryAPI(unittest.TestCase):
    def setUp(self):
        # Create isolated temporary database for test suite
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_path = self.temp_db.name

        os.environ["DATABASE_PATH"] = self.db_path
        self.db = DatabaseManager(db_path=self.db_path)

        # Monkeypatch app.db to use our isolated test database
        self.orig_db = app_module.db
        app_module.db = self.db

        # Register two separate users
        self.user_a_id = self.db.create_user(
            username="analyst_a",
            email="analyst_a@test.local",
            password="Password123!",
            full_name="Analyst A",
            role="analyst"
        )
        self.user_b_id = self.db.create_user(
            username="analyst_b",
            email="analyst_b@test.local",
            password="Password123!",
            full_name="Analyst B",
            role="analyst"
        )

        # Configure test Flask client
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-key"
        self.client = app.test_client()

    def tearDown(self):
        app_module.db = self.orig_db
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def _login_as(self, username, password="Password123!"):
        return self.client.post("/login", data={
            "username": username,
            "password": password
        }, follow_redirects=True)

    def test_authenticated_scan_persistence_and_isolation(self):
        # 1. Login as User A
        self._login_as("analyst_a")

        # 2. Upload a file for scan
        file_content = b"This is clean mock forensic file data for analysis."
        data = {
            "file": (io.BytesIO(file_content), "case_evidence_001.txt")
        }
        res = self.client.post("/api/scan/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        scan_res = json.loads(res.data)
        self.assertTrue(scan_res.get("success"))
        scan_id = scan_res.get("scan_id")
        self.assertIsNotNone(scan_id)

        # Verify scan has sha256 and metadata in response
        self.assertIn("sha256", scan_res.get("file_info", {}))
        self.assertIn("risk_level", scan_res)

        # 3. Fetch history as User A
        hist_res = self.client.get("/api/scans")
        self.assertEqual(hist_res.status_code, 200)
        hist_data = json.loads(hist_res.data)
        self.assertTrue(hist_data.get("success"))
        self.assertEqual(len(hist_data.get("scans", [])), 1)
        
        saved_scan = hist_data["scans"][0]
        self.assertEqual(saved_scan["scan_id"], scan_id)
        self.assertEqual(saved_scan["filename"], "case_evidence_001.txt")
        self.assertEqual(saved_scan["status"], "COMPLETED")
        self.assertIsNotNone(saved_scan["sha256_hash"])

        # 4. User A can view scan details
        detail_res = self.client.get(f"/api/scan/{scan_id}")
        self.assertEqual(detail_res.status_code, 200)
        detail_data = json.loads(detail_res.data)
        self.assertTrue(detail_data.get("success"))
        self.assertEqual(detail_data["scan"]["scan_id"], scan_id)

        # 5. Switch to User B (Logout A, Login B)
        self.client.get("/logout", follow_redirects=True)
        self._login_as("analyst_b")

        # User B should see 0 scans
        b_hist_res = self.client.get("/api/scans")
        self.assertEqual(b_hist_res.status_code, 200)
        b_hist_data = json.loads(b_hist_res.data)
        self.assertEqual(len(b_hist_data.get("scans", [])), 0)

        # User B attempting to access User A's scan details directly must receive 403 Forbidden or 404 Not Found
        b_detail_res = self.client.get(f"/api/scan/{scan_id}")
        self.assertIn(b_detail_res.status_code, (403, 404))

        # User B attempting to delete User A's scan must receive 403 Forbidden or 404 Not Found
        b_del_res = self.client.delete(f"/api/scan/{scan_id}")
        self.assertIn(b_del_res.status_code, (403, 404))

        # User B attempting to download User A's report must receive 403 Forbidden or 404 Not Found
        b_report_res = self.client.get(f"/api/report/{scan_id}")
        self.assertIn(b_report_res.status_code, (403, 404))

    def test_search_filter_pagination(self):
        self._login_as("analyst_a")

        # Directly seed multiple scans in DB for user A
        for i in range(5):
            fname = f"artifact_{i}_{'critical' if i % 2 == 0 else 'normal'}.dat"
            s_id = f"test-query-scan-{i}"
            risk = "CRITICAL" if i % 2 == 0 else "LOW"
            self.db.create_scan(
                scan_id=s_id,
                target_type="file",
                target_path=f"/evidence/{fname}",
                user_id=self.user_a_id,
                filename=fname,
                file_size=1024 * (i + 1),
                file_type="dat",
                sha256_hash=f"hash-{i}"
            )
            self.db.complete_scan(
                scan_id=s_id,
                total_artifacts=1,
                total_findings=i,
                risk_score=95.0 if risk == "CRITICAL" else 10.0,
                risk_level=risk,
                critical_count=2 if risk == "CRITICAL" else 0,
                duration_seconds=0.8,
                result_json={"filename": fname, "risk_level": risk}
            )

        # Test Search
        res = self.client.get("/api/scans?search=critical")
        data = json.loads(res.data)
        self.assertEqual(len(data["scans"]), 3)

        # Test Risk Level Filter
        res = self.client.get("/api/scans?risk_level=LOW")
        data = json.loads(res.data)
        self.assertEqual(len(data["scans"]), 2)

        # Test Pagination
        res = self.client.get("/api/scans?page=1&limit=2")
        data = json.loads(res.data)
        self.assertEqual(len(data["scans"]), 2)
        self.assertEqual(data["pagination"]["total_records"], 5)
        self.assertEqual(data["pagination"]["total_pages"], 3)

    def test_scan_deletion(self):
        self._login_as("analyst_a")

        s_id = "scan-to-be-deleted"
        self.db.create_scan(
            scan_id=s_id,
            target_type="file",
            user_id=self.user_a_id,
            filename="delete_me.exe"
        )
        self.db.complete_scan(
            scan_id=s_id,
            total_artifacts=1,
            total_findings=0,
            risk_score=0.0,
            risk_level="CLEAN"
        )

        # Verify scan exists
        res = self.client.get(f"/api/scan/{s_id}")
        self.assertEqual(res.status_code, 200)

        # Delete scan
        del_res = self.client.delete(f"/api/scan/{s_id}")
        self.assertEqual(del_res.status_code, 200)
        del_data = json.loads(del_res.data)
        self.assertTrue(del_data.get("success"))

        # Verify scan no longer exists
        res = self.client.get(f"/api/scan/{s_id}")
        self.assertEqual(res.status_code, 404)

    def test_report_regeneration_when_file_missing(self):
        self._login_as("analyst_a")

        s_id = "scan-with-reconstructed-report"
        # Seed scan with full result_json and a non-existent report_path (simulating container restart on Render)
        result_snapshot = {
            "scan_id": s_id,
            "filename": "render_survivor.bin",
            "risk_score": 88.0,
            "risk_level": "HIGH",
            "findings_count": 3,
            "findings": [
                {
                    "rule_id": "TIMESTOMP_001",
                    "title": "Subsecond Nanosecond Zeroing",
                    "severity": "HIGH",
                    "category": "timestamp",
                    "description": "Evidence of MACE timestamp modification"
                }
            ],
            "ml_prediction": {
                "label": "TAMPERED",
                "probability": 0.88,
                "confidence": 0.95
            },
            "file_info": {
                "filename": "render_survivor.bin",
                "file_size": 2048,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        }

        self.db.create_scan(
            scan_id=s_id,
            target_type="file",
            user_id=self.user_a_id,
            filename="render_survivor.bin",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        self.db.complete_scan(
            scan_id=s_id,
            total_artifacts=1,
            total_findings=1,
            risk_score=88.0,
            risk_level="HIGH",
            high_count=1,
            report_path="/ephemeral/container/path/does_not_exist.pdf",
            result_json=result_snapshot
        )

        # Download PDF report via endpoint
        report_res = self.client.get(f"/api/report/{s_id}")
        self.assertEqual(report_res.status_code, 200)
        self.assertEqual(report_res.content_type, "application/pdf")
        self.assertTrue(len(report_res.data) > 1000) # Valid PDF bytes generated


if __name__ == "__main__":
    unittest.main()
