"""
Regression test for file upload interaction and user isolation in Anti-Forensics Detection.
Validates:
  1. Unauthenticated file upload is rejected (401)
  2. Authenticated user can upload an evidence file
  3. Scan result contains valid forensic evaluation and metadata
  4. Scan is recorded in user's isolated history
  5. Other user accounts cannot access the uploaded evidence or report
"""
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app
import app as app_module
from src.db.db_manager import DatabaseManager


class TestUploadInteraction(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_upload_interaction.db")
        self.db = DatabaseManager(self.db_path)

        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-upload-key-123"

        self.orig_db = app_module.db
        self.orig_db_path = app_module.DEFAULT_DB_PATH
        app_module.db = self.db
        app_module.DEFAULT_DB_PATH = self.db_path

        self.client = app.test_client()

        # Register User A and User B directly in database
        self.user_a_email = "analyst_a@forensics.test"
        self.user_a_pwd = "PasswordA123!"
        self.user_a_id = self.db.create_user("analyst_a", self.user_a_pwd, email=self.user_a_email, role="analyst")

        self.user_b_email = "analyst_b@forensics.test"
        self.user_b_pwd = "PasswordB123!"
        self.user_b_id = self.db.create_user("analyst_b", self.user_b_pwd, email=self.user_b_email, role="analyst")

    def tearDown(self):
        app_module.db = self.orig_db
        app_module.DEFAULT_DB_PATH = self.orig_db_path
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass
        if os.path.exists(self.temp_dir):
            try:
                os.rmdir(self.temp_dir)
            except Exception:
                pass

    def test_unauthenticated_upload_rejected(self):
        """Unauthenticated /api/scan/upload must return 401."""
        test_file = (io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00test PE executable content"), "sample.exe")
        resp = self.client.post(
            "/api/scan/upload",
            data={"file": test_file},
            content_type="multipart/form-data"
        )
        self.assertEqual(resp.status_code, 401)

    def test_authenticated_upload_and_scan_interaction(self):
        """User A uploads an evidence file, receives valid scan findings, and history is updated."""
        with app.test_client() as client_a:
            login_resp = client_a.post("/login", data={"email": self.user_a_email, "password": self.user_a_pwd}, follow_redirects=True)
            self.assertEqual(login_resp.status_code, 200)

            # Upload an evidence file
            evidence_content = b"%PDF-1.4\n%test pdf content with evasive hidden data\x00\x00\x00"
            test_file = (io.BytesIO(evidence_content), "suspicious_doc.pdf")

            upload_resp = client_a.post(
                "/api/scan/upload",
                data={"file": test_file},
                content_type="multipart/form-data"
            )
            self.assertEqual(upload_resp.status_code, 200)

            data = json.loads(upload_resp.data)
            self.assertEqual(data.get("status"), "success")
            self.assertIn("result", data)

            res = data["result"]
            scan_id = res.get("scan_id")
            self.assertTrue(bool(scan_id))
            self.assertEqual(res.get("file_name"), "suspicious_doc.pdf")
            self.assertIn("risk_score", res)
            self.assertIn("sha256_hash", res)

            # Verify scan appears in User A's history
            history_resp = client_a.get("/api/scans?limit=10")
            self.assertEqual(history_resp.status_code, 200)
            h_data = json.loads(history_resp.data)
            scan_ids = [s["scan_id"] for s in h_data.get("scans", [])]
            self.assertIn(scan_id, scan_ids)

            # Verify User A can fetch report
            report_resp = client_a.get(f"/api/report/{scan_id}")
            self.assertIn(report_resp.status_code, (200, 302))

        # Strict User Isolation: Verify User B CANNOT see User A's scan
        with app.test_client() as client_b:
            login_b_resp = client_b.post("/login", data={"email": self.user_b_email, "password": self.user_b_pwd}, follow_redirects=True)
            self.assertEqual(login_b_resp.status_code, 200)

            b_history_resp = client_b.get("/api/scans?limit=10")
            b_data = json.loads(b_history_resp.data)
            b_scan_ids = [s["scan_id"] for s in b_data.get("scans", [])]
            self.assertNotIn(scan_id, b_scan_ids)

            # User B cannot access scan details
            b_detail_resp = client_b.get(f"/api/scan/{scan_id}")
            self.assertEqual(b_detail_resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
