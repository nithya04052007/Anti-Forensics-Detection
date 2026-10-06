import unittest
import os
import json
import sqlite3
import tempfile
import io
from app import app
from src.db.db_manager import DatabaseManager
from ml.predict import get_model_metadata

class TestTwoAccountIsolationAndMLMatrix(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_isolation.db")
        self.db = DatabaseManager(self.db_path)
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-isolation-999"
        
        # Patch app db instance and path
        import app as app_module
        self.orig_db = app_module.db
        self.orig_db_path = app_module.DEFAULT_DB_PATH
        app_module.db = self.db
        app_module.DEFAULT_DB_PATH = self.db_path
        
        self.client = app.test_client()

    def tearDown(self):
        import app as app_module
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

    def test_complete_two_user_lifecycle_and_isolation(self):
        """
        Verify Account A creates scans -> logs out -> Account B logs in with 0 scans.
        Verify Account B cannot access A's scans via API, reports, exports, or deletion.
        """
        # 1. Register Account A
        user_a_id = self.db.create_user("user_a", "Password123!", email="usera@dfir.org", role="analyst")
        self.assertIsNotNone(user_a_id)

        # 2. Register Account B
        user_b_id = self.db.create_user("user_b", "Password123!", email="userb@dfir.org", role="analyst")
        self.assertIsNotNone(user_b_id)

        # 3. Log in as Account A and perform a scan
        with self.client as c:
            login_resp = c.post("/login", data={"username": "user_a", "password": "Password123!"}, follow_redirects=True)
            self.assertEqual(login_resp.status_code, 200)

            # Create test file and upload
            dummy_content = b"EVIDENCE_DATA_FROM_USER_A"
            upload_resp = c.post("/api/scan/upload", data={
                "file": (io.BytesIO(dummy_content), "confidential_case_a.docx")
            }, content_type="multipart/form-data")
            self.assertEqual(upload_resp.status_code, 200)
            upload_data = json.loads(upload_resp.data)
            scan_a_id = upload_data["result"]["scan_id"]

            # Verify Account A sees 1 scan in /api/scans
            scans_resp = c.get("/api/scans")
            scans_data = json.loads(scans_resp.data)
            self.assertEqual(scans_data["total"], 1)
            self.assertEqual(len(scans_data["scans"]), 1)
            self.assertEqual(scans_data["scans"][0]["scan_id"], scan_a_id)

            # Account A can access scan details
            detail_resp = c.get(f"/api/scan/{scan_a_id}")
            self.assertEqual(detail_resp.status_code, 200)
            detail_data = json.loads(detail_resp.data)
            self.assertIn("model_metadata", detail_data)
            self.assertIsNotNone(detail_data["model_metadata"])

            # Account A can access report
            report_resp = c.get(f"/api/report/{scan_a_id}")
            self.assertEqual(report_resp.status_code, 200)

            # 4. Account A logs out
            logout_resp = c.get("/logout", follow_redirects=False)
            self.assertEqual(logout_resp.status_code, 302)
            self.assertIn("no-store", logout_resp.headers.get("Cache-Control", ""))

        # 5. Log in as Account B in a fresh client session
        client_b = app.test_client()
        with client_b as cb:
            login_b = cb.post("/login", data={"username": "user_b", "password": "Password123!"}, follow_redirects=True)
            self.assertEqual(login_b.status_code, 200)

            # Account B must have ZERO scans
            scans_b_resp = cb.get("/api/scans")
            scans_b_data = json.loads(scans_b_resp.data)
            self.assertEqual(scans_b_data["total"], 0)
            self.assertEqual(len(scans_b_data["scans"]), 0)
            self.assertEqual(scans_b_data["stats"]["total_scans"], 0)

            # Account B IDOR attack: GET /api/scan/<scan_a_id> -> MUST RETURN 404
            idor_get = cb.get(f"/api/scan/{scan_a_id}")
            self.assertEqual(idor_get.status_code, 404)

            # Account B IDOR attack: GET /api/report/<scan_a_id> -> MUST RETURN 404
            idor_report = cb.get(f"/api/report/{scan_a_id}")
            self.assertEqual(idor_report.status_code, 404)

            # Account B IDOR attack: GET /api/features/export/<scan_a_id> -> MUST RETURN 404
            idor_export = cb.get(f"/api/features/export/{scan_a_id}")
            self.assertEqual(idor_export.status_code, 404)

            # Account B IDOR attack: DELETE /api/scan/<scan_a_id> -> MUST RETURN 404
            idor_del = cb.delete(f"/api/scan/{scan_a_id}")
            self.assertEqual(idor_del.status_code, 404)

    def test_ml_model_metadata_endpoint(self):
        """
        Verify /api/ml/model returns 16 real Random Forest feature names and exact importance weights.
        """
        user_id = self.db.create_user("analyst_ml", "Password123!", email="ml@dfir.org", role="analyst")
        self.assertIsNotNone(user_id)
        with self.client as c:
            login_resp = c.post("/login", data={"username": "analyst_ml", "password": "Password123!"})
            self.assertEqual(login_resp.status_code, 302)
            resp = c.get("/api/ml/model")
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.data)
            self.assertTrue(data["success"])
            model = data["model"]
            self.assertEqual(model["model_type"], "Random Forest Classifier")
            self.assertEqual(model["feature_count"], 16)
            self.assertEqual(len(model["feature_names"]), 16)
            self.assertEqual(len(model["feature_importances"]), 16)
            # Verify feature importances sum to approximately 1.0 (100%)
            total_weight = sum(model["feature_importances"].values())
            self.assertAlmostEqual(total_weight, 1.0, places=2)

if __name__ == "__main__":
    unittest.main()
