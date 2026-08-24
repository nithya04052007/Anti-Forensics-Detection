"""
Comprehensive Phase 2 Test Suite
Tests all 6 required test cases (Normal PDF, Normal TXT, Normal JPG, Hidden file,
Hidden folder, Harmless extension mismatch sample), ML prediction, SQLite persistence, and PDF reporting.

NOTE: Test files are created in tests/test_data/ (NOT tempfile.TemporaryDirectory) because
Windows AppData\Local\Temp directories have the HIDDEN attribute on this system, which causes
hidden_folder.py to correctly flag them as suspicious — making ML predictions non-deterministic
for test assertions. Using a stable project subfolder ensures is_in_hidden_folder = 0.0
for genuinely normal files.
"""

import unittest
import os
import sys
import shutil
import ctypes

from TeamMember1.scanner import scan_evidence_file
from ml.predict import predict_risk
from src.analysis.file_scanner import run_single_file_scan
from src.db.db_manager import DatabaseManager

# Use a stable project subfolder, NOT tempfile, to avoid Windows Temp HIDDEN attribute
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_DATA_DIR = os.path.join(BASE_DIR, "tests", "test_data")
TEST_DB_PATH = os.path.join(BASE_DIR, "tests", "test_forensic.db")


class TestPhase2Workflow(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Create test_data directory and all test files once for all tests."""
        os.makedirs(TEST_DATA_DIR, exist_ok=True)

        # Remove hidden attribute from the test_data folder itself (safety measure)
        if sys.platform == "win32":
            ctypes.windll.kernel32.SetFileAttributesW(TEST_DATA_DIR, 0x20)  # ARCHIVE only

        # 1. Normal PDF
        cls.normal_pdf = os.path.join(TEST_DATA_DIR, "document.pdf")
        with open(cls.normal_pdf, "wb") as f:
            f.write(b"%PDF-1.5\n%Forensic test PDF document body for DFIR analysis\n%%EOF")

        # 2. Normal TXT
        cls.normal_txt = os.path.join(TEST_DATA_DIR, "notes.txt")
        with open(cls.normal_txt, "w", encoding="utf-8") as f:
            f.write("Regular plain text evidence file for forensic analysis.\nNo suspicious indicators.")

        # 3. Normal JPG (JFIF magic bytes)
        cls.normal_jpg = os.path.join(TEST_DATA_DIR, "photo.jpg")
        with open(cls.normal_jpg, "wb") as f:
            f.write(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C")

        # 4. Hidden File (set HIDDEN attribute after creation)
        cls.hidden_file = os.path.join(TEST_DATA_DIR, "hidden_data.txt")
        with open(cls.hidden_file, "w", encoding="utf-8") as f:
            f.write("Hidden secret text data used to test HIDDEN attribute detection.")
        if sys.platform == "win32":
            ctypes.windll.kernel32.SetFileAttributesW(cls.hidden_file, 0x02)  # FILE_ATTRIBUTE_HIDDEN

        # 5. Hidden Folder sample
        cls.hidden_subdir = os.path.join(TEST_DATA_DIR, "hidden_vault")
        os.makedirs(cls.hidden_subdir, exist_ok=True)
        if sys.platform == "win32":
            ctypes.windll.kernel32.SetFileAttributesW(cls.hidden_subdir, 0x02)  # HIDDEN

        cls.file_in_hidden_folder = os.path.join(cls.hidden_subdir, "payload.bin")
        with open(cls.file_in_hidden_folder, "wb") as f:
            f.write(b"Binary content inside a hidden folder for testing hidden residency detection.")

        # 6. Extension Mismatch Sample — MZ header disguised as .jpg (harmless test)
        cls.mismatch_sample = os.path.join(TEST_DATA_DIR, "innocent_picture.jpg")
        with open(cls.mismatch_sample, "wb") as f:
            # MZ magic header — disguised executable content for detection testing
            f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
                    b"Harmless PE test file for extension mismatch forensic detection")

    @classmethod
    def tearDownClass(cls):
        """Clean up test files and test DB after all tests complete."""
        # Remove HIDDEN attribute from files before deletion
        if sys.platform == "win32":
            try:
                ctypes.windll.kernel32.SetFileAttributesW(cls.hidden_file, 0x20)
            except Exception:
                pass
            try:
                ctypes.windll.kernel32.SetFileAttributesW(cls.hidden_subdir, 0x20)
            except Exception:
                pass

        if os.path.exists(TEST_DATA_DIR):
            shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)

    # =========================================================================
    # Test Case 1: Normal PDF — Correct signature, no suspicious indicators
    # =========================================================================

    def test_case_1_normal_pdf(self):
        """Normal PDF must have correct signature, extension match, and LOW/Normal ML prediction."""
        report = scan_evidence_file(self.normal_pdf)

        # Forensic signature checks
        self.assertEqual(report.signature.actual_type, "PDF Document")
        self.assertTrue(report.signature.extension_match, "PDF extension should match its header")
        self.assertFalse(report.signature.is_extension_mismatch)
        self.assertFalse(report.signature.is_disguised_executable)

        # Feature vector checks
        self.assertEqual(report.feature_vector["extension_match"], 1.0)
        self.assertEqual(report.feature_vector["has_double_extension"], 0.0)
        self.assertEqual(report.feature_vector["is_hidden"], 0.0)
        self.assertEqual(report.feature_vector["is_in_hidden_folder"], 0.0)

        # ML prediction
        pred = predict_risk(report.feature_vector)
        self.assertEqual(pred["ml_prediction"], "Normal",
                         f"Normal PDF should be classified Normal, got: {pred}")
        self.assertLessEqual(pred["risk_score"], 30.0,
                             f"Normal PDF risk score should be LOW (<=30), got: {pred['risk_score']}")

    # =========================================================================
    # Test Case 2: Normal TXT — Plain text, correct signature
    # =========================================================================

    def test_case_2_normal_txt(self):
        """Normal TXT file must have Plain Text signature, extension match, and Normal ML prediction."""
        report = scan_evidence_file(self.normal_txt)

        self.assertEqual(report.signature.actual_type, "Plain Text / Script")
        self.assertTrue(report.signature.extension_match)

        # Feature vector checks
        self.assertEqual(report.feature_vector["extension_match"], 1.0)
        self.assertEqual(report.feature_vector["is_hidden"], 0.0)
        self.assertEqual(report.feature_vector["is_in_hidden_folder"], 0.0)

        pred = predict_risk(report.feature_vector)
        self.assertEqual(pred["ml_prediction"], "Normal",
                         f"Normal TXT should be classified Normal, got: {pred}")
        self.assertLessEqual(pred["risk_score"], 30.0)

    # =========================================================================
    # Test Case 3: Normal JPG — JPEG magic bytes, correct extension
    # =========================================================================

    def test_case_3_normal_jpg(self):
        """Normal JPG must have JPEG signature, extension match, and Normal ML prediction."""
        report = scan_evidence_file(self.normal_jpg)

        self.assertEqual(report.signature.actual_type, "JPEG Image")
        self.assertTrue(report.signature.extension_match)

        # Feature vector checks
        self.assertEqual(report.feature_vector["extension_match"], 1.0)
        self.assertEqual(report.feature_vector["is_hidden"], 0.0)
        self.assertEqual(report.feature_vector["is_in_hidden_folder"], 0.0)

        pred = predict_risk(report.feature_vector)
        self.assertEqual(pred["ml_prediction"], "Normal",
                         f"Normal JPG should be classified Normal, got: {pred}")
        self.assertLessEqual(pred["risk_score"], 30.0)

    # =========================================================================
    # Test Case 4: Hidden File — HIDDEN attribute must be detected
    # =========================================================================

    def test_case_4_hidden_file(self):
        """File with HIDDEN attribute must have is_hidden=True and feature vector flagged."""
        report = scan_evidence_file(self.hidden_file)

        if sys.platform == "win32":
            self.assertTrue(report.hidden_file.is_hidden,
                            "HIDDEN attribute should be detected on Windows")
            self.assertEqual(report.feature_vector["is_hidden"], 1.0,
                             "is_hidden feature must be 1.0 for hidden files")

            # Validate a finding was generated
            hidden_findings = [f for f in report.findings if f.get("category") == "hidden_attributes"]
            self.assertTrue(len(hidden_findings) > 0,
                            "Should generate a hidden_attributes finding")

    # =========================================================================
    # Test Case 5: Hidden Folder — File in HIDDEN directory must be detected
    # =========================================================================

    def test_case_5_hidden_folder(self):
        """File inside a HIDDEN directory must detect hidden folder residency."""
        report = scan_evidence_file(self.file_in_hidden_folder)

        if sys.platform == "win32":
            self.assertTrue(report.hidden_folder.is_in_hidden_folder,
                            "Should detect that parent directory has HIDDEN attribute")
            self.assertEqual(report.feature_vector["is_in_hidden_folder"], 1.0,
                             "is_in_hidden_folder feature must be 1.0")

            hidden_res_findings = [f for f in report.findings if f.get("category") == "hidden_residency"]
            self.assertTrue(len(hidden_res_findings) > 0,
                            "Should generate a hidden_residency finding")

    # =========================================================================
    # Test Case 6: Extension Mismatch — MZ header disguised as .jpg
    # =========================================================================

    def test_case_6_extension_mismatch_sample(self):
        """Disguised executable (.jpg with MZ header) must be detected as HIGH risk."""
        report = scan_evidence_file(self.mismatch_sample)

        # Signature forensics
        self.assertEqual(report.signature.actual_type, "Windows Executable / PE",
                         "Should identify MZ header as PE executable")
        self.assertEqual(report.signature.claimed_extension, ".jpg")
        self.assertFalse(report.signature.extension_match,
                         "Extension .jpg should NOT match PE signature")
        self.assertTrue(report.signature.is_disguised_executable,
                        "Should flag as disguised executable")

        # Feature vector
        self.assertEqual(report.feature_vector["extension_match"], 0.0)

        # ML prediction — must be Suspicious and HIGH risk
        pred = predict_risk(report.feature_vector)
        self.assertEqual(pred["ml_prediction"], "Suspicious",
                         f"Disguised executable should be Suspicious, got: {pred}")
        self.assertGreaterEqual(pred["risk_score"], 60.0,
                                f"Disguised executable should score HIGH (>=60), got: {pred['risk_score']}")
        self.assertEqual(pred["risk_level"], "HIGH")

    # =========================================================================
    # Test Case 7: End-to-End Pipeline (Scan + SQLite + PDF)
    # =========================================================================

    def test_end_to_end_pipeline_and_sqlite_and_pdf(self):
        """Full pipeline on extension-mismatch sample: scan -> SQLite -> PDF report."""
        res = run_single_file_scan(self.mismatch_sample, db_path=TEST_DB_PATH, generate_pdf=True)
        scan_id = res["scan_id"]

        # Verify result structure
        self.assertIn("scan_id", res)
        self.assertIn("risk_score", res)
        self.assertIn("risk_level", res)
        self.assertIn("ml_prediction", res)
        self.assertIn("findings", res)
        self.assertIn("features", res)

        # Verify SQLite persistence
        db = DatabaseManager(db_path=TEST_DB_PATH)
        scan = db.get_scan(scan_id)
        self.assertIsNotNone(scan, "Scan must be persisted in SQLite")
        self.assertEqual(scan["status"], "COMPLETED")
        self.assertGreaterEqual(scan["risk_score"], 60.0,
                                "Disguised executable must persist HIGH risk score")

        # Verify findings were stored
        findings = db.get_findings(scan_id)
        self.assertTrue(len(findings) > 0, "Findings must be stored in SQLite")

        # Verify PDF report was generated
        self.assertIn("report_path", res, "PDF report path must be in result")
        self.assertTrue(os.path.exists(res["report_path"]),
                        f"PDF report file must exist at: {res['report_path']}")
        self.assertGreater(os.path.getsize(res["report_path"]), 1000,
                           "PDF report must not be empty (>1KB)")


if __name__ == "__main__":
    unittest.main()
