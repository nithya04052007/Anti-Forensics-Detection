"""
Unit tests for Feature Extraction module
"""

import unittest
import pandas as pd

from src.collection.models import (
    FileMetadata,
    AlternateDataStream,
    EventLogEntry,
    RegistryArtifact,
    Finding
)
from src.features.feature_extractor import FeatureExtractor


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor()

    def test_feature_extraction_vector(self):
        files = [
            FileMetadata(
                path="C:\\file1.exe",
                filename="file1.exe",
                size_bytes=100,
                mtime=1700000000.0,
                atime=1700000000.0,
                ctime=1700000000.0,
                birthtime=1700000000.0,
                mtime_ns=1700000000000000000,
                atime_ns=1700000000000000000,
                ctime_ns=1700000000000000000,
                birthtime_ns=1700000000000000000,
                mtime_fractional_ns=0, # Zeroed
                atime_fractional_ns=0,
                ctime_fractional_ns=0,
                birthtime_fractional_ns=0,
                alternate_data_streams=[
                    AlternateDataStream(":evil.exe", 1024, is_executable=True)
                ]
            )
        ]

        event_logs = [
            EventLogEntry(
                event_id=1102,
                record_number=1,
                log_name="Security",
                time_created="2026-08-24T10:00:00Z",
                time_created_epoch=1787565600.0,
                source_name="EventLog",
                level="Audit Success",
                message="Cleared",
                computer="HOST"
            )
        ]

        registry = [
            RegistryArtifact(
                hive="HKLM",
                key_path="PrefetchParameters",
                value_name="EnablePrefetcher",
                value_data=0,
                value_type="REG_DWORD",
                is_anomalous=True
            )
        ]

        findings = [
            Finding(
                category="log",
                severity="CRITICAL",
                title="Security Log Cleared",
                description="Audit log cleared",
                artifact_path="Security"
            ),
            Finding(
                category="hidden_file",
                severity="CRITICAL",
                title="Executable ADS",
                description="Hidden ADS stream",
                artifact_path="C:\\file1.exe:evil.exe"
            )
        ]

        features = self.extractor.extract_features(
            files=files,
            event_logs=event_logs,
            registry_keys=registry,
            findings=findings
        )

        self.assertIn("total_files_scanned", features)
        self.assertEqual(features["total_files_scanned"], 1.0)
        self.assertEqual(features["fractional_zero_count"], 1.0)
        self.assertEqual(features["ads_executable_count"], 1.0)
        self.assertEqual(features["has_ads_executable"], 1.0)
        self.assertEqual(features["log_cleared_count"], 1.0)
        self.assertEqual(features["has_log_cleared"], 1.0)
        self.assertEqual(features["prefetch_disabled_flag"], 1.0)
        self.assertGreater(features["anti_forensics_risk_score"], 50.0)

    def test_to_dataframe(self):
        features = {"total_files_scanned": 5.0, "anti_forensics_risk_score": 85.0}
        df = self.extractor.to_dataframe(features, scan_id="test-scan-uuid")
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 1)
        self.assertEqual(df["scan_id"].iloc[0], "test-scan-uuid")
        self.assertEqual(df["total_files_scanned"].iloc[0], 5.0)


if __name__ == "__main__":
    unittest.main()
