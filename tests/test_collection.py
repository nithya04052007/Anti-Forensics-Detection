"""
Unit tests for Data Collection module
"""

import unittest
import tempfile
import os
import time

from src.collection.file_collector import FileCollector
from src.collection.event_log_collector import EventLogCollector
from src.collection.models import FileMetadata, EventLogEntry


class TestFileCollector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.collector = FileCollector(compute_hashes=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_collect_file_metadata(self):
        # Create a sample test file
        test_file = os.path.join(self.temp_dir.name, "sample.txt")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("Forensic test file content")

        meta = self.collector.collect_file_metadata(test_file)
        self.assertIsNotNone(meta)
        self.assertEqual(meta.filename, "sample.txt")
        self.assertGreater(meta.size_bytes, 0)
        self.assertIsNotNone(meta.md5)
        self.assertIsNotNone(meta.sha256)
        self.assertEqual(meta.extension, ".txt")
        self.assertFalse(meta.is_double_extension)

    def test_double_extension_detection(self):
        deceptive_file = os.path.join(self.temp_dir.name, "invoice.pdf.exe")
        with open(deceptive_file, "w", encoding="utf-8") as f:
            f.write("Malicious payload disguised as PDF")

        meta = self.collector.collect_file_metadata(deceptive_file)
        self.assertIsNotNone(meta)
        self.assertTrue(meta.is_double_extension)
        self.assertEqual(meta.extension, ".exe")

    def test_scan_directory(self):
        f1 = os.path.join(self.temp_dir.name, "file1.txt")
        f2 = os.path.join(self.temp_dir.name, "file2.bin")
        with open(f1, "w") as f:
            f.write("1")
        with open(f2, "w") as f:
            f.write("2")

        files = self.collector.scan_directory(self.temp_dir.name)
        self.assertEqual(len(files), 2)


class TestEventLogCollector(unittest.TestCase):
    def test_dict_to_entry_conversion(self):
        collector = EventLogCollector()
        raw_event = {
            "Id": 1102,
            "RecordId": 450,
            "LogName": "Security",
            "TimeCreated": "2026-08-24T12:00:00.0000000Z",
            "ProviderName": "Microsoft-Windows-Eventlog",
            "LevelDisplayName": "Audit Success",
            "Message": "The audit log was cleared.",
            "MachineName": "DESKTOP-SEC"
        }
        entry = collector._dict_to_entry(raw_event)
        self.assertEqual(entry.event_id, 1102)
        self.assertEqual(entry.record_number, 450)
        self.assertEqual(entry.log_name, "Security")


if __name__ == "__main__":
    unittest.main()
