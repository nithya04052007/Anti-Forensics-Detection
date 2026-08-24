"""
Unit tests for Forensic Analysis modules
"""

import unittest
import time
from datetime import datetime

from src.collection.models import (
    FileMetadata,
    AlternateDataStream,
    EventLogEntry,
    MemoryArtifact
)
from src.analysis.timestamp_analyzer import TimestampAnalyzer
from src.analysis.log_analyzer import LogAnalyzer
from src.analysis.hidden_file_analyzer import HiddenFileAnalyzer
from src.analysis.memory_analyzer import MemoryAnalyzer
from src.analysis.yara_scanner import YaraScanner


class TestTimestampAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = TimestampAnalyzer()

    def test_detect_subsecond_zeroing(self):
        meta = FileMetadata(
            path="C:\\sample.exe",
            filename="sample.exe",
            size_bytes=1024,
            mtime=1700000000.0,
            atime=1700000000.0,
            ctime=1700000000.0,
            birthtime=1700000000.0,
            mtime_ns=1700000000000000000,
            atime_ns=1700000000000000000,
            ctime_ns=1700000000000000000,
            birthtime_ns=1700000000000000000,
            mtime_fractional_ns=0,  # Zeroed out
            atime_fractional_ns=0,
            ctime_fractional_ns=0,
            birthtime_fractional_ns=0
        )
        findings = self.analyzer.analyze_file(meta)
        zero_findings = [f for f in findings if "Sub-Second" in f.title]
        self.assertTrue(len(zero_findings) > 0)
        self.assertEqual(zero_findings[0].severity, "HIGH")

    def test_detect_m_lt_c_inconsistency(self):
        now = time.time()
        past = now - (86400 * 365) # 1 year ago
        meta = FileMetadata(
            path="C:\\implant.dll",
            filename="implant.dll",
            size_bytes=2048,
            mtime=past,
            atime=now,
            ctime=now,
            birthtime=now, # Created now, but modified 1 year ago!
            mtime_ns=int(past * 1e9),
            atime_ns=int(now * 1e9),
            ctime_ns=int(now * 1e9),
            birthtime_ns=int(now * 1e9),
            mtime_fractional_ns=123456,
            atime_fractional_ns=654321,
            ctime_fractional_ns=987654,
            birthtime_fractional_ns=987654
        )
        findings = self.analyzer.analyze_file(meta)
        causal_findings = [f for f in findings if "Modified < Created" in f.title]
        self.assertTrue(len(causal_findings) > 0)
        self.assertEqual(causal_findings[0].severity, "HIGH")

    def test_detect_future_timestamp(self):
        future_time = time.time() + (86400 * 30) # 30 days in future
        meta = FileMetadata(
            path="C:\\future.bin",
            filename="future.bin",
            size_bytes=512,
            mtime=future_time,
            atime=time.time(),
            ctime=time.time(),
            birthtime=time.time(),
            mtime_ns=int(future_time * 1e9),
            atime_ns=int(time.time() * 1e9),
            ctime_ns=int(time.time() * 1e9),
            birthtime_ns=int(time.time() * 1e9),
            mtime_fractional_ns=100,
            atime_fractional_ns=100,
            ctime_fractional_ns=100,
            birthtime_fractional_ns=100
        )
        findings = self.analyzer.analyze_file(meta)
        future_findings = [f for f in findings if "Future Timestamp" in f.title]
        self.assertTrue(len(future_findings) > 0)
        self.assertEqual(future_findings[0].severity, "CRITICAL")


class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = LogAnalyzer()

    def test_detect_log_cleared_event_1102(self):
        entries = [
            EventLogEntry(
                event_id=1102,
                record_number=50,
                log_name="Security",
                time_created="2026-08-24T12:00:00Z",
                time_created_epoch=1787565600.0,
                source_name="Microsoft-Windows-Eventlog",
                level="Audit Success",
                message="The audit log was cleared",
                computer="HOST-01"
            )
        ]
        findings = self.analyzer.analyze_entries(entries)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn("1102", findings[0].title)

    def test_detect_sequence_gap(self):
        entries = [
            EventLogEntry(
                event_id=4624,
                record_number=100,
                log_name="Security",
                time_created="2026-08-24T12:00:00Z",
                time_created_epoch=1787565600.0,
                source_name="Security",
                level="Info",
                message="Logon",
                computer="HOST-01"
            ),
            EventLogEntry(
                event_id=4625,
                record_number=105, # Records 101-104 missing!
                log_name="Security",
                time_created="2026-08-24T12:05:00Z",
                time_created_epoch=1787565900.0,
                source_name="Security",
                level="Info",
                message="Logon failed",
                computer="HOST-01"
            )
        ]
        findings = self.analyzer.analyze_entries(entries)
        gap_findings = [f for f in findings if "Sequence Gap" in f.title]
        self.assertEqual(len(gap_findings), 1)
        self.assertEqual(gap_findings[0].evidence["missing_count"], 4)


class TestHiddenFileAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = HiddenFileAnalyzer()

    def test_detect_executable_ads(self):
        meta = FileMetadata(
            path="C:\\test.txt",
            filename="test.txt",
            size_bytes=100,
            mtime=time.time(),
            atime=time.time(),
            ctime=time.time(),
            birthtime=time.time(),
            mtime_ns=int(time.time() * 1e9),
            atime_ns=int(time.time() * 1e9),
            ctime_ns=int(time.time() * 1e9),
            birthtime_ns=int(time.time() * 1e9),
            mtime_fractional_ns=111,
            atime_fractional_ns=222,
            ctime_fractional_ns=333,
            birthtime_fractional_ns=333,
            alternate_data_streams=[
                AlternateDataStream(
                    name=":payload.exe",
                    size_bytes=4096,
                    is_zone_identifier=False,
                    is_executable=True
                )
            ]
        )
        findings = self.analyzer.analyze_file(meta)
        ads_findings = [f for f in findings if "Executable Alternate Data Stream" in f.title]
        self.assertEqual(len(ads_findings), 1)
        self.assertEqual(ads_findings[0].severity, "CRITICAL")


class TestYaraScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = YaraScanner()

    def test_yara_matches_anti_forensic_commands(self):
        content = b"wevtutil.exe cl Security\nvssadmin delete shadows /all\nsdelete.exe -z"
        findings = self.scanner.scan_bytes(content)
        self.assertTrue(len(findings) > 0)


if __name__ == "__main__":
    unittest.main()
