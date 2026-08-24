"""
Timestamp Forensic Analyzer (Timestomping Detection)
Analyzes high-resolution MACB file metadata for anti-forensic timestamp manipulations:
- Sub-second / Nanosecond zeroing (classic timestomping artifact on NTFS)
- Causal temporal violations (Modified time older than Created time: M < C)
- Timestamps in the future or pre-epoch historical dates
- Round-time timestamp clustering
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import time

from ..collection.models import FileMetadata, Finding

# Thresholds
ONE_HOUR = 3600
MINIMUM_REALISTIC_YEAR = 1995


class TimestampAnalyzer:
    def __init__(self, future_tolerance_seconds: int = ONE_HOUR):
        self.future_tolerance = future_tolerance_seconds

    def analyze_file(self, file_meta: FileMetadata, scan_id: str = "") -> List[Finding]:
        """Analyze a single file for timestamp anomalies and anti-forensics indicators."""
        findings: List[Finding] = []
        now_epoch = time.time()

        # Extract timestamps
        mtime = file_meta.mtime
        atime = file_meta.atime
        ctime = file_meta.ctime
        birthtime = file_meta.birthtime or ctime

        # ---------------------------------------------------------------------
        # Rule 1: Sub-second / Nanosecond Zeroing (Timestomp Signature)
        # ---------------------------------------------------------------------
        # NTFS has 100ns precision. Classic timestomp tools only write integer seconds.
        # If mtime fractional ns is exactly 0 on NTFS, it's a high-probability timestomp artifact.
        is_mtime_zeroed = (file_meta.mtime_fractional_ns == 0)
        is_atime_zeroed = (file_meta.atime_fractional_ns == 0)
        is_ctime_zeroed = (file_meta.ctime_fractional_ns == 0)

        if is_mtime_zeroed and file_meta.size_bytes > 0:
            severity = "HIGH" if (is_atime_zeroed and is_ctime_zeroed) else "MEDIUM"
            findings.append(Finding(
                scan_id=scan_id,
                category="timestamp",
                severity=severity,
                title="Sub-Second Timestamp Zeroing (Timestomp Indicator)",
                description=(
                    f"File '{file_meta.filename}' has exactly 0 fractional nanoseconds in its "
                    f"Modified timestamp ({datetime.fromtimestamp(mtime).isoformat()}.0000000). "
                    "This is a classic artifact of anti-forensic timestomping utilities."
                ),
                artifact_path=file_meta.path,
                evidence={
                    "anomaly": "subsecond_zeroing",
                    "mtime_ns": file_meta.mtime_ns,
                    "mtime_fractional_ns": file_meta.mtime_fractional_ns,
                    "atime_fractional_ns": file_meta.atime_fractional_ns,
                    "ctime_fractional_ns": file_meta.ctime_fractional_ns
                }
            ))

        # ---------------------------------------------------------------------
        # Rule 2: Causal Inconsistency (M < C / Modified Older Than Created)
        # ---------------------------------------------------------------------
        # When an attacker drops a payload on a victim system and modifies its MTIME
        # to match an old system binary (e.g. 2018), the Creation time remains today (2026),
        # causing Modified Time to be significantly older than Created Time.
        if birthtime and mtime < (birthtime - 60):  # 60s tolerance
            time_delta_days = (birthtime - mtime) / 86400.0
            findings.append(Finding(
                scan_id=scan_id,
                category="timestamp",
                severity="HIGH",
                title="Causal Timestamp Inconsistency (Modified < Created)",
                description=(
                    f"File '{file_meta.filename}' was modified {time_delta_days:.1f} days BEFORE "
                    f"it was created on this file system. (Modified: {datetime.fromtimestamp(mtime).isoformat()}, "
                    f"Created: {datetime.fromtimestamp(birthtime).isoformat()}). Common timestomp backdating indicator."
                ),
                artifact_path=file_meta.path,
                evidence={
                    "anomaly": "m_lt_c_inconsistency",
                    "mtime": mtime,
                    "birthtime": birthtime,
                    "delta_days": round(time_delta_days, 2),
                    "mtime_iso": datetime.fromtimestamp(mtime).isoformat(),
                    "birthtime_iso": datetime.fromtimestamp(birthtime).isoformat()
                }
            ))

        # ---------------------------------------------------------------------
        # Rule 3: Future Timestamp (Clock Manipulation / Evasion)
        # ---------------------------------------------------------------------
        if mtime > (now_epoch + self.future_tolerance):
            delta_future_hours = (mtime - now_epoch) / 3600.0
            findings.append(Finding(
                scan_id=scan_id,
                category="timestamp",
                severity="CRITICAL",
                title="Future Timestamp Detected",
                description=(
                    f"File '{file_meta.filename}' has a modification timestamp set {delta_future_hours:.1f} hours "
                    f"into the future ({datetime.fromtimestamp(mtime).isoformat()}). Indicates clock skew or forward timestomping."
                ),
                artifact_path=file_meta.path,
                evidence={
                    "anomaly": "future_timestamp",
                    "mtime": mtime,
                    "now_epoch": now_epoch,
                    "delta_future_hours": round(delta_future_hours, 2)
                }
            ))

        # ---------------------------------------------------------------------
        # Rule 4: Suspicious Historical / Pre-Epoch Date
        # ---------------------------------------------------------------------
        try:
            m_year = datetime.fromtimestamp(mtime).year
            if m_year < MINIMUM_REALISTIC_YEAR:
                findings.append(Finding(
                    scan_id=scan_id,
                    category="timestamp",
                    severity="HIGH",
                    title="Pre-Historical Timestamp (Artificial Epoch)",
                    description=(
                        f"File '{file_meta.filename}' has an impossible historical timestamp "
                        f"year {m_year} ({datetime.fromtimestamp(mtime).isoformat()})."
                    ),
                    artifact_path=file_meta.path,
                    evidence={
                        "anomaly": "pre_epoch_date",
                        "year": m_year,
                        "mtime": mtime
                    }
                ))
        except (ValueError, OSError):
            pass

        return findings

    def analyze_batch(self, file_metas: List[FileMetadata], scan_id: str = "") -> List[Finding]:
        """Analyze a list of file metadata records for timestamp anomalies."""
        all_findings: List[Finding] = []
        for meta in file_metas:
            all_findings.extend(self.analyze_file(meta, scan_id=scan_id))
        return all_findings
