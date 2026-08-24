"""
Forensic Feature Extractor
Transforms raw forensic artifacts and detected findings into a structured, flat feature vector
and pandas DataFrame row suitable for training and evaluating downstream machine learning classifiers.
"""

from typing import List, Dict, Any, Optional
import pandas as pd

from ..collection.models import (
    FileMetadata,
    EventLogEntry,
    RegistryArtifact,
    MemoryArtifact,
    Finding
)


class FeatureExtractor:
    def __init__(self):
        pass

    def extract_features(
        self,
        files: Optional[List[FileMetadata]] = None,
        event_logs: Optional[List[EventLogEntry]] = None,
        registry_keys: Optional[List[RegistryArtifact]] = None,
        memory_artifacts: Optional[List[MemoryArtifact]] = None,
        findings: Optional[List[Finding]] = None
    ) -> Dict[str, float]:
        """
        Extract a comprehensive flat numeric & boolean feature dictionary across all forensic dimensions.
        """
        files = files or []
        event_logs = event_logs or []
        registry_keys = registry_keys or []
        memory_artifacts = memory_artifacts or []
        findings = findings or []

        features: Dict[str, float] = {}

        # ---------------------------------------------------------------------
        # 1. File & Timestamp Features
        # ---------------------------------------------------------------------
        total_files = len(files)
        features["total_files_scanned"] = float(total_files)

        frac_zero_count = sum(1 for f in files if f.mtime_fractional_ns == 0 and f.size_bytes > 0)
        features["fractional_zero_count"] = float(frac_zero_count)

        m_lt_c_count = 0
        for f in files:
            btime = f.birthtime or f.ctime
            if btime and f.mtime < (btime - 60):
                m_lt_c_count += 1
        features["temporal_m_lt_c_count"] = float(m_lt_c_count)

        # Count findings by sub-type
        timestomp_findings = [f for f in findings if f.category == "timestamp"]
        features["timestomp_detected_count"] = float(len(timestomp_findings))
        features["timestomp_anomaly_ratio"] = float(len(timestomp_findings) / max(total_files, 1))
        features["has_timestomp_anomaly"] = 1.0 if len(timestomp_findings) > 0 else 0.0

        future_count = sum(1 for f in timestomp_findings if "future" in f.title.lower())
        features["future_timestamp_count"] = float(future_count)

        # ---------------------------------------------------------------------
        # 2. Covert Storage & Hidden File Features
        # ---------------------------------------------------------------------
        hidden_files = sum(1 for f in files if f.is_hidden)
        features["hidden_files_count"] = float(hidden_files)

        ads_total = sum(len(f.alternate_data_streams) for f in files)
        features["ads_total_count"] = float(ads_total)

        ads_exec = 0
        for f in files:
            for s in f.alternate_data_streams:
                if s.is_executable:
                    ads_exec += 1
        features["ads_executable_count"] = float(ads_exec)
        features["has_ads_executable"] = 1.0 if ads_exec > 0 else 0.0

        double_ext_count = sum(1 for f in files if f.is_double_extension)
        features["double_extension_count"] = float(double_ext_count)

        hidden_findings = [f for f in findings if f.category == "hidden_file"]
        features["hidden_file_findings_count"] = float(len(hidden_findings))

        # ---------------------------------------------------------------------
        # 3. Log Tampering Features
        # ---------------------------------------------------------------------
        features["total_log_entries_scanned"] = float(len(event_logs))

        log_cleared = sum(1 for e in event_logs if e.event_id in (1102, 104))
        features["log_cleared_count"] = float(log_cleared)
        features["has_log_cleared"] = 1.0 if log_cleared > 0 else 0.0

        log_findings = [f for f in findings if f.category == "log"]
        log_gaps = sum(1 for f in log_findings if "gap" in f.title.lower())
        features["log_record_gap_count"] = float(log_gaps)
        features["has_log_sequence_gap"] = 1.0 if log_gaps > 0 else 0.0

        # ---------------------------------------------------------------------
        # 4. Registry Anti-Forensics Configuration Features
        # ---------------------------------------------------------------------
        prefetch_disabled = 0.0
        last_access_disabled = 0.0
        eventlog_disabled = 0.0
        crashdump_disabled = 0.0

        for r in registry_keys:
            if r.value_name == "EnablePrefetcher" and r.value_data == 0:
                prefetch_disabled = 1.0
            elif r.value_name == "NtfsDisableLastAccessUpdate" and r.value_data == 1:
                last_access_disabled = 1.0
            elif r.value_name == "Start" and r.value_data == 4 and "EventLog" in r.key_path:
                eventlog_disabled = 1.0
            elif r.value_name == "CrashDumpEnabled" and r.value_data == 0:
                crashdump_disabled = 1.0

        features["prefetch_disabled_flag"] = prefetch_disabled
        features["last_access_disabled_flag"] = last_access_disabled
        features["eventlog_service_disabled_flag"] = eventlog_disabled
        features["crash_dump_disabled_flag"] = crashdump_disabled
        features["registry_tamper_count"] = float(sum(1 for r in registry_keys if r.is_anomalous))

        # ---------------------------------------------------------------------
        # 5. Memory Forensics Features
        # ---------------------------------------------------------------------
        mem_findings = [f for f in findings if f.category == "memory"]
        unlinked_count = sum(1 for f in mem_findings if "unlinked" in f.title.lower() or "dkom" in f.title.lower())
        injected_count = sum(1 for f in mem_findings if "injected" in f.title.lower() or "hollowing" in f.title.lower())

        features["unlinked_process_count"] = float(unlinked_count)
        features["injected_process_count"] = float(injected_count)
        features["has_unlinked_process"] = 1.0 if unlinked_count > 0 else 0.0
        features["has_memory_injection"] = 1.0 if injected_count > 0 else 0.0

        # ---------------------------------------------------------------------
        # 6. YARA Signature Features
        # ---------------------------------------------------------------------
        yara_findings = [f for f in findings if f.category in ("yara", "file_wiping", "evidence_elimination")]
        features["yara_matches_count"] = float(len(yara_findings))
        features["yara_high_severity_count"] = float(sum(1 for f in yara_findings if f.severity in ("HIGH", "CRITICAL")))
        features["has_yara_match"] = 1.0 if len(yara_findings) > 0 else 0.0

        # ---------------------------------------------------------------------
        # 7. Finding Severity Breakdown & Composite Risk Score
        # ---------------------------------------------------------------------
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        med_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")

        features["critical_findings_count"] = float(crit_count)
        features["high_findings_count"] = float(high_count)
        features["medium_findings_count"] = float(med_count)
        features["low_findings_count"] = float(low_count)
        features["total_findings_count"] = float(len(findings))

        # Composite Risk Score Calculation (0.0 to 100.0)
        risk = self.calculate_composite_risk_score(features)
        features["anti_forensics_risk_score"] = float(round(risk, 2))

        return features

    def calculate_composite_risk_score(self, features: Dict[str, float]) -> float:
        """
        Calculate weighted threat score based on forensic evidence severity.
        Weights:
        - Critical findings (log wipe, unlinked DKOM process, exec ADS): 25 pts each
        - High findings (timestomp M<C, YARA match, double ext): 12 pts each
        - Medium findings (subsecond zeroing, clock changes): 5 pts each
        - Registry tampering (prefetch disabled, eventlog stopped): 10 pts each
        """
        score = 0.0
        score += features.get("critical_findings_count", 0.0) * 25.0
        score += features.get("high_findings_count", 0.0) * 12.0
        score += features.get("medium_findings_count", 0.0) * 5.0
        score += features.get("low_findings_count", 0.0) * 1.5

        if features.get("prefetch_disabled_flag", 0.0) > 0:
            score += 10.0
        if features.get("eventlog_service_disabled_flag", 0.0) > 0:
            score += 20.0
        if features.get("has_ads_executable", 0.0) > 0:
            score += 15.0

        return min(100.0, score)

    def to_dataframe(self, features: Dict[str, float], scan_id: str = "") -> pd.DataFrame:
        """Convert feature dictionary into a 1-row pandas DataFrame."""
        row_dict = {"scan_id": scan_id, **features} if scan_id else features
        return pd.DataFrame([row_dict])
