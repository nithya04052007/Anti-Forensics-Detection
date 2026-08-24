"""
TeamMember1 — Core Forensic Scanner Coordinator
Runs read-only inspection of evidence files by orchestrating metadata collection,
hidden file detection, hidden folder detection, and file signature verification.
"""

import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

from .metadata import collect_file_metadata, FileMetadataResult
from .hidden_file import check_hidden_file, HiddenFileResult
from .hidden_folder import check_hidden_folder, HiddenFolderResult
from .signature import check_file_signature, FileSignatureResult


@dataclass
class ForensicFileReport:
    file_name: str
    file_path: str
    metadata: FileMetadataResult
    hidden_file: HiddenFileResult
    hidden_folder: HiddenFolderResult
    signature: FileSignatureResult
    findings: List[Dict[str, Any]] = field(default_factory=list)
    feature_vector: Dict[str, float] = field(default_factory=dict)
    suspicious_indicators_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "file_path": self.file_path,
            "metadata": self.metadata.to_dict(),
            "hidden_file": self.hidden_file.to_dict(),
            "hidden_folder": self.hidden_folder.to_dict(),
            "signature": self.signature.to_dict(),
            "findings": self.findings,
            "feature_vector": self.feature_vector,
            "suspicious_indicators_count": self.suspicious_indicators_count
        }


def scan_evidence_file(file_path: str) -> ForensicFileReport:
    """
    Perform deep forensic analysis on a single evidence file in strict READ-ONLY mode.
    Never alters, renames, or writes to the target evidence file.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Selected evidence file does not exist: {file_path}")

    # 1. Collect Metadata
    meta = collect_file_metadata(file_path)

    # 2. Check Hidden File & ADS
    hidden_f = check_hidden_file(file_path)

    # 3. Check Hidden Folder & Path Residency
    hidden_dir = check_hidden_folder(file_path)

    # 4. Check File Signature & Extension Mismatch
    sig = check_file_signature(file_path)

    # 5. Compile Forensic Findings
    findings: List[Dict[str, Any]] = []

    # Signature & Mismatch Findings
    if sig.is_disguised_executable:
        findings.append({
            "category": "extension_tampering",
            "severity": "CRITICAL",
            "title": "Disguised Executable Binary",
            "description": f"File has extension '{sig.claimed_extension}' but header is an executable PE binary ({sig.actual_type})."
        })
    elif sig.is_extension_mismatch:
        findings.append({
            "category": "extension_tampering",
            "severity": "HIGH",
            "title": "File Extension Mismatch",
            "description": f"Claimed extension '{sig.claimed_extension}' does not match actual signature '{sig.actual_type}'."
        })

    if sig.has_double_extension:
        findings.append({
            "category": "covert_storage",
            "severity": "HIGH",
            "title": "Deceptive Double Extension",
            "description": f"Filename '{meta.file_name}' utilizes double extension to masquerade executable content."
        })

    # Hidden & Covert Findings
    if hidden_f.has_executable_stream:
        findings.append({
            "category": "covert_storage",
            "severity": "CRITICAL",
            "title": "Executable Alternate Data Stream (ADS)",
            "description": "Host file contains a hidden executable payload stream in NTFS ADS."
        })
    elif hidden_f.has_alternate_data_streams:
        non_zone = [s for s in hidden_f.streams if not s.is_zone_identifier]
        if non_zone:
            findings.append({
                "category": "covert_storage",
                "severity": "MEDIUM",
                "title": "Non-Standard Alternate Data Stream",
                "description": f"Contains {len(non_zone)} hidden NTFS Alternate Data Stream(s)."
            })

    if hidden_f.is_hidden and hidden_f.is_system:
        findings.append({
            "category": "hidden_attributes",
            "severity": "HIGH",
            "title": "Hidden & System Attribute Masking",
            "description": "File has both HIDDEN and SYSTEM attributes enabled."
        })
    elif hidden_f.is_hidden:
        findings.append({
            "category": "hidden_attributes",
            "severity": "LOW",
            "title": "Hidden File Attribute Set",
            "description": "File has the Windows HIDDEN attribute set."
        })

    if hidden_dir.is_in_hidden_folder:
        findings.append({
            "category": "hidden_residency",
            "severity": "MEDIUM",
            "title": "Hosted in Hidden Folder",
            "description": f"Resides in hidden directory: '{hidden_dir.hidden_folder_path}'."
        })

    # Timestamp Anomalies
    if meta.is_subsecond_zeroed:
        findings.append({
            "category": "timestamp",
            "severity": "MEDIUM",
            "title": "Sub-Second Timestamp Zeroing (Timestomp)",
            "description": "Modified timestamp has exactly 0 fractional nanoseconds (.0000000 s)."
        })

    if meta.is_m_lt_c:
        findings.append({
            "category": "timestamp",
            "severity": "HIGH",
            "title": "Causal Timestamp Inconsistency (Modified < Created)",
            "description": f"Modified timestamp ({meta.modified_time}) is older than Creation time ({meta.created_time})."
        })

    if meta.is_future_timestamp:
        findings.append({
            "category": "timestamp",
            "severity": "CRITICAL",
            "title": "Future Timestamp Anomaly",
            "description": f"Modification timestamp is set in the future ({meta.modified_time})."
        })

    # 6. Build Standard ML Feature Vector
    features = build_feature_vector(meta, hidden_f, hidden_dir, sig, findings)

    return ForensicFileReport(
        file_name=meta.file_name,
        file_path=meta.file_path,
        metadata=meta,
        hidden_file=hidden_f,
        hidden_folder=hidden_dir,
        signature=sig,
        findings=findings,
        feature_vector=features,
        suspicious_indicators_count=len(findings)
    )


def build_feature_vector(
    meta: FileMetadataResult,
    hidden_f: HiddenFileResult,
    hidden_dir: HiddenFolderResult,
    sig: FileSignatureResult,
    findings: List[Dict[str, Any]]
) -> Dict[str, float]:
    """
    Construct a standardized numeric feature vector for ML training and inference.
    Order and naming must be strictly consistent.
    """
    has_meta_anom = 1.0 if (meta.is_subsecond_zeroed or meta.is_m_lt_c or meta.is_future_timestamp) else 0.0
    has_fname_anom = 1.0 if (sig.has_double_extension or sig.is_disguised_executable) else 0.0

    return {
        "file_size": float(meta.file_size),
        "is_hidden": 1.0 if hidden_f.is_hidden else 0.0,
        "is_in_hidden_folder": 1.0 if hidden_dir.is_in_hidden_folder else 0.0,
        "extension_match": 1.0 if sig.extension_match else 0.0,
        "has_double_extension": 1.0 if sig.has_double_extension else 0.0,
        "has_suspicious_extension": 1.0 if sig.has_suspicious_extension else 0.0,
        "signature_type": float(sig.signature_category_code),
        "metadata_anomaly": has_meta_anom,
        "filename_anomaly": has_fname_anom,
        "access_time_anomaly": 1.0 if meta.accessed_epoch < meta.created_epoch else 0.0,
        "modification_time_anomaly": 1.0 if meta.is_m_lt_c else 0.0,
        "creation_time_anomaly": 1.0 if meta.is_future_timestamp else 0.0,
        "has_ads_streams": 1.0 if hidden_f.has_alternate_data_streams else 0.0,
        "subsecond_zeroed": 1.0 if meta.is_subsecond_zeroed else 0.0,
        "causal_m_lt_c": 1.0 if meta.is_m_lt_c else 0.0,
        "future_timestamp": 1.0 if meta.is_future_timestamp else 0.0
    }
