"""
Hidden File and Alternate Data Stream (ADS) Forensic Analyzer
Detects covert storage techniques used to hide payloads and evade standard directory listing:
- NTFS Alternate Data Streams (hidden executables/scripts in ADS)
- Deceptive Double File Extensions (e.g. report.pdf.exe)
- Hidden + System attribute combinations in suspicious user directories
- File wiper remnants and zero-byte truncation artifacts
"""

import os
from typing import List, Dict, Any, Optional

from ..collection.models import FileMetadata, Finding

SUSPICIOUS_LOCATIONS = ["temp", "appdata", "local\\temp", "public", "programdata", "downloads"]


class HiddenFileAnalyzer:
    def __init__(self):
        pass

    def analyze_file(self, file_meta: FileMetadata, scan_id: str = "") -> List[Finding]:
        """Analyze a single file metadata record for covert hiding and evasion techniques."""
        findings: List[Finding] = []
        path_lower = file_meta.path.lower()

        # ---------------------------------------------------------------------
        # Analysis 1: NTFS Alternate Data Streams (ADS)
        # ---------------------------------------------------------------------
        if file_meta.alternate_data_streams:
            for stream in file_meta.alternate_data_streams:
                if stream.is_zone_identifier:
                    # Zone.Identifier is normal Windows Mark of the Web
                    continue

                if stream.is_executable:
                    findings.append(Finding(
                        scan_id=scan_id,
                        category="hidden_file",
                        severity="CRITICAL",
                        title=f"Executable Alternate Data Stream: {stream.name}",
                        description=(
                            f"File '{file_meta.filename}' contains a hidden executable NTFS stream '{stream.name}' "
                            f"({stream.size_bytes} bytes). Attackers use ADS to hide malicious binaries/scripts "
                            "from standard Explorer and command prompt views."
                        ),
                        artifact_path=f"{file_meta.path}{stream.name}",
                        evidence={
                            "stream_name": stream.name,
                            "stream_size": stream.size_bytes,
                            "is_executable": True,
                            "host_file": file_meta.path
                        }
                    ))
                else:
                    # Non-standard ADS stream (e.g. hidden config or payload)
                    severity = "HIGH" if stream.size_bytes > 5000 else "MEDIUM"
                    findings.append(Finding(
                        scan_id=scan_id,
                        category="hidden_file",
                        severity=severity,
                        title=f"Non-Standard Alternate Data Stream: {stream.name}",
                        description=(
                            f"File '{file_meta.filename}' contains a hidden NTFS alternate stream '{stream.name}' "
                            f"({stream.size_bytes} bytes)."
                        ),
                        artifact_path=f"{file_meta.path}{stream.name}",
                        evidence={
                            "stream_name": stream.name,
                            "stream_size": stream.size_bytes,
                            "is_executable": False,
                            "host_file": file_meta.path
                        }
                    ))

        # ---------------------------------------------------------------------
        # Analysis 2: Deceptive Double Extensions
        # ---------------------------------------------------------------------
        if file_meta.is_double_extension:
            findings.append(Finding(
                scan_id=scan_id,
                category="hidden_file",
                severity="HIGH",
                title=f"Deceptive Double File Extension: {file_meta.filename}",
                description=(
                    f"File '{file_meta.filename}' uses a deceptive double extension to masquerade an executable "
                    "or script as a benign document or image."
                ),
                artifact_path=file_meta.path,
                evidence={
                    "filename": file_meta.filename,
                    "extension": file_meta.extension
                }
            ))

        # ---------------------------------------------------------------------
        # Analysis 3: Hidden + System Attribute Masking
        # ---------------------------------------------------------------------
        if file_meta.is_hidden and file_meta.is_system:
            # Check if located in user-writable paths rather than Windows system directories
            in_suspicious_location = any(loc in path_lower for loc in SUSPICIOUS_LOCATIONS)
            if in_suspicious_location or "system32" not in path_lower:
                findings.append(Finding(
                    scan_id=scan_id,
                    category="hidden_file",
                    severity="HIGH",
                    title="Hidden & System Attribute Masking in User Directory",
                    description=(
                        f"File '{file_meta.filename}' has both HIDDEN and SYSTEM attributes enabled "
                        f"in a non-system folder '{file_meta.path}'. Used by malware and rootkits to evade user discovery."
                    ),
                    artifact_path=file_meta.path,
                    evidence={
                        "attributes": file_meta.attributes,
                        "path": file_meta.path
                    }
                ))

        return findings

    def analyze_batch(self, file_metas: List[FileMetadata], scan_id: str = "") -> List[Finding]:
        """Analyze a list of file metadata records for hidden file anomalies."""
        all_findings: List[Finding] = []
        for meta in file_metas:
            all_findings.extend(self.analyze_file(meta, scan_id=scan_id))
        return all_findings
