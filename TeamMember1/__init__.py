"""
TeamMember1 Forensic Analysis Package
Provides read-only forensic collectors for metadata, hidden files, hidden folders,
file signatures / magic bytes, and extension mismatch detection.
"""

from .metadata import collect_file_metadata, FileMetadataResult
from .hidden_file import check_hidden_file, check_alternate_data_streams, HiddenFileResult
from .hidden_folder import check_hidden_folder, HiddenFolderResult
from .signature import check_file_signature, FileSignatureResult
from .scanner import scan_evidence_file, ForensicFileReport

__all__ = [
    "collect_file_metadata",
    "FileMetadataResult",
    "check_hidden_file",
    "check_alternate_data_streams",
    "HiddenFileResult",
    "check_hidden_folder",
    "HiddenFolderResult",
    "check_file_signature",
    "FileSignatureResult",
    "scan_evidence_file",
    "ForensicFileReport"
]
