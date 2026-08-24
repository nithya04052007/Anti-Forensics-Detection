"""
TeamMember1 — Metadata Collector
Extracts file size, MACB timestamps with nanosecond resolution, Windows attributes,
and cryptographic hashes in strict READ-ONLY mode.
"""

import os
import sys
import time
import ctypes
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

# Windows Attribute Constants
FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN   = 0x00000002
FILE_ATTRIBUTE_SYSTEM   = 0x00000004
FILE_ATTRIBUTE_ARCHIVE  = 0x00000020


@dataclass
class FileMetadataResult:
    file_name: str
    file_path: str
    file_size: int
    extension: str
    created_time: str
    created_epoch: float
    modified_time: str
    modified_epoch: float
    accessed_time: str
    accessed_epoch: float
    mtime_ns: int
    atime_ns: int
    ctime_ns: int
    birthtime_ns: Optional[int]
    mtime_fractional_ns: int
    is_m_lt_c: bool = False
    is_future_timestamp: bool = False
    is_subsecond_zeroed: bool = False
    file_attributes: List[str] = field(default_factory=list)
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def collect_file_metadata(file_path: str) -> FileMetadataResult:
    """
    Collect comprehensive forensic metadata for a target file in strict READ-ONLY mode.
    Never modifies, renames, or executes the target file.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    abs_path = os.path.abspath(file_path)
    file_name = os.path.basename(abs_path)
    ext = os.path.splitext(file_name)[1].lower()

    stat_res = os.stat(abs_path, follow_symlinks=False)
    size_bytes = stat_res.st_size

    # Timestamps
    mtime = stat_res.st_mtime
    atime = stat_res.st_atime
    ctime = stat_res.st_ctime
    birthtime = getattr(stat_res, 'st_birthtime', None)
    if birthtime is None and sys.platform == "win32":
        birthtime = ctime

    mtime_ns = getattr(stat_res, 'st_mtime_ns', int(mtime * 1_000_000_000))
    atime_ns = getattr(stat_res, 'st_atime_ns', int(atime * 1_000_000_000))
    ctime_ns = getattr(stat_res, 'st_ctime_ns', int(ctime * 1_000_000_000))
    birthtime_ns = getattr(stat_res, 'st_birthtime_ns', int((birthtime or ctime) * 1_000_000_000))

    # Nanosecond Sub-second analysis
    mtime_fractional = mtime_ns % 1_000_000_000
    is_zeroed = (mtime_fractional == 0 and size_bytes > 0)

    # Anomaly checks
    now_epoch = time.time()
    effective_birth = birthtime or ctime
    is_m_lt_c = bool(effective_birth and mtime < (effective_birth - 60))
    is_future = bool(mtime > (now_epoch + 3600))

    # Attributes
    attrs = []
    if sys.platform == "win32":
        try:
            raw_attrs = ctypes.windll.kernel32.GetFileAttributesW(abs_path)
            if raw_attrs != 0xFFFFFFFF and raw_attrs != -1:
                if raw_attrs & FILE_ATTRIBUTE_READONLY: attrs.append("READONLY")
                if raw_attrs & FILE_ATTRIBUTE_HIDDEN: attrs.append("HIDDEN")
                if raw_attrs & FILE_ATTRIBUTE_SYSTEM: attrs.append("SYSTEM")
                if raw_attrs & FILE_ATTRIBUTE_ARCHIVE: attrs.append("ARCHIVE")
        except Exception:
            pass

    # Read-only hashing
    md5_str, sha256_str = _compute_hashes_readonly(abs_path)

    # Formatted ISO strings
    created_iso = datetime.fromtimestamp(effective_birth, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    modified_iso = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    accessed_iso = datetime.fromtimestamp(atime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return FileMetadataResult(
        file_name=file_name,
        file_path=abs_path,
        file_size=size_bytes,
        extension=ext,
        created_time=created_iso,
        created_epoch=effective_birth,
        modified_time=modified_iso,
        modified_epoch=mtime,
        accessed_time=accessed_iso,
        accessed_epoch=atime,
        mtime_ns=mtime_ns,
        atime_ns=atime_ns,
        ctime_ns=ctime_ns,
        birthtime_ns=birthtime_ns,
        mtime_fractional_ns=mtime_fractional,
        is_m_lt_c=is_m_lt_c,
        is_future_timestamp=is_future,
        is_subsecond_zeroed=is_zeroed,
        file_attributes=attrs,
        md5_hash=md5_str,
        sha256_hash=sha256_str
    )


def _compute_hashes_readonly(path: str):
    """Compute MD5 and SHA256 hashes strictly in read-only mode."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except Exception:
        return None, None
