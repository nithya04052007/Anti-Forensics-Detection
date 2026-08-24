"""
File Metadata and Alternate Data Stream (ADS) Collector
Extracts high-resolution MACB timestamps, nanosecond precision, Windows file attributes,
Alternate Data Streams, and cryptographic hashes.
"""

import os
import sys
import ctypes
import hashlib
from typing import List, Dict, Any, Optional, Generator
from datetime import datetime

from .models import FileMetadata, AlternateDataStream

# Win32 API Constants for File Attributes & Streams
FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_ARCHIVE = 0x00000020
FILE_ATTRIBUTE_NORMAL = 0x00000080

SUSPICIOUS_EXECUTABLE_EXTENSIONS = {
    ".exe", ".vbs", ".bat", ".cmd", ".ps1", ".scr", ".pif", ".dll", ".js", ".hta", ".cpl"
}

DOUBLE_EXTENSION_DECEPTIVE_PREFIXES = {
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".png", ".jpg", ".jpeg", ".txt", ".csv"
}


class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [
        ("StreamSize", ctypes.c_longlong),
        ("cStreamName", ctypes.c_wchar * 296),
    ]


class FileCollector:
    def __init__(self, max_files: int = 10000, compute_hashes: bool = True):
        self.max_files = max_files
        self.compute_hashes = compute_hashes
        self._is_windows = (sys.platform == "win32")

    def collect_file_metadata(self, file_path: str) -> Optional[FileMetadata]:
        """Collect deep forensic metadata for a single file."""
        if not os.path.exists(file_path):
            return None

        try:
            stat_res = os.stat(file_path, follow_symlinks=False)
        except (PermissionError, FileNotFoundError, OSError):
            return None

        filename = os.path.basename(file_path)
        size_bytes = stat_res.st_size

        # Timestamps (Epoch seconds & Nanoseconds)
        mtime = stat_res.st_mtime
        atime = stat_res.st_atime
        ctime = stat_res.st_ctime

        mtime_ns = getattr(stat_res, 'st_mtime_ns', int(mtime * 1_000_000_000))
        atime_ns = getattr(stat_res, 'st_atime_ns', int(atime * 1_000_000_000))
        ctime_ns = getattr(stat_res, 'st_ctime_ns', int(ctime * 1_000_000_000))

        # Windows Birthtime / Creation time
        birthtime = getattr(stat_res, 'st_birthtime', None)
        birthtime_ns = getattr(stat_res, 'st_birthtime_ns', None)
        if birthtime is None and self._is_windows:
            # On Windows, st_ctime is the file creation time
            birthtime = ctime
            birthtime_ns = ctime_ns

        # Fractional Nanoseconds (modulo 1 second = 1,000,000,000 ns)
        mtime_frac = mtime_ns % 1_000_000_000
        atime_frac = atime_ns % 1_000_000_000
        ctime_frac = ctime_ns % 1_000_000_000
        birthtime_frac = (birthtime_ns % 1_000_000_000) if birthtime_ns is not None else None

        # File Attributes (Hidden, System, ReadOnly)
        attributes, is_hidden, is_system, is_readonly = self._get_file_attributes(file_path, stat_res)

        # Alternate Data Streams (ADS) on NTFS
        streams = self.get_alternate_data_streams(file_path)

        # Extension analysis
        ext = os.path.splitext(filename)[1].lower()
        is_double_ext = self._check_double_extension(filename)

        # Hashes
        md5_hash = None
        sha256_hash = None
        if self.compute_hashes and os.path.isfile(file_path) and size_bytes < 50 * 1024 * 1024:
            md5_hash, sha256_hash = self._calculate_hashes(file_path)

        return FileMetadata(
            path=os.path.abspath(file_path),
            filename=filename,
            size_bytes=size_bytes,
            mtime=mtime,
            atime=atime,
            ctime=ctime,
            birthtime=birthtime,
            mtime_ns=mtime_ns,
            atime_ns=atime_ns,
            ctime_ns=ctime_ns,
            birthtime_ns=birthtime_ns,
            mtime_fractional_ns=mtime_frac,
            atime_fractional_ns=atime_frac,
            ctime_fractional_ns=ctime_frac,
            birthtime_fractional_ns=birthtime_frac,
            is_hidden=is_hidden,
            is_system=is_system,
            is_readonly=is_readonly,
            attributes=attributes,
            alternate_data_streams=streams,
            md5=md5_hash,
            sha256=sha256_hash,
            extension=ext,
            is_double_extension=is_double_ext
        )

    def scan_directory(self, root_dir: str) -> List[FileMetadata]:
        """Recursively collect metadata for all files in a directory tree."""
        collected: List[FileMetadata] = []
        if not os.path.exists(root_dir):
            return collected

        count = 0
        for root, dirs, files in os.walk(root_dir):
            # Check directory itself
            for f in files:
                full_path = os.path.join(root, f)
                meta = self.collect_file_metadata(full_path)
                if meta:
                    collected.append(meta)
                    count += 1
                    if count >= self.max_files:
                        return collected

        return collected

    def get_alternate_data_streams(self, file_path: str) -> List[AlternateDataStream]:
        """Enumerate NTFS Alternate Data Streams (ADS) using Windows API or fallback."""
        streams: List[AlternateDataStream] = []
        if not self._is_windows or not os.path.isfile(file_path):
            return streams

        try:
            kernel32 = ctypes.windll.kernel32
            find_first_stream = kernel32.FindFirstStreamW
            find_next_stream = kernel32.FindNextStreamW
            find_close = kernel32.FindClose

            find_first_stream.argtypes = [
                ctypes.c_wchar_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint
            ]
            find_first_stream.restype = ctypes.c_void_p

            find_next_stream.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            find_next_stream.restype = ctypes.c_bool

            find_close.argtypes = [ctypes.c_void_p]
            find_close.restype = ctypes.c_bool

            stream_data = WIN32_FIND_STREAM_DATA()
            handle = find_first_stream(
                os.path.abspath(file_path), 0, ctypes.byref(stream_data), 0
            )

            # INVALID_HANDLE_VALUE is -1 or 0xFFFFFFFFFFFFFFFF
            if handle and handle != ctypes.c_void_p(-1).value and handle != -1:
                try:
                    while True:
                        s_name = stream_data.cStreamName
                        s_size = stream_data.StreamSize

                        # Standard main data stream is "::$DATA", skip it
                        if s_name and s_name != "::$DATA":
                            clean_name = s_name.lstrip(":").split(":$DATA")[0]
                            is_zone_id = ("Zone.Identifier" in s_name)
                            is_exec = any(clean_name.lower().endswith(ext) for ext in SUSPICIOUS_EXECUTABLE_EXTENSIONS)
                            streams.append(AlternateDataStream(
                                name=s_name,
                                size_bytes=s_size,
                                is_zone_identifier=is_zone_id,
                                is_executable=is_exec
                            ))

                        if not find_next_stream(handle, ctypes.byref(stream_data)):
                            break
                finally:
                    find_close(handle)
        except Exception:
            # Fallback or permission denial on specific system stream
            pass

        return streams

    def _get_file_attributes(self, file_path: str, stat_res: os.stat_result):
        """Extract Windows file attributes."""
        attrs = []
        is_hidden = False
        is_system = False
        is_readonly = False

        if self._is_windows:
            try:
                raw_attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
                if raw_attrs != 0xFFFFFFFF and raw_attrs != -1:
                    if raw_attrs & FILE_ATTRIBUTE_HIDDEN:
                        is_hidden = True
                        attrs.append("HIDDEN")
                    if raw_attrs & FILE_ATTRIBUTE_SYSTEM:
                        is_system = True
                        attrs.append("SYSTEM")
                    if raw_attrs & FILE_ATTRIBUTE_READONLY:
                        is_readonly = True
                        attrs.append("READONLY")
                    if raw_attrs & FILE_ATTRIBUTE_ARCHIVE:
                        attrs.append("ARCHIVE")
            except Exception:
                pass
        else:
            # Linux/Unix hidden file convention (starts with dot)
            if os.path.basename(file_path).startswith("."):
                is_hidden = True
                attrs.append("HIDDEN")

        return attrs, is_hidden, is_system, is_readonly

    def _check_double_extension(self, filename: str) -> bool:
        """Check for deceptive double extension masking (e.g. report.pdf.exe)."""
        lower = filename.lower()
        parts = lower.split(".")
        if len(parts) >= 3:
            second_ext = "." + parts[-2]
            final_ext = "." + parts[-1]
            if second_ext in DOUBLE_EXTENSION_DECEPTIVE_PREFIXES and final_ext in SUSPICIOUS_EXECUTABLE_EXTENSIONS:
                return True
        return False

    def _calculate_hashes(self, file_path: str):
        """Compute MD5 and SHA256 hashes."""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except Exception:
            return None, None
