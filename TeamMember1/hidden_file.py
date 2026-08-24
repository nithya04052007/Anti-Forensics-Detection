"""
TeamMember1 — Hidden File & ADS Detector
Detects hidden and system attributes on files and inspects NTFS Alternate Data Streams (ADS).
"""

import os
import sys
import ctypes
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004

SUSPICIOUS_STREAM_EXTENSIONS = {".exe", ".vbs", ".bat", ".cmd", ".ps1", ".scr", ".dll", ".js", ".hta"}


class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [
        ("StreamSize", ctypes.c_longlong),
        ("cStreamName", ctypes.c_wchar * 296),
    ]


@dataclass
class AlternateDataStreamInfo:
    stream_name: str
    stream_size: int
    is_zone_identifier: bool
    is_executable: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HiddenFileResult:
    is_hidden: bool
    is_system: bool
    has_alternate_data_streams: bool
    has_executable_stream: bool
    streams: List[AlternateDataStreamInfo] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["streams"] = [s.to_dict() if hasattr(s, "to_dict") else s for s in self.streams]
        return d


def check_hidden_file(file_path: str) -> HiddenFileResult:
    """Check if the evidence file has hidden/system attributes or hidden NTFS streams."""
    abs_path = os.path.abspath(file_path)
    file_name = os.path.basename(abs_path)

    is_hidden = False
    is_system = False
    reasons = []

    if sys.platform == "win32":
        try:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(abs_path)
            if attrs != 0xFFFFFFFF and attrs != -1:
                if attrs & FILE_ATTRIBUTE_HIDDEN:
                    is_hidden = True
                    reasons.append("Windows FILE_ATTRIBUTE_HIDDEN flag is set")
                if attrs & FILE_ATTRIBUTE_SYSTEM:
                    is_system = True
                    reasons.append("Windows FILE_ATTRIBUTE_SYSTEM flag is set")
        except Exception:
            pass
    else:
        if file_name.startswith("."):
            is_hidden = True
            reasons.append("Filename starts with dot (Unix hidden file)")

    # Alternate Data Streams
    streams = check_alternate_data_streams(abs_path)
    has_ads = len(streams) > 0
    has_exec_ads = any(s.is_executable for s in streams)

    if has_ads:
        non_zone = [s for s in streams if not s.is_zone_identifier]
        if non_zone:
            reasons.append(f"Contains {len(non_zone)} non-standard Alternate Data Stream(s)")
    if has_exec_ads:
        reasons.append("Contains executable Alternate Data Stream payload")

    return HiddenFileResult(
        is_hidden=is_hidden,
        is_system=is_system,
        has_alternate_data_streams=has_ads,
        has_executable_stream=has_exec_ads,
        streams=streams,
        reasons=reasons
    )


def check_alternate_data_streams(file_path: str) -> List[AlternateDataStreamInfo]:
    """Enumerate NTFS Alternate Data Streams (ADS) using Windows kernel32 API in read-only mode."""
    streams: List[AlternateDataStreamInfo] = []
    if sys.platform != "win32" or not os.path.isfile(file_path):
        return streams

    try:
        kernel32 = ctypes.windll.kernel32
        find_first = kernel32.FindFirstStreamW
        find_next = kernel32.FindNextStreamW
        find_close = kernel32.FindClose

        find_first.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
        find_first.restype = ctypes.c_void_p
        find_next.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        find_next.restype = ctypes.c_bool
        find_close.argtypes = [ctypes.c_void_p]
        find_close.restype = ctypes.c_bool

        stream_data = WIN32_FIND_STREAM_DATA()
        handle = find_first(os.path.abspath(file_path), 0, ctypes.byref(stream_data), 0)

        if handle and handle != ctypes.c_void_p(-1).value and handle != -1:
            try:
                while True:
                    name = stream_data.cStreamName
                    size = stream_data.StreamSize

                    if name and name != "::$DATA":
                        clean_name = name.lstrip(":").split(":$DATA")[0]
                        is_zone = ("Zone.Identifier" in name)
                        is_exec = any(clean_name.lower().endswith(ext) for ext in SUSPICIOUS_STREAM_EXTENSIONS)

                        streams.append(AlternateDataStreamInfo(
                            stream_name=name,
                            stream_size=size,
                            is_zone_identifier=is_zone,
                            is_executable=is_exec
                        ))

                    if not find_next(handle, ctypes.byref(stream_data)):
                        break
            finally:
                find_close(handle)
    except Exception:
        pass

    return streams
