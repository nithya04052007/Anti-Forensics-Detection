"""
TeamMember1 — Hidden Folder & Path Residency Detector
Inspects parent directories to determine if the evidence file is hosted within
a hidden folder or suspicious temporary location.
"""

import os
import sys
import ctypes
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any

FILE_ATTRIBUTE_HIDDEN = 0x00000002

SUSPICIOUS_PATH_KEYWORDS = ["appdata\\local\\temp", "appdata\\roaming", "programdata", "users\\public", "\\temp\\"]


@dataclass
class HiddenFolderResult:
    is_in_hidden_folder: bool
    is_in_suspicious_location: bool
    hidden_folder_path: str = ""
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def check_hidden_folder(file_path: str) -> HiddenFolderResult:
    """Inspect parent directory path to check for hidden folder residency."""
    abs_path = os.path.abspath(file_path)
    parent_dir = os.path.dirname(abs_path)
    path_lower = abs_path.lower()

    is_in_hidden = False
    hidden_path = ""
    reasons = []

    # Check parent folders upward
    curr = parent_dir
    while curr and os.path.dirname(curr) != curr:
        folder_name = os.path.basename(curr)
        if sys.platform == "win32":
            try:
                attrs = ctypes.windll.kernel32.GetFileAttributesW(curr)
                if attrs != 0xFFFFFFFF and attrs != -1 and (attrs & FILE_ATTRIBUTE_HIDDEN):
                    is_in_hidden = True
                    hidden_path = curr
                    reasons.append(f"Parent directory '{folder_name}' has HIDDEN attribute")
                    break
            except Exception:
                pass
        else:
            if folder_name.startswith(".") and folder_name not in (".", ".."):
                is_in_hidden = True
                hidden_path = curr
                reasons.append(f"Parent directory '{folder_name}' is a dot-hidden folder")
                break
        curr = os.path.dirname(curr)

    # Check suspicious path location
    is_suspicious_loc = any(kw in path_lower for kw in SUSPICIOUS_PATH_KEYWORDS)
    if is_suspicious_loc:
        reasons.append("File is located in a high-risk user temp/staging path (e.g. AppData/Temp/Public)")

    return HiddenFolderResult(
        is_in_hidden_folder=is_in_hidden,
        is_in_suspicious_location=is_suspicious_loc,
        hidden_folder_path=hidden_path,
        reasons=reasons
    )
