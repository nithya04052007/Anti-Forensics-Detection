"""
TeamMember1 — File Signature & Magic Bytes Analyzer
Identifies true file types by reading header magic bytes and detects anti-forensic
extension tampering, disguised executables, and deceptive double extensions.
"""

import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Set

SUSPICIOUS_EXECUTABLE_EXTS = {
    ".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".cpl", ".pif", ".dll", ".js", ".wsf"
}

DECEPTIVE_PREFIX_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".txt", ".csv"
}

# Signature Table: (Category, Name, Expected Extensions, Magic Bytes, Offset)
SIGNATURE_TABLE = [
    # Executables / Binaries
    ("Executable", "Windows Executable / PE", {".exe", ".dll", ".sys", ".scr", ".cpl", ".pif", ".ocx"}, b"MZ", 0),
    ("Executable", "Linux ELF Binary", {".elf", ".bin", ".so"}, b"\x7fELF", 0),
    
    # Documents & Office
    ("Document", "PDF Document", {".pdf"}, b"%PDF-", 0),
    ("Document", "Microsoft Office / ZIP Package", {".docx", ".xlsx", ".pptx", ".zip", ".jar", ".apk"}, b"PK\x03\x04", 0),
    ("Document", "Rich Text Format (RTF)", {".rtf"}, b"{\\rtf", 0),
    ("Document", "Legacy MS Office Document (OLE2)", {".doc", ".xls", ".ppt", ".msg"}, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0),
    
    # Images
    ("Image", "JPEG Image", {".jpg", ".jpeg", ".jpe"}, b"\xff\xd8\xff", 0),
    ("Image", "PNG Image", {".png"}, b"\x89PNG\r\n\x1a\n", 0),
    ("Image", "GIF Image", {".gif"}, b"GIF87a", 0),
    ("Image", "GIF Image", {".gif"}, b"GIF89a", 0),
    ("Image", "Bitmap Image", {".bmp"}, b"BM", 0),
    ("Image", "TIFF Image", {".tif", ".tiff"}, b"II*\x00", 0),
    ("Image", "TIFF Image", {".tif", ".tiff"}, b"MM\x00*", 0),
    
    # Archives
    ("Archive", "7-Zip Archive", {".7z"}, b"7z\xbc\xaf'\x1c", 0),
    ("Archive", "RAR Archive", {".rar"}, b"Rar!\x1a\x07", 0),
    ("Archive", "GZIP Archive", {".gz", ".tgz"}, b"\x1f\x8b\x08", 0),
    
    # Databases & Media
    ("Database", "SQLite 3 Database", {".db", ".sqlite", ".sqlite3"}, b"SQLite format 3\x00", 0),
    ("Media", "MP3 Audio (ID3)", {".mp3"}, b"ID3", 0),
]


@dataclass
class FileSignatureResult:
    actual_type: str
    signature_category: str
    signature_category_code: int  # 0=Unknown, 1=Document, 2=Image, 3=Executable, 4=Archive, 5=Script/Text, 6=Database/Media
    claimed_extension: str
    expected_extensions: List[str]
    extension_match: bool
    is_extension_mismatch: bool
    is_disguised_executable: bool
    has_double_extension: bool
    has_suspicious_extension: bool
    magic_hex: str
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def check_file_signature(file_path: str) -> FileSignatureResult:
    """
    Read file header bytes in strict READ-ONLY mode and evaluate against claimed extension.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    abs_path = os.path.abspath(file_path)
    file_name = os.path.basename(abs_path)
    claimed_ext = os.path.splitext(file_name)[1].lower()

    # Read first 64 bytes in binary read-only mode
    header_bytes = b""
    try:
        with open(abs_path, "rb") as f:
            header_bytes = f.read(64)
    except (PermissionError, OSError):
        header_bytes = b""

    magic_hex = header_bytes[:16].hex().upper()

    # Match against known magic signatures
    actual_type = "Unknown"
    sig_category = "Unknown"
    cat_code = 0
    expected_exts: Set[str] = set()

    for cat, name, exts, magic, offset in SIGNATURE_TABLE:
        if len(header_bytes) >= offset + len(magic):
            if header_bytes[offset:offset + len(magic)] == magic:
                actual_type = name
                sig_category = cat
                expected_exts = exts
                break

    # If no binary magic matched, check if plain text / script
    if actual_type == "Unknown" and len(header_bytes) > 0:
        if _is_printable_text(header_bytes):
            actual_type = "Plain Text / Script"
            sig_category = "Script/Text"
            expected_exts = {".txt", ".log", ".csv", ".json", ".xml", ".html", ".py", ".ps1", ".bat", ".sh", ".md", ".ini", ".cfg", ".yml", ".yaml"}

    # Map category to numeric code
    cat_code_map = {
        "Unknown": 0,
        "Document": 1,
        "Image": 2,
        "Executable": 3,
        "Archive": 4,
        "Script/Text": 5,
        "Database": 6,
        "Media": 6
    }
    cat_code = cat_code_map.get(sig_category, 0)

    # Extension Mismatch Analysis
    reasons = []
    extension_match = True
    is_mismatch = False
    is_disguised_exe = False

    if expected_exts:
        if claimed_ext not in expected_exts:
            extension_match = False
            is_mismatch = True
            reasons.append(f"Extension '{claimed_ext}' does not match actual signature '{actual_type}' (expected: {', '.join(sorted(list(expected_exts)[:4]))})")

            if sig_category == "Executable" and claimed_ext in DECEPTIVE_PREFIX_EXTS:
                is_disguised_exe = True
                reasons.append(f"CRITICAL: Executable binary disguised as benign document/image ({claimed_ext})")

    # Double Extension Analysis (e.g. invoice.pdf.exe)
    has_double_ext = _check_double_extension(file_name)
    if has_double_ext:
        reasons.append(f"Deceptive double extension detected: '{file_name}'")

    has_suspicious_ext = claimed_ext in SUSPICIOUS_EXECUTABLE_EXTS

    return FileSignatureResult(
        actual_type=actual_type,
        signature_category=sig_category,
        signature_category_code=cat_code,
        claimed_extension=claimed_ext,
        expected_extensions=sorted(list(expected_exts)),
        extension_match=extension_match,
        is_extension_mismatch=is_mismatch,
        is_disguised_executable=is_disguised_exe,
        has_double_extension=has_double_ext,
        has_suspicious_extension=has_suspicious_ext,
        magic_hex=magic_hex,
        reasons=reasons
    )


def _is_printable_text(data: bytes) -> bool:
    """Check if byte header consists of ASCII / UTF-8 printable text."""
    try:
        text = data.decode("utf-8")
        return all(c.isprintable() or c in "\r\n\t" for c in text)
    except UnicodeDecodeError:
        return False


def _check_double_extension(filename: str) -> bool:
    """Check for deceptive double extensions (e.g. document.pdf.exe)."""
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        sec_ext = "." + parts[-2]
        final_ext = "." + parts[-1]
        if sec_ext in DECEPTIVE_PREFIX_EXTS and final_ext in SUSPICIOUS_EXECUTABLE_EXTS:
            return True
    return False
