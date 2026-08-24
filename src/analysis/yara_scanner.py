"""
YARA Pattern Matching Scanner
Scans files, directories, and memory buffers against anti-forensic tool signatures
(SDelete, Timestomp, Invoke-Phant0m, BleachBit, Eraser, Wiper scripts).
"""

import os
import re
from typing import List, Dict, Any, Optional

from ..collection.models import Finding

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


class YaraScanner:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path or self._get_default_rules_path()
        self.compiled_rules = None
        self._fallback_rules = []
        self._load_rules()

    def _get_default_rules_path(self) -> str:
        """Locate default anti-forensics YARA rules file."""
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        rule_file = os.path.join(base_dir, "rules", "anti_forensics.yar")
        if not os.path.exists(rule_file):
            rule_file = os.path.join("rules", "anti_forensics.yar")
        return rule_file

    def _load_rules(self) -> None:
        """Compile YARA ruleset from disk or initialize fallback parser."""
        if HAS_YARA and os.path.exists(self.rules_path):
            try:
                self.compiled_rules = yara.compile(filepath=self.rules_path)
                return
            except Exception:
                self.compiled_rules = None

        # Fallback pure-Python signature patterns if yara-python binary is unavailable
        self._init_fallback_patterns()

    def _init_fallback_patterns(self) -> None:
        """Initialize fallback regex signatures for key anti-forensics tools."""
        self._fallback_rules = [
            {
                "rule": "AntiForensics_Timestomp_Tool",
                "category": "timestomp",
                "severity": "HIGH",
                "description": "Timestomping tool or PowerShell timestamp modification pattern",
                "patterns": [
                    re.compile(rb"SetLastWriteTime", re.IGNORECASE),
                    re.compile(rb"SetCreationTime", re.IGNORECASE),
                    re.compile(rb"timestomp\.exe", re.IGNORECASE),
                    re.compile(rb"\[System\.IO\.File\]::SetLastWriteTime", re.IGNORECASE)
                ]
            },
            {
                "rule": "AntiForensics_Log_Wiping_Utility",
                "category": "log_tampering",
                "severity": "CRITICAL",
                "description": "Event log clearing or disabling utility command",
                "patterns": [
                    re.compile(rb"wevtutil(\.exe)?\s+cl", re.IGNORECASE),
                    re.compile(rb"Clear-EventLog", re.IGNORECASE),
                    re.compile(rb"Invoke-Phant0m", re.IGNORECASE),
                    re.compile(rb"event::clear", re.IGNORECASE)
                ]
            },
            {
                "rule": "AntiForensics_File_Wiper_Shredder",
                "category": "file_wiping",
                "severity": "HIGH",
                "description": "Secure file deletion or disk wiping signature",
                "patterns": [
                    re.compile(rb"Sysinternals\s+SDelete", re.IGNORECASE),
                    re.compile(rb"sdelete\.exe", re.IGNORECASE),
                    re.compile(rb"BleachBit", re.IGNORECASE),
                    re.compile(rb"cipher\.exe\s+/w:", re.IGNORECASE),
                    re.compile(rb"shred\s+-u", re.IGNORECASE)
                ]
            },
            {
                "rule": "AntiForensics_Evidence_Elimination_Commands",
                "category": "evidence_elimination",
                "severity": "CRITICAL",
                "description": "Shadow copy or USN journal deletion command",
                "patterns": [
                    re.compile(rb"vssadmin\s+delete\s+shadows", re.IGNORECASE),
                    re.compile(rb"wmic\s+shadowcopy\s+delete", re.IGNORECASE),
                    re.compile(rb"fsutil\s+usn\s+deletejournal", re.IGNORECASE),
                    re.compile(rb"NtfsDisableLastAccessUpdate", re.IGNORECASE)
                ]
            }
        ]

    def scan_file(self, file_path: str, scan_id: str = "") -> List[Finding]:
        """Scan a file on disk against anti-forensic YARA signatures."""
        findings: List[Finding] = []
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return findings

        # 1. Native YARA Engine
        if self.compiled_rules is not None:
            try:
                matches = self.compiled_rules.match(file_path)
                for match in matches:
                    meta = match.meta or {}
                    findings.append(Finding(
                        scan_id=scan_id,
                        category=meta.get("category", "yara"),
                        severity=meta.get("severity", "HIGH"),
                        title=f"YARA Signature Match: {match.rule}",
                        description=meta.get("description", f"Matched anti-forensics rule {match.rule}"),
                        artifact_path=file_path,
                        evidence={
                            "rule_name": match.rule,
                            "tags": match.tags,
                            "strings": [str(s) for s in match.strings[:5]],
                            "engine": "yara-python"
                        }
                    ))
                return findings
            except Exception:
                pass

        # 2. Fallback Regex Engine
        try:
            with open(file_path, "rb") as f:
                content = f.read(10 * 1024 * 1024) # Scan first 10MB
            findings.extend(self.scan_bytes(content, artifact_name=file_path, scan_id=scan_id))
        except (PermissionError, OSError):
            pass

        return findings

    def scan_bytes(self, data: bytes, artifact_name: str = "memory_buffer", scan_id: str = "") -> List[Finding]:
        """Scan a raw byte buffer (e.g. process memory dump or script content)."""
        findings: List[Finding] = []
        if not data:
            return findings

        if self.compiled_rules is not None:
            try:
                matches = self.compiled_rules.match(data=data)
                for match in matches:
                    meta = match.meta or {}
                    findings.append(Finding(
                        scan_id=scan_id,
                        category=meta.get("category", "yara"),
                        severity=meta.get("severity", "HIGH"),
                        title=f"YARA Signature Match: {match.rule}",
                        description=meta.get("description", f"Matched anti-forensics rule {match.rule}"),
                        artifact_path=artifact_name,
                        evidence={
                            "rule_name": match.rule,
                            "tags": match.tags,
                            "engine": "yara-python"
                        }
                    ))
                return findings
            except Exception:
                pass

        # Fallback regex scanning
        for rule in self._fallback_rules:
            matched_count = 0
            for pat in rule["patterns"]:
                if pat.search(data):
                    matched_count += 1

            if matched_count > 0:
                findings.append(Finding(
                    scan_id=scan_id,
                    category=rule["category"],
                    severity=rule["severity"],
                    title=f"YARA Fallback Match: {rule['rule']}",
                    description=rule["description"],
                    artifact_path=artifact_name,
                    evidence={
                        "rule_name": rule["rule"],
                        "matched_patterns": matched_count,
                        "engine": "pure_python_regex"
                    }
                ))

        return findings

    def scan_directory(self, root_dir: str, scan_id: str = "", max_files: int = 5000) -> List[Finding]:
        """Scan all files in a directory tree against YARA rules."""
        findings: List[Finding] = []
        count = 0
        for root, _, files in os.walk(root_dir):
            for f in files:
                p = os.path.join(root, f)
                findings.extend(self.scan_file(p, scan_id=scan_id))
                count += 1
                if count >= max_files:
                    return findings
        return findings
