"""
Data Models for Anti-Forensics Detection System
Structured representations of forensic artifacts, findings, features, and scan sessions.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json
import uuid


@dataclass
class AlternateDataStream:
    name: str
    size_bytes: int
    is_zone_identifier: bool = False
    is_executable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileMetadata:
    path: str
    filename: str
    size_bytes: int
    mtime: float                # Last Modified
    atime: float                # Last Accessed
    ctime: float                # Windows Created / Metadata change
    birthtime: Optional[float]  # Windows Creation Time (stat st_birthtime or win32 creation time)
    mtime_ns: int
    atime_ns: int
    ctime_ns: int
    birthtime_ns: Optional[int]
    mtime_fractional_ns: int    # Fractional nanoseconds (mtime_ns % 1_000_000_000)
    atime_fractional_ns: int
    ctime_fractional_ns: int
    birthtime_fractional_ns: Optional[int]
    is_hidden: bool = False
    is_system: bool = False
    is_readonly: bool = False
    attributes: List[str] = field(default_factory=list)
    alternate_data_streams: List[AlternateDataStream] = field(default_factory=list)
    md5: Optional[str] = None
    sha256: Optional[str] = None
    extension: str = ""
    is_double_extension: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["alternate_data_streams"] = [s.to_dict() if hasattr(s, 'to_dict') else s for s in self.alternate_data_streams]
        return d


@dataclass
class EventLogEntry:
    event_id: int
    record_number: int
    log_name: str
    time_created: str
    time_created_epoch: float
    source_name: str
    level: str
    message: str
    computer: str
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RegistryArtifact:
    hive: str
    key_path: str
    value_name: str
    value_data: Any
    value_type: str
    is_anomalous: bool = False
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MemoryArtifact:
    artifact_type: str          # 'unlinked_process', 'injected_code', 'hidden_driver', 'hook'
    pid: Optional[int]
    process_name: Optional[str]
    memory_address: Optional[str]
    protection: Optional[str]
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    category: str               # 'timestamp', 'log', 'hidden_file', 'memory', 'yara', 'registry'
    severity: str               # 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    title: str
    description: str
    artifact_path: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_type: str = "filesystem"
    target_path: str = ""
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None
    status: str = "IN_PROGRESS"
    total_artifacts: int = 0
    total_findings: int = 0
    findings: List[Finding] = field(default_factory=list)
    features: Dict[str, float] = field(default_factory=dict)
    risk_score: float = 0.0
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() if hasattr(f, 'to_dict') else f for f in self.findings]
        return d
