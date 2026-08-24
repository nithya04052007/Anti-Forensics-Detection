"""
Anti-Forensics Test Sandbox and Artifact Simulator
Generates controlled, safe test artifacts exhibiting anti-forensic evasion techniques:
- Timestomped files (nanosecond zeroing, backdating M < C, future dates)
- Covert Alternate Data Streams (ADS) and double extensions
- Wiper and log cleaner scripts
- Simulated event log clear records and sequence gaps
- Simulated memory injection and DKOM artifacts
"""

import os
import sys
import time
import tempfile
from typing import Dict, List, Tuple
from datetime import datetime

from ..collection.models import (
    EventLogEntry,
    MemoryArtifact,
    RegistryArtifact
)


class ForensicSandboxSimulator:
    def __init__(self, base_dir: str = None):
        self.base_dir = base_dir or os.path.join(tempfile.gettempdir(), "anti_forensics_demo_sandbox")

    def create_simulated_environment(self) -> Tuple[str, List[EventLogEntry], List[RegistryArtifact], List[MemoryArtifact]]:
        """
        Generate all simulated artifacts in a temporary sandbox directory.
        Returns: (sandbox_path, event_logs, registry_artifacts, memory_artifacts)
        """
        os.makedirs(self.base_dir, exist_ok=True)

        # 1. Timestomped File: Exact Integer Seconds / Sub-second Zeroing
        p1 = os.path.join(self.base_dir, "timestomped_tool.dll")
        with open(p1, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 512 + b"Timestomp simulated binary payload")
        # Set integer epoch time (e.g. 1700000000.0) -> fractional ns = 0
        os.utime(p1, (1700000000.0, 1700000000.0))

        # 2. Timestomped File: Backdated Causal Inconsistency (M < C)
        p2 = os.path.join(self.base_dir, "backdated_implant.exe")
        with open(p2, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 256 + b"Backdated attack payload")
        # Set modify time to 5 years ago (2019)
        five_years_ago = time.time() - (86400 * 365 * 5)
        os.utime(p2, (five_years_ago, five_years_ago))

        # 3. Future Dated File (Clock Manipulation)
        p3 = os.path.join(self.base_dir, "future_artifact.tmp")
        with open(p3, "wb") as f:
            f.write(b"Future timestamp anomaly marker file")
        future_time = time.time() + (86400 * 100) # 100 days in future
        os.utime(p3, (future_time, future_time))

        # 4. Deceptive Double Extension File
        p4 = os.path.join(self.base_dir, "Quarterly_Financial_Report.pdf.exe")
        with open(p4, "wb") as f:
            f.write(b"MZ\x90\x00Masquerading executable file")

        # 5. Anti-Forensic Wiping / Log Cleaner Script (Triggers YARA rules)
        p5 = os.path.join(self.base_dir, "cleanup_traces.ps1")
        with open(p5, "w", encoding="utf-8") as f:
            f.write(
                "# Anti-Forensics Cleanup Script\n"
                "wevtutil.exe cl Security\n"
                "wevtutil.exe cl System\n"
                "vssadmin delete shadows /all /quiet\n"
                "fsutil usn deletejournal /d C:\n"
                "sdelete.exe -z -c -q C:\\Temp\\*\n"
                "[System.IO.File]::SetLastWriteTime('C:\\payload.exe', (Get-Date '01/01/2018'))\n"
            )

        # 6. NTFS Alternate Data Stream (ADS)
        p6 = os.path.join(self.base_dir, "innocent_notes.txt")
        with open(p6, "w", encoding="utf-8") as f:
            f.write("This is a normal notes file containing benign text.")

        if sys.platform == "win32":
            # Create hidden executable ADS stream on NTFS: innocent_notes.txt:hidden_payload.exe
            ads_path = f"{p6}:hidden_payload.exe"
            try:
                with open(ads_path, "wb") as f:
                    f.write(b"MZ\x90\x00Hidden stream executable payload")
            except Exception:
                pass

        # 7. Synthetic Event Log Entries (Log Wiping & Gap Detection)
        event_logs: List[EventLogEntry] = [
            EventLogEntry(
                event_id=4624,
                record_number=1001,
                log_name="Security",
                time_created="2026-08-24T10:00:00Z",
                time_created_epoch=1787565600.0,
                source_name="Microsoft-Windows-Security-Auditing",
                level="Information",
                message="An account was successfully logged on.",
                computer="WORKSTATION-01"
            ),
            EventLogEntry(
                event_id=1102, # SECURITY AUDIT LOG CLEARED
                record_number=1002,
                log_name="Security",
                time_created="2026-08-24T10:15:22Z",
                time_created_epoch=1787566522.0,
                source_name="Microsoft-Windows-Eventlog",
                level="Audit Success",
                message="The audit log was cleared by Administrator.",
                computer="WORKSTATION-01"
            ),
            # Gap simulation: record 1003-1010 deleted! Next is 1011
            EventLogEntry(
                event_id=4625,
                record_number=1011,
                log_name="Security",
                time_created="2026-08-24T10:30:00Z",
                time_created_epoch=1787567400.0,
                source_name="Microsoft-Windows-Security-Auditing",
                level="Information",
                message="An account failed to log on.",
                computer="WORKSTATION-01"
            )
        ]

        # 8. Synthetic Registry Anti-Forensic Artifacts
        registry_artifacts: List[RegistryArtifact] = [
            RegistryArtifact(
                hive="HKLM",
                key_path=r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
                value_name="EnablePrefetcher",
                value_data=0,
                value_type="REG_DWORD",
                is_anomalous=True,
                description="Prefetching is disabled (value=0). Prevents execution artifact logging."
            ),
            RegistryArtifact(
                hive="HKLM",
                key_path=r"SYSTEM\CurrentControlSet\Services\EventLog",
                value_name="Start",
                value_data=4,
                value_type="REG_DWORD",
                is_anomalous=True,
                description="EventLog service startup is DISABLED (value=4)."
            )
        ]

        # 9. Synthetic Memory Artifacts (DKOM unlinking & injection)
        memory_artifacts: List[MemoryArtifact] = [
            MemoryArtifact(
                artifact_type="unlinked_process",
                pid=4820,
                process_name="svchost_hidden.exe",
                memory_address="0xffff9d8012340000",
                protection="PAGE_EXECUTE_READWRITE",
                details={
                    "technique": "DKOM_unlinked_process",
                    "offset": "0x12345000",
                    "reason": "Process found in psscan pool tags but omitted from ActiveProcessLinks."
                }
            ),
            MemoryArtifact(
                artifact_type="injected_code",
                pid=1944,
                process_name="explorer.exe",
                memory_address="0x0000021b0000",
                protection="PAGE_EXECUTE_READWRITE",
                details={
                    "technique": "malfind_rwx_injection",
                    "vad_tag": "VadS",
                    "has_pe_header": True
                }
            )
        ]

        return self.base_dir, event_logs, registry_artifacts, memory_artifacts
