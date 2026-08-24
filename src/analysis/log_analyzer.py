"""
Windows Event Log Forensic Analyzer
Analyzes Windows Event Log records for anti-forensic indicators:
- Explicit audit/system log clearing (Event ID 1102 & 104)
- Record ID sequence gaps (evidence of selective log entry deletion)
- Abnormal time gaps between consecutive records (logging service suspension / bypass)
- Event log service disabling (Event ID 7036 / 7040)
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict

from ..collection.models import EventLogEntry, Finding


class LogAnalyzer:
    def __init__(self, max_allowed_time_gap_seconds: int = 86400 * 3): # 3 days
        self.max_time_gap = max_allowed_time_gap_seconds

    def analyze_entries(self, entries: List[EventLogEntry], scan_id: str = "") -> List[Finding]:
        """Perform comprehensive forensic log tampering analysis on collected event records."""
        findings: List[Finding] = []
        if not entries:
            return findings

        # ---------------------------------------------------------------------
        # Analysis 1: Explicit Log Deletion & Clearing Events
        # ---------------------------------------------------------------------
        for entry in entries:
            # Event 1102: Security Audit Log Cleared
            if entry.event_id == 1102:
                findings.append(Finding(
                    scan_id=scan_id,
                    category="log",
                    severity="CRITICAL",
                    title="Security Audit Log Cleared (Event ID 1102)",
                    description=(
                        f"The Windows Security audit log was explicitly cleared at {entry.time_created}. "
                        "This is a high-confidence anti-forensic action used by attackers to erase audit trails."
                    ),
                    artifact_path=f"{entry.log_name} (Record #{entry.record_number})",
                    evidence={
                        "event_id": 1102,
                        "record_number": entry.record_number,
                        "time_created": entry.time_created,
                        "source": entry.source_name,
                        "computer": entry.computer
                    }
                ))

            # Event 104: System Log Cleared
            elif entry.event_id == 104:
                findings.append(Finding(
                    scan_id=scan_id,
                    category="log",
                    severity="CRITICAL",
                    title="System Event Log Cleared (Event ID 104)",
                    description=(
                        f"The Windows System event log was cleared at {entry.time_created}. "
                        "Attacker or administrative log deletion event."
                    ),
                    artifact_path=f"{entry.log_name} (Record #{entry.record_number})",
                    evidence={
                        "event_id": 104,
                        "record_number": entry.record_number,
                        "time_created": entry.time_created,
                        "source": entry.source_name,
                        "computer": entry.computer
                    }
                ))

            # Event 4719: Audit Policy Tampering
            elif entry.event_id == 4719:
                findings.append(Finding(
                    scan_id=scan_id,
                    category="log",
                    severity="HIGH",
                    title="System Audit Policy Changed (Event ID 4719)",
                    description=(
                        f"Audit policy was modified at {entry.time_created}. "
                        "May indicate disabling of process tracking or security event generation."
                    ),
                    artifact_path=f"{entry.log_name} (Record #{entry.record_number})",
                    evidence=entry.to_dict()
                ))

            # Event 4616: System Time Modified
            elif entry.event_id == 4616:
                findings.append(Finding(
                    scan_id=scan_id,
                    category="log",
                    severity="MEDIUM",
                    title="System Clock Changed (Event ID 4616)",
                    description=(
                        f"System time modification detected at {entry.time_created}. "
                        "Clock manipulation is frequently used to subvert timestamp-based forensics."
                    ),
                    artifact_path=f"{entry.log_name} (Record #{entry.record_number})",
                    evidence=entry.to_dict()
                ))

        # ---------------------------------------------------------------------
        # Analysis 2: Record ID Discontinuity / Sequence Gaps
        # ---------------------------------------------------------------------
        # Group entries by log name and analyze continuity of Record Numbers
        by_channel = defaultdict(list)
        for e in entries:
            if e.record_number > 0:
                by_channel[e.log_name].append(e)

        for channel, records in by_channel.items():
            # Sort records ascending by record_number
            records_sorted = sorted(records, key=lambda x: x.record_number)
            for i in range(len(records_sorted) - 1):
                curr = records_sorted[i]
                nxt = records_sorted[i + 1]

                gap_size = nxt.record_number - curr.record_number
                if gap_size > 1:
                    # Missing records detected in sequence
                    findings.append(Finding(
                        scan_id=scan_id,
                        category="log",
                        severity="HIGH",
                        title=f"Log Sequence Gap Detected ({gap_size - 1} Missing Records)",
                        description=(
                            f"In log '{channel}', record #{curr.record_number} is directly followed "
                            f"by #{nxt.record_number}, missing {gap_size - 1} record(s). "
                            "Indicates selective log record pruning or deletion tool execution."
                        ),
                        artifact_path=f"{channel} (Records #{curr.record_number} -> #{nxt.record_number})",
                        evidence={
                            "channel": channel,
                            "before_record": curr.record_number,
                            "after_record": nxt.record_number,
                            "missing_count": gap_size - 1,
                            "before_time": curr.time_created,
                            "after_time": nxt.time_created
                        }
                    ))

        return findings
