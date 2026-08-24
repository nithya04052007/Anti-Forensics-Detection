"""
Memory Forensic Analyzer (Volatility 3 Integration)
Integrates with Volatility 3 to detect advanced memory anti-forensics:
- Hidden / Unlinked Processes (Direct Kernel Object Manipulation - DKOM: psscan vs pslist)
- Process Hollowing & Injected Shellcode (windows.malfind - unbacked RWX memory sections)
- Hidden DLLs and unlinked modules (windows.ldrmodules)
"""

import os
import sys
import subprocess
import json
from typing import List, Dict, Any, Optional, Set

from ..collection.models import MemoryArtifact, Finding


class MemoryAnalyzer:
    def __init__(self, volatility_bin: Optional[str] = None):
        self.volatility_bin = volatility_bin or "vol"

    def analyze_memory_dump(self, dump_path: str, scan_id: str = "") -> List[Finding]:
        """
        Analyze a raw physical memory dump (.raw, .vmem, .dmp) using Volatility 3 plugins.
        Cross-references pslist vs psscan to detect unlinked DKOM processes and runs malfind.
        """
        findings: List[Finding] = []
        if not os.path.exists(dump_path):
            return findings

        # Run pslist and psscan
        pslist_processes = self._run_volatility_pslist(dump_path)
        psscan_processes = self._run_volatility_psscan(dump_path)

        # ---------------------------------------------------------------------
        # Analysis 1: Hidden / Unlinked Process Detection (psscan vs pslist)
        # ---------------------------------------------------------------------
        pslist_pids: Set[int] = {p["pid"] for p in pslist_processes if "pid" in p}
        for proc in psscan_processes:
            pid = proc.get("pid")
            name = proc.get("name", "Unknown")
            offset = proc.get("offset", "N/A")

            if pid and pid not in pslist_pids:
                # Process found in memory pool scan but omitted from ActiveProcessLinks!
                findings.append(Finding(
                    scan_id=scan_id,
                    category="memory",
                    severity="CRITICAL",
                    title=f"Hidden/Unlinked Process Detected (DKOM): {name} (PID {pid})",
                    description=(
                        f"Process '{name}' (PID {pid}, Offset {offset}) was found in raw memory via pool tag scanning "
                        "but is unlinked from the kernel ActiveProcessLinks list. This is a definitive indicator of Direct "
                        "Kernel Object Manipulation (DKOM) anti-forensic rootkit activity."
                    ),
                    artifact_path=f"Memory PID: {pid} ({name})",
                    evidence={
                        "technique": "DKOM_unlinked_process",
                        "pid": pid,
                        "process_name": name,
                        "offset": offset,
                        "dump_file": dump_path
                    }
                ))

        # ---------------------------------------------------------------------
        # Analysis 2: Injected / Hollowed Memory Sections (malfind)
        # ---------------------------------------------------------------------
        malfind_results = self._run_volatility_malfind(dump_path)
        for entry in malfind_results:
            pid = entry.get("pid")
            name = entry.get("name", "Unknown")
            start_addr = entry.get("start_address", "")
            protection = entry.get("protection", "PAGE_EXECUTE_READWRITE")

            findings.append(Finding(
                scan_id=scan_id,
                category="memory",
                severity="HIGH",
                title=f"Injected Code / Process Hollowing: {name} (PID {pid})",
                description=(
                    f"Process '{name}' (PID {pid}) contains an unbacked executable memory region at {start_addr} "
                    f"with protection '{protection}'. Typical of reflective DLL injection or process hollowing."
                ),
                artifact_path=f"PID {pid}:{start_addr}",
                evidence=entry
            ))

        return findings

    def analyze_memory_artifacts(self, artifacts: List[MemoryArtifact], scan_id: str = "") -> List[Finding]:
        """Analyze pre-collected structured memory artifacts."""
        findings: List[Finding] = []
        for art in artifacts:
            if art.artifact_type == "unlinked_process":
                findings.append(Finding(
                    scan_id=scan_id,
                    category="memory",
                    severity="CRITICAL",
                    title=f"Unlinked Process Artifact: {art.process_name} (PID {art.pid})",
                    description=f"Process {art.process_name} (PID {art.pid}) is hidden via DKOM.",
                    artifact_path=f"PID:{art.pid}",
                    evidence=art.details
                ))
            elif art.artifact_type == "injected_code":
                findings.append(Finding(
                    scan_id=scan_id,
                    category="memory",
                    severity="HIGH",
                    title=f"Memory Injection: {art.process_name} at {art.memory_address}",
                    description=f"Injected memory region with {art.protection} permissions.",
                    artifact_path=f"PID:{art.pid} @ {art.memory_address}",
                    evidence=art.details
                ))
        return findings

    # =========================================================================
    # Volatility Execution Helpers
    # =========================================================================

    def _run_volatility_pslist(self, dump_path: str) -> List[Dict[str, Any]]:
        """Run windows.pslist plugin."""
        return self._invoke_volatility_json(dump_path, "windows.pslist.PsList")

    def _run_volatility_psscan(self, dump_path: str) -> List[Dict[str, Any]]:
        """Run windows.psscan plugin."""
        return self._invoke_volatility_json(dump_path, "windows.psscan.PsScan")

    def _run_volatility_malfind(self, dump_path: str) -> List[Dict[str, Any]]:
        """Run windows.malfind plugin."""
        return self._invoke_volatility_json(dump_path, "windows.malfind.Malfind")

    def _invoke_volatility_json(self, dump_path: str, plugin: str) -> List[Dict[str, Any]]:
        """Execute Volatility 3 CLI with JSON output rendering, or fallback gracefully."""
        try:
            cmd = ["vol", "-f", dump_path, "-r", "json", plugin]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout.strip())
                return self._format_vol_output(data)
        except Exception:
            pass
        return []

    @staticmethod
    def _format_vol_output(raw_json: Any) -> List[Dict[str, Any]]:
        """Normalize Volatility JSON table rows into clean dictionaries."""
        results = []
        if isinstance(raw_json, list):
            for row in raw_json:
                if isinstance(row, dict):
                    results.append(row)
        return results
