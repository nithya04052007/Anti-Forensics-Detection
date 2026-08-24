"""
Windows Event Log Collector
Collects and extracts event records from live Windows Event Logs (Security, System, PowerShell)
or offline .evtx files, specifically hunting for log deletion, service suspension, and tampering events.
"""

import os
import sys
import subprocess
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .models import EventLogEntry

# Target Event IDs for Anti-Forensics Analysis
ANTI_FORENSIC_EVENT_IDS = {
    1102: "Security Audit Log Cleared",
    104: "System Log Cleared",
    102: "Log file changed / resized",
    7036: "Service Control Manager: Service Status Change",
    7040: "Service Control Manager: Service Start Type Changed",
    4104: "PowerShell Script Block Execution (Potential Wiping Script)",
    4719: "System Audit Policy Changed",
    4616: "System Time Changed (Potential Timestomp / Clock Tamper)"
}


class EventLogCollector:
    def __init__(self):
        self._is_windows = (sys.platform == "win32")

    def collect_live_logs(
        self,
        log_names: Optional[List[str]] = None,
        max_events_per_log: int = 500
    ) -> List[EventLogEntry]:
        """Collect recent event records from live Windows event channels."""
        if not self._is_windows:
            return []

        if log_names is None:
            log_names = ["Security", "System", "Microsoft-Windows-PowerShell/Operational"]

        entries: List[EventLogEntry] = []
        for log_name in log_names:
            entries.extend(self._query_channel_via_powershell(log_name, max_events_per_log))

        return entries

    def parse_evtx_file(self, evtx_path: str, max_events: int = 1000) -> List[EventLogEntry]:
        """Parse offline .evtx file if available using python-evtx or PowerShell."""
        entries: List[EventLogEntry] = []
        if not os.path.exists(evtx_path):
            return entries

        try:
            import Evtx.Evtx as evtx
            import xml.etree.ElementTree as ET

            with evtx.Evtx(evtx_path) as log:
                count = 0
                for record in log.records():
                    xml_str = record.xml()
                    entry = self._parse_xml_record(xml_str, os.path.basename(evtx_path))
                    if entry:
                        entries.append(entry)
                        count += 1
                        if count >= max_events:
                            break
        except Exception:
            # Fallback to powershell Get-WinEvent -Path
            if self._is_windows:
                entries = self._query_evtx_via_powershell(evtx_path, max_events)

        return entries

    def _query_channel_via_powershell(self, log_name: str, max_events: int) -> List[EventLogEntry]:
        """Query live event log channel using PowerShell Get-WinEvent."""
        entries: List[EventLogEntry] = []
        ps_script = f"""
        try {{
            $events = Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} -ErrorAction SilentlyContinue
            if ($events) {{
                $list = @()
                foreach ($e in $events) {{
                    $list += [PSCustomObject]@{{
                        Id = $e.Id
                        RecordId = $e.RecordId
                        LogName = '{log_name}'
                        TimeCreated = $e.TimeCreated.ToString('o')
                        ProviderName = $e.ProviderName
                        LevelDisplayName = $e.LevelDisplayName
                        Message = if ($e.Message) {{ $e.Message.Substring(0, [Math]::Min(300, $e.Message.Length)) }} else {{ "" }}
                        MachineName = $e.MachineName
                    }}
                }}
                $list | ConvertTo-Json -Compress
            }}
        }} catch {{
            # Channel may not exist or access denied without elevated privs
        }}
        """

        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=15
            )
            out = proc.stdout.strip()
            if out:
                raw_json = json.loads(out)
                if isinstance(raw_json, dict):
                    raw_json = [raw_json]
                for item in raw_json:
                    entries.append(self._dict_to_entry(item))
        except Exception:
            pass

        return entries

    def _query_evtx_via_powershell(self, evtx_path: str, max_events: int) -> List[EventLogEntry]:
        """Query offline evtx file using PowerShell."""
        entries: List[EventLogEntry] = []
        ps_script = f"""
        try {{
            $events = Get-WinEvent -Path '{evtx_path}' -MaxEvents {max_events} -ErrorAction SilentlyContinue
            if ($events) {{
                $list = @()
                foreach ($e in $events) {{
                    $list += [PSCustomObject]@{{
                        Id = $e.Id
                        RecordId = $e.RecordId
                        LogName = '{os.path.basename(evtx_path)}'
                        TimeCreated = $e.TimeCreated.ToString('o')
                        ProviderName = $e.ProviderName
                        LevelDisplayName = $e.LevelDisplayName
                        Message = if ($e.Message) {{ $e.Message.Substring(0, [Math]::Min(300, $e.Message.Length)) }} else {{ "" }}
                        MachineName = $e.MachineName
                    }}
                }}
                $list | ConvertTo-Json -Compress
            }}
        }} catch {{}}
        """
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=20
            )
            out = proc.stdout.strip()
            if out:
                raw_json = json.loads(out)
                if isinstance(raw_json, dict):
                    raw_json = [raw_json]
                for item in raw_json:
                    entries.append(self._dict_to_entry(item))
        except Exception:
            pass

        return entries

    def _dict_to_entry(self, item: Dict[str, Any]) -> EventLogEntry:
        """Convert parsed JSON object to EventLogEntry dataclass."""
        time_str = item.get("TimeCreated", datetime.now(timezone.utc).isoformat())
        epoch = 0.0
        try:
            # Handle ISO formats
            dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            epoch = dt.timestamp()
        except Exception:
            epoch = datetime.now(timezone.utc).timestamp()

        return EventLogEntry(
            event_id=int(item.get("Id", 0)),
            record_number=int(item.get("RecordId", 0)),
            log_name=str(item.get("LogName", "")),
            time_created=time_str,
            time_created_epoch=epoch,
            source_name=str(item.get("ProviderName", "")),
            level=str(item.get("LevelDisplayName", "Information")),
            message=str(item.get("Message", "")),
            computer=str(item.get("MachineName", "LOCAL")),
            raw_data=item
        )

    def _parse_xml_record(self, xml_str: str, log_name: str) -> Optional[EventLogEntry]:
        """Parse XML string from python-evtx record."""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_str)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

            sys_elem = root.find("ns:System", ns)
            if sys_elem is None:
                return None

            event_id = int(sys_elem.find("ns:EventID", ns).text or 0)
            record_num = int(sys_elem.find("ns:EventRecordID", ns).text or 0)
            time_elem = sys_elem.find("ns:TimeCreated", ns)
            time_created = time_elem.get("SystemTime", "") if time_elem is not None else ""
            provider = sys_elem.find("ns:Provider", ns)
            provider_name = provider.get("Name", "") if provider is not None else ""
            computer_elem = sys_elem.find("ns:Computer", ns)
            computer = computer_elem.text if computer_elem is not None else "LOCAL"

            epoch = 0.0
            try:
                dt = datetime.fromisoformat(time_created.replace("Z", "+00:00"))
                epoch = dt.timestamp()
            except Exception:
                epoch = 0.0

            return EventLogEntry(
                event_id=event_id,
                record_number=record_num,
                log_name=log_name,
                time_created=time_created,
                time_created_epoch=epoch,
                source_name=provider_name,
                level="Information",
                message=f"Event {event_id} from {provider_name}",
                computer=computer,
                raw_data={"xml": xml_str[:300]}
            )
        except Exception:
            return None
