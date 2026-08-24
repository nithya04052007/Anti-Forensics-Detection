"""
Windows Registry Collector
Inspects Windows Registry keys and configurations commonly manipulated by attackers
to disable forensic logging, disable prefetching, suppress last access times, or wipe MRU history.
"""

import sys
from typing import List, Dict, Any, Optional

from .models import RegistryArtifact

if sys.platform == "win32":
    import winreg
else:
    winreg = None


class RegistryCollector:
    def __init__(self):
        self._is_windows = (sys.platform == "win32")

    def collect_anti_forensic_keys(self) -> List[RegistryArtifact]:
        """Query key registry locations known for anti-forensics tampering."""
        artifacts: List[RegistryArtifact] = []
        if not self._is_windows or winreg is None:
            return artifacts

        # Check 1: Prefetcher Configuration
        # Default value: 3 (Prefetch application & boot). If 0 -> Disabled (Anti-forensics indicator)
        val, vtype = self._read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
            "EnablePrefetcher"
        )
        if val is not None:
            is_anom = (val == 0)
            artifacts.append(RegistryArtifact(
                hive="HKLM",
                key_path=r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
                value_name="EnablePrefetcher",
                value_data=val,
                value_type=vtype,
                is_anomalous=is_anom,
                description="Prefetching is disabled (value=0). Prevents execution artifact logging." if is_anom else "Prefetching is enabled."
            ))

        # Check 2: NTFS Last Access Time Updates
        # Default value: 1 or 2 (in modern Windows), but value 1 disables last access updates.
        val, vtype = self._read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\FileSystem",
            "NtfsDisableLastAccessUpdate"
        )
        if val is not None:
            is_anom = (val == 1)
            artifacts.append(RegistryArtifact(
                hive="HKLM",
                key_path=r"SYSTEM\CurrentControlSet\Control\FileSystem",
                value_name="NtfsDisableLastAccessUpdate",
                value_data=val,
                value_type=vtype,
                is_anomalous=is_anom,
                description="NTFS Last Access timestamp updates are disabled (value=1)." if is_anom else "NTFS Last Access setting normal."
            ))

        # Check 3: Windows EventLog Service Configuration
        # Start type: 2 = Auto, 3 = Manual, 4 = Disabled (Anti-forensics indicator)
        val, vtype = self._read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\EventLog",
            "Start"
        )
        if val is not None:
            is_anom = (val == 4)
            artifacts.append(RegistryArtifact(
                hive="HKLM",
                key_path=r"SYSTEM\CurrentControlSet\Services\EventLog",
                value_name="Start",
                value_data=val,
                value_type=vtype,
                is_anomalous=is_anom,
                description="EventLog service startup is DISABLED (value=4). Tampering detected." if is_anom else "EventLog service startup is normal."
            ))

        # Check 4: Crash Dump Generation (Memory Forensics Prevention)
        # CrashDumpEnabled: 0 = None (Prevents crash memory dump generation)
        val, vtype = self._read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\CrashControl",
            "CrashDumpEnabled"
        )
        if val is not None:
            is_anom = (val == 0)
            artifacts.append(RegistryArtifact(
                hive="HKLM",
                key_path=r"SYSTEM\CurrentControlSet\Control\CrashControl",
                value_name="CrashDumpEnabled",
                value_data=val,
                value_type=vtype,
                is_anomalous=is_anom,
                description="Crash memory dump generation is disabled (value=0)." if is_anom else "Crash dump setting normal."
            ))

        # Check 5: UserAssist Logging (HKCU)
        val, vtype = self._read_registry_value(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\Settings",
            "NoLog"
        )
        if val is not None:
            is_anom = (val == 1)
            artifacts.append(RegistryArtifact(
                hive="HKCU",
                key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\Settings",
                value_name="NoLog",
                value_data=val,
                value_type=vtype,
                is_anomalous=is_anom,
                description="UserAssist GUI execution logging is disabled (NoLog=1)." if is_anom else "UserAssist setting normal."
            ))

        return artifacts

    def _read_registry_value(self, hive: int, subkey: str, value_name: str):
        """Safely read a specific registry value."""
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                data, val_type = winreg.QueryValueEx(key, value_name)
                type_name = self._get_type_name(val_type)
                return data, type_name
        except (FileNotFoundError, PermissionError, OSError):
            return None, None

    @staticmethod
    def _get_type_name(val_type: int) -> str:
        mapping = {
            1: "REG_SZ",
            2: "REG_EXPAND_SZ",
            3: "REG_BINARY",
            4: "REG_DWORD",
            7: "REG_MULTI_SZ",
            11: "REG_QWORD"
        }
        return mapping.get(val_type, f"TYPE_{val_type}")
