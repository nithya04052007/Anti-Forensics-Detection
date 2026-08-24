/*
    Anti-Forensics Detection System — Starter YARA Ruleset
    Targeting Anti-Forensics Tools, Timestomping, Log Wiping, File Shredding, and Evasion Artifacts
*/

rule AntiForensics_Timestomp_Tool {
    meta:
        description = "Detects Timestomping tools and PowerShell timestamp manipulation scripts"
        author = "Anti-Forensics Detection System"
        category = "timestomp"
        severity = "HIGH"
    strings:
        $s1 = "SetLastWriteTime" ascii wide nocase
        $s2 = "SetCreationTime" ascii wide nocase
        $s3 = "SetLastAccessTime" ascii wide nocase
        $s4 = "timestomp.exe" ascii wide nocase
        $s5 = "[System.IO.File]::SetLastWriteTime" ascii wide nocase
        $s6 = "New-ItemProperty" ascii wide nocase
        $s7 = "Touch-File" ascii wide nocase
        $s8 = "Timestomp" ascii wide nocase
    condition:
        ($s4 or $s8) or 
        (2 of ($s1, $s2, $s3, $s5, $s6, $s7))
}

rule AntiForensics_Log_Wiping_Utility {
    meta:
        description = "Detects tools and commands that clear, delete, or suspend Windows Event Logs"
        author = "Anti-Forensics Detection System"
        category = "log_tampering"
        severity = "CRITICAL"
    strings:
        $cmd1 = "wevtutil.exe cl" ascii wide nocase
        $cmd2 = "wevtutil cl" ascii wide nocase
        $cmd3 = "Clear-EventLog" ascii wide nocase
        $cmd4 = "Remove-EventLog" ascii wide nocase
        $cmd5 = "Limit-EventLog" ascii wide nocase
        $phant0m1 = "Invoke-Phant0m" ascii wide nocase
        $phant0m2 = "Phant0m" ascii wide nocase
        $mim1 = "event::drop" ascii wide nocase
        $mim2 = "event::clear" ascii wide nocase
        $dander = "eventlogedit" ascii wide nocase
    condition:
        any of ($cmd1, $cmd2, $cmd3, $cmd4, $cmd5, $phant0m1, $phant0m2, $mim1, $mim2, $dander)
}

rule AntiForensics_File_Wiper_Shredder {
    meta:
        description = "Detects Secure Deletion and File Wiping utilities (SDelete, BleachBit, Eraser, Cipher)"
        author = "Anti-Forensics Detection System"
        category = "file_wiping"
        severity = "HIGH"
    strings:
        $sdel1 = "Sysinternals SDelete" ascii wide nocase
        $sdel2 = "sdelete.exe" ascii wide nocase
        $sdel3 = "-z -c -q" ascii wide nocase
        $bleach = "BleachBit" ascii wide nocase
        $eraser = "Eraser.exe" ascii wide nocase
        $cipher = "cipher.exe /w:" ascii wide nocase
        $shred = "shred -u -z -n" ascii wide nocase
        $zerofill = "ZeroMemory" ascii wide nocase
    condition:
        any of ($sdel1, $sdel2, $sdel3, $bleach, $eraser, $cipher, $shred)
}

rule AntiForensics_Evidence_Elimination_Commands {
    meta:
        description = "Detects common batch/PowerShell commands used to delete shadow copies and USN journals"
        author = "Anti-Forensics Detection System"
        category = "evidence_elimination"
        severity = "CRITICAL"
    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "wmic shadowcopy delete" ascii wide nocase
        $vss3 = "Resize-Partition" ascii wide nocase
        $usn1 = "fsutil usn deletejournal" ascii wide nocase
        $reg1 = "NtfsDisableLastAccessUpdate" ascii wide nocase
        $reg2 = "EnablePrefetcher" ascii wide nocase
        $bcde = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
    condition:
        any of ($vss1, $vss2, $usn1, $reg1, $reg2, $bcde)
}

rule AntiForensics_Process_Hollowing_Artifacts {
    meta:
        description = "Detects API signatures typical of process hollowing and memory-based unlinking"
        author = "Anti-Forensics Detection System"
        category = "memory_injection"
        severity = "HIGH"
    strings:
        $api1 = "NtUnmapViewOfSection" ascii wide nocase
        $api2 = "ZwUnmapViewOfSection" ascii wide nocase
        $api3 = "VirtualAllocEx" ascii wide nocase
        $api4 = "WriteProcessMemory" ascii wide nocase
        $api5 = "SetThreadContext" ascii wide nocase
        $api6 = "ResumeThread" ascii wide nocase
        $api7 = "QueueUserAPC" ascii wide nocase
    condition:
        ($api1 or $api2) and 3 of ($api3, $api4, $api5, $api6, $api7)
}
