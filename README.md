# Automated Anti-Forensics Detection System

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Forensics Engine](https://img.shields.io/badge/Forensics-Volatility3%20%7C%20YARA-orange.svg)](#)
[![Database](https://img.shields.io/badge/Storage-SQLite3-green.svg)](#)
[![Project Milestone](https://img.shields.io/badge/Milestone-Phase%201%20(50%25)-purple.svg)](#)

An enterprise-grade Digital Forensics and Incident Response (DFIR) platform built in Python to detect, quantify, and store evidence of **anti-forensic evasion techniques** deployed by cyber adversaries to erase audit trails, conceal payloads, and manipulate forensic artifacts.

---

## Current Scope (Phase 1 — 50% Milestone)

This release implements the core backend forensic pipeline through **Feature Extraction** and **SQLite Storage**:

- [x] **Data Collection Module**: File metadata (MACB + 100ns precision), NTFS Alternate Data Streams (ADS), Windows Event Logs, and Registry evasion configurations.
- [x] **Forensic Analysis Module**:
  - **Timestamp Analysis**: Fractional-second zeroing, temporal $M < C$ causal violations, future dates, historical pre-epoch stamps.
  - **Event Log Tampering**: Event ID 1102 / 104 clearing detection, Record ID sequence gaps (selective deletion), logging suspension.
  - **Covert Storage & Hidden Files**: NTFS Alternate Data Streams (executable streams), deceptive double extensions, hidden+system attribute masking.
  - **Memory Forensics (Volatility 3)**: Hidden/unlinked processes (DKOM $psscan \setminus pslist$), process hollowing, unbacked RWX memory sections.
  - **YARA Signature Matching**: Starter ruleset targeting SDelete, BleachBit, Timestomp, Invoke-Phant0m, shadow copy & USN journal deletion.
- [x] **Feature Extraction Module**: Converts forensic findings into flat, ML-ready feature vectors and pandas DataFrames (35+ engineered forensic features + composite risk scoring).
- [x] **SQLite Database Layer**: Relational schema (`scans`, `findings`, `features`) with query, reporting, and feature matrix export functions.
- [x] **CLI Entry Point (`main.py`)**: End-to-end scanner with live host scanning, offline forensics, sandbox simulation (`--demo`), and feature export.

*(Phase 2 will introduce the ML Random Forest/XGBoost classifier, Flask analyst dashboard, and automated PDF forensic reporting).*

---

## System Architecture

```
                                  Target Artifacts
           [ Filesystem | Event Logs (.evtx) | Registry | Memory Dumps (.raw) ]
                                         │
                                         ▼
                             ┌───────────────────────┐
                             │ 1. Data Collection    │
                             │ (MACB, ADS, EVTX, Reg)│
                             └───────────┬───────────┘
                                         │
                                         ▼
                             ┌───────────────────────┐
                             │ 2. Forensic Analysis  │
                             │ ├─ Timestamp Analyzer │
                             │ ├─ Log Tamper Engine  │
                             │ ├─ Hidden File / ADS  │
                             │ ├─ Memory (Volatility)│
                             │ └─ YARA Pattern Match │
                             └───────────┬───────────┘
                                         │
                                         ▼
                             ┌───────────────────────┐
                             │ 3. Feature Extraction │
                             │ (36+ Anomaly Features │
                             │  & Composite Score)   │
                             └───────────┬───────────┘
                                         │
                         ┌───────────────┴───────────────┐
                         ▼                               ▼
              ┌─────────────────────┐         ┌─────────────────────┐
              │ 4. SQLite Database  │         │ 5. ML Feature Matrix│
              │ (scans, findings,   │         │ (CSV / DataFrame    │
              │  features tables)   │         │  for ML Classifiers)│
              └─────────────────────┘         └─────────────────────┘
```

---

## Anti-Forensics Techniques Detected

| Category | Anti-Forensics Technique | Detection Methodology | Severity |
| :--- | :--- | :--- | :--- |
| **Timestomping** | Sub-second Zeroing | Identifies `.000000000` fractional nanosecond timestamps on NTFS typical of basic touch/timestomp utilities. | `MEDIUM` / `HIGH` |
| **Timestomping** | Causal Inconsistency ($M < C$) | Flags when file Modified Time is older than File Creation Time ($M < C$), indicating backdated malware. | `HIGH` |
| **Timestomping** | Future / Pre-Epoch Dates | Detects timestamps set into the future ($T > Now$) or prior to OS epoch (e.g. year 1980). | `CRITICAL` |
| **Log Tampering** | Audit Log Clearing | Detects Security Event 1102 and System Event 104 ("Log file cleared"). | `CRITICAL` |
| **Log Tampering** | Selective Event Deletion | Detects discontinuities and missing record numbers in sequential event streams ($R_{i+1} - R_i > 1$). | `HIGH` |
| **Covert Storage** | NTFS Alternate Data Streams | Enumerate NTFS streams via Win32 `FindFirstStreamW`; flags executable/script streams (e.g. `file.txt:payload.exe`). | `CRITICAL` |
| **Covert Storage** | Deceptive Double Extensions | Flags deceptive filenames like `invoice.pdf.exe` or `report.xlsx.vbs`. | `HIGH` |
| **Covert Storage** | Attribute Masking | Flags files with both `HIDDEN` and `SYSTEM` attributes enabled in user directories (`AppData`, `Temp`, `Public`). | `HIGH` |
| **Registry Evasion**| Prefetch / Log Disabling | Audits `EnablePrefetcher = 0`, `NtfsDisableLastAccessUpdate = 1`, and `EventLog` service startup `Start = 4`. | `HIGH` |
| **Memory Forensics**| Direct Kernel Manipulation | Volatility 3: cross-references `windows.pslist` vs `windows.psscan` to detect unlinked rootkit processes. | `CRITICAL` |
| **Memory Forensics**| Process Hollowing / Injection | Volatility 3 `windows.malfind`: flags unbacked `PAGE_EXECUTE_READWRITE` memory sections with injected code. | `HIGH` |
| **Tool Signatures** | Anti-Forensic Tool Execution | YARA ruleset targeting SDelete, BleachBit, Eraser, Invoke-Phant0m, Timestomp, and Shadow Copy wipers. | `HIGH` / `CRITICAL` |

---

## Project Structure

```
Anti-Forensics Detection/
│
├── schema.sql                     # SQLite schema (scans, findings, features)
├── requirements.txt               # Dependencies
├── README.md                      # Documentation
├── main.py                        # CLI Entry Point
├── features_demo.csv              # Exported ML feature matrix sample
│
├── rules/
│   └── anti_forensics.yar         # YARA ruleset for anti-forensic tools & scripts
│
├── src/
│   ├── __init__.py
│   ├── collection/
│   │   ├── models.py              # Strongly-typed dataclasses for artifacts & findings
│   │   ├── file_collector.py      # File metadata, nanosecond timestamps, ADS collection
│   │   ├── event_log_collector.py # Windows Event Log extraction (live & offline .evtx)
│   │   └── registry_collector.py  # Anti-forensic registry inspection
│   │
│   ├── analysis/
│   │   ├── timestamp_analyzer.py  # Timestomp, sub-second zeroing, causal inconsistency
│   │   ├── log_analyzer.py        # Log clearing, sequence gaps, timestamp anomalies
│   │   ├── hidden_file_analyzer.py# ADS, hidden/system attributes, double extensions
│   │   ├── memory_analyzer.py     # Volatility 3 integration (pslist vs psscan, malfind)
│   │   └── yara_scanner.py        # YARA engine & pure-Python regex fallback
│   │
│   ├── features/
│   │   └── feature_extractor.py   # Anomaly quantification, 36+ features & DataFrame conversion
│   │
│   ├── db/
│   │   └── db_manager.py          # SQLite CRUD operations, transactions & ML dataframe export
│   │
│   └── utils/
│       ├── logger.py              # Colored terminal logging & DFIR formatted tables
│       └── simulator.py           # Safe test sandbox & artifact generator
│
└── tests/
    ├── test_collection.py         # File, event log, and registry collector tests
    ├── test_analysis.py           # Timestomp, log, ADS, memory, and YARA tests
    ├── test_features.py           # Feature vector calculation & DataFrame export tests
    └── test_db.py                 # SQLite CRUD and schema tests
```

---

## Installation & Setup

### Prerequisites
- **Python 3.10+** (Windows 10/11 or Windows Server recommended for live registry and event log analysis)
- Optional: Volatility 3 for raw physical memory dump analysis (`pip install volatility3`)

### 1. Clone & Install Dependencies
```powershell
cd "Anti-Forensics Detection"
pip install -r requirements.txt
```

---

## Usage Guide

### 1. Run Built-in Sandbox Demonstration Mode (`--demo`)
Generates controlled, safe simulated anti-forensic artifacts (timestomped files, ADS executable streams, log clearing events, memory injection artifacts, and wiping scripts), runs the full forensic analysis pipeline, stores results in SQLite, and exports an ML feature vector:

```powershell
python main.py --demo --export-features features_demo.csv
```

### 2. Scan a Specific Directory on Disk
Scans a target directory for timestomping, hidden files, NTFS Alternate Data Streams, double extensions, and YARA anti-forensics tool matches:

```powershell
python main.py --target-dir "C:\Users\Target\Downloads" --export-features features.csv
```

### 3. Analyze Live Windows Event Logs or Offline EVTX Files
Inspects Windows Event Logs for Event ID 1102 (Security audit cleared), Event ID 104 (System cleared), and record number sequence gaps:

```powershell
# Live Windows Event Logs (Requires Admin for Security log)
python main.py --event-logs

# Offline EVTX file
python main.py --event-logs "C:\Cases\Evidence\Security.evtx"
```

### 4. Audit Windows Registry for Anti-Forensic Tampering
Checks whether attackers disabled prefetching, NTFS last access updates, or the Windows EventLog service:

```powershell
python main.py --registry
```

### 5. Analyze Physical Memory Dumps with Volatility 3
Cross-references `psscan` vs `pslist` to detect unlinked rootkit processes (DKOM) and scans for hollowed/injected processes (`malfind`):

```powershell
python main.py --memory-dump "C:\Cases\Evidence\memdump.raw"
```

### 6. Full Live Host Audit
Executes a multi-source forensic scan across filesystem, event logs, and registry on the local machine:

```powershell
python main.py --scan-all --db live_audit.db --export-features live_features.csv
```

### 7. View Historical Forensic Scans
```powershell
python main.py --list-scans
```

---

## Database Schema (`schema.sql`)

The system utilizes SQLite with Foreign Key constraints enabled and dedicated indexes:

- **`scans`**: Stores scan sessions, target metadata, start/end timestamps, overall threat score (0-100), and summary metrics.
- **`findings`**: Stores discrete forensic anomalies, severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), anomaly titles, descriptions, target paths, and JSON structured evidence.
- **`features`**: Stores flat numeric/boolean feature entries per scan (`feature_name`, `feature_value`, `feature_type`), ready for dynamic pivot into wide ML feature tables via `db.get_features_dataframe()`.

---

## Running Automated Tests

Execute the comprehensive unit and integration test suite:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

All 16 unit test cases covering collection, analysis, feature extraction, and SQLite persistence pass in `< 0.6s`.

---

## Next Steps (Phase 2 — 50% to 100%)

1. **Machine Learning Classifier**: Train Supervised (Random Forest, XGBoost) and Unsupervised (Isolation Forest) models on the extracted feature vectors to classify scans as Benign vs Anti-Forensic Attack.
2. **Web Dashboard**: Interactive Flask/FastAPI interface with visual timeline mapping, forensic graph analytics, and anomaly heatmaps.
3. **Forensic Report Generator**: Automated DFIR investigation PDF reports with chain-of-custody metadata and MITRE ATT&CK technique mapping.
