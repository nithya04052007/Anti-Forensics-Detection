"""
Automated Anti-Forensics Detection System — CLI Entry Point
Main orchestrator for DFIR data collection, forensic analysis, feature extraction, and SQLite storage.
"""

import os
import sys
import argparse
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
import pandas as pd

from src.collection.models import (
    FileMetadata,
    EventLogEntry,
    RegistryArtifact,
    MemoryArtifact,
    Finding,
    ScanResult
)
from src.collection.file_collector import FileCollector
from src.collection.event_log_collector import EventLogCollector
from src.collection.registry_collector import RegistryCollector

from src.analysis.timestamp_analyzer import TimestampAnalyzer
from src.analysis.log_analyzer import LogAnalyzer
from src.analysis.hidden_file_analyzer import HiddenFileAnalyzer
from src.analysis.memory_analyzer import MemoryAnalyzer
from src.analysis.yara_scanner import YaraScanner

from src.features.feature_extractor import FeatureExtractor
from src.db.db_manager import DatabaseManager
from src.utils.logger import ForensicLogger
from src.utils.simulator import ForensicSandboxSimulator


def run_pipeline(
    target_type: str,
    target_path: str,
    files: List[FileMetadata],
    event_logs: List[EventLogEntry],
    registry_keys: List[RegistryArtifact],
    memory_artifacts: List[MemoryArtifact],
    memory_dump_path: Optional[str] = None,
    yara_rules_path: Optional[str] = None,
    db_path: Optional[str] = None,
    export_features_path: Optional[str] = None,
    user_id: Optional[int] = None
) -> ScanResult:
    """Execute end-to-end DFIR analysis, feature extraction, and database persistence."""
    start_perf = datetime.now()
    scan_id = str(uuid.uuid4())
    effective_db = db_path or os.environ.get("DATABASE_PATH") or os.environ.get("DB_PATH") or "anti_forensics.db"

    ForensicLogger.header("AUTOMATED ANTI-FORENSICS DETECTION SYSTEM")
    ForensicLogger.info(f"Initiating Forensic Scan: {scan_id}")
    ForensicLogger.info(f"Target Type: {target_type} | Target: {target_path or 'Local System'}")

    display_name = os.path.basename(target_path) if target_path else target_type

    # 1. Initialize Database
    db = DatabaseManager(db_path=effective_db)
    db.create_scan(
        scan_id=scan_id,
        target_type=target_type,
        target_path=target_path,
        user_id=user_id,
        filename=display_name,
        detector_version="DFIR-Pipeline-v2.0"
    )

    findings: List[Finding] = []

    # 2. Forensic Analysis - Timestomping & Timestamps
    ForensicLogger.subheader("Phase 1: File & Timestamp Forensics")
    ts_analyzer = TimestampAnalyzer()
    ts_findings = ts_analyzer.analyze_batch(files, scan_id=scan_id)
    findings.extend(ts_findings)
    ForensicLogger.info(f"Analyzed {len(files)} file artifacts -> Found {len(ts_findings)} timestamp anomalies.")

    # 3. Forensic Analysis - Hidden Files & Alternate Data Streams (ADS)
    ForensicLogger.subheader("Phase 2: Covert Storage & Hidden Stream Forensics")
    hidden_analyzer = HiddenFileAnalyzer()
    hidden_findings = hidden_analyzer.analyze_batch(files, scan_id=scan_id)
    findings.extend(hidden_findings)
    ForensicLogger.info(f"Found {len(hidden_findings)} covert storage / ADS anomalies.")

    # 4. Forensic Analysis - YARA Signature Matching
    ForensicLogger.subheader("Phase 3: Anti-Forensic Tool YARA Signatures")
    yara_scanner = YaraScanner(rules_path=yara_rules_path)
    yara_findings: List[Finding] = []
    if target_path and os.path.isdir(target_path):
        yara_findings = yara_scanner.scan_directory(target_path, scan_id=scan_id)
    elif files:
        for f in files:
            yara_findings.extend(yara_scanner.scan_file(f.path, scan_id=scan_id))
    findings.extend(yara_findings)
    ForensicLogger.info(f"Found {len(yara_findings)} anti-forensic tool signature matches.")

    # 5. Forensic Analysis - Windows Event Log Tampering
    ForensicLogger.subheader("Phase 4: Event Log Tampering & Deletion Analysis")
    log_analyzer = LogAnalyzer()
    log_findings = log_analyzer.analyze_entries(event_logs, scan_id=scan_id)
    findings.extend(log_findings)
    ForensicLogger.info(f"Analyzed {len(event_logs)} event log records -> Found {len(log_findings)} tampering indicators.")

    # 6. Forensic Analysis - Registry Configurations
    ForensicLogger.subheader("Phase 5: Anti-Forensics Registry Configuration Audit")
    for r in registry_keys:
        if r.is_anomalous:
            f = Finding(
                scan_id=scan_id,
                category="registry",
                severity="HIGH" if "EventLog" in r.key_path or "EnablePrefetcher" in r.value_name else "MEDIUM",
                title=f"Anti-Forensic Registry Setting: {r.value_name}",
                description=r.description,
                artifact_path=f"{r.hive}\\{r.key_path}\\{r.value_name}",
                evidence=r.to_dict()
            )
            findings.append(f)
    reg_anom_count = sum(1 for r in registry_keys if r.is_anomalous)
    ForensicLogger.info(f"Audited {len(registry_keys)} registry keys -> Found {reg_anom_count} anomalous settings.")

    # 7. Forensic Analysis - Memory Anomaly & Volatility 3
    ForensicLogger.subheader("Phase 6: Memory Forensics (Volatility 3 & Injections)")
    mem_analyzer = MemoryAnalyzer()
    if memory_dump_path and os.path.exists(memory_dump_path):
        ForensicLogger.info(f"Running Volatility 3 plugins against memory dump: {memory_dump_path}")
        mem_findings = mem_analyzer.analyze_memory_dump(memory_dump_path, scan_id=scan_id)
        findings.extend(mem_findings)
    elif memory_artifacts:
        mem_findings = mem_analyzer.analyze_memory_artifacts(memory_artifacts, scan_id=scan_id)
        findings.extend(mem_findings)
    ForensicLogger.info(f"Found {sum(1 for f in findings if f.category == 'memory')} memory evasion artifacts.")

    # 8. Feature Extraction for Machine Learning
    ForensicLogger.subheader("Phase 7: Feature Extraction (ML Matrix Generation)")
    extractor = FeatureExtractor()
    features = extractor.extract_features(
        files=files,
        event_logs=event_logs,
        registry_keys=registry_keys,
        memory_artifacts=memory_artifacts,
        findings=findings
    )
    risk_score = features.get("anti_forensics_risk_score", 0.0)

    # 9. Database Storage
    ForensicLogger.subheader("Phase 8: SQLite Database Storage")
    db.insert_findings_batch(scan_id, findings)
    db.insert_features(scan_id, features)

    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    risk_level = "CRITICAL" if risk_score >= 80 else ("HIGH" if risk_score >= 61 else ("MEDIUM" if risk_score >= 31 else "LOW"))

    end_perf = datetime.now()
    duration_s = max(0.01, round((end_perf - start_perf).total_seconds(), 2))

    summary = {
        "file_name": display_name,
        "files_scanned": len(files),
        "logs_scanned": len(event_logs),
        "registry_keys_audited": len(registry_keys),
        "findings_count": len(findings),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "critical_count": crit_count,
        "high_count": high_count,
        "suspicious_indicators": len(findings),
        "ml_prediction": "Suspicious" if risk_score >= 50.0 else "Normal",
        "ml_probability": round(risk_score / 100.0, 3)
    }

    result_snapshot = {
        "scan_id": scan_id,
        "user_id": user_id,
        "target_type": target_type,
        "target_path": target_path,
        "file_name": display_name,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "duration_seconds": duration_s,
        "total_findings": len(findings),
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
        "features": features
    }

    db.complete_scan(
        scan_id=scan_id,
        total_artifacts=len(files) + len(event_logs) + len(registry_keys),
        total_findings=len(findings),
        risk_score=risk_score,
        summary=summary,
        status="COMPLETED",
        risk_level=risk_level,
        critical_count=crit_count,
        high_count=high_count,
        evasion_findings_count=len(findings),
        ml_prediction=summary["ml_prediction"],
        ml_probability=summary["ml_probability"],
        duration_seconds=duration_s,
        result_json=result_snapshot,
        filename=display_name
    )
    ForensicLogger.success(f"Scan results, {len(findings)} findings, and {len(features)} ML features saved to '{effective_db}'.")

    # 10. Optional Feature Export to CSV
    if export_features_path:
        df = extractor.to_dataframe(features, scan_id=scan_id)
        df.to_csv(export_features_path, index=False)
        ForensicLogger.success(f"Exported ML feature vector to '{export_features_path}'.")

    # 11. Presentation Summary
    findings_dicts = [f.to_dict() for f in findings]
    ForensicLogger.print_findings_summary(findings_dicts)
    ForensicLogger.print_features_summary(features, risk_score)

    return ScanResult(
        scan_id=scan_id,
        target_type=target_type,
        target_path=target_path,
        status="COMPLETED",
        total_artifacts=len(files) + len(event_logs) + len(registry_keys),
        total_findings=len(findings),
        findings=findings,
        features=features,
        risk_score=risk_score,
        summary=summary
    )


def main():
    parser = argparse.ArgumentParser(
        description="Automated Anti-Forensics Detection System (DFIR Cyber Defense)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--file",
        type=str,
        help="Path to single evidence file for read-only forensic inspection, signature verification, and ML risk scoring."
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run end-to-end sandbox demonstration simulating timestomping, ADS, wiped logs, and memory evasion."
    )
    parser.add_argument(
        "--target-dir",
        type=str,
        help="Path to directory for filesystem, timestamp, and YARA anti-forensics scanning."
    )
    parser.add_argument(
        "--event-logs",
        type=str,
        nargs="?",
        const="live",
        help="Collect and analyze Windows Event Logs ('live' for live OS or specify .evtx file path)."
    )
    parser.add_argument(
        "--registry",
        action="store_true",
        help="Audit Windows Registry for anti-forensic configurations (Prefetch, LastAccess, EventLog service)."
    )
    parser.add_argument(
        "--memory-dump",
        type=str,
        help="Path to raw memory dump (.raw, .vmem, .dmp) for Volatility 3 process & injection analysis."
    )
    parser.add_argument(
        "--scan-all",
        action="store_true",
        help="Run full live host anti-forensics audit (filesystem, event logs, registry)."
    )
    parser.add_argument(
        "--yara-rules",
        type=str,
        help="Custom YARA rules file path (defaults to rules/anti_forensics.yar)."
    )
    parser.add_argument(
        "--db",
        type=str,
        default="database/forensic_data.db",
        help="SQLite database path (default: database/forensic_data.db)."
    )
    parser.add_argument(
        "--export-features",
        type=str,
        help="Path to export extracted ML feature matrix (e.g. features.csv)."
    )
    parser.add_argument(
        "--list-scans",
        action="store_true",
        help="List historical scans recorded in the database."
    )

    args = parser.parse_args()

    # Handle list-scans
    if args.list_scans:
        db = DatabaseManager(db_path=args.db)
        scans = db.list_scans()
        ForensicLogger.header("HISTORICAL FORENSIC SCANS")
        if not scans:
            print("No scans found in database.")
        else:
            for s in scans:
                print(f"ID: {s['scan_id']} | Type: {s['target_type']} | Risk: {s['risk_score']} | Findings: {s['total_findings']} | Time: {s['start_time']}")
        return

    # Handle Single File Scan (Phase 2)
    if args.file:
        from src.analysis.file_scanner import run_single_file_scan
        ForensicLogger.header("SINGLE EVIDENCE FILE FORENSIC SCAN (READ-ONLY)")
        ForensicLogger.info(f"Target Evidence File: {args.file}")
        try:
            res = run_single_file_scan(args.file, db_path=args.db, generate_pdf=True)
            meta = res["metadata"]
            sig = res["signature"]

            ForensicLogger.subheader("Evidence Properties")
            print(f"  File Name      : {res['file_name']}")
            print(f"  File Size      : {res['file_size']:,} bytes")
            print(f"  Claimed Ext    : {sig['claimed_extension']}")
            print(f"  Actual Sig     : {sig['actual_type']}")
            print(f"  Signature Match: {'MATCH' if sig['extension_match'] else 'MISMATCH / TAMPERED'}")
            print(f"  Hidden Status  : {'HIDDEN' if res['is_hidden'] else 'NORMAL'}")
            print(f"  Created (UTC)  : {meta['created_time']}")
            print(f"  Modified (UTC) : {meta['modified_time']}")
            print(f"  Accessed (UTC) : {meta['accessed_time']}")

            ForensicLogger.subheader("Machine Learning Assessment (Random Forest)")
            print(f"  ML Prediction  : {res['ml_prediction']}")
            print(f"  Suspicious Prob: {res['ml_probability'] * 100:.1f}%")
            print(f"  Risk Score     : {res['risk_score']:.1f} / 100.0 ({res['risk_level']} RISK)")

            ForensicLogger.print_findings_summary(res["findings"])
            ForensicLogger.print_features_summary(res["features"], res["risk_score"])
            if res.get("report_path"):
                ForensicLogger.success(f"Forensic PDF report generated: {res['report_path']}")
            ForensicLogger.success(f"Scan permanently stored in SQLite database: {args.db}")
            return
        except Exception as e:
            ForensicLogger.alert(f"Scan error: {str(e)}")
            return

    # 1. Demonstration Mode
    if args.demo:
        ForensicLogger.info("Starting Anti-Forensics Simulation Demo...")
        simulator = ForensicSandboxSimulator()
        sandbox_path, event_logs, registry_artifacts, memory_artifacts = simulator.create_simulated_environment()

        file_collector = FileCollector()
        files = file_collector.scan_directory(sandbox_path)

        run_pipeline(
            target_type="demo_simulation",
            target_path=sandbox_path,
            files=files,
            event_logs=event_logs,
            registry_keys=registry_artifacts,
            memory_artifacts=memory_artifacts,
            yara_rules_path=args.yara_rules,
            db_path=args.db,
            export_features_path=args.export_features
        )
        return

    # 2. Live Scan or Targeted Scan
    files: List[FileMetadata] = []
    event_logs: List[EventLogEntry] = []
    registry_keys: List[RegistryArtifact] = []
    memory_artifacts: List[MemoryArtifact] = []

    target_dir = args.target_dir
    if args.scan_all and not target_dir:
        target_dir = os.getcwd()

    if target_dir:
        ForensicLogger.info(f"Collecting file metadata from: {target_dir}")
        file_collector = FileCollector()
        files = file_collector.scan_directory(target_dir)

    if args.event_logs or args.scan_all:
        el_collector = EventLogCollector()
        if args.event_logs and args.event_logs != "live" and os.path.exists(args.event_logs):
            ForensicLogger.info(f"Parsing offline EVTX file: {args.event_logs}")
            event_logs = el_collector.parse_evtx_file(args.event_logs)
        else:
            ForensicLogger.info("Collecting live Windows Event Logs (Security, System, PowerShell)...")
            event_logs = el_collector.collect_live_logs()

    if args.registry or args.scan_all:
        ForensicLogger.info("Auditing Windows Registry keys for forensic tampering...")
        reg_collector = RegistryCollector()
        registry_keys = reg_collector.collect_anti_forensic_keys()

    if not files and not event_logs and not registry_keys and not args.memory_dump:
        parser.print_help()
        print("\n[!] Please specify a scan target (e.g. --demo, --target-dir <path>, --scan-all, or --event-logs).")
        return

    target_type = "live_system" if args.scan_all else ("filesystem" if target_dir else "forensic_target")
    run_pipeline(
        target_type=target_type,
        target_path=target_dir or "Live Host",
        files=files,
        event_logs=event_logs,
        registry_keys=registry_keys,
        memory_artifacts=memory_artifacts,
        memory_dump_path=args.memory_dump,
        yara_rules_path=args.yara_rules,
        db_path=args.db,
        export_features_path=args.export_features
    )


if __name__ == "__main__":
    main()
