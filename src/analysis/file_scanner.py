"""
Single Evidence File Forensic Scanner Orchestrator (Phase 2)
Coordinates TeamMember1 read-only inspection, ML risk inference, SQLite storage,
and PDF report generation for user-selected evidence files.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from TeamMember1.scanner import scan_evidence_file, ForensicFileReport
from ml.predict import predict_risk
from src.db.db_manager import DatabaseManager
from src.collection.models import Finding
from src.utils.pdf_generator import generate_forensic_pdf_report

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "database", "forensic_data.db")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


def run_single_file_scan(
    file_path: str,
    db_path: Optional[str] = None,
    generate_pdf: bool = True
) -> Dict[str, Any]:
    """
    Execute full Phase 2 forensic pipeline on a user-selected file:
    1. TeamMember1 read-only inspection (metadata, signature, hidden, ADS)
    2. ML feature extraction & Random Forest risk prediction
    3. Composite risk score calculation (0-100, LOW/MEDIUM/HIGH)
    4. Permanent SQLite database persistence
    5. DFIR PDF report generation
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Selected evidence file does not exist: {file_path}")

    scan_id = str(uuid.uuid4())
    scan_date_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Step 1: TeamMember1 Read-Only Scan
    report: ForensicFileReport = scan_evidence_file(file_path)

    # Step 2: ML Risk Inference & Scoring
    ml_result = predict_risk(report.feature_vector, len(report.findings))

    risk_score = ml_result["risk_score"]
    risk_level = ml_result["risk_level"]
    ml_pred = ml_result["ml_prediction"]
    ml_prob = ml_result["ml_probability"]

    # Step 3: Compile Complete Result
    summary = {
        "file_name": report.file_name,
        "file_path": report.file_path,
        "file_size": report.metadata.file_size,
        "extension": report.metadata.extension,
        "signature_type": report.signature.actual_type,
        "extension_match": report.signature.extension_match,
        "is_hidden": report.hidden_file.is_hidden,
        "is_in_hidden_folder": report.hidden_folder.is_in_hidden_folder,
        "created_time": report.metadata.created_time,
        "modified_time": report.metadata.modified_time,
        "accessed_time": report.metadata.accessed_time,
        "suspicious_indicators": report.suspicious_indicators_count,
        "ml_prediction": ml_pred,
        "ml_probability": ml_prob,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "critical_count": sum(1 for f in report.findings if f.get("severity") == "CRITICAL"),
        "high_count": sum(1 for f in report.findings if f.get("severity") == "HIGH")
    }

    complete_result = {
        "scan_id": scan_id,
        "scan_date": scan_date_iso,
        "target_type": "single_file",
        "target_path": report.file_path,
        "file_name": report.file_name,
        "file_path": report.file_path,
        "file_size": report.metadata.file_size,
        "extension": report.metadata.extension,
        "signature_type": report.signature.actual_type,
        "extension_match": report.signature.extension_match,
        "is_hidden": report.hidden_file.is_hidden,
        "created_time": report.metadata.created_time,
        "modified_time": report.metadata.modified_time,
        "accessed_time": report.metadata.accessed_time,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "ml_prediction": ml_pred,
        "ml_probability": ml_prob,
        "ml_confidence_percent": ml_result.get("ml_confidence_percent", 0.0),
        "metadata": report.metadata.to_dict(),
        "hidden_file": report.hidden_file.to_dict(),
        "hidden_folder": report.hidden_folder.to_dict(),
        "signature": report.signature.to_dict(),
        "findings": report.findings,
        "features": report.feature_vector,
        "summary": summary
    }

    # Step 4: Persistent SQLite Storage
    effective_db = db_path or DEFAULT_DB_PATH
    db = DatabaseManager(db_path=effective_db)
    db.create_scan(scan_id, target_type="single_file", target_path=report.file_path)

    # Insert findings
    finding_objects = [
        Finding(
            scan_id=scan_id,
            category=f.get("category", "forensics"),
            severity=f.get("severity", "LOW"),
            title=f.get("title", ""),
            description=f.get("description", ""),
            artifact_path=report.file_path,
            evidence=f
        )
        for f in report.findings
    ]
    db.insert_findings_batch(scan_id, finding_objects)
    db.insert_features(scan_id, report.feature_vector)

    db.complete_scan(
        scan_id=scan_id,
        total_artifacts=1,
        total_findings=len(report.findings),
        risk_score=risk_score,
        summary=summary,
        status="COMPLETED"
    )

    # Step 5: PDF Report Generation
    pdf_path = None
    if generate_pdf:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        pdf_path = os.path.join(REPORTS_DIR, f"report_{scan_id}.pdf")
        generate_forensic_pdf_report(complete_result, pdf_path)
        complete_result["report_path"] = pdf_path

    return complete_result
