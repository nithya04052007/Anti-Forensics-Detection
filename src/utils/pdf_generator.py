"""
DFIR PDF Forensic Report Generator
Generates court-admissible, styled PDF investigation reports for scanned evidence files using ReportLab.
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)


def generate_forensic_pdf_report(scan_data: Dict[str, Any], output_pdf_path: str) -> str:
    """
    Generate a formatted DFIR investigation PDF report from a completed scan result dictionary.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_pdf_path)), exist_ok=True)
    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=12
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )
    mono_style = ParagraphStyle(
        "ReportMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("AUTOMATED ANTI-FORENSICS DETECTION SYSTEM", title_style))
    story.append(Paragraph("DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) — EVIDENCE INVESTIGATION REPORT", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

    # 2. Executive Case Summary Table
    scan_id = scan_data.get("scan_id", "N/A")
    scan_date = scan_data.get("scan_date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    file_name = scan_data.get("file_name", "N/A")
    file_path = scan_data.get("file_path", "N/A")
    file_size = scan_data.get("file_size", 0)
    risk_score = scan_data.get("risk_score", 0.0)
    risk_level = scan_data.get("risk_level", "LOW")
    ml_pred = scan_data.get("ml_prediction", "Normal")

    # Risk badge color
    risk_color = colors.HexColor("#16a34a") # green
    if risk_level == "HIGH":
        risk_color = colors.HexColor("#dc2626") # red
    elif risk_level == "MEDIUM":
        risk_color = colors.HexColor("#d97706") # orange

    summary_data = [
        [Paragraph("<b>Scan Session ID:</b>", body_style), Paragraph(scan_id, mono_style),
         Paragraph("<b>Assessment Date:</b>", body_style), Paragraph(scan_date, body_style)],
        [Paragraph("<b>Evidence File:</b>", body_style), Paragraph(file_name, body_style),
         Paragraph("<b>File Size:</b>", body_style), Paragraph(f"{file_size:,} bytes", body_style)],
        [Paragraph("<b>Threat Risk Level:</b>", body_style),
         Paragraph(f"<font color='{risk_color.hexval()}'><b>{risk_level} ({risk_score:.1f}/100)</b></font>", body_style),
         Paragraph("<b>ML Prediction:</b>", body_style), Paragraph(f"<b>{ml_pred}</b>", body_style)]
    ]

    summary_table = Table(summary_data, colWidths=[110, 160, 110, 160])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    # 3. File Identification & Cryptographic Hashes
    story.append(Paragraph("1. Evidence Identification & Cryptographic Hashes", section_heading))
    meta = scan_data.get("metadata", {})
    md5_val = meta.get("md5_hash", scan_data.get("md5", "N/A"))
    sha256_val = meta.get("sha256_hash", scan_data.get("sha256", "N/A"))

    id_data = [
        [Paragraph("<b>Full Evidence Path</b>", body_style), Paragraph(file_path, mono_style)],
        [Paragraph("<b>MD5 Hash</b>", body_style), Paragraph(str(md5_val), mono_style)],
        [Paragraph("<b>SHA-256 Hash</b>", body_style), Paragraph(str(sha256_val), mono_style)],
        [Paragraph("<b>Windows Attributes</b>", body_style), Paragraph(", ".join(meta.get("file_attributes", [])) or "NORMAL", body_style)]
    ]
    id_table = Table(id_data, colWidths=[130, 410])
    id_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#ffffff")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(id_table)
    story.append(Spacer(1, 10))

    # 4. MACB Timeline & Timestamp Analysis
    story.append(Paragraph("2. MACB Timeline & Timestomping Analysis", section_heading))
    c_time = meta.get("created_time", scan_data.get("created_time", "N/A"))
    m_time = meta.get("modified_time", scan_data.get("modified_time", "N/A"))
    a_time = meta.get("accessed_time", scan_data.get("accessed_time", "N/A"))

    ts_zero = "Yes (Suspicious .0000000 s zeroing)" if meta.get("is_subsecond_zeroed") else "No (Natural 100ns precision)"
    ts_mc = "Yes (Causal Anomaly: Modified < Created)" if meta.get("is_m_lt_c") else "No (Consistent)"
    ts_future = "Yes (Clock skew/tamper detected)" if meta.get("is_future_timestamp") else "No (Valid)"

    timeline_data = [
        [Paragraph("<b>Timestamp Type</b>", body_style), Paragraph("<b>Recorded Value (UTC)</b>", body_style), Paragraph("<b>Forensic Anomaly Check</b>", body_style)],
        [Paragraph("Creation Time ($STANDARD_INFO)", body_style), Paragraph(str(c_time), body_style), Paragraph(f"Future Dated: {ts_future}", body_style)],
        [Paragraph("Modification Time (MTIME)", body_style), Paragraph(str(m_time), body_style), Paragraph(f"Sub-second Zeroed: {ts_zero}", body_style)],
        [Paragraph("Last Access Time (ATIME)", body_style), Paragraph(str(a_time), body_style), Paragraph(f"Backdated (M < C): {ts_mc}", body_style)]
    ]
    timeline_table = Table(timeline_data, colWidths=[160, 190, 190])
    timeline_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(timeline_table)
    story.append(Spacer(1, 10))

    # 5. File Signature & Extension Tampering
    story.append(Paragraph("3. Magic Header Signature & Extension Verification", section_heading))
    sig = scan_data.get("signature", {})
    actual_type = sig.get("actual_type", scan_data.get("signature_type", "Unknown"))
    claimed_ext = sig.get("claimed_extension", scan_data.get("extension", "N/A"))
    match_status = "MATCH (Signature aligns with extension)" if sig.get("extension_match", scan_data.get("extension_match", True)) else "<font color='red'><b>MISMATCH / TAMPERED (Disguised File Type)</b></font>"

    sig_data = [
        [Paragraph("<b>Claimed Extension:</b>", body_style), Paragraph(str(claimed_ext), mono_style),
         Paragraph("<b>Magic Header Bytes:</b>", body_style), Paragraph(str(sig.get("magic_hex", "N/A")), mono_style)],
        [Paragraph("<b>Actual Signature Type:</b>", body_style), Paragraph(str(actual_type), body_style),
         Paragraph("<b>Signature Match Status:</b>", body_style), Paragraph(match_status, body_style)]
    ]
    sig_table = Table(sig_data, colWidths=[120, 150, 120, 150])
    sig_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#ffffff")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(sig_table)
    story.append(Spacer(1, 10))

    # 6. Forensic Findings Table
    story.append(Paragraph("4. Forensic Findings & Evasion Indicators", section_heading))
    findings = scan_data.get("findings", [])
    if not findings:
        story.append(Paragraph("<i>No suspicious anti-forensic indicators detected for this evidence file.</i>", body_style))
    else:
        findings_data = [
            [Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Category</b>", body_style), Paragraph("<b>Anomaly Title & Description</b>", body_style)]
        ]
        for f in findings:
            sev = f.get("severity", "INFO")
            sev_color_code = "#dc2626" if sev == "CRITICAL" else ("#ea580c" if sev == "HIGH" else ("#d97706" if sev == "MEDIUM" else "#0284c7"))
            findings_data.append([
                Paragraph(f"<font color='{sev_color_code}'><b>{sev}</b></font>", body_style),
                Paragraph(f.get("category", "N/A"), body_style),
                Paragraph(f"<b>{f.get('title', '')}</b><br/>{f.get('description', '')}", body_style)
            ])
        findings_table = Table(findings_data, colWidths=[70, 110, 360])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(findings_table)

    story.append(Spacer(1, 14))

    # 7. Chain of Custody & Disclaimer
    disclaimer = (
        "<b>DFIR FORENSIC INTEGRITY NOTICE:</b> This analysis was conducted strictly in <b>READ-ONLY mode</b>. "
        "The target evidence file was not altered, renamed, executed, or overwritten during this inspection. "
        "Threat risk scores combine supervised Machine Learning pattern recognition with deterministic DFIR heuristic rules."
    )
    story.append(Paragraph(disclaimer, ParagraphStyle("Disc", parent=body_style, fontSize=7.5, textColor=colors.HexColor("#64748b"))))

    # Build Document
    doc.build(story)
    return output_pdf_path
