"""ThreatLens Executive Security Report and CSV Export Engine."""

import io
import datetime
import pandas as pd
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from src.config import setup_logger

logger = setup_logger("threatlens.reports")

def generate_pdf_report(
    scan_meta: Dict[str, Any],
    threat_summary: pd.DataFrame,
    model_comparison: Optional[pd.DataFrame] = None
) -> bytes:
    """Generates a professional executive PDF cybersecurity report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=15
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=12,
        spaceAfter=8
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#64748B")
    )

    elements = []

    # Header / Title
    elements.append(Paragraph("<b>THREATLENS</b> | Cybersecurity Audit & Decision Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | "
        f"File: <b>{scan_meta.get('filename', 'Unknown')}</b> | "
        f"Scan ID: #{scan_meta.get('scan_id', 'N/A')}",
        subtitle_style
    ))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#00E5FF"), spaceAfter=15))

    # Executive Summary Cards Table
    total_records = scan_meta.get("total_records", 0)
    threat_count = scan_meta.get("threat_count", 0)
    benign_count = scan_meta.get("benign_count", 0)
    rule_alerts = scan_meta.get("rule_alerts", 0)
    disagreements = scan_meta.get("model_disagreements", 0)
    consensus_rate = scan_meta.get("consensus_rate", 0.0)

    threat_pct = (threat_count / total_records * 100) if total_records > 0 else 0
    consensus_pct = consensus_rate * 100

    metric_data = [
        [
            Paragraph("<b>Total Records</b>", body_style),
            Paragraph("<b>Threats Detected</b>", body_style),
            Paragraph("<b>Benign Traffic</b>", body_style),
            Paragraph("<b>Rule Alerts</b>", body_style),
            Paragraph("<b>Consensus Rate</b>", body_style),
        ],
        [
            Paragraph(f"<font size=14><b>{total_records:,}</b></font>", body_style),
            Paragraph(f"<font size=14 color='#EF4444'><b>{threat_count:,} ({threat_pct:.1f}%)</b></font>", body_style),
            Paragraph(f"<font size=14 color='#10B981'><b>{benign_count:,}</b></font>", body_style),
            Paragraph(f"<font size=14 color='#F59E0B'><b>{rule_alerts:,}</b></font>", body_style),
            Paragraph(f"<font size=14 color='#00E5FF'><b>{consensus_pct:.1f}%</b></font>", body_style),
        ]
    ]

    t_metrics = Table(metric_data, colWidths=[105, 110, 105, 100, 110])
    t_metrics.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    elements.append(t_metrics)
    elements.append(Spacer(1, 15))

    # Threat Distribution Breakdown Table
    elements.append(Paragraph("<b>1. Threat Classification Breakdown</b>", heading_style))

    breakdown_rows = [[
        Paragraph("<b>Class Label</b>", body_style),
        Paragraph("<b>Severity</b>", body_style),
        Paragraph("<b>Category</b>", body_style),
        Paragraph("<b>Count</b>", body_style),
        Paragraph("<b>Share (%)</b>", body_style),
    ]]

    if not threat_summary.empty:
        for _, row in threat_summary.iterrows():
            cnt = int(row.get("Count", 0))
            pct = float(row.get("Percentage", 0.0))
            breakdown_rows.append([
                Paragraph(str(row.get("Class", "")), body_style),
                Paragraph(str(row.get("Severity", "")), body_style),
                Paragraph(str(row.get("Category", "")), body_style),
                Paragraph(f"{cnt:,}", body_style),
                Paragraph(f"{pct:.2f}%", body_style),
            ])
    else:
        breakdown_rows.append([Paragraph("No threats identified.", body_style)] * 5)

    t_breakdown = Table(breakdown_rows, colWidths=[150, 80, 160, 70, 70])
    t_breakdown.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_breakdown)
    elements.append(Spacer(1, 15))

    # Model Consensus & Benchmark Summary
    if model_comparison is not None and not model_comparison.empty:
        elements.append(Paragraph("<b>2. Model Performance Benchmarks</b>", heading_style))
        comp_rows = [[
            Paragraph("<b>Model</b>", body_style),
            Paragraph("<b>Accuracy</b>", body_style),
            Paragraph("<b>Precision</b>", body_style),
            Paragraph("<b>Recall</b>", body_style),
            Paragraph("<b>F1-Score</b>", body_style),
        ]]
        for _, r in model_comparison.iterrows():
            comp_rows.append([
                Paragraph(str(r.get("Model", "")), body_style),
                Paragraph(f"{float(r.get('Accuracy', 0)):.4f}", body_style),
                Paragraph(f"{float(r.get('Precision', 0)):.4f}", body_style),
                Paragraph(f"{float(r.get('Recall', 0)):.4f}", body_style),
                Paragraph(f"{float(r.get('F1 Score', r.get('F1-Score', 0))):.4f}", body_style),
            ])
        t_comp = Table(comp_rows, colWidths=[170, 90, 90, 90, 90])
        t_comp.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(t_comp)
        elements.append(Spacer(1, 15))

    # Ethical Considerations & Limitations
    elements.append(Paragraph("<b>3. Ethical Considerations, Fairness & System Limitations</b>", heading_style))
    limitations_text = (
        "<b>Important Notice:</b> ThreatLens is an AI-assisted decision-support prototype. "
        "High model agreement does not guarantee 100% attack detection. Training data exhibits significant class imbalance "
        "(predominantly Benign traffic), which may lead to reduced sensitivity for rare attack vectors (e.g. Infiltration, "
        "Heartbleed, SQL Injection). Analysts must verify critical alerts against raw packet captures and endpoint logs. "
        "This tool does not autonomously alter firewall configurations or block traffic."
    )
    elements.append(Paragraph(limitations_text, small_style))

    doc.build(elements)
    buffer.seek(0)
    pdf_bytes = buffer.getvalue()
    logger.info("Generated PDF report (%d bytes).", len(pdf_bytes))
    return pdf_bytes

def convert_results_to_csv_bytes(results_df: pd.DataFrame) -> bytes:
    """Exports the full decision results DataFrame to CSV bytes."""
    return results_df.to_csv(index=False).encode("utf-8")
