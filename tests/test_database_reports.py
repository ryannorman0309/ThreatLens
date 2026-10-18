"""Unit Tests for Database Persistence and Executive Report Generation."""

import pytest
import pandas as pd
from src.database import init_db, save_scan, get_recent_scans, get_summary_metrics, clear_history
from src.reports import generate_pdf_report, convert_results_to_csv_bytes

def test_database_lifecycle():
    init_db()
    clear_history()

    # Save scan
    scan_id = save_scan(
        filename="test_run.csv",
        total_records=200,
        benign_count=180,
        threat_count=20,
        rule_alerts=15,
        model_disagreements=2,
        consensus_rate=0.92,
        primary_threat="DoS Hulk",
        class_breakdown={"Benign": 180, "DoS Hulk": 20}
    )
    assert scan_id > 0

    scans = get_recent_scans(5)
    assert len(scans) == 1
    assert scans[0]["filename"] == "test_run.csv"

    metrics = get_summary_metrics()
    assert metrics["total_scans"] == 1
    assert metrics["total_records_analyzed"] == 200
    assert metrics["total_threats_detected"] == 20

    clear_history()
    metrics_empty = get_summary_metrics()
    assert metrics_empty["total_scans"] == 0

def test_pdf_and_csv_report_generation():
    meta = {
        "filename": "audit_logs.csv",
        "scan_id": 42,
        "total_records": 100,
        "threat_count": 10,
        "benign_count": 90,
        "rule_alerts": 5,
        "model_disagreements": 1,
        "consensus_rate": 0.95
    }
    threat_df = pd.DataFrame([
        {"Class": "Benign", "Count": 90, "Percentage": 90.0, "Severity": "Low", "Category": "Normal Traffic"},
        {"Class": "DoS Hulk", "Count": 10, "Percentage": 10.0, "Severity": "High", "Category": "Denial of Service"}
    ])

    pdf_bytes = generate_pdf_report(meta, threat_df)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")

    dummy_df = pd.DataFrame({"col1": [1, 2], "col2": ["A", "B"]})
    csv_bytes = convert_results_to_csv_bytes(dummy_df)
    assert len(csv_bytes) > 0
    assert b"col1,col2" in csv_bytes
