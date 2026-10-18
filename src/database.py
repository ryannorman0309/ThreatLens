"""ThreatLens SQLite Persistence Layer for Security Audit History."""

import sqlite3
import datetime
from typing import List, Dict, Any, Optional
from src.config import DB_PATH, setup_logger

logger = setup_logger("threatlens.database")

def get_connection() -> sqlite3.Connection:
    """Returns a SQLite database connection with row factory enabled."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initializes database tables if they do not exist."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    total_records INTEGER NOT NULL,
                    benign_count INTEGER NOT NULL,
                    threat_count INTEGER NOT NULL,
                    rule_alerts INTEGER NOT NULL,
                    model_disagreements INTEGER NOT NULL,
                    consensus_rate REAL NOT NULL,
                    primary_threat TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_breakdown (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    class_name TEXT NOT NULL,
                    record_count INTEGER NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
                )
            """)
            conn.commit()
            logger.info("Database initialized successfully at %s", DB_PATH)
    except Exception as e:
        logger.error("Failed to initialize database: %s", e)
        raise

def save_scan(
    filename: str,
    total_records: int,
    benign_count: int,
    threat_count: int,
    rule_alerts: int,
    model_disagreements: int,
    consensus_rate: float,
    primary_threat: str,
    status: str = "Completed",
    class_breakdown: Optional[Dict[str, int]] = None
) -> int:
    """Saves a scan execution and its per-class breakdown."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (
                timestamp, filename, total_records, benign_count, threat_count,
                rule_alerts, model_disagreements, consensus_rate, primary_threat, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, filename, total_records, benign_count, threat_count,
            rule_alerts, model_disagreements, consensus_rate, primary_threat, status
        ))
        scan_id = cursor.lastrowid

        if class_breakdown:
            for cls_name, count in class_breakdown.items():
                cursor.execute("""
                    INSERT INTO scan_breakdown (scan_id, class_name, record_count)
                    VALUES (?, ?, ?)
                """, (scan_id, cls_name, count))

        conn.commit()
        logger.info("Saved scan ID %d for file '%s'", scan_id, filename)
        return scan_id

def get_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent scans ordered by timestamp descending."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM scan_history ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves details of a single scan by ID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        scan = dict(row)

        cursor.execute("SELECT class_name, record_count FROM scan_breakdown WHERE scan_id = ?", (scan_id,))
        scan["breakdown"] = {r["class_name"]: r["record_count"] for r in cursor.fetchall()}
        return scan

def get_summary_metrics() -> Dict[str, Any]:
    """Computes aggregate analytics metrics across all recorded scans."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total_scans,
                COALESCE(SUM(total_records), 0) as total_records_analyzed,
                COALESCE(SUM(threat_count), 0) as total_threats_detected,
                COALESCE(SUM(rule_alerts), 0) as total_rule_alerts,
                COALESCE(SUM(model_disagreements), 0) as total_disagreements
            FROM scan_history
        """)
        row = cursor.fetchone()
        return dict(row) if row else {
            "total_scans": 0,
            "total_records_analyzed": 0,
            "total_threats_detected": 0,
            "total_rule_alerts": 0,
            "total_disagreements": 0
        }

def clear_history() -> None:
    """Clears all scan history."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_breakdown")
        cursor.execute("DELETE FROM scan_history")
        conn.commit()
        logger.info("Cleared scan history tables.")
