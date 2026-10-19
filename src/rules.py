"""ThreatLens Isolated Rule-Based AI Engine."""

import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple
from src.config import RULE_THRESHOLDS, setup_logger

logger = setup_logger("threatlens.rules")

def evaluate_rules(X: pd.DataFrame) -> Tuple[np.ndarray, List[str], List[int]]:
    """Evaluates empirical statistical outlier rules across all 20 network flow features.
    
    Returns:
        (rule_triggered_array, rule_evidence_list, anomaly_count_list)
    """
    n_samples = len(X)
    rule_triggered = np.zeros(n_samples, dtype=bool)
    rule_evidence: List[str] = []
    anomaly_counts: List[int] = []

    # Vectorized comparison against thresholds
    for i in range(n_samples):
        row = X.iloc[i]
        triggered_rules_for_row = []

        for feat, threshold in RULE_THRESHOLDS.items():
            if feat in row.index:
                val = row[feat]
                if pd.notna(val) and val > threshold:
                    # Format matching exact Task 9 report:
                    # R-OUTLIER: feat=val exceeds training threshold thresh
                    val_str = f"{val:.4g}"
                    thresh_str = f"{threshold:.4g}"
                    triggered_rules_for_row.append(
                        f"R-OUTLIER: {feat}={val_str} exceeds training threshold {thresh_str}"
                    )

        if triggered_rules_for_row:
            rule_triggered[i] = True
            rule_evidence.append("; ".join(triggered_rules_for_row))
            anomaly_counts.append(len(triggered_rules_for_row))
        else:
            rule_evidence.append("No configured outlier rule matched")
            anomaly_counts.append(0)

    logger.info("Rule evaluation complete. %d / %d records flagged.", int(rule_triggered.sum()), n_samples)
    return rule_triggered, rule_evidence, anomaly_counts

def get_rule_definitions() -> List[Dict[str, Any]]:
    """Returns documentation and threshold metadata for all configured AI rules."""
    rules = []
    for feat, thresh in RULE_THRESHOLDS.items():
        clean_name = feat.replace("numeric__", "")
        rules.append({
            "rule_id": "R-OUTLIER",
            "feature": clean_name,
            "raw_feature": feat,
            "threshold": thresh,
            "logic": f"{clean_name} > {thresh}",
            "description": f"Flags statistical anomaly when scaled {clean_name} exceeds upper quartile threshold ({thresh}).",
            "threat_indication": "Volumetric anomaly, abnormal window sizing, or timing pattern indicative of attack traffic."
        })
    return rules

def get_task2_domain_rules() -> List[Dict[str, Any]]:
    """Returns the forward-chaining expert system domain rules from Task 2."""
    return [
        {
            "id": "R001",
            "name": "Authentication Suspicion",
            "type": "Derived Fact",
            "conditions": "ssh_or_ftp_activity AND high_auth_activity",
            "conclusion": "authentication_suspicious",
            "risk": "Medium",
            "explanation": "Authentication service activity combined with high request frequency."
        },
        {
            "id": "R002",
            "name": "Scan Behavior",
            "type": "Derived Fact",
            "conditions": "common_service_port AND scan_like_activity",
            "conclusion": "scan_behavior",
            "risk": "Medium",
            "explanation": "Indicators associated with systematic port and host scanning."
        },
        {
            "id": "R003",
            "name": "Flooding Behavior",
            "type": "Derived Fact",
            "conditions": "high_packet_rate AND short_or_repetitive_flow",
            "conclusion": "flooding_behavior",
            "risk": "High",
            "explanation": "Extreme packet volume within a short window indicating volumetric flooding."
        },
        {
            "id": "R004",
            "name": "Brute Force Attack Identification",
            "type": "Threat Conclusion",
            "conditions": "authentication_suspicious",
            "conclusion": "Brute Force Attack",
            "risk": "High",
            "explanation": "Repeated credential guessing or automated authentication barrage identified."
        },
        {
            "id": "R005",
            "name": "Port Scan Identification",
            "type": "Threat Conclusion",
            "conditions": "scan_behavior",
            "conclusion": "Port Scan",
            "risk": "Medium",
            "explanation": "Systematic probe across network ports to identify active services."
        },
        {
            "id": "R006",
            "name": "Denial of Service Identification",
            "type": "Threat Conclusion",
            "conditions": "flooding_behavior",
            "conclusion": "DoS Attack",
            "risk": "High",
            "explanation": "Target resource exhaustion attempted via high packet-rate traffic."
        },
        {
            "id": "R007",
            "name": "Distributed Denial of Service Identification",
            "type": "Threat Conclusion",
            "conditions": "flooding_behavior AND distributed_source_evidence",
            "conclusion": "DDoS Attack",
            "risk": "Critical",
            "explanation": "Coordinated multi-source flooding traffic aimed at total service disruption."
        },
        {
            "id": "R008",
            "name": "Normal Baseline Traffic",
            "type": "Default Baseline",
            "conditions": "normal_flow_characteristics",
            "conclusion": "Normal (Benign)",
            "risk": "Low",
            "explanation": "Flow statistics and packet inter-arrival times conform to baseline parameters."
        }
    ]
