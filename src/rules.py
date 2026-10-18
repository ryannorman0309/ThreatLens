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
            rule_evidence.append("None")
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
