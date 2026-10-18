"""ThreatLens Explainability & Model Interpretability Module (Task 8 & 9)."""

import os
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional
from src.config import ARTIFACTS_DIR, RULE_THRESHOLDS, CLASS_NAMES, setup_logger

logger = setup_logger("threatlens.explain")

def get_feature_importance_data() -> pd.DataFrame:
    """Loads precomputed feature importance and mutual information from Task 5/8."""
    path = ARTIFACTS_DIR / "ThreatLens_Feature_Importance.csv"
    if not os.path.exists(path):
        logger.warning("Feature importance file missing at %s", path)
        return pd.DataFrame()

    df = pd.read_csv(path)
    # Clean feature names for clean UI display
    df["Clean_Feature"] = df["Feature"].str.replace("numeric__", "")
    df = df.sort_values(by="Mutual_Information", ascending=False)
    return df

def get_model_misclassifications() -> Dict[str, pd.DataFrame]:
    """Loads error pattern and misclassification breakdowns from Task 8."""
    result = {}
    files = {
        "Decision Tree": ARTIFACTS_DIR / "ThreatLens_DecisionTree_Misclassifications.csv",
        "Logistic Regression": ARTIFACTS_DIR / "ThreatLens_Logistic_Misclassifications.csv",
        "Random Forest": ARTIFACTS_DIR / "ThreatLens_RandomForest_Misclassifications.csv",
        "Error Summary": ARTIFACTS_DIR / "ThreatLens_Error_Summary.csv",
        "Error Patterns": ARTIFACTS_DIR / "ThreatLens_Error_Pattern_Comparison.csv",
    }

    for name, path in files.items():
        if os.path.exists(path):
            df = pd.read_csv(path)
            # Add readable class labels if Actual and Predicted columns exist
            if "Actual" in df.columns and "Predicted" in df.columns:
                df["Actual_Name"] = df["Actual"].map(CLASS_NAMES)
                df["Predicted_Name"] = df["Predicted"].map(CLASS_NAMES)
            result[name] = df
    return result

def explain_single_record(
    record_features: pd.Series,
    decision_row: pd.Series
) -> Dict[str, Any]:
    """Provides local interpretability breakdown for an individual security event."""
    deviations = []
    for feat, thresh in RULE_THRESHOLDS.items():
        if feat in record_features.index:
            val = record_features[feat]
            clean_name = feat.replace("numeric__", "")
            is_anomaly = val > thresh
            deviations.append({
                "feature": clean_name,
                "value": round(float(val), 4),
                "threshold": round(float(thresh), 4),
                "exceeds_threshold": is_anomaly,
                "ratio_to_threshold": round(float(val / thresh), 2) if thresh != 0 else 1.0,
            })

    # Sort so top anomalies appear first
    deviations = sorted(deviations, key=lambda x: (not x["exceeds_threshold"], -x["value"]))

    return {
        "predicted_label": decision_row.get("Predicted_Label", "Unknown"),
        "severity": decision_row.get("Severity", "Low"),
        "threat_category": decision_row.get("Threat_Category", "Normal"),
        "decision_status": decision_row.get("Decision_Status", ""),
        "model_agreement": decision_row.get("Model_Agreement", 1.0),
        "rule_triggered": decision_row.get("Rule_Triggered", False),
        "rule_evidence": decision_row.get("Rule_Evidence", "None"),
        "recommended_action": decision_row.get("Recommended_Action", ""),
        "feature_deviations": deviations,
    }
