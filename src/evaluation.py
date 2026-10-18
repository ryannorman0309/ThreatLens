"""ThreatLens Performance Evaluation & Task 10 Validation Engine."""

import os
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional, Tuple
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from src.config import ARTIFACTS_DIR, CLASS_NAMES, setup_logger

logger = setup_logger("threatlens.evaluation")

def get_precomputed_benchmarks() -> pd.DataFrame:
    """Loads validated academic benchmark metrics from Task 9/10 artifacts."""
    comp_path = ARTIFACTS_DIR / "ThreatLens_Task9_Model_Comparison.csv"
    if os.path.exists(comp_path):
        df = pd.read_csv(comp_path)
        return df

    # Fallback to individual evaluation files
    m_path = ARTIFACTS_DIR / "ThreatLens_Model_Evaluation.csv"
    lstm_path = ARTIFACTS_DIR / "ThreatLens_LSTM_Evaluation.csv"
    frames = []
    if os.path.exists(m_path):
        frames.append(pd.read_csv(m_path))
    if os.path.exists(lstm_path):
        frames.append(pd.read_csv(lstm_path))

    if frames:
        return pd.concat(frames, ignore_index=True)
    return pd.DataFrame()

def evaluate_predictions_against_ground_truth(
    y_true: pd.Series,
    y_pred: np.ndarray,
    model_name: str
) -> Dict[str, Any]:
    """Calculates comprehensive classification metrics against ground truth.
    
    Handles multi-class classification using both weighted and macro averages.
    """
    # Filter out NaNs if any (e.g. model disagreement unresolved ties)
    valid_mask = pd.notna(y_true) & pd.notna(y_pred)
    y_t = np.array(y_true[valid_mask]).astype(int)
    y_p = np.array(y_pred[valid_mask]).astype(int)

    if len(y_t) == 0:
        return {"error": "No valid ground-truth comparisons available."}

    acc = float(accuracy_score(y_t, y_p))
    prec_macro = float(precision_score(y_t, y_p, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_t, y_p, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_t, y_p, average="macro", zero_division=0))

    prec_weighted = float(precision_score(y_t, y_p, average="weighted", zero_division=0))
    rec_weighted = float(recall_score(y_t, y_p, average="weighted", zero_division=0))
    f1_weighted = float(f1_score(y_t, y_p, average="weighted", zero_division=0))

    # Binary Threat detection metrics (Benign=0 vs Attack!=0)
    y_t_binary = (y_t != 0).astype(int)
    y_p_binary = (y_p != 0).astype(int)

    # Confusion Matrix (Binary)
    # [ [True Negative (Benign as Benign), False Positive (Benign as Attack)],
    #   [False Negative (Attack as Benign), True Positive (Attack as Attack)] ]
    tn, fp, fn, tp = 0, 0, 0, 0
    if len(np.unique(y_t_binary)) > 1 or len(np.unique(y_p_binary)) > 1:
        cm_bin = confusion_matrix(y_t_binary, y_p_binary, labels=[0, 1])
        tn, fp, fn, tp = int(cm_bin[0, 0]), int(cm_bin[0, 1]), int(cm_bin[1, 0]), int(cm_bin[1, 1])

    # Per-class metrics
    unique_classes = np.unique(np.concatenate([y_t, y_p]))
    per_class = []
    for cls_idx in sorted(unique_classes):
        cls_t = (y_t == cls_idx)
        cls_p = (y_p == cls_idx)
        p = float(precision_score(cls_t, cls_p, zero_division=0))
        r = float(recall_score(cls_t, cls_p, zero_division=0))
        f = float(f1_score(cls_t, cls_p, zero_division=0))
        supp = int(cls_t.sum())
        per_class.append({
            "class_code": int(cls_idx),
            "class_name": CLASS_NAMES.get(cls_idx, f"Class {cls_idx}"),
            "precision": round(p, 4),
            "recall": round(r, 4),
            "f1_score": round(f, 4),
            "support": supp
        })

    return {
        "model_name": model_name,
        "sample_count": len(y_t),
        "accuracy": round(acc, 4),
        "precision_macro": round(prec_macro, 4),
        "recall_macro": round(rec_macro, 4),
        "f1_macro": round(f1_macro, 4),
        "precision_weighted": round(prec_weighted, 4),
        "recall_weighted": round(rec_weighted, 4),
        "f1_weighted": round(f1_weighted, 4),
        "binary_confusion": {
            "true_negatives_benign": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives_attacks": tp
        },
        "per_class_metrics": pd.DataFrame(per_class),
    }
