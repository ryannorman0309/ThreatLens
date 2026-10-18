"""ThreatLens Preprocessing and Input Validation Engine."""

import re
import pandas as pd
import numpy as np
from typing import Tuple, Dict, Any, List, Optional
from src.config import FEATURE_NAMES, setup_logger

logger = setup_logger("threatlens.preprocessing")

# Clean standard names (without 'numeric__' prefix) for user-friendly mapping
CLEAN_FEATURE_NAMES = [f.replace("numeric__", "") for f in FEATURE_NAMES]

# Canonical normalization map: lowercase alphanumeric -> official FEATURE_NAME
def _build_normalization_map() -> Dict[str, str]:
    mapping = {}
    for feat in FEATURE_NAMES:
        clean = feat.replace("numeric__", "")
        # e.g., 'avg packet size'
        norm_key = re.sub(r"[^a-zA-Z0-9]", "", clean).lower()
        mapping[norm_key] = feat
        # also map raw key
        mapping[re.sub(r"[^a-zA-Z0-9]", "", feat).lower()] = feat
    return mapping

NORMALIZATION_MAP = _build_normalization_map()

# Ground truth label candidate column names
GROUND_TRUTH_ALIASES = ["label", "actual_class", "actual", "ground_truth", "target", "class"]

def validate_and_prepare_features(
    df: pd.DataFrame
) -> Tuple[pd.DataFrame, Optional[pd.Series], Dict[str, Any]]:
    """Validates an uploaded DataFrame, maps columns, cleans values, and enforces feature order.
    
    Returns:
        (X_prepared, y_ground_truth, validation_summary)
    """
    summary: Dict[str, Any] = {
        "is_valid": False,
        "errors": [],
        "warnings": [],
        "original_rows": len(df),
        "original_cols": len(df.columns),
        "missing_features": [],
        "imputed_cells": 0,
        "has_ground_truth": False,
        "ground_truth_col": None,
    }

    if df.empty:
        summary["errors"].append("Uploaded file is empty (0 records).")
        return pd.DataFrame(), None, summary

    # Detect ground truth column if present
    ground_truth_series: Optional[pd.Series] = None
    for col in df.columns:
        norm_col = re.sub(r"[^a-zA-Z0-9]", "", str(col)).lower()
        if norm_col in GROUND_TRUTH_ALIASES:
            ground_truth_series = df[col].copy()
            summary["has_ground_truth"] = True
            summary["ground_truth_col"] = col
            break

    # Map available input columns to the required 20 features
    col_mapping: Dict[str, str] = {}
    for col in df.columns:
        norm_col = re.sub(r"[^a-zA-Z0-9]", "", str(col)).lower()
        if norm_col in NORMALIZATION_MAP:
            target_feat = NORMALIZATION_MAP[norm_col]
            if target_feat not in col_mapping.values():
                col_mapping[col] = target_feat

    # Check for missing required features
    matched_features = set(col_mapping.values())
    missing = [f for f in FEATURE_NAMES if f not in matched_features]
    if missing:
        readable_missing = [f.replace("numeric__", "") for f in missing]
        summary["missing_features"] = readable_missing
        summary["errors"].append(
            f"Dataset is missing {len(missing)} required network flow features: {', '.join(readable_missing[:5])}"
            + (f" and {len(missing) - 5} more." if len(missing) > 5 else ".")
        )
        return pd.DataFrame(), ground_truth_series, summary

    # Construct feature matrix with exact feature order
    reverse_map = {v: k for k, v in col_mapping.items()}
    ordered_cols = [reverse_map[f] for f in FEATURE_NAMES]
    X = df[ordered_cols].copy()
    X.columns = FEATURE_NAMES

    # Convert to numeric, coerce non-numeric values
    for col in FEATURE_NAMES:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    # Handle NaNs and Infs (safe imputation)
    nan_count = int(X.isna().sum().sum())
    inf_count = int(np.isinf(X.values).sum()) if hasattr(X, "values") else 0
    total_anomalies = nan_count + inf_count

    if total_anomalies > 0:
        summary["imputed_cells"] = total_anomalies
        summary["warnings"].append(
            f"Detected {total_anomalies} missing or non-finite values. Imputed with feature column median."
        )
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(X.median().fillna(0.0))

    summary["is_valid"] = True
    summary["prepared_shape"] = X.shape
    logger.info("Successfully validated and prepared %d records with 20 features.", len(X))
    return X, ground_truth_series, summary
