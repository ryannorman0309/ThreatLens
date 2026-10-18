"""Unit Tests for ThreatLens Preprocessing & Input Validation."""

import pytest
import pandas as pd
import numpy as np
from src.config import FEATURE_NAMES
from src.preprocessing import validate_and_prepare_features

def test_empty_dataframe():
    df = pd.DataFrame()
    X, y, summary = validate_and_prepare_features(df)
    assert not summary["is_valid"]
    assert "empty" in summary["errors"][0].lower()

def test_missing_features():
    df = pd.DataFrame({
        "numeric__Avg Packet Size": [1.0, 2.0],
        "numeric__Bwd Packet Length Mean": [3.0, 4.0]
    })
    X, y, summary = validate_and_prepare_features(df)
    assert not summary["is_valid"]
    assert len(summary["missing_features"]) == 18

def test_valid_dataframe_and_feature_order():
    # Construct data with reversed column order and extra unwanted column
    data = {col: [1.5] for col in reversed(FEATURE_NAMES)}
    data["extra_unwanted_column"] = [999.0]
    data["Label"] = [0]
    df = pd.DataFrame(data)

    X, y, summary = validate_and_prepare_features(df)
    assert summary["is_valid"]
    assert list(X.columns) == FEATURE_NAMES
    assert summary["has_ground_truth"]
    assert y is not None
    assert y.iloc[0] == 0

def test_missing_and_infinite_value_imputation():
    data = {col: [1.0, 2.0, 3.0] for col in FEATURE_NAMES}
    data["numeric__Avg Packet Size"] = [1.0, np.nan, 3.0]
    data["numeric__Flow IAT Max"] = [np.inf, 2.0, 3.0]
    df = pd.DataFrame(data)

    X, y, summary = validate_and_prepare_features(df)
    assert summary["is_valid"]
    assert summary["imputed_cells"] == 2
    assert not X.isna().any().any()
    assert not np.isinf(X.values).any()
