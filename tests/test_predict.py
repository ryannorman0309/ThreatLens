"""Unit Tests for Unified Prediction Pipeline."""

import pytest
import pandas as pd
import numpy as np
from src.config import ARTIFACTS_DIR
from src.predict import predict_all_models

def test_prediction_pipeline_on_sample_logs():
    sample_path = ARTIFACTS_DIR / "sample_test_logs.csv"
    assert sample_path.exists(), "Sample test logs missing from artifacts."

    df = pd.read_csv(sample_path, nrows=25)
    # Exclude Actual_Class column if present
    feature_cols = [c for c in df.columns if c != "Actual_Class"]
    X = df[feature_cols]

    all_preds, all_confs = predict_all_models(X)

    expected_models = ["Logistic Regression", "Decision Tree", "Random Forest", "LSTM"]
    for m in expected_models:
        assert m in all_preds
        assert len(all_preds[m]) == len(X)
        assert np.all(all_preds[m] >= 0)
        assert np.all(all_preds[m] <= 14)

    assert "LSTM" in all_confs
    assert len(all_confs["LSTM"]) == len(X)
    assert np.all(all_confs["LSTM"] >= 0.0)
    assert np.all(all_confs["LSTM"] <= 1.0)
