"""Unit Tests for ThreatLens Model Loading & Deserialization."""

import pytest
from src.model_loader import get_all_models, get_model_status

def test_models_exist_and_load():
    models = get_all_models()
    assert "logistic_regression" in models
    assert "decision_tree" in models
    assert "random_forest" in models
    assert "lstm" in models

def test_model_status():
    status = get_model_status()
    for key in ["logistic_regression", "decision_tree", "random_forest", "lstm"]:
        assert key in status
        assert status[key]["loaded"] is True
        assert status[key]["file_exists"] is True
