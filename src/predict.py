"""ThreatLens Unified Inference Engine across Traditional ML and Deep Learning."""

import pandas as pd
import numpy as np
from typing import Dict, Any, Tuple, Optional
from src.model_loader import get_all_models
from src.config import setup_logger

logger = setup_logger("threatlens.predict")

MODEL_DISPLAY_NAMES = {
    "logistic_regression": "Logistic Regression",
    "decision_tree": "Decision Tree",
    "random_forest": "Random Forest",
    "lstm": "LSTM",
}

def predict_single_model(model_key: str, X: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray]]:
    """Runs inference for a single model and returns (predictions, confidence_probabilities)."""
    models = get_all_models()
    model = models.get(model_key)
    if model is None:
        raise ValueError(f"Model '{model_key}' is not loaded or unavailable.")

    if model_key == "lstm":
        # 3D reshaping required for LSTM: (N, 1, 20)
        X_arr = X.values.astype(np.float32)
        X_3d = X_arr.reshape((X_arr.shape[0], 1, X_arr.shape[1]))
        probabilities = model.predict(X_3d, verbose=0)
        predictions = np.argmax(probabilities, axis=1)
        confidences = np.max(probabilities, axis=1)
        return predictions, confidences

    # Traditional ML models
    predictions = model.predict(X)
    confidences = None
    if hasattr(model, "predict_proba"):
        try:
            probabilities = model.predict_proba(X)
            confidences = np.max(probabilities, axis=1)
        except Exception as e:
            logger.warning("Could not calculate predict_proba for %s: %s", model_key, e)

    return predictions, confidences

def predict_all_models(X: pd.DataFrame) -> Tuple[Dict[str, np.ndarray], Dict[str, np.ndarray]]:
    """Runs inference on all available models.
    
    Returns:
        (predictions_by_model, confidences_by_model)
    """
    models = get_all_models()
    all_preds: Dict[str, np.ndarray] = {}
    all_confs: Dict[str, np.ndarray] = {}

    for key, display_name in MODEL_DISPLAY_NAMES.items():
        if key in models:
            preds, confs = predict_single_model(key, X)
            all_preds[display_name] = preds
            if confs is not None:
                all_confs[display_name] = confs

    logger.info("Generated predictions across %d models for %d samples.", len(all_preds), len(X))
    return all_preds, all_confs
