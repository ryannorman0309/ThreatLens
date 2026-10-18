"""ThreatLens Model Loading & Deserialization Engine."""

import os
import joblib
import numpy as np
from typing import Dict, Any, Optional
from src.config import MODEL_FILES, setup_logger

logger = setup_logger("threatlens.model_loader")

# In-memory model cache for non-Streamlit environments (e.g., CLI / Pytest)
_MODEL_CACHE: Dict[str, Any] = {}

def _apply_keras_compatibility_patch():
    """Applies compatibility patch for Keras 3.12+ deserialization of models saved with quantization_config."""
    try:
        import keras
        orig_from_config = keras.layers.Dense.from_config

        @classmethod
        def patched_dense_from_config(cls, config):
            config_dict = dict(config)
            config_dict.pop("quantization_config", None)
            return orig_from_config.__func__(cls, config_dict)

        keras.layers.Dense.from_config = patched_dense_from_config
        logger.debug("Applied Keras Dense deserialization patch.")
    except Exception as e:
        logger.warning("Could not apply Keras patch: %s", e)

def load_traditional_models() -> Dict[str, Any]:
    """Loads Logistic Regression, Decision Tree, and Random Forest models."""
    models = {}
    trad_keys = ["logistic_regression", "decision_tree", "random_forest"]

    for key in trad_keys:
        path = MODEL_FILES.get(key)
        if not path or not os.path.exists(path):
            logger.warning("Model file for '%s' not found at %s", key, path)
            continue
        try:
            model = joblib.load(path)
            models[key] = model
            logger.info("Loaded '%s' from %s", key, path)
        except Exception as e:
            logger.error("Failed to load '%s': %s", key, e)

    return models

def load_lstm_model() -> Optional[Any]:
    """Loads the trained LSTM Keras deep learning model with compatibility patch."""
    lstm_path = MODEL_FILES.get("lstm")
    if not lstm_path or not os.path.exists(lstm_path):
        logger.warning("LSTM model file not found at %s", lstm_path)
        return None

    try:
        _apply_keras_compatibility_patch()
        import keras
        model = keras.models.load_model(str(lstm_path))
        logger.info("Loaded LSTM model from %s", lstm_path)
        return model
    except Exception as e:
        logger.error("Failed to load LSTM model: %s", e)
        return None

def get_all_models() -> Dict[str, Any]:
    """Retrieves all available models (cached)."""
    global _MODEL_CACHE
    if not _MODEL_CACHE:
        models = load_traditional_models()
        lstm = load_lstm_model()
        if lstm is not None:
            models["lstm"] = lstm
        _MODEL_CACHE = models
    return _MODEL_CACHE

def get_model_status() -> Dict[str, Dict[str, Any]]:
    """Returns status report of all registered models."""
    all_models = get_all_models()
    status = {}
    model_labels = {
        "logistic_regression": "Logistic Regression",
        "decision_tree": "Decision Tree",
        "random_forest": "Random Forest",
        "lstm": "LSTM Neural Network",
    }

    for key, label in model_labels.items():
        is_loaded = key in all_models
        model_obj = all_models.get(key)
        details = {
            "name": label,
            "loaded": is_loaded,
            "type": type(model_obj).__name__ if is_loaded else "None",
            "file_exists": os.path.exists(MODEL_FILES.get(key, "")),
            "file_size_mb": round(os.path.getsize(MODEL_FILES[key]) / (1024 * 1024), 2)
            if os.path.exists(MODEL_FILES.get(key, ""))
            else 0.0,
        }
        status[key] = details
    return status
