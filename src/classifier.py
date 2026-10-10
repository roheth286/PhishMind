"""
Phishing Detection Classifier Module.

Connects the extracted 20-feature vector to the trained Random Forest model (models/random_forest.pkl).

Labels:
   1 -> Legitimate
  -1 -> Phishing
"""

import os
import joblib
from typing import Tuple, List, Optional, Any
import numpy as np

try:
    from src.feature_contract import validate_feature_vector, FEATURE_NAMES
    from src.feature_extractor import extract_features
except ImportError:
    from feature_contract import validate_feature_vector, FEATURE_NAMES
    from feature_extractor import extract_features

# Standard project-relative path to trained model
DEFAULT_MODEL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "models", "random_forest.pkl")
)

LABEL_DESCRIPTIONS = {
    1: "Legitimate",
    -1: "Phishing",
}

_CACHED_MODEL: Optional[Any] = None


def load_model(model_path: Optional[str] = None) -> Any:
    """
    Load the trained Random Forest classifier from the project models directory.
    Caches the loaded model instance in memory to avoid repeated disk reads.

    Raises:
        FileNotFoundError: If the model file does not exist.
        RuntimeError: If model loading fails.
    """
    global _CACHED_MODEL

    target_path = os.path.abspath(model_path) if model_path else DEFAULT_MODEL_PATH

    # Return cached model if default path is requested and already loaded
    if model_path is None and _CACHED_MODEL is not None:
        return _CACHED_MODEL

    if not os.path.exists(target_path):
        raise FileNotFoundError(f"Model file not found at: {target_path}")

    try:
        model = joblib.load(target_path)
    except Exception as e:
        raise RuntimeError(f"Failed to load model from {target_path}: {e}") from e

    # Cache if loading default model
    if model_path is None:
        _CACHED_MODEL = model

    return model


def clear_model_cache() -> None:
    """Reset the in-memory cached model instance."""
    global _CACHED_MODEL
    _CACHED_MODEL = None


def predict_url(url: str, model_path: Optional[str] = None) -> Tuple[int, List[int]]:
    """
    Predict whether a given URL is legitimate (1) or phishing (-1).

    Workflow:
    1. Validates URL input.
    2. Calls extract_features(url) to compute the 20 features.
    3. Validates the feature vector against the authoritative contract.
    4. Loads the trained Random Forest model (models/random_forest.pkl).
    5. Formats the sample into a 2D array of shape (1, 20) preserving exact FEATURE_NAMES order.
    6. Returns (predicted_label, feature_vector), where:
         predicted_label: 1 for Legitimate, -1 for Phishing
         feature_vector: list of 20 integer feature values

    Raises:
        ValueError: If url is invalid, feature vector fails contract validation, or model returns invalid label.
        FileNotFoundError: If model file cannot be found.
        RuntimeError: If feature extraction or model prediction fails.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string.")

    # 1. Extract 20 features using the full extractor
    vector = extract_features(url)

    # 2. Validate feature vector against contract
    validate_feature_vector(vector)

    # 3. Load model
    model = load_model(model_path=model_path)

    # 4. Predict
    try:
        sample = np.array([vector], dtype=int)
        prediction = model.predict(sample)
        pred_label = int(prediction[0])
    except Exception as e:
        raise RuntimeError(f"Model prediction failed: {e}") from e

    if pred_label not in (1, -1):
        raise ValueError(f"Model returned unexpected class label: {pred_label}")

    return pred_label, vector
