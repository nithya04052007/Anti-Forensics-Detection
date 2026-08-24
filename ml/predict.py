"""
Machine Learning Inference & Risk Scoring Engine
Loads the trained Random Forest model, aligns feature vectors to the training schema,
and computes ML risk probability, composite risk score (0-100), and risk level (LOW/MEDIUM/HIGH).
"""

import os
import json
import joblib
import numpy as np
from typing import Dict, Any, Tuple, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "ml", "model")
MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_model.pkl")
SCHEMA_PATH = os.path.join(MODEL_DIR, "feature_columns.json")

_CACHED_MODEL = None
_CACHED_COLUMNS = None


def load_trained_model():
    """Load cached model or train a new instance if missing."""
    global _CACHED_MODEL, _CACHED_COLUMNS

    if _CACHED_MODEL is not None and _CACHED_COLUMNS is not None:
        return _CACHED_MODEL, _CACHED_COLUMNS

    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCHEMA_PATH):
        # Auto-train model if first run
        from .train_model import train_and_evaluate_model
        train_and_evaluate_model()

    _CACHED_MODEL = joblib.load(MODEL_PATH)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        _CACHED_COLUMNS = json.load(f)

    return _CACHED_MODEL, _CACHED_COLUMNS


def predict_risk(feature_dict: Dict[str, float], findings_count: int = 0) -> Dict[str, Any]:
    """
    Run ML prediction and calculate documented composite risk score (0-100).
    
    Risk Calculation Formula:
    1. Base ML Probability component: P(Suspicious) * 50 points
    2. Forensic Rule-Based Indicators:
       - Extension Mismatch / Disguised PE: +30 points
       - Deceptive Double Extension: +20 points
       - Timestomp Anomaly (Zeroed ns / M < C / Future): +25 points
       - Executable / Covert ADS: +25 points
       - Hidden + System Attribute: +15 points
    3. Final Risk Score = min(100, round(ML_component + Rule_component))
    4. Categorization:
       - 0 to 30: LOW (Likely benign)
       - 31 to 60: MEDIUM (Suspicious anomalies observed)
       - 61 to 100: HIGH (High risk anti-forensic evasion detected)
    """
    model, feature_cols = load_trained_model()

    # Align input features strictly with training column order
    input_vector = []
    for col in feature_cols:
        val = feature_dict.get(col, 0.0)
        input_vector.append(float(val))

    X_sample = np.array([input_vector])

    # Model inference
    pred_class = model.predict(X_sample)[0]
    probabilities = model.predict_proba(X_sample)[0]

    # Probability of being suspicious (class 1)
    suspicious_prob = float(probabilities[1]) if len(probabilities) > 1 else float(pred_class)
    prediction_label = "Suspicious" if pred_class == 1 or suspicious_prob >= 0.50 else "Normal"

    # Composite Risk Score Calculation
    ml_points = suspicious_prob * 50.0
    rule_points = 0.0

    # Rule checks from feature vector
    if feature_dict.get("extension_match", 1.0) == 0.0:
        rule_points += 30.0
    if feature_dict.get("has_double_extension", 0.0) > 0.0:
        rule_points += 20.0
    if feature_dict.get("subsecond_zeroed", 0.0) > 0.0 or feature_dict.get("causal_m_lt_c", 0.0) > 0.0:
        rule_points += 25.0
    if feature_dict.get("future_timestamp", 0.0) > 0.0:
        rule_points += 25.0
    if feature_dict.get("has_ads_streams", 0.0) > 0.0 and feature_dict.get("has_suspicious_extension", 0.0) > 0.0:
        rule_points += 25.0
    if feature_dict.get("is_hidden", 0.0) > 0.0:
        rule_points += 15.0

    total_score = min(100.0, round(ml_points + rule_points, 1))

    if total_score <= 30.0:
        risk_level = "LOW"
    elif total_score <= 60.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return {
        "ml_prediction": prediction_label,
        "ml_probability": round(suspicious_prob, 4),
        "ml_confidence_percent": round(max(probabilities) * 100.0, 1),
        "risk_score": total_score,
        "risk_level": risk_level,
        "formula_breakdown": {
            "ml_points": round(ml_points, 1),
            "rule_points": round(rule_points, 1),
            "total": total_score
        }
    }
