"""
Machine Learning Subsystem for Anti-Forensics Risk Prediction
"""

from .predict import predict_risk, load_trained_model

__all__ = ["predict_risk", "load_trained_model"]
