"""
Machine Learning Training Pipeline for Anti-Forensics Detection
Trains a Random Forest Classifier on forensic feature vectors from data/training_dataset.csv,
computes and displays actual evaluation metrics (Accuracy, Precision, Recall, F1-Score),
and saves the trained model and feature schema for inference.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "training_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "ml", "model")
MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_model.pkl")
SCHEMA_PATH = os.path.join(MODEL_DIR, "feature_columns.json")

FEATURE_COLUMNS = [
    "file_size",
    "is_hidden",
    "is_in_hidden_folder",
    "extension_match",
    "has_double_extension",
    "has_suspicious_extension",
    "signature_type",
    "metadata_anomaly",
    "filename_anomaly",
    "access_time_anomaly",
    "modification_time_anomaly",
    "creation_time_anomaly",
    "has_ads_streams",
    "subsecond_zeroed",
    "causal_m_lt_c",
    "future_timestamp"
]


def generate_default_training_dataset(output_path: str, count: int = 300) -> None:
    """Generate a clean, realistic, safe training dataset for ML model training."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    np.random.seed(42)

    rows = []
    half = count // 2

    # --- Class 0: Normal / Benign Files ---
    for _ in range(half):
        sig_type = np.random.choice([1, 2, 4, 5]) # Document, Image, Archive, Script/Text
        size = float(np.random.randint(1024, 25 * 1024 * 1024))
        rows.append({
            "file_size": size,
            "is_hidden": 0.0,
            "is_in_hidden_folder": 0.0,
            "extension_match": 1.0,
            "has_double_extension": 0.0,
            "has_suspicious_extension": 0.0,
            "signature_type": float(sig_type),
            "metadata_anomaly": 0.0,
            "filename_anomaly": 0.0,
            "access_time_anomaly": 0.0,
            "modification_time_anomaly": 0.0,
            "creation_time_anomaly": 0.0,
            "has_ads_streams": float(np.random.choice([0.0, 1.0], p=[0.85, 0.15])), # Zone.Identifier is normal
            "subsecond_zeroed": 0.0,
            "causal_m_lt_c": 0.0,
            "future_timestamp": 0.0,
            "risk_label": 0
        })

    # --- Class 1: Suspicious / Anti-Forensic Evasion Files ---
    evasion_archetypes = [
        # 1. Extension Mismatch / Disguised PE
        {"ext_match": 0.0, "double_ext": 0.0, "susp_ext": 0.0, "sig": 3.0, "meta_anom": 0.0, "fn_anom": 1.0, "zeroed": 0.0, "m_lt_c": 0.0, "future": 0.0, "hidden": 0.0, "ads": 0.0},
        # 2. Deceptive Double Extension (e.g. invoice.pdf.exe)
        {"ext_match": 1.0, "double_ext": 1.0, "susp_ext": 1.0, "sig": 3.0, "meta_anom": 0.0, "fn_anom": 1.0, "zeroed": 0.0, "m_lt_c": 0.0, "future": 0.0, "hidden": 0.0, "ads": 0.0},
        # 3. Timestomped (Subsecond Zeroed + M < C)
        {"ext_match": 1.0, "double_ext": 0.0, "susp_ext": 0.0, "sig": 3.0, "meta_anom": 1.0, "fn_anom": 0.0, "zeroed": 1.0, "m_lt_c": 1.0, "future": 0.0, "hidden": 0.0, "ads": 0.0},
        # 4. Future Timestamp Clock Manipulation
        {"ext_match": 1.0, "double_ext": 0.0, "susp_ext": 0.0, "sig": 1.0, "meta_anom": 1.0, "fn_anom": 0.0, "zeroed": 0.0, "m_lt_c": 0.0, "future": 1.0, "hidden": 0.0, "ads": 0.0},
        # 5. Hidden Executable in Alternate Data Stream
        {"ext_match": 1.0, "double_ext": 0.0, "susp_ext": 0.0, "sig": 5.0, "meta_anom": 0.0, "fn_anom": 0.0, "zeroed": 0.0, "m_lt_c": 0.0, "future": 0.0, "hidden": 0.0, "ads": 1.0},
        # 6. Hidden + System Attribute Masking
        {"ext_match": 1.0, "double_ext": 0.0, "susp_ext": 1.0, "sig": 3.0, "meta_anom": 0.0, "fn_anom": 0.0, "zeroed": 1.0, "m_lt_c": 0.0, "future": 0.0, "hidden": 1.0, "ads": 0.0},
    ]

    for _ in range(half):
        arch = evasion_archetypes[np.random.randint(0, len(evasion_archetypes))]
        size = float(np.random.randint(4096, 50 * 1024 * 1024))
        rows.append({
            "file_size": size,
            "is_hidden": arch["hidden"],
            "is_in_hidden_folder": float(np.random.choice([0.0, 1.0], p=[0.6, 0.4])),
            "extension_match": arch["ext_match"],
            "has_double_extension": arch["double_ext"],
            "has_suspicious_extension": arch["susp_ext"],
            "signature_type": arch["sig"],
            "metadata_anomaly": arch["meta_anom"],
            "filename_anomaly": arch["fn_anom"],
            "access_time_anomaly": float(np.random.choice([0.0, 1.0], p=[0.7, 0.3])),
            "modification_time_anomaly": arch["m_lt_c"],
            "creation_time_anomaly": arch["future"],
            "has_ads_streams": arch["ads"],
            "subsecond_zeroed": arch["zeroed"],
            "causal_m_lt_c": arch["m_lt_c"],
            "future_timestamp": arch["future"],
            "risk_label": 1
        })

    df = pd.DataFrame(rows)
    df.to_csv(output_path, index=False)
    print(f"[+] Generated balanced training dataset at: {output_path} ({len(df)} records)")


def train_and_evaluate_model():
    """Execute the ML training pipeline and serialize the Random Forest model."""
    print("=" * 60)
    print(" ANTI-FORENSICS ML TRAINING PIPELINE (Random Forest)")
    print("=" * 60)

    if not os.path.exists(DATA_PATH):
        print(f"[*] Training dataset not found at '{DATA_PATH}'. Generating default dataset...")
        generate_default_training_dataset(DATA_PATH, count=300)

    # 1. Load and Validate Dataset
    df = pd.read_csv(DATA_PATH)
    print(f"[*] Loaded dataset: {len(df)} samples, {len(df.columns)} columns")
    print(f"[*] Class distribution: Normal (0) = {(df['risk_label'] == 0).sum()}, Suspicious (1) = {(df['risk_label'] == 1).sum()}")

    # 2. Separate X and y
    missing_cols = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Dataset missing required feature columns: {missing_cols}")

    X = df[FEATURE_COLUMNS].values
    y = df["risk_label"].values

    # 3. Train / Test Split (80% train, 20% test with stratified sampling)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[*] Training samples: {len(X_train)} | Test samples: {len(X_test)}")

    # 4. Train Classification Model (Random Forest)
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)

    # 5. Evaluate on Test Set
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("\n--- ACTUAL CALCULATED EVALUATION METRICS ---")
    print(f"  Accuracy  : {acc * 100:.2f}%")
    print(f"  Precision : {prec * 100:.2f}%")
    print(f"  Recall    : {rec * 100:.2f}%")
    print(f"  F1-Score  : {f1 * 100:.2f}%")
    print(f"\nConfusion Matrix:\n{cm}")

    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Normal (0)", "Suspicious (1)"]))

    # 6. Save Model and Feature Schema
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    with open(SCHEMA_PATH, "w", encoding="utf-8") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)

    print(f"[OK] Trained Random Forest model saved to: {MODEL_PATH}")
    print(f"[OK] Feature schema saved to: {SCHEMA_PATH}")
    return model, {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1
    }


if __name__ == "__main__":
    train_and_evaluate_model()
