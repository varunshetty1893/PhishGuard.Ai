"""
PhishGuard AI - Model Training & Evaluation Pipeline
Trains, benchmarks, and evaluates machine learning classifiers on the URL benchmark.
Computes comprehensive validation metrics, confusion matrix, ROC-AUC, and feature importances.
"""

import json
import os
import shutil
import time
from datetime import datetime, timezone
from typing import Dict, Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    classification_report
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from feature_extraction import (
    FEATURE_NAMES,
    extract_url_features,
    features_to_vector
)

BASE_DIR = os.path.dirname(__file__)
DATASET_PATH = os.path.join(BASE_DIR, "data", "dataset.csv")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
BACKEND_ARTIFACTS_DIR = os.path.abspath(
    os.path.join(BASE_DIR, "..", "backend", "app", "ml", "artifacts")
)


def load_and_extract_features(csv_path: str):
    """Loads dataset and extracts 16 lexical/structural features for each URL."""
    print(f"Loading benchmark dataset from: {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df):,} total URL records. Extracting 16 security features...")
    
    start_time = time.time()
    feature_rows = []
    labels = []
    
    for _, row in df.iterrows():
        url = str(row["url"])
        label = int(row["label"])
        feats, _ = extract_url_features(url)
        feature_rows.append(features_to_vector(feats))
        labels.append(label)
        
    duration = time.time() - start_time
    print(f"Feature extraction complete in {duration:.2f} seconds ({len(df)/duration:.1f} URLs/sec).")
    
    X = np.array(feature_rows)
    y = np.array(labels)
    return X, y, df


def train_and_evaluate():
    """Main training, model comparison, and persistence pipeline."""
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(BACKEND_ARTIFACTS_DIR, exist_ok=True)
    
    X, y, df = load_and_extract_features(DATASET_PATH)
    
    # Stratified 80/20 train/test split with reproducible seed
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Train samples: {len(X_train):,}, Test samples: {len(X_test):,}")
    
    # 1. Train Baseline: Logistic Regression
    print("\n--- Training Candidate 1: Logistic Regression ---")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train)
    lr_preds = lr.predict(X_test_scaled)
    lr_probs = lr.predict_proba(X_test_scaled)[:, 1]
    
    lr_acc = accuracy_score(y_test, lr_preds)
    lr_prec = precision_score(y_test, lr_preds)
    lr_rec = recall_score(y_test, lr_preds)
    lr_f1 = f1_score(y_test, lr_preds)
    lr_auc = roc_auc_score(y_test, lr_probs)
    print(f"Logistic Regression: Acc={lr_acc:.4f}, Prec={lr_prec:.4f}, Rec={lr_rec:.4f}, F1={lr_f1:.4f}, AUC={lr_auc:.4f}")
    
    # 2. Train Primary: Random Forest Classifier
    print("\n--- Training Candidate 2: Random Forest Classifier ---")
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    rf_preds = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]
    
    rf_acc = accuracy_score(y_test, rf_preds)
    rf_prec = precision_score(y_test, rf_preds)
    rf_rec = recall_score(y_test, rf_preds)
    rf_f1 = f1_score(y_test, rf_preds)
    rf_auc = roc_auc_score(y_test, rf_probs)
    
    cm = confusion_matrix(y_test, rf_preds)
    tn, fp, fn, tp = cm.ravel()
    
    print(f"Random Forest Classifier: Acc={rf_acc:.4f}, Prec={rf_prec:.4f}, Rec={rf_rec:.4f}, F1={rf_f1:.4f}, AUC={rf_auc:.4f}")
    print(f"Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("\nClassification Report (Random Forest):")
    print(classification_report(y_test, rf_preds, target_names=["Legitimate", "Phishing"]))
    
    # Feature importances from Random Forest
    importances = rf.feature_importances_
    feat_imp_dict = {
        name: float(round(imp, 4))
        for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    }
    print("Feature Importances (Top 5):")
    for k, v in list(feat_imp_dict.items())[:5]:
        print(f"  - {k}: {v:.4f}")
        
    # Serialize Selected Model (Random Forest)
    model_artifact_path = os.path.join(ARTIFACTS_DIR, "phishguard_rf_model.joblib")
    joblib.dump(rf, model_artifact_path)
    print(f"\nPersisted primary model artifact to: {model_artifact_path}")
    
    # Construct complete metadata dictionary
    now_iso = datetime.now(timezone.utc).isoformat()
    metadata: Dict[str, Any] = {
        "model_version": "1.0.0",
        "algorithm": "Random Forest Classifier (n_estimators=150, max_depth=16)",
        "dataset_name": "PhishGuard Academic Benchmark (Curated Mitchell Krogza & Tranco Seeds)",
        "training_date": now_iso,
        "total_samples": int(len(df)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "evaluation_metrics": {
            "accuracy": float(round(rf_acc, 4)),
            "precision": float(round(rf_prec, 4)),
            "recall": float(round(rf_rec, 4)),
            "f1_score": float(round(rf_f1, 4)),
            "roc_auc": float(round(rf_auc, 4)),
        },
        "baseline_comparison": {
            "logistic_regression": {
                "accuracy": float(round(lr_acc, 4)),
                "precision": float(round(lr_prec, 4)),
                "recall": float(round(lr_rec, 4)),
                "f1_score": float(round(lr_f1, 4)),
                "roc_auc": float(round(lr_auc, 4)),
            }
        },
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "feature_schema": FEATURE_NAMES,
        "feature_importances": feat_imp_dict,
        "model_file": "phishguard_rf_model.joblib",
    }
    
    metadata_path = os.path.join(ARTIFACTS_DIR, "model_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"Saved model metadata to: {metadata_path}")
    
    # Also copy artifacts to backend/app/ml/artifacts/ for immediate production runtime
    shutil.copy(model_artifact_path, os.path.join(BACKEND_ARTIFACTS_DIR, "phishguard_rf_model.joblib"))
    shutil.copy(metadata_path, os.path.join(BACKEND_ARTIFACTS_DIR, "model_metadata.json"))
    print(f"Mirrored model artifacts to backend: {BACKEND_ARTIFACTS_DIR}")
    
    # Generate Training Report Markdown
    report_md = f"""# PhishGuard AI - Model Training & Evaluation Report

- **Date Executed:** {now_iso}
- **Model Version:** 1.0.0
- **Primary Algorithm:** Random Forest Classifier
- **Baseline Algorithm:** Logistic Regression

## 1. Dataset Partitioning
- **Total Ingested Samples:** {len(df):,}
- **Training Samples (80%):** {len(X_train):,}
- **Held-Out Test Samples (20%):** {len(X_test):,}
- **Stratification:** Balanced 50% Phishing / 50% Legitimate

## 2. Performance Comparison

| Metric | Random Forest (Primary) | Logistic Regression (Baseline) | Delta |
|---|---|---|---|
| **Accuracy** | **{rf_acc*100:.2f}%** | {lr_acc*100:.2f}% | +{(rf_acc - lr_acc)*100:.2f}% |
| **Precision** | **{rf_prec*100:.2f}%** | {lr_prec*100:.2f}% | +{(rf_prec - lr_prec)*100:.2f}% |
| **Recall (Sensitivity)** | **{rf_rec*100:.2f}%** | {lr_rec*100:.2f}% | +{(rf_rec - lr_rec)*100:.2f}% |
| **F1-Score** | **{rf_f1*100:.2f}%** | {lr_f1*100:.2f}% | +{(rf_f1 - lr_f1)*100:.2f}% |
| **ROC-AUC** | **{rf_auc:.4f}** | {lr_auc:.4f} | +{(rf_auc - lr_auc):.4f} |

## 3. Confusion Matrix (Held-out Test Partition)
- **True Negatives (Legitimate correctly identified):** {tn:,}
- **False Positives (Legitimate falsely flagged):** {fp:,}
- **False Negatives (Phishing missed):** {fn:,}
- **True Positives (Phishing correctly caught):** {tp:,}

## 4. Top Feature Importances (MDI)
"""
    for name, imp in list(feat_imp_dict.items()):
        report_md += f"- **`{name}`**: {imp*100:.2f}%\n"
        
    report_path = os.path.join(REPORTS_DIR, "training_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"Generated evaluation report at: {report_path}")
    
    return metadata


if __name__ == "__main__":
    train_and_evaluate()
