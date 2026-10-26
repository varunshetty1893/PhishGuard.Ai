"""
PhishGuard AI - Model Training Script (v2.1)
============================================
Trains and compares Random Forest and Logistic Regression classifiers
on the unified 60k-URL corpus (PhiUSIIL + LegitPhish).

Data Leakage Prevention:
  - Stratified 80/20 train/test split BEFORE fitting
  - StandardScaler fitted ONLY on training data for Logistic Regression
  - Independent holdout evaluation
  - Full metrics computed & serialized for academic transparency
"""

import os, sys, json, logging
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score,
    classification_report
)

ML_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ML_DIR)
from feature_extraction import FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("phishguard.train")

DATA_PATH     = os.path.join(ML_DIR, "data", "dataset.csv")
ARTIFACTS_DIR = os.path.join(ML_DIR, "artifacts")
REPORT_DIR    = os.path.join(ML_DIR, "reports")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

MODEL_PATH    = os.path.join(ARTIFACTS_DIR, "phishguard_rf_model.joblib")
METADATA_PATH = os.path.join(ARTIFACTS_DIR, "model_metadata.json")

RANDOM_SEED   = 42
TEST_SIZE     = 0.20
VAL_FOLDS     = 5

report_lines = []

def rpt(msg):
    log.info(msg)
    report_lines.append(msg)

def evaluate_model(name, model, X_test, y_test):
    rpt(f"\n--- {name} ---")
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc   = accuracy_score(y_test, y_pred)
    prec  = precision_score(y_test, y_pred, pos_label=1)
    rec   = recall_score(y_test, y_pred, pos_label=1)
    f1    = f1_score(y_test, y_pred, pos_label=1)
    auc   = roc_auc_score(y_test, y_proba)
    cm    = confusion_matrix(y_test, y_pred)

    tn, fp, fn, tp = cm.ravel()
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr  = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    rpt(f"  Accuracy  : {acc:.4f}")
    rpt(f"  Precision : {prec:.4f}")
    rpt(f"  Recall    : {rec:.4f}")
    rpt(f"  F1-Score  : {f1:.4f}")
    rpt(f"  ROC-AUC   : {auc:.4f}")
    rpt(f"  FPR       : {fpr:.4f}")
    rpt(f"  FNR       : {fnr:.4f}")
    rpt(f"  Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")

    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "roc_auc": float(auc),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp)
    }

def main():
    start = datetime.now(timezone.utc)
    rpt("=" * 60)
    rpt("PhishGuard AI - Model Training Pipeline v2.1")
    rpt("=" * 60)
    rpt(f"Started: {start.isoformat()}")
    rpt(f"Random seed: {RANDOM_SEED}")

    rpt(f"\nLoading dataset: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    rpt(f"Total rows: {len(df):,}")
    rpt(f"Label distribution: {df['label_unified'].value_counts().to_dict()}")

    X = df[FEATURE_NAMES].values.astype(float)
    y = df["label_unified"].values.astype(int)

    rpt(f"\nStratified 80/20 train/test split...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    rpt(f"Train size: {len(X_train):,}, Test size: {len(X_test):,}")

    rpt("\n" + "=" * 60)
    rpt("MODEL 1: Random Forest Classifier")
    rpt("=" * 60)
    rf_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=16,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    rpt("Training complete.")

    cv = StratifiedKFold(n_splits=VAL_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    cv_scores = cross_val_score(rf_model, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
    rpt(f"  CV F1 mean: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    rf_metrics = evaluate_model("Random Forest (Test Set)", rf_model, X_test, y_test)

    importances = rf_model.feature_importances_
    feat_importance = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    rpt("\n  Feature Importances (Top 10):")
    for fname, imp in feat_importance[:10]:
        rpt(f"    {fname:<30} {imp:.4f}")

    rpt("\n" + "=" * 60)
    rpt("MODEL 2: Logistic Regression")
    rpt("=" * 60)
    lr_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(
            C=1.0,
            max_iter=1000,
            class_weight="balanced",
            random_state=RANDOM_SEED
        ))
    ])
    lr_pipeline.fit(X_train, y_train)
    rpt("Training complete.")

    cv_scores_lr = cross_val_score(lr_pipeline, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
    rpt(f"  CV F1 mean: {cv_scores_lr.mean():.4f} (+/- {cv_scores_lr.std():.4f})")

    lr_metrics = evaluate_model("Logistic Regression (Test Set)", lr_pipeline, X_test, y_test)

    rpt("\n" + "=" * 60)
    rpt("MODEL SELECTION")
    rpt("=" * 60)
    rpt(f"  Random Forest: F1={rf_metrics['f1']:.4f}, Recall={rf_metrics['recall']:.4f}, AUC={rf_metrics['roc_auc']:.4f}")
    rpt(f"  Logistic Reg : F1={lr_metrics['f1']:.4f}, Recall={lr_metrics['recall']:.4f}, AUC={lr_metrics['roc_auc']:.4f}")

    if rf_metrics["f1"] >= lr_metrics["f1"]:
        selected_name = "Random Forest Classifier"
        selected_model = rf_model
        selected_metrics = rf_metrics
    else:
        selected_name = "Logistic Regression"
        selected_model = lr_pipeline
        selected_metrics = lr_metrics

    rpt(f"SELECTED: {selected_name}")

    rpt(f"\nSaving model to: {MODEL_PATH}")
    joblib.dump(selected_model, MODEL_PATH)
    rpt("Model saved.")

    end = datetime.now(timezone.utc)

    metadata = {
        "model_version": "2.1.0",
        "algorithm": selected_name,
        "dataset_name": "Unified PhishGuard Corpus (PhiUSIIL + LegitPhish)",
        "training_date": end.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_samples": int(len(X)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "evaluation_metrics": {
            "accuracy": selected_metrics["accuracy"],
            "precision": selected_metrics["precision"],
            "recall": selected_metrics["recall"],
            "f1": selected_metrics["f1"],
            "roc_auc": selected_metrics["roc_auc"],
            "fpr": selected_metrics["fpr"],
            "fnr": selected_metrics["fnr"]
        },
        "confusion_matrix": {
            "true_negatives": selected_metrics["tn"],
            "false_positives": selected_metrics["fp"],
            "false_negatives": selected_metrics["fn"],
            "true_positives": selected_metrics["tp"],
            "tn": selected_metrics["tn"],
            "fp": selected_metrics["fp"],
            "fn": selected_metrics["fn"],
            "tp": selected_metrics["tp"]
        },
        "feature_schema": FEATURE_NAMES,
        "feature_importances": {fname: round(float(imp), 4) for fname, imp in feat_importance},
        "dataset_sources": [
            "PhiUSIIL_Phishing_URL_Dataset.csv (235,795 rows)",
            "url_features_extracted1.csv / LegitPhish (101,219 rows)"
        ],
        "label_mapping": {"0": "Legitimate", "1": "Phishing"},
        "all_model_metrics": {
            "random_forest": rf_metrics,
            "logistic_regression": lr_metrics
        },
        "rf_cv_f1_mean": float(cv_scores.mean()),
        "rf_cv_f1_std": float(cv_scores.std()),
        "lr_cv_f1_mean": float(cv_scores_lr.mean()),
        "lr_cv_f1_std": float(cv_scores_lr.std())
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    rpt(f"Metadata saved to: {METADATA_PATH}")

    # Generate Markdown Report
    report_path = os.path.join(REPORT_DIR, "model_evaluation_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# PhishGuard AI - Model Evaluation & Benchmark Report\n\n```\n")
        f.write("\n".join(report_lines))
        f.write("\n```\n")

    rpt("DONE!")

if __name__ == "__main__":
    main()
