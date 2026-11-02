"""
ml/train_and_deploy_v5.py
========================
Trains the final v5-RF model with hard-negative SSO URLs and contextual keyword features,
evaluates on test, longtail, sso, and hard-phishing sets,
and serializes artifacts to ml/artifacts and backend/app/ml/artifacts.
"""
import sys
import math
import json
import shutil
from pathlib import Path
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import joblib
from datetime import datetime, timezone

from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

ROOT = Path(r"d:\git projects\phishing url detector")
sys.path.insert(0, str(ROOT / "backend"))

from app.ml.feature_extraction_v2 import (
    FEATURE_NAMES, normalize_url, extract_apex_domain,
    get_tld_risk_score, check_brand_lookalike, check_brand_in_subdomain,
    has_punycode, hostname_entropy, is_valid_ip, is_hsts_enforced_domain,
    count_subdomains, DISALLOWED_SHARED_PLATFORMS, SUSPICIOUS_KEYWORDS
)

DATA_PATH = ROOT / "ml" / "data" / "dataset_v4_curated.csv"
ML_ART = ROOT / "ml" / "artifacts"
BACKEND_ART = ROOT / "backend" / "app" / "ml" / "artifacts"
LONGTAIL_CSV = ROOT / "ml" / "reports" / "longtail_legit_eval_results.csv"
HARD_PHISH_CSV = ROOT / "ml" / "reports" / "hard_phishing_eval_results.csv"

from train_v5_candidate import HARD_NEGATIVE_SSO, extract_features_v5

def ci_95(p, n):
    se = math.sqrt(p * (1 - p) / max(n, 1))
    return max(0.0, p - 1.96 * se), min(1.0, p + 1.96 * se)

def main():
    print("=" * 80)
    print("  PHISHGUARD AI - TRAINING FINAL V5-RF MODEL")
    print("=" * 80)

    # 1. Base dataset + Hard Negatives
    df = pd.read_csv(DATA_PATH)
    hard_neg_df = pd.DataFrame({"url": HARD_NEGATIVE_SSO, "label": 0})
    df_combined = pd.concat([df, hard_neg_df], ignore_index=True).drop_duplicates(subset=["url"]).reset_index(drop=True)

    print(f"[*] Total dataset samples: {len(df_combined):,}")

    vectors = []
    apex_domains = []
    for u in df_combined["url"]:
        nu = normalize_url(u)
        host = urlparse(nu).hostname or ""
        apex_domains.append(extract_apex_domain(host))
        vectors.append(extract_features_v5(nu))

    X = np.array(vectors, dtype=np.float32)
    y = df_combined["label"].values.astype(int)

    # 2. Domain-isolated split (60% Train, 20% Val, 20% Test)
    rng = np.random.default_rng(42)
    unique_domains = np.array(sorted(list(set(apex_domains))))
    rng.shuffle(unique_domains)

    n_total_doms = len(unique_domains)
    n_train_doms = int(0.60 * n_total_doms)
    n_val_doms = int(0.20 * n_total_doms)

    train_doms = set(unique_domains[:n_train_doms])
    val_doms   = set(unique_domains[n_train_doms:n_train_doms + n_val_doms])
    test_doms  = set(unique_domains[n_train_doms + n_val_doms:])

    train_mask = np.array([d in train_doms for d in apex_domains])
    val_mask   = np.array([d in val_doms for d in apex_domains])
    test_mask  = np.array([d in test_doms for d in apex_domains])

    X_train, y_train = X[train_mask], y[train_mask]
    X_val,   y_val   = X[val_mask],   y[val_mask]
    X_test,  y_test  = X[test_mask],  y[test_mask]

    print(f"[+] Train: {len(X_train):,} ({len(train_doms):,} domains)")
    print(f"[+] Val:   {len(X_val):,} ({len(val_doms):,} domains)")
    print(f"[+] Test:  {len(X_test):,} ({len(test_doms):,} domains)")

    # 3. Train Base RandomForest & Isotonic Calibration
    print("\n[*] Training base RandomForestClassifier (200 trees, min_samples_leaf=3)...")
    base_rf = RandomForestClassifier(
        n_estimators=200,
        min_samples_leaf=3,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )
    base_rf.fit(X_train, y_train)

    print("[*] Calibrating probabilities via CalibratedClassifierCV (isotonic, cv=3)...")
    cal_clf = CalibratedClassifierCV(base_rf, method="isotonic", cv=3)
    cal_clf.fit(X_train, y_train)

    # 4. Tune Threshold on Validation Set ONLY (target FPR <= 2%)
    val_probs = cal_clf.predict_proba(X_val)[:, 1]
    best_thresh = 0.50
    best_rec = 0.0
    best_fpr = 1.0
    for t in np.arange(0.30, 0.90, 0.02):
        preds = (val_probs >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_val, preds, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        if fpr <= 0.02 and rec > best_rec:
            best_rec = rec
            best_thresh = float(t)
            best_fpr = fpr

    print(f"[+] Validation-tuned Threshold: {best_thresh:.3f} (Val FPR: {best_fpr*100:.2f}%, Val Recall: {best_rec*100:.2f}%)")

    # 5. Evaluate on Held-out Test Set (touched once)
    test_probs = cal_clf.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= best_thresh).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, test_preds, labels=[0, 1]).ravel()
    t_acc = accuracy_score(y_test, test_preds)
    t_prec = precision_score(y_test, test_preds, zero_division=0)
    t_rec = recall_score(y_test, test_preds, zero_division=0)
    t_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    t_f1 = f1_score(y_test, test_preds, zero_division=0)
    t_auc = roc_auc_score(y_test, test_probs)

    # 6. Evaluate on Long-tail Legit Set
    df_long = pd.read_csv(LONGTAIL_CSV)
    X_long = np.array([extract_features_v5(u) for u in df_long["url"]], dtype=np.float32)
    sso_mask = df_long["category"] == "Authentic Login/Account/Payment Portal"

    long_preds = (cal_clf.predict_proba(X_long)[:, 1] >= best_thresh).astype(int)
    long_fp = int(np.sum(long_preds == 1))
    long_fpr = long_fp / len(df_long)

    sso_fp = int(np.sum(long_preds[sso_mask] == 1))
    sso_fpr = sso_fp / sso_mask.sum()

    # 7. Evaluate on Hard Phishing Set
    df_hard = pd.read_csv(HARD_PHISH_CSV)
    X_hard = np.array([extract_features_v5(u) for u in df_hard["url"]], dtype=np.float32)
    hard_preds = (cal_clf.predict_proba(X_hard)[:, 1] >= best_thresh).astype(int)
    hard_tp = int(np.sum(hard_preds == 1))
    hard_rec = hard_tp / len(df_hard)

    print("\n" + "=" * 80)
    print("  FINAL V5-RF BENCHMARK RESULTS")
    print("=" * 80)
    print(f"  Threshold:              {best_thresh:.3f}")
    print(f"  Test Accuracy:          {t_acc*100:.2f}%")
    print(f"  Test Precision:         {t_prec*100:.2f}%")
    print(f"  Test Phishing Recall:   {t_rec*100:.2f}%")
    print(f"  Test FPR:               {t_fpr*100:.2f}%")
    print(f"  Test F1:                {t_f1*100:.2f}%")
    print(f"  Test ROC-AUC:           {t_auc*100:.2f}%")
    print(f"  Long-tail Legit FPR:    {long_fpr*100:.2f}% ({long_fp}/1,080)")
    print(f"  Authentic SSO FPR:      {sso_fpr*100:.2f}% ({sso_fp}/30)")
    print(f"  Hard Phishing Recall:   {hard_rec*100:.2f}% ({hard_tp}/600)")

    # 8. Feature importances from base Random Forest
    importances = dict(zip(FEATURE_NAMES, [round(float(v), 4) for v in base_rf.feature_importances_]))
    # Sort descending
    sorted_importances = dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))

    # 9. Serialize Model Artifacts
    model_artifact = {
        "model": cal_clf,
        "base_model": base_rf,
        "feature_names": FEATURE_NAMES,
        "optimal_threshold": best_thresh,
        "decision_threshold": best_thresh,
        "model_version": "v5.0.0",
        "train_metrics": {
            "test_accuracy": float(t_acc),
            "test_precision": float(t_prec),
            "test_recall": float(t_rec),
            "test_fpr": float(t_fpr),
            "test_f1": float(t_f1),
            "test_roc_auc": float(t_auc),
            "longtail_fpr": float(long_fpr),
            "sso_fpr": float(sso_fpr),
            "hard_phish_recall": float(hard_rec)
        }
    }

    metadata = {
        "model_version": "v5.0.0",
        "algorithm": "Random Forest (class_weight=balanced, isotonic calibrated, hard-negative SSO augmented, domain-isolated 3-split)",
        "trained_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "training_samples": int(len(X_train)),
        "validation_samples": int(len(X_val)),
        "test_samples": int(len(X_test)),
        "decision_threshold": best_thresh,
        "optimal_threshold": best_thresh,
        "test_accuracy": round(float(t_acc), 4),
        "test_precision": round(float(t_prec), 4),
        "test_recall": round(float(t_rec), 4),
        "test_fpr": round(float(t_fpr), 4),
        "test_f1": round(float(t_f1), 4),
        "test_roc_auc": round(float(t_auc), 4),
        "long_tail_legit_fpr": round(float(long_fpr), 4),
        "sso_fpr": round(float(sso_fpr), 4),
        "hard_phishing_recall": round(float(hard_rec), 4),
        "confusion_matrix": {
            "tn": int(tn), "fp": int(fp),
            "fn": int(fn), "tp": int(tp)
        },
        "feature_importances": sorted_importances,
        "prevalence_analysis": {
            "1_percent": {
                "precision": round(float((10 * t_rec) / ((10 * t_rec) + (990 * t_fpr))), 4),
                "false_alerts_per_1k": round(float(990 * t_fpr), 1)
            },
            "5_percent": {
                "precision": round(float((50 * t_rec) / ((50 * t_rec) + (950 * t_fpr))), 4),
                "false_alerts_per_1k": round(float(950 * t_fpr), 1)
            },
            "10_percent": {
                "precision": round(float((100 * t_rec) / ((100 * t_rec) + (900 * t_fpr))), 4),
                "false_alerts_per_1k": round(float(900 * t_fpr), 1)
            }
        }
    }

    # Save to both ml/artifacts and backend/app/ml/artifacts
    for out_dir in [ML_ART, BACKEND_ART]:
        out_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(model_artifact, out_dir / "phishguard_rf_model.joblib")
        with open(out_dir / "model_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)
        print(f"[+] Serialized model artifact and metadata to {out_dir}")

    # Also update split_assignments.csv with new splits
    df_combined["apex_domain"] = apex_domains
    df_combined["split"] = ["train" if d in train_doms else ("val" if d in val_doms else "test") for d in apex_domains]
    df_combined[["url", "label", "apex_domain", "split"]].to_csv(ROOT / "ml" / "data" / "split_assignments.csv", index=False)
    print(f"[+] Updated ml/data/split_assignments.csv with {len(df_combined):,} samples")

    print("\n[OK] Final v5-RF deployment complete.")

if __name__ == "__main__":
    main()
