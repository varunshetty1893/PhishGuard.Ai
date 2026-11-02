"""
PhishGuard AI — Step 2: Remove 'path = phishing' Bias
Retrains Random Forest with 3,500+ authentic deep links and evaluates:
- Held-out test set (domain-isolated)
- Long-tail legit FPR
- FPR on URLs with paths
- Expanded SSO FPR (120 authentic SSO URLs)
- Hard-phishing recall (600 real-world active phish)
"""
import sys
import math
import json
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from backend.app.ml.feature_extraction_v2 import (
    FEATURE_NAMES, normalize_url, extract_apex_domain,
    get_tld_risk_score, check_brand_lookalike, check_brand_in_subdomain,
    has_punycode, hostname_entropy, is_valid_ip, is_hsts_enforced_domain,
    count_subdomains, DISALLOWED_SHARED_PLATFORMS, SUSPICIOUS_KEYWORDS,
    extract_url_features, features_to_vector
)

from ml.train_v5_candidate import HARD_NEGATIVE_SSO

DATA_PATH = ROOT / "ml" / "data" / "dataset_v4_curated.csv"
DEEP_LINKS_PATH = ROOT / "ml" / "data" / "legit_deep_links_6000.csv"
SSO_PATH = ROOT / "ml" / "data" / "sso_eval_100.csv"
LONGTAIL_CSV = ROOT / "ml" / "reports" / "longtail_legit_eval_results.csv"
HARD_PHISH_CSV = ROOT / "ml" / "reports" / "hard_phishing_eval_results.csv"

ML_ART = ROOT / "ml" / "artifacts"
BACKEND_ART = ROOT / "backend" / "app" / "ml" / "artifacts"


def extract_features_v6(raw_url: str):
    features, _ = extract_url_features(raw_url)
    return features_to_vector(features)


def main():
    print("=" * 80)
    print("  PHISHGUARD AI - STEP 2: REMOVE PATH BIAS VIA DEEP LINKS RETRAINING")
    print("=" * 80)

    # 1. Load curated dataset + legitimate deep links + hard-negative SSO
    df_base = pd.read_csv(DATA_PATH)[["url", "label"]]
    df_deep = pd.read_csv(DEEP_LINKS_PATH)[["url", "label"]]
    hard_neg_df = pd.DataFrame({"url": HARD_NEGATIVE_SSO, "label": 0})
    df_combined = pd.concat([df_base, df_deep, hard_neg_df], ignore_index=True).drop_duplicates(subset=["url"]).reset_index(drop=True)
    print(f"[+] Loaded {len(df_base):,} base samples + {len(df_deep):,} deep links + {len(hard_neg_df)} SSO -> {len(df_combined):,} combined samples")

    # 2. Extract Apex Domains for Strict Domain-Isolated Split
    print("[*] Extracting apex domains for domain-isolated partitioning...")
    apex_domains = []
    for u in df_combined["url"]:
        host = urlparse(normalize_url(u)).hostname or ""
        apex_domains.append(extract_apex_domain(host))
    df_combined["apex_domain"] = apex_domains

    unique_domains = sorted(list(set(apex_domains)))
    np.random.seed(42)
    shuffled_domains = np.random.permutation(unique_domains)
    n_doms = len(shuffled_domains)
    n_train_d = int(n_doms * 0.60)
    n_val_d = int(n_doms * 0.20)

    train_doms = set(shuffled_domains[:n_train_d])
    val_doms = set(shuffled_domains[n_train_d:n_train_d + n_val_d])
    test_doms = set(shuffled_domains[n_train_d + n_val_d:])

    train_mask = df_combined["apex_domain"].isin(train_doms)
    val_mask = df_combined["apex_domain"].isin(val_doms)
    test_mask = df_combined["apex_domain"].isin(test_doms)

    train_df = df_combined[train_mask].reset_index(drop=True)
    val_df = df_combined[val_mask].reset_index(drop=True)
    test_df = df_combined[test_mask].reset_index(drop=True)

    print(f"[+] Splits (Domain-Isolated):")
    print(f"    Train: {len(train_df):,} samples ({len(train_doms):,} domains)")
    print(f"    Val:   {len(val_df):,} samples ({len(val_doms):,} domains)")
    print(f"    Test:  {len(test_df):,} samples ({len(test_doms):,} domains)")

    # 3. Vectorize Features
    print("[*] Vectorizing features (16 dimensions)...")
    X_train = np.array([extract_features_v6(u) for u in train_df["url"]], dtype=np.float32)
    y_train = train_df["label"].values.astype(int)

    X_val = np.array([extract_features_v6(u) for u in val_df["url"]], dtype=np.float32)
    y_val = val_df["label"].values.astype(int)

    X_test = np.array([extract_features_v6(u) for u in test_df["url"]], dtype=np.float32)
    y_test = test_df["label"].values.astype(int)

    # 4. Train Random Forest Classifier
    print("[*] Training balanced Random Forest (200 trees, min_samples_leaf=3)...")
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

    # 5. Tune Threshold on Validation Set ONLY (target operational FPR <= 1.5%)
    val_probs = cal_clf.predict_proba(X_val)[:, 1]
    best_thresh = 0.50
    best_rec = 0.0
    best_fpr = 1.0
    for t in np.arange(0.30, 0.90, 0.02):
        preds = (val_probs >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_val, preds, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        if fpr <= 0.015 and rec > best_rec:
            best_rec = rec
            best_thresh = float(t)
            best_fpr = fpr

    print(f"[+] Validation-tuned Threshold: {best_thresh:.3f} (Val FPR: {best_fpr*100:.2f}%, Val Recall: {best_rec*100:.2f}%)")

    # 6. Evaluate on Held-out Test Set
    test_probs = cal_clf.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= best_thresh).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, test_preds, labels=[0, 1]).ravel()
    t_acc = accuracy_score(y_test, test_preds)
    t_prec = precision_score(y_test, test_preds, zero_division=0)
    t_rec = recall_score(y_test, test_preds, zero_division=0)
    t_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    t_f1 = f1_score(y_test, test_preds, zero_division=0)
    t_auc = roc_auc_score(y_test, test_probs)

    # 7. Evaluate on Long-tail Legit Set & Path breakdown
    df_long = pd.read_csv(LONGTAIL_CSV)
    X_long = np.array([extract_features_v6(u) for u in df_long["url"]], dtype=np.float32)
    long_probs = cal_clf.predict_proba(X_long)[:, 1]
    long_preds = (long_probs >= best_thresh).astype(int)
    long_fp = int(np.sum(long_preds == 1))
    long_fpr = long_fp / len(df_long)

    # Separate URLs with path vs without path
    has_path = df_long["url"].apply(lambda u: len(urlparse(u).path.strip("/")) > 0).values
    path_fp = int(np.sum(long_preds[has_path] == 1))
    path_total = int(np.sum(has_path))
    path_fpr = path_fp / max(path_total, 1)

    nopath_fp = int(np.sum(long_preds[~has_path] == 1))
    nopath_total = int(np.sum(~has_path))
    nopath_fpr = nopath_fp / max(nopath_total, 1)

    # 8. Evaluate on Expanded 100+ SSO Set
    df_sso = pd.read_csv(SSO_PATH)
    X_sso = np.array([extract_features_v6(u) for u in df_sso["url"]], dtype=np.float32)
    sso_probs = cal_clf.predict_proba(X_sso)[:, 1]
    sso_preds = (sso_probs >= best_thresh).astype(int)
    sso_fp = int(np.sum(sso_preds == 1))
    sso_fpr = sso_fp / len(df_sso)

    # 9. Evaluate on Hard Phishing Set
    df_hard = pd.read_csv(HARD_PHISH_CSV)
    X_hard = np.array([extract_features_v6(u) for u in df_hard["url"]], dtype=np.float32)
    hard_probs = cal_clf.predict_proba(X_hard)[:, 1]
    hard_preds = (hard_probs >= best_thresh).astype(int)
    hard_tp = int(np.sum(hard_preds == 1))
    hard_rec = hard_tp / len(df_hard)

    print("\n" + "=" * 80)
    print("  STEP 2 EVALUATION REPORT (REAL MEASUREMENTS)")
    print("=" * 80)
    print(f"  Optimal Threshold:         {best_thresh:.3f}")
    print(f"  Test Accuracy:             {t_acc*100:.2f}%")
    print(f"  Test Precision:            {t_prec*100:.2f}%")
    print(f"  Test Phishing Recall:      {t_rec*100:.2f}%")
    print(f"  Test FPR:                  {t_fpr*100:.2f}%")
    print(f"  Test F1-Score:             {t_f1*100:.2f}%")
    print(f"  Test ROC-AUC:              {t_auc*100:.2f}%")
    print(f"  Long-tail Legit FPR:       {long_fpr*100:.2f}% ({long_fp}/{len(df_long)})")
    print(f"  FPR for URLs WITH path:    {path_fpr*100:.2f}% ({path_fp}/{path_total})")
    print(f"  FPR for URLs WITHOUT path: {nopath_fpr*100:.2f}% ({nopath_fp}/{nopath_total})")
    print(f"  Expanded SSO FPR (100+):   {sso_fpr*100:.2f}% ({sso_fp}/{len(df_sso)})")
    print(f"  Hard Phishing Recall:      {hard_rec*100:.2f}% ({hard_tp}/{len(df_hard)})")

    # 10. Check Deployment Gates:
    # "Deploy only if long-tail FPR drops below 6% and recall drops by no more than 1 point."
    baseline_recall = 0.9513 # From v5.0.0
    recall_drop = baseline_recall - t_rec
    gate_fpr = long_fpr < 0.06
    gate_recall = recall_drop <= 0.01

    print("\n" + "=" * 80)
    print("  DEPLOYMENT GATES CHECK")
    print("=" * 80)
    print(f"  Gate 1: Long-tail FPR < 6.0%?        {long_fpr*100:.2f}% -> {'PASSED [OK]' if gate_fpr else 'FAILED [X]'}")
    print(f"  Gate 2: Recall drop <= 1.0 point?    {recall_drop*100:+.2f}% -> {'PASSED [OK]' if gate_recall else 'FAILED [X]'}")

    if gate_fpr and gate_recall:
        print("\n[+] Both deployment gates PASSED! Deploying v6 model artifacts...")

        importances = dict(zip(FEATURE_NAMES, [round(float(v), 4) for v in base_rf.feature_importances_]))
        sorted_importances = dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))

        model_artifact = {
            "model": cal_clf,
            "base_model": base_rf,
            "feature_names": FEATURE_NAMES,
            "optimal_threshold": best_thresh,
            "decision_threshold": best_thresh,
            "model_version": "v6.0.0",
            "train_metrics": {
                "test_accuracy": float(t_acc),
                "test_precision": float(t_prec),
                "test_recall": float(t_rec),
                "test_fpr": float(t_fpr),
                "test_f1": float(t_f1),
                "test_roc_auc": float(t_auc),
                "longtail_fpr": float(long_fpr),
                "path_fpr": float(path_fpr),
                "nopath_fpr": float(nopath_fpr),
                "sso_fpr": float(sso_fpr),
                "hard_phish_recall": float(hard_rec)
            }
        }

        metadata = {
            "model_version": "v6.0.0",
            "algorithm": "Random Forest (class_weight=balanced, isotonic calibrated, 3.5k deep links augmented, domain-isolated 3-split)",
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
            "path_fpr": round(float(path_fpr), 4),
            "nopath_fpr": round(float(nopath_fpr), 4),
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

        for out_dir in [ML_ART, BACKEND_ART]:
            out_dir.mkdir(parents=True, exist_ok=True)
            joblib.dump(model_artifact, out_dir / "phishguard_rf_model.joblib")
            with open(out_dir / "model_metadata.json", "w") as f:
                json.dump(metadata, f, indent=2)
            print(f"[+] Serialized model artifact and metadata to {out_dir}")

        # Update split_assignments.csv with new splits
        df_combined["split"] = ["train" if d in train_doms else ("val" if d in val_doms else "test") for d in apex_domains]
        df_combined[["url", "label", "apex_domain", "split"]].to_csv(ROOT / "ml" / "data" / "split_assignments.csv", index=False)
        print(f"[+] Updated ml/data/split_assignments.csv with {len(df_combined):,} samples")

        # Save evaluation report to ml/reports/step2_path_bias_report.json
        report_data = {
            "model_version": "v6.0.0",
            "optimal_threshold": best_thresh,
            "test_accuracy": float(t_acc),
            "test_precision": float(t_prec),
            "test_recall": float(t_rec),
            "test_fpr": float(t_fpr),
            "test_f1": float(t_f1),
            "test_roc_auc": float(t_auc),
            "long_tail_legit_fpr": float(long_fpr),
            "path_fpr": float(path_fpr),
            "nopath_fpr": float(nopath_fpr),
            "sso_fpr": float(sso_fpr),
            "hard_phishing_recall": float(hard_rec),
            "gates_passed": True
        }
        with open(ROOT / "ml" / "reports" / "step2_path_bias_report.json", "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"[+] Saved report to ml/reports/step2_path_bias_report.json")
    else:
        print("\n[!] Deployment gates were NOT met. Preserving existing model.")
        report_data = {
            "candidate_version": "v6.0.0-candidate",
            "optimal_threshold": best_thresh,
            "test_accuracy": float(t_acc),
            "test_recall": float(t_rec),
            "long_tail_legit_fpr": float(long_fpr),
            "path_fpr": float(path_fpr),
            "nopath_fpr": float(nopath_fpr),
            "sso_fpr": float(sso_fpr),
            "hard_phishing_recall": float(hard_rec),
            "gates_passed": False
        }
        with open(ROOT / "ml" / "reports" / "step2_path_bias_report.json", "w") as f:
            json.dump(report_data, f, indent=2)

    print("\n[OK] Step 2 execution complete.")


if __name__ == "__main__":
    main()
