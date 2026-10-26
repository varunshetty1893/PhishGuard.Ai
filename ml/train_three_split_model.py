"""
PhishGuard AI - Three-Split Domain-Isolated Model Training (Prompt 2)
===================================================================
1. Apex Domain-Isolated Split: 60% Train, 20% Validation, 20% Test
2. Fit base Random Forest & Isotonic Calibration on TRAIN ONLY
3. Select decision threshold on VALIDATION ONLY
4. Evaluate on TEST exactly ONCE
5. Save split assignments to ml/data/split_assignments.csv
6. Compute metrics and prevalence projections (1%, 5%, 10%)
7. Save model artifact and sync metadata
"""

import sys
import json
import time
from pathlib import Path
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import joblib
from datetime import datetime, timezone

ROOT = Path(r"d:\git projects\phishing url detector")
sys.path.insert(0, str(ROOT / "backend"))
from app.ml.feature_extraction import (
    FEATURE_NAMES, extract_url_features, features_to_vector,
    normalize_url, extract_apex_domain
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)

DATA_PATH = ROOT / "ml" / "data" / "dataset_v4_curated.csv"
SPLIT_CSV = ROOT / "ml" / "data" / "split_assignments.csv"
ML_ART = ROOT / "ml" / "artifacts"
BACKEND_ART = ROOT / "backend" / "app" / "ml" / "artifacts"
REPORTS_DIR = ROOT / "ml" / "reports"

def run_prompt_2():
    print("=" * 75)
    print("  PHISHGUARD AI - PROMPT 2: THREE-SPLIT DOMAIN-ISOLATED RETRAINING")
    print("=" * 75)

    df = pd.read_csv(DATA_PATH)
    print(f"[+] Loaded {len(df):,} curated samples from {DATA_PATH.name}")

    # Extract features & apex domains
    print("[*] Extracting lexical features and apex domains...")
    urls = df["url"].tolist()
    vectors = []
    apex_domains = []
    norm_urls = []

    for u in urls:
        try:
            feats, _ = extract_url_features(u)
            vec = features_to_vector(feats)
            vectors.append(vec)
            norm = normalize_url(u)
            norm_urls.append(norm)
            host = urlparse(norm).hostname or ""
            apex_domains.append(extract_apex_domain(host))
        except Exception:
            vectors.append(None)
            norm_urls.append(u)
            apex_domains.append("")

    valid_mask = [v is not None for v in vectors]
    df = df[valid_mask].reset_index(drop=True)
    X = np.array([v for v in vectors if v is not None], dtype=np.float32)
    y = df["label"].values
    df["norm_url"] = [nu for i, nu in enumerate(norm_urls) if valid_mask[i]]
    df["apex_domain"] = [a for i, a in enumerate(apex_domains) if valid_mask[i]]

    # Step 1: Create three domain-isolated splits (60% Train, 20% Val, 20% Test)
    print("\n[*] Creating domain-isolated 60% Train / 20% Val / 20% Test split...")
    rng = np.random.default_rng(42)
    unique_domains = np.array(sorted(list(set(df["apex_domain"]))))
    rng.shuffle(unique_domains)

    n_total_doms = len(unique_domains)
    n_train_doms = int(0.60 * n_total_doms)
    n_val_doms = int(0.20 * n_total_doms)

    train_doms = set(unique_domains[:n_train_doms])
    val_doms   = set(unique_domains[n_train_doms:n_train_doms + n_val_doms])
    test_doms  = set(unique_domains[n_train_doms + n_val_doms:])

    # Verify zero domain overlap
    assert len(train_doms & val_doms) == 0, "Train and Val share domains!"
    assert len(train_doms & test_doms) == 0, "Train and Test share domains!"
    assert len(val_doms & test_doms) == 0, "Val and Test share domains!"

    # Assign split labels
    split_col = []
    for d in df["apex_domain"]:
        if d in train_doms:
            split_col.append("train")
        elif d in val_doms:
            split_col.append("val")
        else:
            split_col.append("test")
    df["split"] = split_col

    train_mask = (df["split"] == "train").values
    val_mask   = (df["split"] == "val").values
    test_mask  = (df["split"] == "test").values

    X_train, y_train = X[train_mask], y[train_mask]
    X_val,   y_val   = X[val_mask],   y[val_mask]
    X_test,  y_test  = X[test_mask],  y[test_mask]

    print(f"[+] Train: {len(X_train):,} URLs ({len(train_doms):,} domains) | Legit: {(y_train==0).sum():,}, Phish: {(y_train==1).sum():,}")
    print(f"[+] Val:   {len(X_val):,} URLs ({len(val_doms):,} domains) | Legit: {(y_val==0).sum():,}, Phish: {(y_val==1).sum():,}")
    print(f"[+] Test:  {len(X_test):,} URLs ({len(test_doms):,} domains) | Legit: {(y_test==0).sum():,}, Phish: {(y_test==1).sum():,}")

    # Save split assignments to disk
    df[["url", "norm_url", "label", "apex_domain", "split"]].to_csv(SPLIT_CSV, index=False)
    print(f"[+] Saved split assignments to {SPLIT_CSV.name}")

    # Step 2: Fit model and calibration on TRAIN ONLY
    print("\n[*] Fitting base Random Forest (n_estimators=200, class_weight='balanced') on TRAIN ONLY...")
    base_rf = RandomForestClassifier(
        n_estimators=200,
        min_samples_leaf=3,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )
    base_rf.fit(X_train, y_train)

    print("[*] Fitting CalibratedClassifierCV (isotonic, cv=3) on TRAIN ONLY...")
    cal_clf = CalibratedClassifierCV(base_rf, method="isotonic", cv=3)
    cal_clf.fit(X_train, y_train)
    print("[+] Training and calibration complete")

    # Step 3: Choose decision threshold on VALIDATION ONLY
    print("\n[*] Selecting optimal decision threshold on VALIDATION SET ONLY...")
    val_probs = cal_clf.predict_proba(X_val)[:, 1]

    # Target: Low FPR (<= 2%) with maximum recall
    target_fpr = 0.02
    best_thresh = 0.50
    best_rec = 0.0
    best_fpr = 1.0

    print(f"{'Threshold':<12} {'Val Precision':<15} {'Val Recall':<15} {'Val FPR':<12} {'Val F1':<10}")
    print("-" * 65)
    for t in np.arange(0.30, 0.90, 0.02):
        preds = (val_probs >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_val, preds, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        if t in [0.40, 0.50, 0.60, 0.64, 0.70, 0.80]:
            print(f"{t:<12.2f} {prec*100:<15.2f}% {rec*100:<15.2f}% {fpr*100:<12.2f}% {f1*100:<10.2f}%")
        if fpr <= target_fpr and rec > best_rec:
            best_rec = rec
            best_thresh = float(t)
            best_fpr = fpr

    print("-" * 65)
    print(f"[+] Optimal Validation Threshold: {best_thresh:.3f} (Val FPR: {best_fpr*100:.2f}%, Val Recall: {best_rec*100:.2f}%)")

    # Step 4: Evaluate on TEST SET EXACTLY ONCE
    print("\n" + "=" * 75)
    print("  EVALUATION ON TEST SET (TOUCHED EXACTLY ONCE)")
    print("=" * 75)
    test_probs = cal_clf.predict_proba(X_test)[:, 1]

    def eval_test(thresh):
        preds = (test_probs >= thresh).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds, zero_division=0)
        rec = recall_score(y_test, preds, zero_division=0)
        f1 = f1_score(y_test, preds, zero_division=0)
        auc = roc_auc_score(y_test, test_probs)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return dict(acc=acc, prec=prec, rec=rec, f1=f1, auc=auc, fpr=fpr, tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp))

    m_def = eval_test(0.50)
    m_opt = eval_test(best_thresh)

    print(f"{'Metric':<28} {'Default @0.50':>16} {'Tuned @' + str(round(best_thresh, 3)):>18}")
    print("-" * 68)
    print(f"  {'Accuracy':<26} {m_def['acc']*100:>15.2f}% {m_opt['acc']*100:>17.2f}%")
    print(f"  {'Precision':<26} {m_def['prec']*100:>15.2f}% {m_opt['prec']*100:>17.2f}%")
    print(f"  {'Phishing Recall':<26} {m_def['rec']*100:>15.2f}% {m_opt['rec']*100:>17.2f}%")
    print(f"  {'False Positive Rate (FPR)':<26} {m_def['fpr']*100:>15.2f}% {m_opt['fpr']*100:>17.2f}%")
    print(f"  {'F1-Score':<26} {m_def['f1']*100:>15.2f}% {m_opt['f1']*100:>17.2f}%")
    print(f"  {'ROC-AUC':<26} {m_def['auc']*100:>15.2f}% {m_opt['auc']*100:>17.2f}%")
    print(f"\n  Confusion Matrix on Test Set @ Tuned Threshold ({best_thresh:.3f}):")
    print(f"    [[TN: {m_opt['tn']:>5,},  FP: {m_opt['fp']:>5,}]")
    print(f"     [FN: {m_opt['fn']:>5,},  TP: {m_opt['tp']:>5,}]]")

    # Prevalence Projections (1%, 5%, 10%)
    print("\n" + "-" * 75)
    print("PREVALENCE ANALYSIS (PER 1,000 SCANS IN PRODUCTION)")
    print("-" * 75)
    tpr = m_opt['rec']
    fpr = m_opt['fpr']

    print(f"{'Prevalence':<14} {'Phish/Legit':<16} {'True Pos':<12} {'False Pos':<12} {'Precision':<14} {'False Alerts/1k'}")
    print("-" * 75)
    for p in [0.01, 0.05, 0.10]:
        n_p = int(1000 * p)
        n_l = 1000 - n_p
        tp_exp = n_p * tpr
        fp_exp = n_l * fpr
        prec_exp = tp_exp / (tp_exp + fp_exp) if (tp_exp + fp_exp) > 0 else 0.0
        print(f"{p*100:>4.1f}%          {f'{n_p}/{n_l}':<16} {tp_exp:>6.1f}       {fp_exp:>6.1f}       {prec_exp*100:>7.2f}%        {fp_exp:>5.1f} per 1k")

    # Step 5: Save Model Artifact & Metadata
    model_data = {
        "model": cal_clf,
        "base_model": base_rf,
        "feature_names": FEATURE_NAMES,
        "optimal_threshold": best_thresh,
        "train_metrics": {
            "test_accuracy": float(m_opt['acc']),
            "test_precision": float(m_opt['prec']),
            "test_recall": float(m_opt['rec']),
            "test_fpr": float(m_opt['fpr']),
            "test_f1": float(m_opt['f1']),
            "test_roc_auc": float(m_opt['auc'])
        }
    }
    for art_dir in [ML_ART, BACKEND_ART]:
        joblib.dump(model_data, art_dir / "phishguard_rf_model.joblib")
    print(f"\n[+] Saved updated model artifact to ml/artifacts and backend/app/ml/artifacts")

    meta = {
        "model_version": "v4.1.0",
        "algorithm": "Random Forest (class_weight=balanced, isotonic calibrated, domain-isolated 3-split)",
        "trained_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "training_samples": int(len(X_train)),
        "validation_samples": int(len(X_val)),
        "test_samples": int(len(X_test)),
        "decision_threshold": best_thresh,
        "test_accuracy": round(float(m_opt['acc']), 4),
        "test_precision": round(float(m_opt['prec']), 4),
        "test_recall": round(float(m_opt['rec']), 4),
        "test_fpr": round(float(m_opt['fpr']), 4),
        "test_f1": round(float(m_opt['f1']), 4),
        "test_roc_auc": round(float(m_opt['auc']), 4),
        "confusion_matrix": {
            "tn": m_opt['tn'], "fp": m_opt['fp'],
            "fn": m_opt['fn'], "tp": m_opt['tp']
        },
        "prevalence_analysis": {
            "1_percent": {"precision": round(float((10*tpr)/(10*tpr + 990*fpr)), 4), "false_alerts_per_1k": round(float(990*fpr), 1)},
            "5_percent": {"precision": round(float((50*tpr)/(50*tpr + 950*fpr)), 4), "false_alerts_per_1k": round(float(950*fpr), 1)},
            "10_percent": {"precision": round(float((100*tpr)/(100*tpr + 900*fpr)), 4), "false_alerts_per_1k": round(float(900*fpr), 1)}
        }
    }
    for art_dir in [ML_ART, BACKEND_ART]:
        with open(art_dir / "model_metadata.json", "w") as f:
            json.dump(meta, f, indent=2)
    print(f"[+] Saved updated metadata to model_metadata.json")

if __name__ == '__main__':
    run_prompt_2()
