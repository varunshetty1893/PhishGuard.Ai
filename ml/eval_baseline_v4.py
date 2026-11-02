"""
Compute baseline metrics for current deployed v4.1.0 model on all 4 sets:
1. Held-out test set (7,118 samples)
2. Long-tail legit set (1,080 samples)
3. Authentic SSO set (30 samples)
4. Hard phishing set (600 samples)
With 95% Confidence Intervals.
"""
import sys
import math
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

ROOT = Path(r"d:\git projects\phishing url detector")
sys.path.insert(0, str(ROOT / "backend"))
from app.ml.feature_extraction import extract_url_features, features_to_vector

MODEL_PATH = ROOT / "backend" / "app" / "ml" / "artifacts" / "phishguard_rf_model.joblib"
SPLIT_CSV = ROOT / "ml" / "data" / "split_assignments.csv"
LONGTAIL_CSV = ROOT / "ml" / "reports" / "longtail_legit_eval_results.csv"
HARD_PHISH_CSV = ROOT / "ml" / "reports" / "hard_phishing_eval_results.csv"

def ci_95(p, n):
    se = math.sqrt(p * (1 - p) / max(n, 1))
    return max(0.0, p - 1.96 * se), min(1.0, p + 1.96 * se)

def main():
    art = joblib.load(MODEL_PATH)
    clf = art["model"]
    thresh = float(art.get("optimal_threshold", 0.640))
    print(f"Model: {art.get('model_version', 'v4.1.0')}, threshold: {thresh:.4f}")

    # 1. Held-out test set
    df_splits = pd.read_csv(SPLIT_CSV)
    df_test = df_splits[df_splits["split"] == "test"].copy()
    X_test = []
    y_test = []
    for u, y in zip(df_test["url"], df_test["label"]):
        f, _ = extract_url_features(u)
        X_test.append(features_to_vector(f))
        y_test.append(y)
    X_test = np.array(X_test, dtype=np.float32)
    y_test = np.array(y_test, dtype=int)
    probs_test = clf.predict_proba(X_test)[:, 1]
    preds_test = (probs_test >= thresh).astype(int)

    tp = np.sum((preds_test == 1) & (y_test == 1))
    fp = np.sum((preds_test == 1) & (y_test == 0))
    tn = np.sum((preds_test == 0) & (y_test == 0))
    fn = np.sum((preds_test == 0) & (y_test == 1))

    test_acc = (tp + tn) / len(y_test)
    test_rec = tp / (tp + fn)
    test_fpr = fp / (fp + tn)
    rec_ci = ci_95(test_rec, tp + fn)
    fpr_ci = ci_95(test_fpr, fp + tn)

    print("\n--- 1. Held-out Test Set (N=7,118) ---")
    print(f"Accuracy: {test_acc*100:.2f}%")
    print(f"Recall:   {test_rec*100:.2f}% (95% CI: [{rec_ci[0]*100:.2f}%, {rec_ci[1]*100:.2f}%])")
    print(f"FPR:      {test_fpr*100:.2f}% (95% CI: [{fpr_ci[0]*100:.2f}%, {fpr_ci[1]*100:.2f}%])")

    # 2. Long-tail legit set
    df_long = pd.read_csv(LONGTAIL_CSV)
    X_long = np.array([features_to_vector(extract_url_features(u)[0]) for u in df_long["url"]], dtype=np.float32)
    probs_long = clf.predict_proba(X_long)[:, 1]
    preds_long = (probs_long >= thresh).astype(int)
    long_fp = np.sum(preds_long == 1)
    long_fpr = long_fp / len(df_long)
    long_ci = ci_95(long_fpr, len(df_long))

    print("\n--- 2. Long-Tail Legit Set (N=1,080) ---")
    print(f"FPR: {long_fpr*100:.2f}% ({long_fp}/{len(df_long)}) (95% CI: [{long_ci[0]*100:.2f}%, {long_ci[1]*100:.2f}%])")

    # 3. Authentic SSO set (subset of long-tail)
    sso_mask = df_long["category"] == "Authentic Login/Account/Payment Portal"
    df_sso = df_long[sso_mask]
    sso_fp = np.sum(preds_long[sso_mask] == 1)
    sso_fpr = sso_fp / len(df_sso)
    sso_ci = ci_95(sso_fpr, len(df_sso))

    print("\n--- 3. Authentic SSO / Login Set (N=30) ---")
    print(f"FPR: {sso_fpr*100:.2f}% ({sso_fp}/{len(df_sso)}) (95% CI: [{sso_ci[0]*100:.2f}%, {sso_ci[1]*100:.2f}%])")

    # 4. Hard Phishing set
    df_hard = pd.read_csv(HARD_PHISH_CSV)
    X_hard = np.array([features_to_vector(extract_url_features(u)[0]) for u in df_hard["url"]], dtype=np.float32)
    probs_hard = clf.predict_proba(X_hard)[:, 1]
    preds_hard = (probs_hard >= thresh).astype(int)
    hard_tp = np.sum(preds_hard == 1)
    hard_rec = hard_tp / len(df_hard)
    hard_ci = ci_95(hard_rec, len(df_hard))

    print("\n--- 4. Hard Phishing Set (N=600) ---")
    print(f"Recall: {hard_rec*100:.2f}% ({hard_tp}/{len(df_hard)}) (95% CI: [{hard_ci[0]*100:.2f}%, {hard_ci[1]*100:.2f}%])")

if __name__ == "__main__":
    main()
