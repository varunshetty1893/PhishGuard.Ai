"""
PhishGuard AI - Fresh Data Evaluation Script (Vectorized & Suppressed Warnings)
=============================================================================
Tests the RETRAINED model against genuinely new data it has NEVER seen:
  - ~500 phishing URLs from OpenPhish / URLhaus live feeds
  - ~500 legitimate URLs from Tranco top-1M list (newly sampled)

Reports:
  - Accuracy, Precision, Phishing Recall, False Positive Rate, F1, ROC-AUC
  - Evaluated at both Default (0.50) and Tuned Threshold (0.64)
  - Side-by-side with training set metrics
"""

import sys
import json
import time
import io
import zipfile
import warnings
from pathlib import Path
from urllib.parse import urlparse
import urllib.request

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
from app.ml.feature_extraction import (
    FEATURE_NAMES, extract_url_features, features_to_vector
)

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)

ARTIFACTS_DIR = ROOT / "ml" / "artifacts"
REPORTS_DIR   = ROOT / "ml" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def fetch_openphish(n=500):
    print("[*] Fetching live phishing URLs from OpenPhish...")
    try:
        req = urllib.request.Request(
            "https://openphish.com/feed.txt",
            headers={"User-Agent": "PhishGuardAI-Research/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            lines = [line.decode("utf-8", errors="ignore").strip() for line in r]
        urls = [u for u in lines if u.startswith(("http://", "https://"))][:n]
        print(f"    Fetched {len(urls):,} live phishing URLs from OpenPhish")
        return urls
    except Exception as e:
        print(f"    [WARN] OpenPhish unavailable ({e}), using fallback feed...")
        # Fallback to URLhaus recent URLs
        try:
            req2 = urllib.request.Request(
                "https://urlhaus.abuse.ch/downloads/text_recent/",
                headers={"User-Agent": "PhishGuardAI-Research/1.0"}
            )
            with urllib.request.urlopen(req2, timeout=15) as r:
                lines = [line.decode("utf-8", errors="ignore").strip() for line in r]
            urls = [u for u in lines if u.startswith("http") and not u.startswith("#")][:n]
            print(f"    Fetched {len(urls):,} phishing URLs from URLhaus fallback")
            return urls
        except Exception as e2:
            print(f"    [FAIL] Fallback also failed ({e2})")
            return []


def fetch_tranco(n=500):
    print("[*] Fetching Tranco top-sites list for fresh testing...")
    cache_path = ROOT / "ml" / "data" / "tranco_top50k.txt"
    if cache_path.exists():
        domains = [line.strip() for line in open(cache_path, encoding="utf-8") if line.strip()]
        # Sample from ranks 5000-50000 (test domains not in top 1k)
        sample_doms = domains[5000:15000]
        import random; random.seed(999); random.shuffle(sample_doms)
        urls = [f"https://{d}" for d in sample_doms[:n]]
        print(f"    Sampled {len(urls):,} fresh legitimate URLs from Tranco ranks 5,000-15,000")
        return urls
    return []


def evaluate_batch(clf, urls, label):
    vectors = []
    valid_urls = []
    for u in urls:
        try:
            f, _ = extract_url_features(u)
            vec = features_to_vector(f)
            vectors.append(vec)
            valid_urls.append(u)
        except Exception:
            pass

    X = np.array(vectors, dtype=np.float32)
    probs = clf.predict_proba(X)[:, 1]
    return valid_urls, probs, [label] * len(valid_urls)


def compute_metrics(y_true, probs, threshold):
    preds = (probs >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, preds, labels=[0, 1]).ravel()
    return dict(
        acc=float(accuracy_score(y_true, preds)),
        prec=float(precision_score(y_true, preds, zero_division=0)),
        rec=float(recall_score(y_true, preds, zero_division=0)),
        f1=float(f1_score(y_true, preds, zero_division=0)),
        auc=float(roc_auc_score(y_true, probs)),
        fpr=float(fp / (fp + tn) if (fp + tn) > 0 else 0.0),
        fnr=float(fn / (fn + tp) if (fn + tp) > 0 else 0.0),
        tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp)
    )


def main():
    print("=" * 70)
    print("  PHISHGUARD AI - FRESH EXTERNAL DATA EVALUATION")
    print("=" * 70)

    model_path = ARTIFACTS_DIR / "phishguard_rf_model.joblib"
    meta_path  = ARTIFACTS_DIR / "model_metadata.json"

    clf = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    opt_thresh = float(meta.get("optimal_threshold", 0.64))
    print(f"[+] Loaded Model: {meta['algorithm']} (v{meta['version']})")
    print(f"[+] Optimal Threshold Configured: {opt_thresh:.3f}")

    phish_urls = fetch_openphish(500)
    legit_urls = fetch_tranco(500)

    if not phish_urls or not legit_urls:
        print("[!] Failed to obtain fresh URLs. Exiting.")
        sys.exit(1)

    print(f"\n[*] Evaluating on {len(phish_urls):,} live phishing + {len(legit_urls):,} fresh Tranco URLs...")
    p_urls, p_probs, p_y = evaluate_batch(clf, phish_urls, label=1)
    l_urls, l_probs, l_y = evaluate_batch(clf, legit_urls, label=0)

    all_urls = p_urls + l_urls
    all_probs = np.concatenate([p_probs, l_probs])
    all_y = np.array(p_y + l_y)

    m_default = compute_metrics(all_y, all_probs, 0.50)
    m_tuned   = compute_metrics(all_y, all_probs, opt_thresh)

    print("\n" + "=" * 70)
    print("  RESULTS: Held-Out Training vs Fresh External Data")
    print("=" * 70)
    print(f"{'Metric':<25} {'Held-Out Test':>15} {'Fresh @0.50':>14} {'Fresh @' + str(round(opt_thresh,2)):>14}")
    print("-" * 70)
    key_map = [("acc", "accuracy", "Accuracy"), ("prec", "precision", "Precision"), ("rec", "recall", "Phishing Recall"),
                ("fpr", "false_positive_rate", "False Positive Rate"), ("f1", "f1_score", "F1-Score"), ("auc", "roc_auc", "ROC-AUC")]
    for mk, tk, name in key_map:
        train_val = meta.get(tk, 0.0) * 100
        print(f"  {name:<23} {train_val:>14.2f}% {m_default[mk]*100:>13.2f}% {m_tuned[mk]*100:>13.2f}%")

    print(f"\n  Confusion Matrix on Fresh External Data (@{opt_thresh:.2f}):")
    print(f"    True Negative (Clean Legit):   {m_tuned['tn']:>6,}")
    print(f"    False Positive (False Alarm):  {m_tuned['fp']:>6,}")
    print(f"    False Negative (Missed Phish): {m_tuned['fn']:>6,}")
    print(f"    True Positive (Caught Phish):  {m_tuned['tp']:>6,}")

    # Top false positives
    fp_indices = [i for i, y in enumerate(l_y) if l_probs[i] >= opt_thresh]
    print(f"\n  Top False Positives on Fresh Tranco Sites ({len(fp_indices)} total):")
    for idx in sorted(fp_indices, key=lambda i: l_probs[i], reverse=True)[:5]:
        print(f"    {l_probs[idx]*100:5.1f}%: {l_urls[idx]}")

    # Save fresh evaluation report
    report_data = {
        "evaluation_name": "Fresh External Data Evaluation (Tranco + OpenPhish)",
        "model_version": meta["version"],
        "evaluated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "optimal_threshold": opt_thresh,
        "n_fresh_phishing": len(p_urls),
        "n_fresh_legitimate": len(l_urls),
        "held_out_metrics": {k: meta[k] for k in ["acc", "prec", "rec", "fpr", "f1", "auc"] if k in meta},
        "fresh_metrics_default_0_50": m_default,
        "fresh_metrics_tuned": m_tuned
    }
    rep_path = REPORTS_DIR / "fresh_data_evaluation.json"
    with open(rep_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n[+] Detailed evaluation report saved to: {rep_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()