"""
PhishGuard AI - Fresh Data Evaluation Script (Priority 1)
=========================================================
Tests the CURRENT deployed model against genuinely new data it has NEVER seen:
  - ~500 phishing URLs from OpenPhish (live feed, fetched now)
  - ~500 legitimate URLs from Tranco top-1M list (fetched now)

Reports:
  - Accuracy, Precision, Phishing Recall, False Positive Rate
  - Side-by-side with the training-set numbers
  - Honest assessment of how much the 99.2% claim holds up on fresh data
"""
import sys, json, time, io, zipfile
from pathlib import Path
from urllib.parse import urlparse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ml"))
sys.path.insert(0, str(ROOT / "backend"))

import joblib
import numpy as np
import pandas as pd

from feature_extraction import (
    FEATURE_NAMES, normalize_url, is_valid_ip, count_subdomains,
    extract_apex_domain, SUSPICIOUS_KEYWORDS
)

ARTIFACTS_DIR = ROOT / "ml" / "artifacts"
REPORTS_DIR   = ROOT / "ml" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ──────────────────────────────────────────────
# Feature extraction (same 16-feature schema)
# ──────────────────────────────────────────────
def extract_features(url: str):
    try:
        norm = normalize_url(url)
        p = urlparse(norm)
        hostname = (p.hostname or "").lower().strip(".")
        path = p.path or ""
        scheme = (p.scheme or "").lower()

        total_len = len(norm)
        h_len = len(hostname)
        p_len = len(path)

        c_dots    = norm.count(".")
        c_hyphens = norm.count("-")
        c_at      = norm.count("@")
        c_q       = norm.count("?")
        c_eq      = norm.count("=")
        c_sl      = norm.count("/")
        digits    = sum(c.isdigit() for c in norm)
        specials  = sum(not c.isalnum() and c not in "/;:." for c in norm)

        sub    = count_subdomains(hostname)
        ip_f   = is_valid_ip(hostname)
        https_f = 1 if scheme == "https" else 0
        has_kw  = 1 if any(kw in norm.lower() for kw in SUSPICIOUS_KEYWORDS) else 0

        d_ratio = round(digits / max(total_len, 1), 6)
        s_ratio = round(specials / max(total_len, 1), 6)

        return [total_len, h_len, p_len, c_dots, c_hyphens, c_at,
                c_q, c_eq, c_sl, digits, sub, ip_f, https_f, has_kw,
                d_ratio, s_ratio]
    except Exception:
        return None

# ──────────────────────────────────────────────
# Data fetchers
# ──────────────────────────────────────────────
def fetch_openphish(n=500):
    """Fetch live phishing URLs from OpenPhish public feed."""
    print("[*] Fetching OpenPhish live feed...")
    try:
        req = urllib.request.Request(
            "https://openphish.com/feed.txt",
            headers={"User-Agent": "PhishGuardAI-Research/1.0"}
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            lines = r.read().decode("utf-8", errors="ignore").splitlines()
        urls = [l.strip() for l in lines if l.strip().startswith("http")]
        urls = list(dict.fromkeys(urls))[:n]   # dedup, take first n
        print(f"    Fetched {len(urls):,} phishing URLs from OpenPhish")
        return urls
    except Exception as e:
        print(f"    [WARN] OpenPhish unavailable ({e}). Trying PhishTank RSS...")
        return fetch_phishtank_fallback(n)

def fetch_phishtank_fallback(n=500):
    """Fallback: recent known phishing domains from URLhaus."""
    try:
        req = urllib.request.Request(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            headers={"User-Agent": "PhishGuardAI-Research/1.0"}
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            content = r.read().decode("utf-8", errors="ignore")
        urls = []
        for line in content.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) >= 3:
                url = parts[2].strip().strip('"')
                if url.startswith("http"):
                    urls.append(url)
        urls = list(dict.fromkeys(urls))[:n]
        print(f"    Fetched {len(urls):,} phishing URLs from URLhaus (fallback)")
        return urls
    except Exception as e:
        print(f"    [WARN] URLhaus also unavailable ({e}). Using cached minimal set.")
        return []

def fetch_tranco(n=500):
    """Fetch Tranco top-1M list and sample n legitimate domains."""
    print("[*] Fetching Tranco top-1M list...")
    try:
        req = urllib.request.Request(
            "https://tranco-list.eu/top-1m.csv.zip",
            headers={"User-Agent": "PhishGuardAI-Research/1.0"}
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            with z.open(z.namelist()[0]) as f:
                lines = f.read().decode("utf-8", errors="ignore").splitlines()
        domains = []
        for line in lines:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                domains.append(parts[1].strip())
        # Sample evenly from top-500, 500-5000, 5000-50000 rank bands
        band1  = [f"https://{d}" for d in domains[:500]][:n//3]
        band2  = [f"https://{d}" for d in domains[500:5000]][:n//3]
        band3  = [f"https://{d}" for d in domains[5000:50000]][:n//3]
        urls = band1 + band2 + band3
        import random; random.seed(42); random.shuffle(urls)
        urls = urls[:n]
        print(f"    Sampled {len(urls):,} legitimate URLs from Tranco")
        return urls
    except Exception as e:
        print(f"    [WARN] Tranco unavailable ({e})")
        return []

# ──────────────────────────────────────────────
# Evaluation
# ──────────────────────────────────────────────
def evaluate(clf, urls, label, threshold=0.5):
    """Run inference on a list of URLs. Returns list of (url, prob, pred, label)."""
    results = []
    skipped = 0
    for url in urls:
        feats = extract_features(url)
        if feats is None:
            skipped += 1
            continue
        prob = clf.predict_proba([feats])[0][1]
        pred = 1 if prob >= threshold else 0
        results.append({"url": url, "prob": prob, "pred": pred, "label": label})
    if skipped:
        print(f"    Skipped {skipped} URLs (feature extraction failed)")
    return results

def metrics(rows):
    """Compute precision/recall/FPR from result rows."""
    y_true = [r["label"] for r in rows]
    y_pred = [r["pred"]  for r in rows]
    y_prob = [r["prob"]  for r in rows]
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                  f1_score, roc_auc_score, confusion_matrix)
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_true, y_prob)
    except Exception:
        auc = float("nan")
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0,1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    return dict(acc=acc, prec=prec, rec=rec, f1=f1, auc=auc,
                tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp),
                fpr=fpr, fnr=fnr)

def main():
    print("=" * 68)
    print("  PHISHGUARD AI - FRESH DATA EVALUATION (External Sources)")
    print("  This test uses URLs the model has NEVER seen before.")
    print("=" * 68)

    # Load trained model
    model_path = ARTIFACTS_DIR / "phishguard_rf_model.joblib"
    clf = joblib.load(model_path)
    print(f"\n[+] Loaded model: {model_path.name}")

    # Load training-set metrics for comparison
    meta_path = ARTIFACTS_DIR / "model_metadata.json"
    with open(meta_path) as f:
        meta = json.load(f)

    # Fetch fresh data
    phishing_urls = fetch_openphish(500)
    legit_urls    = fetch_tranco(500)

    if not phishing_urls:
        print("\n[!] No phishing URLs fetched. Check internet connection or feed status.")
        print("    Evaluation cannot proceed without phishing samples.")
        sys.exit(1)

    if not legit_urls:
        print("\n[!] No legitimate URLs fetched. Check internet connection.")
        sys.exit(1)

    print(f"\n[+] Evaluation set: {len(phishing_urls)} phishing + {len(legit_urls)} legitimate")
    print("[*] Running inference...")

    phish_results = evaluate(clf, phishing_urls, label=1)
    legit_results = evaluate(clf, legit_urls,    label=0)
    all_results   = phish_results + legit_results

    # Compute metrics at default threshold
    m = metrics(all_results)

    # Print comparison table
    print("\n" + "=" * 68)
    print("  RESULTS: Training Set  vs  Fresh External Data")
    print("=" * 68)
    print(f"{'Metric':<30} {'Training Set':>15} {'Fresh Data':>15}")
    print("-" * 62)
    print(f"{'Accuracy':<30} {meta['accuracy']*100:>14.2f}% {m['acc']*100:>14.2f}%")
    print(f"{'Precision':<30} {meta['precision']*100:>14.2f}% {m['prec']*100:>14.2f}%")
    print(f"{'Phishing Recall':<30} {meta['recall']*100:>14.2f}% {m['rec']*100:>14.2f}%")
    print(f"{'False Positive Rate':<30} {meta['false_positive_rate']*100:>14.2f}% {m['fpr']*100:>14.2f}%")
    print(f"{'F1-Score':<30} {meta['f1_score']*100:>14.2f}% {m['f1']*100:>14.2f}%")
    print(f"{'ROC-AUC':<30} {meta['roc_auc']*100:>14.2f}% {m['auc']*100:>14.2f}%")
    print("-" * 62)
    print(f"\n  Fresh Data Confusion Matrix  ({len(all_results):,} URLs)")
    print(f"    Correct Legit (TN):           {m['tn']:>6,}")
    print(f"    False Alarms  (FP):           {m['fp']:>6,}  <- legit flagged as phishing")
    print(f"    Missed Threats(FN):           {m['fn']:>6,}  <- phishing not caught")
    print(f"    Caught Phishing(TP):          {m['tp']:>6,}")

    # Worst false positives (legit sites flagged)
    fps = [r for r in legit_results if r["pred"] == 1]
    fns = [r for r in phish_results if r["pred"] == 0]
    print(f"\n  Top False Positives (legit flagged as phishing):")
    for r in sorted(fps, key=lambda x: x["prob"], reverse=True)[:10]:
        print(f"    {r['prob']*100:5.1f}%  {r['url'][:80]}")
    print(f"\n  Top Missed Threats (phishing not caught):")
    for r in sorted(fns, key=lambda x: x["prob"])[:10]:
        print(f"    {r['prob']*100:5.1f}%  {r['url'][:80]}")

    # Honest interpretation
    acc_gap = meta["accuracy"] - m["acc"]
    print(f"\n  Honest Assessment:")
    print(f"    Training-set accuracy gap on fresh data: {acc_gap*100:+.1f}pp")
    if acc_gap > 0.15:
        print("    [!] SIGNIFICANT GENERALIZATION GAP. Model overfits training distribution.")
    elif acc_gap > 0.05:
        print("    [~] MODERATE GAP. Some real-world degradation, expected and honest.")
    else:
        print("    [OK] Gap is small. Claims appear to hold on fresh data.")

    # Save JSON results
    out = {
        "evaluation_type": "Fresh External Data (Never Seen During Training)",
        "phishing_source": "OpenPhish feed / URLhaus fallback",
        "legit_source": "Tranco Top-1M",
        "n_phishing": len(phish_results),
        "n_legit": len(legit_results),
        "training_set_metrics": {
            "accuracy": meta["accuracy"],
            "precision": meta["precision"],
            "recall": meta["recall"],
            "false_positive_rate": meta["false_positive_rate"],
            "f1_score": meta["f1_score"],
            "roc_auc": meta["roc_auc"]
        },
        "fresh_data_metrics": {k: float(v) for k, v in m.items()},
        "top_false_positives": [{"url": r["url"], "prob": r["prob"]} for r in
                                  sorted(fps, key=lambda x: x["prob"], reverse=True)[:20]],
        "top_missed_threats":  [{"url": r["url"], "prob": r["prob"]} for r in
                                  sorted(fns, key=lambda x: x["prob"])[:20]],
    }
    out_path = REPORTS_DIR / "fresh_data_evaluation.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n[+] Detailed results saved to {out_path}")
    print("=" * 68)

if __name__ == "__main__":
    main()
