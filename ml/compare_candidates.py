"""
Phase 3: Detailed comparison of RandomForest vs HistGradientBoosting
on the exact same benchmark sets.
"""
import sys
import math
import json
from pathlib import Path
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

ROOT = Path(r"d:\git projects\phishing url detector")
sys.path.insert(0, str(ROOT / "backend"))

try:
    from backend.app.ml.feature_extraction_v2 import (
        FEATURE_NAMES, normalize_url, extract_apex_domain,
        get_tld_risk_score, check_brand_lookalike, check_brand_in_subdomain,
        has_punycode, hostname_entropy, is_valid_ip, is_hsts_enforced_domain,
        count_subdomains, DISALLOWED_SHARED_PLATFORMS, SUSPICIOUS_KEYWORDS
    )
except ImportError:
    from app.ml.feature_extraction_v2 import (
        FEATURE_NAMES, normalize_url, extract_apex_domain,
        get_tld_risk_score, check_brand_lookalike, check_brand_in_subdomain,
        has_punycode, hostname_entropy, is_valid_ip, is_hsts_enforced_domain,
        count_subdomains, DISALLOWED_SHARED_PLATFORMS, SUSPICIOUS_KEYWORDS
    )

DATA_PATH = ROOT / "ml" / "data" / "dataset_v4_curated.csv"
LONGTAIL_CSV = ROOT / "ml" / "reports" / "longtail_legit_eval_results.csv"
HARD_PHISH_CSV = ROOT / "ml" / "reports" / "hard_phishing_eval_results.csv"

def ci_95(p, n):
    se = math.sqrt(p * (1 - p) / max(n, 1))
    return max(0.0, p - 1.96 * se), min(1.0, p + 1.96 * se)

def extract_features_v5(raw_url: str):
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    scheme = (parsed.scheme or "").lower()

    url_length = len(normalized)
    hostname_length = len(hostname)
    path_length = len(path)
    count_dots = normalized.count(".")
    count_hyphens = normalized.count("-")
    count_at = normalized.count("@")
    count_question = normalized.count("?")
    count_equal = normalized.count("=")
    count_slash = normalized.count("/")
    digits = sum(c.isdigit() for c in normalized)
    specials = sum(not c.isalnum() and c not in "/;:." for c in normalized)
    subdomains = count_subdomains(hostname)
    ip_flag = is_valid_ip(hostname)
    hsts_enforced = is_hsts_enforced_domain(hostname)
    https_flag = 1 if (scheme == "https" or hsts_enforced) else 0

    url_lower = normalized.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

    keyword_flag = 0
    if found_keywords:
        has_risk_context = (
            get_tld_risk_score(hostname) >= 0.5
            or check_brand_lookalike(hostname)
            or check_brand_in_subdomain(hostname)
            or ip_flag
            or has_punycode(hostname)
            or any(plat in hostname for plat in DISALLOWED_SHARED_PLATFORMS)
            or hostname_entropy(hostname) >= 3.6
            or scheme == "http"
            or hostname.count("-") >= 2
            or hostname.count(".") >= 3
        )
        keyword_flag = 1 if has_risk_context else 0

    digit_ratio = round(digits / max(url_length, 1), 6)
    special_char_ratio = round(specials / max(url_length, 1), 6)

    return [
        float(url_length), float(hostname_length), float(path_length),
        float(count_dots), float(count_hyphens), float(count_at),
        float(count_question), float(count_equal), float(count_slash),
        float(digits), float(subdomains), float(ip_flag),
        float(https_flag), float(keyword_flag), float(digit_ratio),
        float(special_char_ratio)
    ]

try:
    from ml.train_v5_candidate import HARD_NEGATIVE_SSO
except ImportError:
    from train_v5_candidate import HARD_NEGATIVE_SSO

def main():
    df = pd.read_csv(DATA_PATH)
    hard_neg_df = pd.DataFrame({"url": HARD_NEGATIVE_SSO, "label": 0})
    df_combined = pd.concat([df, hard_neg_df], ignore_index=True).drop_duplicates(subset=["url"]).reset_index(drop=True)

    vectors = []
    apex_domains = []
    for u in df_combined["url"]:
        nu = normalize_url(u)
        host = urlparse(nu).hostname or ""
        apex_domains.append(extract_apex_domain(host))
        vectors.append(extract_features_v5(nu))

    X = np.array(vectors, dtype=np.float32)
    y = df_combined["label"].values.astype(int)

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

    df_long = pd.read_csv(LONGTAIL_CSV)
    X_long = np.array([extract_features_v5(u) for u in df_long["url"]], dtype=np.float32)
    sso_mask = df_long["category"] == "Authentic Login/Account/Payment Portal"

    df_hard = pd.read_csv(HARD_PHISH_CSV)
    X_hard = np.array([extract_features_v5(u) for u in df_hard["url"]], dtype=np.float32)

    candidates = {
        "RandomForest (v5-RF)": RandomForestClassifier(
            n_estimators=200, min_samples_leaf=3, class_weight="balanced", n_jobs=-1, random_state=42
        ),
        "HistGradientBoosting (v5-HGB)": HistGradientBoostingClassifier(
            max_iter=150, min_samples_leaf=20, class_weight="balanced", random_state=42
        )
    }

    results = {}
    for name, base in candidates.items():
        print(f"\nTraining and calibrating {name}...")
        cal = CalibratedClassifierCV(base, method="isotonic", cv=3)
        cal.fit(X_train, y_train)

        # Select threshold on validation only (target FPR <= 2%)
        val_probs = cal.predict_proba(X_val)[:, 1]
        best_t = 0.50
        best_rec = 0.0
        best_fpr = 1.0
        for t in np.arange(0.30, 0.90, 0.02):
            preds = (val_probs >= t).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_val, preds, labels=[0, 1]).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            if fpr <= 0.02 and rec > best_rec:
                best_rec = rec
                best_t = float(t)
                best_fpr = fpr

        # Evaluate on test, longtail, sso, hard phish
        test_probs = cal.predict_proba(X_test)[:, 1]
        test_preds = (test_probs >= best_t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, test_preds, labels=[0, 1]).ravel()
        t_rec = tp / (tp + fn)
        t_fpr = fp / (fp + tn)

        long_preds = (cal.predict_proba(X_long)[:, 1] >= best_t).astype(int)
        long_fpr = np.mean(long_preds == 1)
        sso_fpr = np.mean(long_preds[sso_mask] == 1)

        hard_preds = (cal.predict_proba(X_hard)[:, 1] >= best_t).astype(int)
        hard_rec = np.mean(hard_preds == 1)

        results[name] = {
            "thresh": best_t,
            "test_rec": t_rec,
            "test_fpr": t_fpr,
            "longtail_fpr": long_fpr,
            "longtail_fp": int(np.sum(long_preds == 1)),
            "sso_fpr": sso_fpr,
            "sso_fp": int(np.sum(long_preds[sso_mask] == 1)),
            "hard_rec": hard_rec,
            "hard_tp": int(np.sum(hard_preds == 1)),
            "cal": cal,
            "base": base
        }

    rf_res = results["RandomForest (v5-RF)"]
    hgb_res = results["HistGradientBoosting (v5-HGB)"]

    rf_trec = f"{rf_res['test_rec']*100:.2f}%"
    hgb_trec = f"{hgb_res['test_rec']*100:.2f}%"
    rf_tfpr = f"{rf_res['test_fpr']*100:.2f}%"
    hgb_tfpr = f"{hgb_res['test_fpr']*100:.2f}%"
    rf_lfpr = f"{rf_res['longtail_fpr']*100:.2f}% ({rf_res['longtail_fp']})"
    hgb_lfpr = f"{hgb_res['longtail_fpr']*100:.2f}% ({hgb_res['longtail_fp']})"
    rf_sso = f"{rf_res['sso_fpr']*100:.2f}% ({rf_res['sso_fp']}/30)"
    hgb_sso = f"{hgb_res['sso_fpr']*100:.2f}% ({hgb_res['sso_fp']}/30)"
    rf_hrec = f"{rf_res['hard_rec']*100:.2f}% ({rf_res['hard_tp']})"
    hgb_hrec = f"{hgb_res['hard_rec']*100:.2f}% ({hgb_res['hard_tp']})"

    print("\n" + "=" * 90)
    print(f"{'Metric':<25} {'Baseline v4.1.0':<18} {'v5-RF':<18} {'v5-HGB':<18}")
    print("-" * 90)
    print(f"{'Threshold':<25} {'0.640':<18} {rf_res['thresh']:<18.3f} {hgb_res['thresh']:<18.3f}")
    print(f"{'Held-out Test Rec':<25} {'95.23%':<18} {rf_trec:<18} {hgb_trec:<18}")
    print(f"{'Held-out Test FPR':<25} {'1.96%':<18} {rf_tfpr:<18} {hgb_tfpr:<18}")
    print(f"{'Long-tail Legit FPR':<25} {'13.06% (141)':<18} {rf_lfpr:<18} {hgb_lfpr:<18}")
    print(f"{'Authentic SSO FPR':<25} {'46.67% (14/30)':<18} {rf_sso:<18} {hgb_sso:<18}")
    print(f"{'Hard Phishing Rec':<25} {'96.67% (580)':<18} {rf_hrec:<18} {hgb_hrec:<18}")
    print("=" * 90)

    # Save to JSON
    with open(ROOT / "ml" / "reports" / "phase3_detailed_comparison.json", "w") as f:
        exportable = {
            k: {kk: (float(vv) if isinstance(vv, (float, np.floating)) else vv) for kk, vv in v.items() if kk not in ("cal", "base")}
            for k, v in results.items()
        }
        json.dump(exportable, f, indent=2)

if __name__ == "__main__":
    main()
