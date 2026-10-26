"""
PhishGuard AI - v4 Pipeline Leakage & Overlap Audit
===================================================
"""
import sys
import json
from pathlib import Path
from urllib.parse import urlparse
import pandas as pd
import numpy as np

ROOT = Path(r"d:\git projects\phishing url detector")
sys.path.insert(0, str(ROOT / "backend"))
from app.ml.feature_extraction import extract_apex_domain, normalize_url
from sklearn.model_selection import GroupShuffleSplit

DATA_PATH = ROOT / "ml" / "data" / "dataset_v4_curated.csv"
TRANCO_CACHE = ROOT / "ml" / "data" / "tranco_top50k.txt"
FRESH_EVAL_JSON = ROOT / "ml" / "reports" / "fresh_data_evaluation.json"
P1_PATH = ROOT / "dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"
P2_PATH = ROOT / "dataset" / "url_features_extracted1.csv"

def run_audit():
    print("=" * 75)
    print("  PHISHGUARD AI - AUDIT REPORT: DATA LEAKAGE & OVERLAP IN v4 PIPELINE")
    print("=" * 75)

    df = pd.read_csv(DATA_PATH)
    print(f"\n[1] Total samples in dataset_v4_curated.csv: {len(df):,}")
    print(f"    Legitimate: {(df['label'] == 0).sum():,} | Phishing: {(df['label'] == 1).sum():,}")

    # Extract apex domains
    apex_list = []
    norm_urls = []
    for u in df["url"]:
        nu = normalize_url(u)
        norm_urls.append(nu)
        host = urlparse(nu).hostname or ""
        apex_list.append(extract_apex_domain(host))
    df["norm_url"] = norm_urls
    df["apex_domain"] = apex_list

    # Reproduce GroupShuffleSplit from train_curated_model.py
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, test_idx = next(gss.split(df, df["label"], groups=df["apex_domain"]))
    
    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()

    print(f"\n[2] Training Split (80%): {len(train_df):,} samples ({len(set(train_df['apex_domain'])):,} unique domains)")
    print(f"    - Legit: {(train_df['label'] == 0).sum():,} | Phish: {(train_df['label'] == 1).sum():,}")
    print(f"    Held-out Test Split (20%): {len(test_df):,} samples ({len(set(test_df['apex_domain'])):,} unique domains)")
    print(f"    - Legit: {(test_df['label'] == 0).sum():,} | Phish: {(test_df['label'] == 1).sum():,}")

    # --- Part 1: Provenance of Phishing URLs ---
    print("\n" + "-" * 75)
    print("PART 1: PHISHING URL PROVENANCE")
    print("-" * 75)
    phish_in_train = train_df[train_df["label"] == 1]["url"].tolist()

    p1_urls = set()
    p2_urls = set()
    if P1_PATH.exists():
        df_p1 = pd.read_csv(P1_PATH, usecols=["URL", "label"], low_memory=False)
        p1_urls = set(df_p1[df_p1["label"] == 0]["URL"].dropna().astype(str))
    if P2_PATH.exists():
        df_p2 = pd.read_csv(P2_PATH, usecols=["URL", "ClassLabel"], low_memory=False)
        p2_urls = set(df_p2[df_p2["ClassLabel"] == 0]["URL"].dropna().astype(str))

    from_p1 = sum(1 for u in phish_in_train if u in p1_urls)
    from_p2 = sum(1 for u in phish_in_train if u in p2_urls and u not in p1_urls)
    from_both = sum(1 for u in phish_in_train if u in p1_urls and u in p2_urls)

    print(f"Phishing URLs in Training Split: {len(phish_in_train):,}")
    print(f"  * From PhiUSIIL (UCI ML Repository, published 2024, collected ~2021-2023): {from_p1:,} ({from_p1/len(phish_in_train)*100:.1f}%)")
    print(f"  * From url_features_extracted1 (Kaggle/Research, collected ~2020): {from_p2:,} ({from_p2/len(phish_in_train)*100:.1f}%)")
    print(f"  * Overlapping in both raw source files: {from_both:,}")
    print(f"  * Real-time / Live Feed Content: 0% (All historical archival feeds).")

    # --- Part 2: Overlap Analysis ---
    print("\n" + "-" * 75)
    print("PART 2: OVERLAP BETWEEN TRAINING SET AND EVALUATION SETS")
    print("-" * 75)

    train_urls_set = set(train_df["norm_url"])
    train_apex_set = set(train_df["apex_domain"])

    # (a) Held-out Test Set
    test_urls_set = set(test_df["norm_url"])
    test_apex_set = set(test_df["apex_domain"])
    shared_test_urls = train_urls_set & test_urls_set
    shared_test_apex = train_apex_set & test_apex_set

    # (b) Fresh Tranco Set from evaluate_fresh_data.py
    tranco_domains = [line.strip() for line in open(TRANCO_CACHE, encoding="utf-8") if line.strip()]
    fresh_tranco_doms = tranco_domains[5000:15000]
    import random
    random.seed(999)
    random.shuffle(fresh_tranco_doms)
    fresh_tranco_urls = [normalize_url(f"https://{d}") for d in fresh_tranco_doms[:500]]
    fresh_tranco_apex = [extract_apex_domain(urlparse(u).hostname or "") for u in fresh_tranco_urls]

    shared_tranco_urls = train_urls_set & set(fresh_tranco_urls)
    shared_tranco_apex = train_apex_set & set(fresh_tranco_apex)

    # (c) OpenPhish Fresh Set
    shared_openphish_urls = set()
    shared_openphish_apex = set()
    try:
        import urllib.request
        req = urllib.request.Request("https://openphish.com/feed.txt", headers={"User-Agent": "Audit/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            live_op = [line.decode("utf-8", errors="ignore").strip() for line in resp if line.strip()]
            live_op_norm = [normalize_url(u) for u in live_op[:300]]
            shared_openphish_urls = train_urls_set & set(live_op_norm)
            live_op_apex = set(extract_apex_domain(urlparse(u).hostname or "") for u in live_op_norm)
            shared_openphish_apex = train_apex_set & live_op_apex
    except Exception as e:
        print(f"Note: Live OpenPhish check: {e}")

    print(f"(a) Training Set vs Held-out Test Set:")
    print(f"    - Shared Exact URLs:     {len(shared_test_urls)}")
    print(f"    - Shared Apex Domains:   {len(shared_test_apex)}")
    print(f"    -> Status: Isolated on apex domain by GroupShuffleSplit.")

    print(f"\n(b) Training Set vs 500 'Fresh' Tranco Test Set:")
    print(f"    - Shared Exact URLs:     {len(shared_tranco_urls)} ({len(shared_tranco_urls)/500*100:.1f}%)")
    print(f"    - Shared Apex Domains:   {len(shared_tranco_apex)} ({len(shared_tranco_apex)/500*100:.1f}%)")
    print(f"    -> Status: SEVERE LEAKAGE. 500 'fresh' Tranco URLs were drawn from ranks 5k-15k, which was already consumed during training set creation.")

    print(f"\n(c) Training Set vs 300 OpenPhish Test Set:")
    print(f"    - Shared Exact URLs:     {len(shared_openphish_urls)}")
    print(f"    - Shared Apex Domains:   {len(shared_openphish_apex)}")
    if shared_openphish_apex:
        print(f"      Shared Apex Domains: {sorted(list(shared_openphish_apex))}")

    # --- Part 3: Smoke Test URLs Check ---
    print("\n" + "-" * 75)
    print("PART 3: SMOKE TEST URLS IN TRAINING DATA")
    print("-" * 75)
    smoke_urls = [
        "https://google.com",
        "https://github.com",
        "https://uni-hamburg.de",
        "https://3gppnetwork.org",
        "https://wikipedia.org",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://github.com/torvalds/linux",
        "http://secure-paypal-login-verify.update-account.xyz/signin",
        "http://192.168.1.1/login.php"
    ]
    for s in smoke_urls:
        ns = normalize_url(s)
        in_all = ns in set(df["norm_url"])
        in_train = ns in train_urls_set
        in_test = ns in test_urls_set
        host = urlparse(ns).hostname or ""
        apex = extract_apex_domain(host)
        dom_in_train = apex in train_apex_set
        dom_in_test = apex in test_apex_set
        print(f"  * {s:<60}")
        print(f"    In TRAIN: exact={in_train}, domain={dom_in_train} | In TEST: exact={in_test}, domain={dom_in_test}")

    # --- Part 4: Threshold Selection Split ---
    print("\n" + "-" * 75)
    print("PART 4: THRESHOLD SELECTION PROVENANCE")
    print("-" * 75)
    print("Code Location: train_curated_model.py line 62:")
    print("  `opt_thresh, opt_fpr, opt_rec = find_optimal_threshold(cal_clf, X_test, y_test, target_fpr=0.02)`")
    print("Audit Confirmation:")
    print("  YES, THE 0.640 THRESHOLD WAS CHOSEN DIRECTLY ON THE HELD-OUT TEST SET.")
    print("  No separate validation set was used. The test set was touched twice (threshold selection + evaluation).")

if __name__ == '__main__':
    run_audit()
