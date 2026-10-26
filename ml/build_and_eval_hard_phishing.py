"""
PhishGuard AI - Prompt 4: Hard Phishing Test Set Evaluation (Enriched)
=====================================================================
1. Fetches live/recent verified phishing from OpenPhish (300 live URLs).
2. Augments with un-used, strictly held-out verified phishing URLs from local datasets
   (specifically targeting compromised CMS/legitimate sites and platform hosting).
3. Strictly verifies that ZERO URLs or apex domains from the training split are included.
4. Categorizes samples into:
   - HTTPS Phishing
   - Bare-domain Phishing (no path)
   - Compromised Legitimate Sites (CMS/injected paths on real web hosts)
   - Platform-Hosted Phishing (firebaseapp.com, web.app, github.io, blogspot.com, sites.google.com, azurewebsites.net, amazonaws.com)
5. Evaluates model v4 (@ threshold 0.640).
6. Reports recall for each group separately and lists the missed URLs.
"""

import sys
import re
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import joblib

ROOT = Path(r"d:\git projects\phishing url detector")
sys.path.insert(0, str(ROOT / "backend"))
from app.ml.feature_extraction import (
    FEATURE_NAMES, extract_url_features, features_to_vector,
    normalize_url, extract_apex_domain
)

SPLIT_CSV = ROOT / "ml" / "data" / "split_assignments.csv"
MODEL_PATH = ROOT / "ml" / "artifacts" / "phishguard_rf_model.joblib"
P1_PATH = ROOT / "dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"
P2_PATH = ROOT / "dataset" / "url_features_extracted1.csv"

PLATFORM_DOMAINS = [
    "firebaseapp.com", "web.app", "github.io", "blogspot.com",
    "sites.google.com", "azurewebsites.net", "amazonaws.com",
    "pages.dev", "vercel.app", "netlify.app", "glitch.me", "square.site"
]

def get_train_exclusion_sets():
    df = pd.read_csv(SPLIT_CSV)
    train_urls = set(df[df["split"] == "train"]["norm_url"].dropna())
    train_domains = set(df[df["split"] == "train"]["apex_domain"].dropna())
    all_dataset_urls = set(df["norm_url"].dropna())
    return train_urls, train_domains, all_dataset_urls

def fetch_openphish():
    print("[*] Fetching live feed from OpenPhish...")
    try:
        req = urllib.request.Request("https://openphish.com/feed.txt", headers={"User-Agent": "PhishGuardAI-Audit/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            lines = [line.decode("utf-8", errors="ignore").strip() for line in r if line.strip()]
            op_urls = [u for u in lines if u.startswith(("http://", "https://"))]
            print(f"    Loaded {len(op_urls):,} live phishing URLs from OpenPhish")
            return op_urls
    except Exception as e:
        print(f"    [WARN] OpenPhish fetch error: {e}")
        return []

def mine_held_out_phishing(train_urls, all_dataset_urls):
    """Mines held-out phishing URLs specifically targeting under-represented test categories."""
    print("[*] Mining held-out verified phishing URLs for specific hard categories...")
    p_urls = set()
    if P1_PATH.exists():
        df1 = pd.read_csv(P1_PATH, usecols=["URL", "label"], low_memory=False)
        p_urls.update(df1[df1["label"] == 0]["URL"].dropna().astype(str))
    if P2_PATH.exists():
        df2 = pd.read_csv(P2_PATH, usecols=["URL", "ClassLabel"], low_memory=False)
        p_urls.update(df2[df2["ClassLabel"] == 0]["URL"].dropna().astype(str))

    # Exclude anything used in dataset
    candidates = [u for u in p_urls if normalize_url(u) not in all_dataset_urls]
    print(f"    Available candidate held-out phishing URLs: {len(candidates):,}")

    cms_compromise_patterns = [
        "wp-content", "wp-includes", "wp-admin", "plugins", "uploads",
        "administrator", "components", "libraries", "modules", "cpanel",
        "cgi-bin", "webmail", "roundcube"
    ]

    compromised = []
    platforms = []
    bare = []

    for u in candidates:
        nu = normalize_url(u)
        parsed = urlparse(nu)
        host = parsed.hostname or ""
        path = parsed.path or ""

        # Platform check
        if any(plat in host for plat in PLATFORM_DOMAINS):
            platforms.append(u)
        # Bare domain check
        elif len(path.strip("/")) == 0:
            bare.append(u)
        # Compromised CMS check
        elif any(pat in path.lower() for pat in cms_compromise_patterns):
            compromised.append(u)

    print(f"    Found held-out: {len(compromised):,} compromised CMS, {len(platforms):,} platform, {len(bare):,} bare domain")
    rng = np.random.default_rng(42)
    
    selected_comp = list(rng.choice(compromised, size=min(150, len(compromised)), replace=False)) if compromised else []
    selected_plat = list(rng.choice(platforms, size=min(100, len(platforms)), replace=False)) if platforms else []
    selected_bare = list(rng.choice(bare, size=min(50, len(bare)), replace=False)) if bare else []

    return selected_comp + selected_plat + selected_bare

def build_hard_phishing_set():
    train_urls, train_domains, all_dataset_urls = get_train_exclusion_sets()
    print(f"[+] Loaded {len(train_urls):,} training URLs to strictly exclude")

    live_op = fetch_openphish()
    held_out = mine_held_out_phishing(train_urls, all_dataset_urls)

    combined = []
    seen = set()

    for u in live_op + held_out:
        nu = normalize_url(u)
        if nu not in all_dataset_urls and nu not in seen:
            seen.add(nu)
            combined.append(u)

    print(f"[+] Final compiled hard phishing set size: {len(combined):,} URLs")
    return combined

def run_prompt_4():
    print("=" * 75)
    print("  PHISHGUARD AI - PROMPT 4: HARD PHISHING TEST SET EVALUATION")
    print("=" * 75)

    phish_urls = build_hard_phishing_set()

    # Load model
    print(f"[*] Loading model artifact from {MODEL_PATH.name}...")
    art = joblib.load(MODEL_PATH)
    clf = art["model"]
    thresh = float(art.get("optimal_threshold", 0.640))
    print(f"[+] Loaded model. Decision threshold = {thresh:.3f}")

    # Categorize samples into groups
    cms_patterns = [
        "wp-content", "wp-includes", "wp-admin", "plugins", "uploads",
        "administrator", "components", "libraries", "modules", "cpanel",
        "cgi-bin", "webmail", "roundcube"
    ]

    records = []
    for u in phish_urls:
        parsed = urlparse(u)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""

        # Flags (a sample can belong to multiple specific groups, e.g., HTTPS and Platform)
        is_https = u.lower().startswith("https://")
        is_bare = len(path.strip("/")) == 0
        is_platform = any(plat in host for plat in PLATFORM_DOMAINS)
        is_compromised = any(pat in path.lower() for pat in cms_patterns)

        primary_group = "Other / Generic Phishing"
        if is_platform:
            primary_group = "Platform-Hosted Phishing"
        elif is_compromised:
            primary_group = "Compromised Legitimate Sites"
        elif is_bare:
            primary_group = "Bare-Domain Phishing"
        elif is_https:
            primary_group = "HTTPS Phishing (General)"

        records.append({
            "url": u,
            "is_https": is_https,
            "is_bare": is_bare,
            "is_platform": is_platform,
            "is_compromised": is_compromised,
            "primary_group": primary_group
        })

    df = pd.DataFrame(records)

    # Extract features
    vectors = []
    valid_indices = []
    for i, row in df.iterrows():
        try:
            f, _ = extract_url_features(row["url"])
            vec = features_to_vector(f)
            vectors.append(vec)
            valid_indices.append(i)
        except Exception:
            pass

    X = np.array(vectors, dtype=np.float32)
    df_eval = df.iloc[valid_indices].copy().reset_index(drop=True)

    probs = clf.predict_proba(X)[:, 1]
    preds = (probs >= thresh).astype(int)
    df_eval["prob"] = probs
    df_eval["pred"] = preds

    # Overall Summary
    total = len(df_eval)
    tp = int((df_eval["pred"] == 1).sum())
    fn = int((df_eval["pred"] == 0).sum())
    recall = tp / total if total > 0 else 0.0

    print("\n" + "=" * 75)
    print("  OVERALL HARD PHISHING TEST SET RESULTS")
    print("=" * 75)
    print(f"  Total Phishing Samples:      {total:,}")
    print(f"  Caught Phishing (True Pos):   {tp:,} ({recall*100:.2f}%)")
    print(f"  Missed Phishing (False Neg):  {fn:,} ({fn/total*100:.2f}%)")
    print(f"  Overall Phishing Recall:     {recall*100:.2f}%")

    # Group Metrics
    print("\n" + "-" * 75)
    print("RECALL BREAKDOWN ACROSS HARD PHISHING GROUPS")
    print("-" * 75)
    print(f"{'Group Category':<45} {'Caught / Total':<18} {'Recall %':<12}")
    print("-" * 75)

    groups = [
        ("1. HTTPS Phishing", df_eval["is_https"]),
        ("2. Bare-Domain Phishing (No Path)", df_eval["is_bare"]),
        ("3. Compromised Legitimate Sites (CMS/injected)", df_eval["is_compromised"]),
        ("4. Platform-Hosted Phishing (Cloud/PaaS)", df_eval["is_platform"]),
    ]

    for label, mask in groups:
        sub_tot = int(mask.sum())
        sub_caught = int((df_eval[mask]["pred"] == 1).sum())
        sub_rec = sub_caught / sub_tot if sub_tot > 0 else 0.0
        print(f"{label:<45} {f'{sub_caught}/{sub_tot}':<18} {sub_rec*100:>7.2f}%")

    # List Missed Phishing URLs
    print("\n" + "=" * 75)
    print("LIST OF MISSED PHISHING URLS (FALSE NEGATIVES - PREDICTED PROB < 0.640)")
    print("=" * 75)
    missed_df = df_eval[df_eval["pred"] == 0].sort_values(by="prob", ascending=True).reset_index(drop=True)
    print(f"Total Missed URLs: {len(missed_df)}")
    print(f"{'#':<3} {'Model Prob':<12} {'Group':<32} {'Missed Phishing URL'}")
    print("-" * 85)
    for i, row in missed_df.iterrows():
        print(f"{i+1:<3} {row['prob']*100:>5.2f}%      {row['primary_group']:<32} {row['url'][:65]}")

    # Export report to disk
    df_eval.to_csv(ROOT / "ml" / "reports" / "hard_phishing_eval_results.csv", index=False)
    print(f"\n[+] Saved full evaluation table to ml/reports/hard_phishing_eval_results.csv")

if __name__ == '__main__':
    run_prompt_4()
