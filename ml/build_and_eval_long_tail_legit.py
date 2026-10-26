"""
PhishGuard AI - Prompt 3: Long-tail Legitimate Test Set
======================================================
1. Fetches Tranco domains from ranks 200,000 to 1,000,000.
2. Excludes any apex domain appearing in training/curated dataset.
3. Incorporates:
   - 500+ long-tail Tranco domains (ranks 200k - 1M)
   - Real login/account/payment pages (accounts.google.com, banks, universities, etc.)
   - Legitimate URLs containing "secure", "account", "update", "verify"
   - Small business, school, regional sites with hyphens or digits in hostname
4. Evaluates model v4 @ threshold 0.640.
5. Computes FPR with 95% Confidence Interval.
6. Lists the 30 most confidently wrong predictions.
"""

import sys
import io
import math
import zipfile
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

DATA_PATH = ROOT / "ml" / "data" / "dataset_v4_curated.csv"
MODEL_PATH = ROOT / "ml" / "artifacts" / "phishguard_rf_model.joblib"
LONG_TAIL_CACHE = ROOT / "ml" / "data" / "tranco_longtail_200k_1m.txt"

def get_training_domains():
    df = pd.read_csv(DATA_PATH)
    train_doms = set()
    for u in df["url"]:
        nu = normalize_url(u)
        host = urlparse(nu).hostname or ""
        train_doms.add(extract_apex_domain(host))
    return train_doms

def fetch_tranco_longtail(n_samples=600):
    cache_path = LONG_TAIL_CACHE
    if cache_path.exists():
        print(f"[*] Loading cached long-tail domains from {cache_path.name}...")
        with open(cache_path, "r", encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip()]
            return domains

    print("[*] Downloading Tranco Top-1M list for long-tail extraction (ranks 200k - 1M)...")
    req = urllib.request.Request(
        "https://tranco-list.eu/top-1m.csv.zip",
        headers={"User-Agent": "PhishGuardAI-Research/1.0"}
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()

    print("[*] Extracting domains from ranks 200,000 to 1,000,000...")
    longtail_pool = []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        with z.open(z.namelist()[0]) as f:
            for line_no, raw_line in enumerate(f, 1):
                if line_no < 200000:
                    continue
                if line_no > 1000000:
                    break
                decoded = raw_line.decode("utf-8", errors="ignore").strip()
                if "," in decoded:
                    _, dom = decoded.split(",", 1)
                    longtail_pool.append(dom.strip())

    print(f"[+] Total long-tail pool size: {len(longtail_pool):,} domains")
    # Save a subset of 5,000 for cache
    rng = np.random.default_rng(42)
    selected = rng.choice(longtail_pool, size=min(10000, len(longtail_pool)), replace=False).tolist()
    with open(cache_path, "w", encoding="utf-8") as f:
        f.write("\n".join(selected))
    return selected

def build_longtail_legit_set():
    train_doms = get_training_domains()
    print(f"[+] Loaded {len(train_doms):,} excluded training apex domains")

    raw_longtail = fetch_tranco_longtail()
    
    # Filter out any training domains
    filtered_longtail = [
        d for d in raw_longtail 
        if extract_apex_domain(d) not in train_doms
    ]
    print(f"[+] Filtered long-tail domains (excluding training): {len(filtered_longtail):,}")

    test_urls = []

    # Group A: 500+ general long-tail domains from ranks 200k-1M
    rng = np.random.default_rng(123)
    general_pool = [d for d in filtered_longtail if "-" not in d and not any(c.isdigit() for c in d)]
    rng.shuffle(general_pool)
    for d in general_pool[:550]:
        proto = "https" if rng.random() > 0.10 else "http"
        test_urls.append((f"{proto}://{d}", "Long-tail Tranco Rank 200k-1M"))

    # Group B: Real login/account/payment pages of known legitimate services
    # (Notice: some apex domains like google.com were in training, but specific authentic subdomains/paths test hard boundaries)
    authentic_portals = [
        "https://accounts.google.com/ServiceLogin",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://auth.berkeley.edu/cas/login",
        "https://my.harvard.edu/portal/login",
        "https://portal.chase.com/auth/login",
        "https://secure.bankofamerica.com/login/auth",
        "https://signin.aws.amazon.com/oauth",
        "https://id.apple.com/sign-in",
        "https://auth.atlassian.com/login",
        "https://login.salesforce.com/",
        "https://secure.chase.com/web/auth/dashboard",
        "https://www.paypal.com/signin",
        "https://identity.stanford.edu/idp/AuthnEngine",
        "https://login.live.com/login.srf",
        "https://account.box.com/login",
        "https://accounts.spotify.com/en/login",
        "https://secure.payu.in/",
        "https://login.uber.com/",
        "https://login.yahoo.com/account/create",
        "https://secure.stripe.com/",
        "https://auth.max.gov/cas/login",
        "https://login.oracle.com/mysso/signon.jsp",
        "https://account.adobe.com/",
        "https://identity.mit.edu/idp/profile/SAML2/Redirect/SSO",
        "https://secure.ing.de/app/login",
        "https://banking.anz.com/signon",
        "https://login.okta.com/",
        "https://account.docusign.com/",
        "https://auth.nih.gov/affiliate/login.asp",
        "https://signin.ebay.com/ws/eBayISAPI.dll?SignIn"
    ]
    for u in authentic_portals:
        test_urls.append((u, "Authentic Login/Account/Payment Portal"))

    # Group C: Long-tail domains containing keywords "secure", "account", "update", "verify"
    keyword_patterns = [
        ("secure", "https://{d}/secure/login"),
        ("account", "https://{d}/account/settings"),
        ("update", "https://{d}/update/preferences"),
        ("verify", "https://{d}/verify/email"),
        ("billing", "https://{d}/billing/invoices"),
        ("portal", "https://{d}/portal/dashboard")
    ]
    kw_domains = filtered_longtail[600:900]
    for i, d in enumerate(kw_domains):
        kw, template = keyword_patterns[i % len(keyword_patterns)]
        u = template.format(d=d)
        test_urls.append((u, f"Legitimate with Keyword ({kw})"))

    # Group D: Small business, school, regional sites with hyphens or digits
    hyphen_digit_pool = [
        d for d in filtered_longtail 
        if ("-" in d or any(c.isdigit() for c in d))
    ]
    rng.shuffle(hyphen_digit_pool)
    for d in hyphen_digit_pool[:200]:
        proto = "https" if rng.random() > 0.08 else "http"
        test_urls.append((f"{proto}://{d}", "Hyphen/Digit Regional/School/SMB"))

    # Deduplicate by URL
    seen = set()
    final_test = []
    for u, cat in test_urls:
        if u not in seen:
            seen.add(u)
            final_test.append((u, cat))

    print(f"[+] Total constructed long-tail legitimate evaluation set: {len(final_test):,} URLs")
    return final_test

def evaluate_longtail():
    print("=" * 75)
    print("  PHISHGUARD AI - PROMPT 3: LONG-TAIL LEGITIMATE EVALUATION")
    print("=" * 75)

    test_data = build_longtail_legit_set()

    # Load model
    print(f"[*] Loading model artifact from {MODEL_PATH.name}...")
    art = joblib.load(MODEL_PATH)
    clf = art["model"]
    thresh = float(art.get("optimal_threshold", 0.640))
    print(f"[+] Loaded model. Decision threshold = {thresh:.3f}")

    urls = [x[0] for x in test_data]
    categories = [x[1] for x in test_data]

    # Extract features
    vectors = []
    valid_indices = []
    for i, u in enumerate(urls):
        try:
            f, _ = extract_url_features(u)
            vec = features_to_vector(f)
            vectors.append(vec)
            valid_indices.append(i)
        except Exception:
            pass

    X = np.array(vectors, dtype=np.float32)
    urls = [urls[i] for i in valid_indices]
    categories = [categories[i] for i in valid_indices]

    # Model inference
    probs = clf.predict_proba(X)[:, 1]
    preds = (probs >= thresh).astype(int)

    n_total = len(urls)
    fp_count = int(np.sum(preds == 1))
    tn_count = int(np.sum(preds == 0))
    fpr = fp_count / n_total

    # 95% Confidence Interval
    # Wald interval (or Wilson score)
    se = math.sqrt(fpr * (1 - fpr) / n_total)
    ci_lower = max(0.0, fpr - 1.96 * se)
    ci_upper = min(1.0, fpr + 1.96 * se)

    print("\n" + "=" * 75)
    print("  LONG-TAIL LEGITIMATE SET EVALUATION RESULTS")
    print("=" * 75)
    print(f"  Total Evaluated:             {n_total:,}")
    print(f"  True Negatives (Correct):     {tn_count:,} ({tn_count/n_total*100:.2f}%)")
    print(f"  False Positives (False Alarms): {fp_count:,} ({fpr*100:.2f}%)")
    print(f"  False Positive Rate (FPR):    {fpr*100:.2f}%")
    print(f"  95% Confidence Interval:      [{ci_lower*100:.2f}%, {ci_upper*100:.2f}%]")

    # Breakdown by category
    print("\n" + "-" * 75)
    print("BREAKDOWN BY SUBSET CATEGORY")
    print("-" * 75)
    df_res = pd.DataFrame({"url": urls, "category": categories, "prob": probs, "pred": preds})
    for cat, grp in df_res.groupby("category"):
        grp_fp = (grp["pred"] == 1).sum()
        grp_total = len(grp)
        grp_fpr = grp_fp / grp_total if grp_total > 0 else 0.0
        print(f"  * {cat:<40}: {grp_fp:>3}/{grp_total:<4} FP ({grp_fpr*100:>5.2f}% FPR)")

    # 30 Most Confidently Wrong Predictions (False Positives sorted by prob descending)
    print("\n" + "=" * 75)
    print("TOP 30 MOST CONFIDENTLY WRONG PREDICTIONS (HIGHEST RISK FALSE POSITIVES)")
    print("=" * 75)
    fps = df_res[df_res["pred"] == 1].sort_values(by="prob", ascending=False).reset_index(drop=True)
    if len(fps) == 0:
        print("  None! Model achieved 0 False Positives on this set.")
    else:
        print(f"{'#':<3} {'Predicted Prob':<16} {'Category':<35} {'URL'}")
        print("-" * 80)
        for i, row in fps.head(30).iterrows():
            print(f"{i+1:<3} {row['prob']*100:>6.2f}%         {row['category']:<35} {row['url'][:55]}")

    # Also save detailed report to disk
    df_res.to_csv(ROOT / "ml" / "reports" / "longtail_legit_eval_results.csv", index=False)
    print(f"\n[+] Full long-tail evaluation results exported to ml/reports/longtail_legit_eval_results.csv")

if __name__ == '__main__':
    evaluate_longtail()
