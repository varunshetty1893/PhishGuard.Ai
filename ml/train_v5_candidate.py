"""
Phase 3: Detection Quality Experimentation and Model Comparison
===============================================================
1. Incorporates hard-negative SSO/portal URLs with domain-isolated splits.
2. Refines keyword feature extraction: keywords are only flagged when in combination
   with brand mismatch, suspicious TLD, raw IP, high entropy, shared PaaS, or anomalous structure.
3. Compares Random Forest vs HistGradientBoosting (both isotonic calibrated).
4. Tunes decision threshold on VALIDATION SET ONLY.
5. Evaluates on:
   - Held-out test split (touched once)
   - Long-tail legit set (1,080 URLs)
   - Authentic SSO set (30 URLs)
   - Hard phishing set (600 URLs)
6. Reports all metrics with 95% Confidence Intervals.
"""
import sys
import math
import json
from pathlib import Path
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import joblib
from datetime import datetime, timezone

from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

ROOT = Path(r"d:\git projects\phishing url detector")
sys.path.insert(0, str(ROOT / "backend"))

from app.ml.feature_extraction_v2 import (
    FEATURE_NAMES, normalize_url, extract_apex_domain,
    get_tld_risk_score, check_brand_lookalike, check_brand_in_subdomain,
    has_punycode, hostname_entropy, is_valid_ip, is_hsts_enforced_domain,
    count_subdomains, is_high_reputation_domain,
    DISALLOWED_SHARED_PLATFORMS, SUSPICIOUS_KEYWORDS
)

DATA_PATH = ROOT / "ml" / "data" / "dataset_v4_curated.csv"
SPLIT_CSV = ROOT / "ml" / "data" / "split_assignments.csv"
LONGTAIL_CSV = ROOT / "ml" / "reports" / "longtail_legit_eval_results.csv"
HARD_PHISH_CSV = ROOT / "ml" / "reports" / "hard_phishing_eval_results.csv"

def ci_95(p, n):
    se = math.sqrt(p * (1 - p) / max(n, 1))
    return max(0.0, p - 1.96 * se), min(1.0, p + 1.96 * se)

def extract_features_v5(raw_url: str):
    """
    16-feature schema compatible with production.
    Reduces keyword over-reliance: keywords are flagged ONLY when combined with
    risk signals (brand lookalike, brand in subdomain, suspicious TLD, raw IP,
    punycode, shared PaaS, unencrypted HTTP, or anomalous hyphens/dots).
    """
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

    # Keyword feature: condition on contextual risk signals
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

    vec = [
        float(url_length), float(hostname_length), float(path_length),
        float(count_dots), float(count_hyphens), float(count_at),
        float(count_question), float(count_equal), float(count_slash),
        float(digits), float(subdomains), float(ip_flag),
        float(https_flag), float(keyword_flag), float(digit_ratio),
        float(special_char_ratio)
    ]
    return vec

# Additional hard-negative authentic portal URLs across diverse domains
HARD_NEGATIVE_SSO = [
    # Universities worldwide
    "https://auth.ox.ac.uk/login",
    "https://raven.cam.ac.uk/auth/authenticate.html",
    "https://idp.ethz.ch/idp/profile/SAML2/Redirect/SSO",
    "https://shibboleth.ucla.edu/idp/profile/SAML2/Redirect/SSO",
    "https://weblogin.umich.edu/",
    "https://login.utexas.edu/login/login.fcc",
    "https://cas.columbia.edu/cas/login",
    "https://fed.princeton.edu/cas/login",
    "https://idp.yale.edu/idp/profile/SAML2/Redirect/SSO",
    "https://weblogin.pennkey.upenn.edu/login",
    "https://login.cornell.edu/idp/profile/SAML2/Redirect/SSO",
    "https://login.gatech.edu/cas/login",
    "https://shibboleth.illinois.edu/idp/profile/SAML2/Redirect/SSO",
    "https://identity.ucsd.edu/idp/profile/SAML2/Redirect/SSO",
    "https://idp.u.washington.edu/idp/profile/SAML2/Redirect/SSO",
    "https://shibboleth.nyu.edu/idp/profile/SAML2/Redirect/SSO",
    "https://nusid.nus.edu.sg/adfs/ls/",
    "https://login.utoronto.ca/idp/profile/SAML2/Redirect/SSO",
    "https://authentication.ubc.ca/cas/login",
    "https://sso.unimelb.edu.au/idp/profile/SAML2/Redirect/SSO",
    # Global Banks & Credit Unions
    "https://connect.wellsfargo.com/auth/login/present",
    "https://online.citi.com/US/login.do",
    "https://onlinebanking.usbank.com/auth/login",
    "https://onlinebanking.pnc.com/alservlet/login",
    "https://verified.capitalone.com/auth/signin",
    "https://www.hsbc.com.au/security/log-on/",
    "https://bank.barclays.co.uk/olb/authlogin/loginAppContainer.do",
    "https://www.rbs.co.uk/secure/login",
    "https://online.db.com/login",
    "https://keydirect.ubs.com/login",
    "https://sc.com/global/security-and-login/",
    "https://internet-banking.dbs.com.sg/IB/Welcome",
    "https://infinity.icicibank.com/corp/AuthenticationController",
    "https://netbanking.hdfcbank.com/netbanking/",
    "https://retail.onlinesbi.sbi/retail/login.htm",
    "https://ib.nab.com.au/nabib/index.jsp",
    "https://banking.westpac.com.au/wbc/banking/handler",
    "https://royalbank.com/onlinebanking/login",
    "https://easyweb.td.com/waw/idp/login.htm",
    "https://www1.bmo.com/onlinebanking/cgi-bin/netbnx/NBlogin",
    "https://scotiaonline.scotiabank.com/online/authentication/authentication.bns",
    # Enterprise & Identity Providers
    "https://login.gov/sign-in/",
    "https://auth.services.gov.uk/login",
    "https://account.servicecanada.gc.ca/msca-mdsc/portal-portail/pro/portal-portail",
    "https://my.gov.au/en/services/mygov-sign-in",
    "https://identity.cloudflare.com/login",
    "https://cloud.digitalocean.com/login",
    "https://dashboard.heroku.com/login",
    "https://login.linode.com/",
    "https://manage.fastly.com/login",
    "https://app.sendgrid.com/login",
    "https://www.twilio.com/login",
    "https://app.datadoghq.com/account/login",
    "https://login.newrelic.com/login",
    "https://identity.pagerduty.com/global/login",
    "https://login.splunk.com/",
    "https://app.snowflake.com/login",
    "https://account.mongodb.com/account/login",
    "https://cloud.elastic.co/login",
    "https://portal.azure.com/",
    "https://gitlab.com/users/sign_in",
    "https://bitbucket.org/account/signin/",
    "https://id.atlassian.com/login",
    "https://signin.rockwellautomation.com/",
    "https://auth.pingidentity.com/",
    "https://auth.onelogin.com/",
    "https://duo.com/login",
    "https://console.jumpcloud.com/login"
]

def main():
    print("=" * 80)
    print("  PHISHGUARD AI - PHASE 3 DETECTION QUALITY: V5 CANDIDATE RETRAINING")
    print("=" * 80)

    # 1. Load curated dataset
    df = pd.read_csv(DATA_PATH)
    print(f"[+] Loaded base curated dataset: {len(df):,} samples ({DATA_PATH.name})")

    # Add hard-negative SSO URLs to legitimate pool
    hard_neg_df = pd.DataFrame({"url": HARD_NEGATIVE_SSO, "label": 0})
    df_combined = pd.concat([df, hard_neg_df], ignore_index=True).drop_duplicates(subset=["url"]).reset_index(drop=True)
    print(f"[+] Added {len(HARD_NEGATIVE_SSO)} hard-negative SSO URLs (Total: {len(df_combined):,})")

    # Extract features and apex domains
    print("[*] Extracting features with refined keyword context logic...")
    vectors = []
    apex_domains = []
    norm_urls = []
    for u in df_combined["url"]:
        nu = normalize_url(u)
        norm_urls.append(nu)
        host = urlparse(nu).hostname or ""
        apex = extract_apex_domain(host)
        apex_domains.append(apex)
        vec = extract_features_v5(nu)
        vectors.append(vec)

    X = np.array(vectors, dtype=np.float32)
    y = df_combined["label"].values.astype(int)
    df_combined["apex_domain"] = apex_domains

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

    assert len(train_doms & val_doms) == 0
    assert len(train_doms & test_doms) == 0
    assert len(val_doms & test_doms) == 0

    train_mask = np.array([d in train_doms for d in apex_domains])
    val_mask   = np.array([d in val_doms for d in apex_domains])
    test_mask  = np.array([d in test_doms for d in apex_domains])

    X_train, y_train = X[train_mask], y[train_mask]
    X_val,   y_val   = X[val_mask],   y[val_mask]
    X_test,  y_test  = X[test_mask],  y[test_mask]

    print(f"[+] Train: {len(X_train):,} ({len(train_doms):,} domains)")
    print(f"[+] Val:   {len(X_val):,} ({len(val_doms):,} domains)")
    print(f"[+] Test:  {len(X_test):,} ({len(test_doms):,} domains)")

    # 3. Load Long-tail legit and Hard phishing sets for benchmark
    df_long = pd.read_csv(LONGTAIL_CSV)
    X_long = np.array([extract_features_v5(u) for u in df_long["url"]], dtype=np.float32)
    sso_mask = df_long["category"] == "Authentic Login/Account/Payment Portal"

    df_hard = pd.read_csv(HARD_PHISH_CSV)
    X_hard = np.array([extract_features_v5(u) for u in df_hard["url"]], dtype=np.float32)

    # 4. Compare Model Architectures: Random Forest vs HistGradientBoosting
    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, min_samples_leaf=3, class_weight="balanced", n_jobs=-1, random_state=42
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=150, min_samples_leaf=20, class_weight="balanced", random_state=42
        )
    }

    best_candidate = None
    best_candidate_name = None
    best_candidate_thresh = 0.50
    best_candidate_val_metrics = None

    print("\n" + "=" * 80)
    print("  MODEL TRAINING, CALIBRATION & VALIDATION THRESHOLD SELECTION")
    print("=" * 80)

    for m_name, base_model in models.items():
        print(f"\n[*] Training and Calibrating {m_name} on TRAIN ONLY...")
        cal_clf = CalibratedClassifierCV(base_model, method="isotonic", cv=3)
        cal_clf.fit(X_train, y_train)

        # Tune threshold on VALIDATION ONLY
        val_probs = cal_clf.predict_proba(X_val)[:, 1]
        target_fpr = 0.02
        best_t = 0.50
        best_rec = 0.0
        best_fpr = 1.0

        for t in np.arange(0.30, 0.90, 0.02):
            preds = (val_probs >= t).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_val, preds, labels=[0, 1]).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            if fpr <= target_fpr and rec > best_rec:
                best_rec = rec
                best_t = float(t)
                best_fpr = fpr

        print(f"[+] {m_name} Optimal Val Threshold: {best_t:.3f} (Val FPR: {best_fpr*100:.2f}%, Val Recall: {best_rec*100:.2f}%)")

        if best_candidate is None or best_rec > best_candidate_val_metrics["val_rec"]:
            best_candidate = cal_clf
            best_candidate_name = m_name
            best_candidate_thresh = best_t
            best_candidate_val_metrics = {"val_fpr": best_fpr, "val_rec": best_rec, "base_model": base_model}

    print(f"\n[+] Selected Best Model Architecture: {best_candidate_name} @ Threshold {best_candidate_thresh:.3f}")

    # 5. Evaluate Best Candidate on All Sets
    print("\n" + "=" * 80)
    print("  FULL BENCHMARK EVALUATION (TOUCHED EXACTLY ONCE)")
    print("=" * 80)

    # 5.1 Held-out Test
    test_probs = best_candidate.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= best_candidate_thresh).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, test_preds, labels=[0, 1]).ravel()
    t_acc = accuracy_score(y_test, test_preds)
    t_prec = precision_score(y_test, test_preds, zero_division=0)
    t_rec = recall_score(y_test, test_preds, zero_division=0)
    t_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    t_f1 = f1_score(y_test, test_preds, zero_division=0)
    t_auc = roc_auc_score(y_test, test_probs)

    rec_ci = ci_95(t_rec, tp + fn)
    fpr_ci = ci_95(t_fpr, fp + tn)

    # 5.2 Long-tail Legit
    long_probs = best_candidate.predict_proba(X_long)[:, 1]
    long_preds = (long_probs >= best_candidate_thresh).astype(int)
    long_fp = np.sum(long_preds == 1)
    long_fpr = long_fp / len(df_long)
    long_ci = ci_95(long_fpr, len(df_long))

    # 5.3 SSO subset
    sso_fp = np.sum(long_preds[sso_mask] == 1)
    sso_fpr = sso_fp / sso_mask.sum()
    sso_ci = ci_95(sso_fpr, sso_mask.sum())

    # 5.4 Hard Phishing
    hard_probs = best_candidate.predict_proba(X_hard)[:, 1]
    hard_preds = (hard_probs >= best_candidate_thresh).astype(int)
    hard_tp = np.sum(hard_preds == 1)
    hard_rec = hard_tp / len(df_hard)
    hard_ci = ci_95(hard_rec, len(df_hard))

    print(f"\nResults for Candidate ({best_candidate_name} @ {best_candidate_thresh:.3f}):")
    print(f"  Held-out Test Acc:    {t_acc*100:.2f}%")
    print(f"  Held-out Test Rec:    {t_rec*100:.2f}% (95% CI: [{rec_ci[0]*100:.2f}%, {rec_ci[1]*100:.2f}%])")
    print(f"  Held-out Test FPR:    {t_fpr*100:.2f}% (95% CI: [{fpr_ci[0]*100:.2f}%, {fpr_ci[1]*100:.2f}%])")
    print(f"  Long-tail Legit FPR:  {long_fpr*100:.2f}% ({long_fp}/{len(df_long)}) (95% CI: [{long_ci[0]*100:.2f}%, {long_ci[1]*100:.2f}%])")
    print(f"  Authentic SSO FPR:    {sso_fpr*100:.2f}% ({sso_fp}/{sso_mask.sum()}) (95% CI: [{sso_ci[0]*100:.2f}%, {sso_ci[1]*100:.2f}%])")
    print(f"  Hard Phishing Recall: {hard_rec*100:.2f}% ({hard_tp}/{len(df_hard)}) (95% CI: [{hard_ci[0]*100:.2f}%, {hard_ci[1]*100:.2f}%])")

    # Baseline v4.1.0 numbers for comparison:
    # Held-out Rec: 95.23%
    # Long-tail FPR: 13.06%
    # Authentic SSO FPR: 46.67%
    # Hard Phish Rec: 96.67%
    print("\n" + "=" * 80)
    print("  COMPARISON: BASELINE v4.1.0 vs CANDIDATE")
    print("=" * 80)
    print(f"{'Metric':<25} {'Baseline v4.1.0':<20} {'Candidate v5':<20} {'Improvement'}")
    print("-" * 80)
    print(f"{'Held-out Test Recall':<25} {'95.23%':<20} {f'{t_rec*100:.2f}%':<20} {t_rec*100 - 95.23:+.2f}%")
    print(f"{'Held-out Test FPR':<25} {'1.96%':<20} {f'{t_fpr*100:.2f}%':<20} {t_fpr*100 - 1.96:+.2f}%")
    print(f"{'Long-tail Legit FPR':<25} {'13.06% (141/1080)':<20} {f'{long_fpr*100:.2f}% ({long_fp}/{len(df_long)})':<20} {long_fpr*100 - 13.06:+.2f}%")
    print(f"{'Authentic SSO FPR':<25} {'46.67% (14/30)':<20} {f'{sso_fpr*100:.2f}% ({sso_fp}/{sso_mask.sum()})':<20} {sso_fpr*100 - 46.67:+.2f}%")
    print(f"{'Hard Phishing Recall':<25} {'96.67% (580/600)':<20} {f'{hard_rec*100:.2f}% ({hard_tp}/{len(df_hard)})':<20} {hard_rec*100 - 96.67:+.2f}%")

    # Gate check:
    # "5. Only replace the deployed model if long-tail FPR AND SSO FPR improve without recall dropping more than 1 point. Otherwise keep v4.1.0 and document why."
    recall_drop = max(0.0, 96.67 - hard_rec * 100)
    replaces_model = (long_fpr < 0.1306) and (sso_fpr < 0.4667) and (recall_drop <= 1.0)
    print("\n" + "=" * 80)
    print(f"DEPLOYMENT GATE: Long-tail FPR improved: {long_fpr < 0.1306} | SSO FPR improved: {sso_fpr < 0.4667} | Recall drop <= 1.0%: {recall_drop <= 1.0}")
    print(f"DECISION: {'REPLACE MODEL WITH V5' if replaces_model else 'KEEP V4.1.0'}")
    print("=" * 80)

    # Save candidate report to file
    cand_report = {
        "candidate_model": best_candidate_name,
        "decision_threshold": best_candidate_thresh,
        "test_accuracy": float(t_acc),
        "test_precision": float(t_prec),
        "test_recall": float(t_rec),
        "test_fpr": float(t_fpr),
        "test_f1": float(t_f1),
        "test_roc_auc": float(t_auc),
        "longtail_fpr": float(long_fpr),
        "longtail_fp_count": int(long_fp),
        "sso_fpr": float(sso_fpr),
        "sso_fp_count": int(sso_fp),
        "hard_phish_recall": float(hard_rec),
        "hard_phish_tp_count": int(hard_tp),
        "replaces_model": bool(replaces_model)
    }
    with open(ROOT / "ml" / "reports" / "phase3_candidate_evaluation.json", "w") as f:
        json.dump(cand_report, f, indent=2)

    return best_candidate, best_candidate_name, best_candidate_thresh, cand_report

if __name__ == "__main__":
    main()

