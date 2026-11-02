import numpy as np
import pandas as pd
from urllib.parse import urlparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from ml.experiment_contextual_model import (
    DATA_PATH, SSO_PATH, LONGTAIL_CSV, HARD_PHISH_CSV,
    extract_apex_domain, normalize_url,
    get_tld_risk_score, check_brand_lookalike, check_brand_in_subdomain,
    has_punycode, hostname_entropy, is_valid_ip, is_hsts_enforced_domain,
    count_subdomains, DISALLOWED_SHARED_PLATFORMS, SUSPICIOUS_KEYWORDS,
    COMMON_SSO_SUBDOMAINS, ACADEMIC_GOV_TLDS, TOP_BRANDS
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV

SCRIPT_EXTS = {'.php', '.html', '.htm', '.cgi', '.asp', '.aspx', '.jsp', '.exe'}

def get_domain_tier(u):
    nu = normalize_url(u)
    parsed = urlparse(nu)
    h = (parsed.hostname or '').lower().rstrip('.')
    
    is_acad = any(h.endswith('.' + tld) or h == tld for tld in ACADEMIC_GOV_TLDS)
    brand_sub = check_brand_in_subdomain(h)
    brand_look = check_brand_lookalike(h)
    tld_risk = get_tld_risk_score(h)
    ip_f = is_valid_ip(h)
    puny = has_punycode(h)
    is_shared = any(plat in h for plat in DISALLOWED_SHARED_PLATFORMS)
    sub = count_subdomains(h)
    parts = h.split('.')
    is_sso_sub = (sub >= 1 and len(parts) >= 3 and any(tok in COMMON_SSO_SUBDOMAINS for tok in parts[:-2]))
    
    if (brand_sub or brand_look or tld_risk >= 0.6 or ip_f or puny):
        return 2  # High-risk
    elif (is_acad or (is_sso_sub and tld_risk < 0.2 and not is_shared)):
        return 0  # Authoritative / Low-risk
    return 1      # Neutral

def extract_features_v7_1(u):
    nu = normalize_url(u)
    parsed = urlparse(nu)
    h = (parsed.hostname or '').lower().rstrip('.')
    p = parsed.path or ''
    scheme = (parsed.scheme or '').lower()

    sub = count_subdomains(h)
    ip_f = is_valid_ip(h)
    tld_risk = get_tld_risk_score(h)
    is_acad = 1 if any(h.endswith('.' + tld) or h == tld for tld in ACADEMIC_GOV_TLDS) else 0
    brand_sub = check_brand_in_subdomain(h)
    brand_look = check_brand_lookalike(h)
    is_shared = 1 if any(plat in h for plat in DISALLOWED_SHARED_PLATFORMS) else 0
    puny = has_punycode(h)
    ent = hostname_entropy(h)
    dom_feats = [float(len(h)), float(sub), float(ip_f), float(tld_risk), float(is_acad),
                 float(brand_sub), float(brand_look), float(is_shared), float(puny), float(ent)]

    url_len = len(nu)
    path_len = len(p)
    dots = nu.count('.')
    hyphens = nu.count('-')
    slashes = nu.count('/')
    digits = sum(c.isdigit() for c in nu)
    specials = sum(not c.isalnum() and c not in '/;:.' for c in nu)
    https_f = 1 if (scheme == 'https' or is_hsts_enforced_domain(h)) else 0
    
    path_lower = p.lower()
    has_script = 1 if any(path_lower.endswith(ext) or (ext + '?') in path_lower for ext in SCRIPT_EXTS) else 0
    
    apex = extract_apex_domain(h)
    brand_in_path = 0
    if not any(brand in apex for brand in TOP_BRANDS):
        if any(brand in path_lower for brand in TOP_BRANDS):
            brand_in_path = 1
            
    parts = h.split('.')
    is_sso = 1 if (dom_feats[1] >= 1 and len(parts) >= 3 and any(tok in COMMON_SSO_SUBDOMAINS for tok in parts[:-2])) else 0
    
    kw_flag = 0
    found_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in nu.lower()]
    if found_kws:
        if dom_feats[3] >= 0.5 or dom_feats[5] or dom_feats[6] or dom_feats[7] or dom_feats[9] >= 4.0 or brand_in_path or has_script or scheme == 'http':
            kw_flag = 1
            
    path_feats = [
        float(url_len), float(path_len), float(dots), float(hyphens), float(slashes),
        float(digits), float(https_f), float(kw_flag), float(has_script), float(brand_in_path),
        float(is_sso), float(round(digits/max(url_len,1), 6)), float(round(specials/max(url_len,1), 6)),
        float(nu.count('?')), float(nu.count('='))
    ]
    return dom_feats + path_feats

print("[*] Loading datasets...")
df_base = pd.read_csv(DATA_PATH)[['url', 'label']]
df_deep = pd.read_csv('ml/data/legit_deep_links_6000.csv')[['url', 'label']]
df_sso = pd.read_csv(SSO_PATH)[['url', 'label']]
df_comb = pd.concat([df_base, df_deep, df_sso], ignore_index=True).drop_duplicates(subset=['url']).reset_index(drop=True)

apex = [extract_apex_domain(urlparse(normalize_url(u)).hostname or '') for u in df_comb['url']]
df_comb['apex'] = apex
unq = np.array(sorted(list(set(apex))))
rng = np.random.default_rng(42)
rng.shuffle(unq)
train_d = set(unq[:int(len(unq)*0.6)])
val_d = set(unq[int(len(unq)*0.6):int(len(unq)*0.8)])
test_d = set(unq[int(len(unq)*0.8):])

train_df = df_comb[df_comb['apex'].isin(train_d)].reset_index(drop=True)
val_df = df_comb[df_comb['apex'].isin(val_d)].reset_index(drop=True)
test_df = df_comb[df_comb['apex'].isin(test_d)].reset_index(drop=True)

print("[*] Extracting train/val/test features...")
X_train = np.array([extract_features_v7_1(u) for u in train_df['url']], dtype=np.float32)
y_train = train_df['label'].values.astype(int)
X_val = np.array([extract_features_v7_1(u) for u in val_df['url']], dtype=np.float32)
y_val = val_df['label'].values.astype(int)
X_test = np.array([extract_features_v7_1(u) for u in test_df['url']], dtype=np.float32)
y_test = test_df['label'].values.astype(int)

print("[*] Training RF and calibrating...")
rf = RandomForestClassifier(n_estimators=200, min_samples_leaf=2, class_weight='balanced', n_jobs=-1, random_state=42)
rf.fit(X_train, y_train)
cal = CalibratedClassifierCV(rf, method='isotonic', cv=3)
cal.fit(X_train, y_train)

# Batch probabilities
print("[*] Running batch inferences...")
val_p = cal.predict_proba(X_val)[:, 1]
val_tiers = np.array([get_domain_tier(u) for u in val_df['url']])

test_p = cal.predict_proba(X_test)[:, 1]
test_tiers = np.array([get_domain_tier(u) for u in test_df['url']])

df_long = pd.read_csv(LONGTAIL_CSV)
X_long = np.array([extract_features_v7_1(u) for u in df_long['url']], dtype=np.float32)
long_p = cal.predict_proba(X_long)[:, 1]
long_tiers = np.array([get_domain_tier(u) for u in df_long['url']])

df_sso_eval = pd.read_csv(SSO_PATH)
X_sso_eval = np.array([extract_features_v7_1(u) for u in df_sso_eval['url']], dtype=np.float32)
sso_p = cal.predict_proba(X_sso_eval)[:, 1]
sso_tiers = np.array([get_domain_tier(u) for u in df_sso_eval['url']])

df_hard = pd.read_csv(HARD_PHISH_CSV)
X_hard = np.array([extract_features_v7_1(u) for u in df_hard['url']], dtype=np.float32)
hard_p = cal.predict_proba(X_hard)[:, 1]
hard_tiers = np.array([get_domain_tier(u) for u in df_hard['url']])

def eval_config(t_high, t_neut, t_auth):
    # Vectorized decision
    def predict(p, tiers):
        threshs = np.where(tiers == 2, t_high, np.where(tiers == 0, t_auth, t_neut))
        return (p >= threshs).astype(int)
    
    val_pred = predict(val_p, val_tiers)
    v_fpr = np.mean(val_pred[y_val == 0] == 1)
    v_rec = np.mean(val_pred[y_val == 1] == 1)
    
    test_pred = predict(test_p, test_tiers)
    t_fpr = np.mean(test_pred[y_test == 0] == 1)
    t_rec = np.mean(test_pred[y_test == 1] == 1)
    
    long_pred = predict(long_p, long_tiers)
    l_fpr = np.mean(long_pred == 1)
    
    sso_pred = predict(sso_p, sso_tiers)
    s_fpr = np.mean(sso_pred == 1)
    
    hard_pred = predict(hard_p, hard_tiers)
    h_rec = np.mean(hard_pred == 1)
    
    return v_fpr, v_rec, t_fpr, t_rec, l_fpr, s_fpr, h_rec

print("\n" + "=" * 90)
print(f"{'t_hi':<5} {'t_neu':<5} {'t_auth':<6} | {'Val FPR':<7} {'Val Rec':<7} | {'Test FPR':<8} {'Test Rec':<8} | {'Longtail':<8} {'SSO FPR':<7} {'Hard Phish':<10} | Gates")
print("=" * 90)

for t_hi in [0.25, 0.30, 0.35]:
    for t_neu in [0.38, 0.40, 0.42, 0.44]:
        for t_auth in [0.55, 0.60, 0.65]:
            v_fpr, v_rec, t_fpr, t_rec, l_fpr, s_fpr, h_rec = eval_config(t_hi, t_neu, t_auth)
            gate_lt = l_fpr < 0.06
            gate_rec = h_rec >= 0.95
            gate_sso = s_fpr <= 0.15
            all_pass = gate_lt and gate_rec and gate_sso
            print(f"{t_hi:.2f}  {t_neu:.2f}  {t_auth:.2f}   | {v_fpr*100:6.2f}% {v_rec*100:6.2f}% | {t_fpr*100:7.2f}% {t_rec*100:7.2f}% | {l_fpr*100:7.2f}% {s_fpr*100:6.2f}% {h_rec*100:9.2f}% | {'*** ALL GATES PASS ***' if all_pass else 'FAIL'}")

