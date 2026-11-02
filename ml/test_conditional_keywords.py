"""
Test script for hypothesis 3(a):
Keyword features only in combination with brand-mismatch, suspicious TLD, or suspicious structure.
Let's see how the feature behaves on the actual datasets!
"""
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

ROOT = Path(r"d:\git projects\phishing url detector")
sys.path.insert(0, str(ROOT / "backend"))
from app.ml.feature_extraction_v2 import (
    extract_url_features, features_to_vector, normalize_url,
    get_tld_risk_score, check_brand_lookalike, check_brand_in_subdomain,
    has_punycode, hostname_entropy, is_valid_ip, extract_apex_domain,
    DISALLOWED_SHARED_PLATFORMS, SUSPICIOUS_KEYWORDS
)
from urllib.parse import urlparse

def conditional_keyword_flag(url: str) -> int:
    nu = normalize_url(url)
    parsed = urlparse(nu)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    url_lower = nu.lower()

    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if not found_kw:
        return 0

    # If keywords exist, check if there is risk context:
    # 1. High risk TLD
    if get_tld_risk_score(hostname) >= 0.5:
        return 1
    # 2. Brand lookalike or brand in subdomain
    if check_brand_lookalike(hostname) or check_brand_in_subdomain(hostname):
        return 1
    # 3. Raw IP
    if is_valid_ip(hostname):
        return 1
    # 4. Punycode
    if has_punycode(hostname):
        return 1
    # 5. Shared platform often abused
    if any(plat in hostname for plat in DISALLOWED_SHARED_PLATFORMS):
        return 1
    # 6. High entropy
    if hostname_entropy(hostname) >= 3.6:
        return 1
    # 7. Unencrypted HTTP with sensitive keyword
    if (parsed.scheme or "").lower() == "http":
        return 1
    # 8. Suspicious hyphenation or high dot count
    if hostname.count("-") >= 2 or hostname.count(".") >= 3:
        return 1

    return 0

# Check on sample URLs
test_cases = [
    ("https://portal.chase.com/auth/login", "Legit Bank SSO"),
    ("https://accounts.google.com/ServiceLogin", "Legit Google SSO"),
    ("https://login.microsoftonline.com/common/oauth2", "Legit Microsoft SSO"),
    ("https://auth.berkeley.edu/cas/login", "Legit University SSO"),
    ("http://login.paypal.com.account-verify.xyz/signin", "Phishing PayPal"),
    ("https://maildinshaakckjnw54.firebaseapp.com/", "Phishing Firebase"),
    ("http://203.0.113.195/secure/login.php", "Phishing IP"),
    ("https://secure-update-banking.co.uk/verify/index.html", "Phishing Hyphen"),
]

for url, desc in test_cases:
    old_kw = 1 if any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS) else 0
    new_kw = conditional_keyword_flag(url)
    print(f"{desc:<25} | Old kw: {old_kw} | New kw: {new_kw} | URL: {url}")
