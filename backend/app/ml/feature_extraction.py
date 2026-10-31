"""
PhishGuard AI - Backend Feature Extraction (v2 enhanced signals)
Wraps feature_extraction_v2.py: uses 16-feature schema for model inference
but enriches suspicious_reasons with v2 signals (TLD risk, brand lookalike, etc.)
"""
import sys
from pathlib import Path
# Import everything from the v2 module so it all works transparently
from app.ml.feature_extraction_v2 import (  # noqa: F401
    FEATURE_NAMES,
    FEATURE_NAMES_V2,
    SUSPICIOUS_KEYWORDS,
    KNOWN_SHORTENERS,
    HIGH_REPUTATION_DOMAINS,
    TOP_BRANDS,
    normalize_url,
    is_valid_ip,
    count_subdomains,
    extract_apex_domain,
    is_high_reputation_domain,
    is_hsts_enforced_domain,
    get_tld_risk_score,
    check_brand_lookalike,
    check_brand_in_subdomain,
    has_punycode,
    hostname_entropy,
    get_domain_age_days,
    extract_url_features,       # v1 16-feat (used by deployed model)
    extract_url_features_v2,    # v2 22-feat (for next-gen model)
    features_to_vector,
)
