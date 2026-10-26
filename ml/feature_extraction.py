"""
PhishGuard AI - Feature Extraction Engine
Extracts deterministic lexical, structural, and semantic features from URLs
matching the retrained 16-dimensional production model schema.
Also includes domain extraction and high-reputation domain baseline logic.
"""

import ipaddress
import re
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse

# Sensitive security, finance, and authentication keywords commonly abused in phishing paths
SUSPICIOUS_KEYWORDS: List[str] = [
    "login", "verify", "signin", "banking", "secure", "update", "account",
    "wallet", "confirm", "password", "security", "authenticate", "validation",
    "recover", "billing", "portal", "support", "service", "appleid", "paypal"
]

# Recognized URL shortening domains used to conceal destination URLs
KNOWN_SHORTENERS: set = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink"
}

# High-reputation global apex domains (enterprise cloud, tech, infrastructure, financial roots)
HIGH_REPUTATION_DOMAINS: set = {
    # Alphabet / Google
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "youtube.com", "googlevideo.com", "android.com", "googleblog.com",
    "google.co.in", "google.co.uk", "google.de", "google.fr", "google.ca",
    # Microsoft / Azure
    "microsoft.com", "office.com", "azure.com", "live.com", "microsoftonline.com",
    "visualstudio.com", "windows.net", "bing.com", "linkedin.com", "github.com",
    # Amazon / AWS
    "amazon.com", "amazonaws.com", "aws.amazon.com", "media-amazon.com",
    # Apple
    "apple.com", "icloud.com",
    # Cloud & Infrastructure
    "cloudflare.com", "fastly.com", "akamai.com", "digitalocean.com",
    "docker.com", "gitlab.com", "npmjs.com", "pypi.org",
    "mozilla.org", "wikipedia.org", "wikimedia.org", "chatgpt.com", "openai.com",
    # Financial primary roots
    "paypal.com", "stripe.com",
}

# Exact 16 feature names in the trained Random Forest model artifact
FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_question",
    "count_equal",
    "count_slash",
    "count_digits",
    "count_subdomains",
    "has_ip",
    "is_https",
    "has_suspicious_keywords",
    "digit_ratio",
    "special_char_ratio"
]


def normalize_url(raw_url: str) -> str:
    """
    Safely sanitizes and normalizes an untrusted URL string.
    Ensures safe prefixing of standard http scheme if missing.
    """
    if not raw_url:
        return ""
    
    url = raw_url.strip()
    # Strip dangerous control characters
    url = re.sub(r'[\r\n\t]', '', url)
    
    # If no scheme is present, default to http:// for parsing purposes
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = "http://" + url
        
    return url


def is_valid_ip(hostname: str) -> int:
    """Checks whether the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return 0
    host = hostname.split(':')[0].strip('[]')
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def count_subdomains(hostname: str) -> int:
    """Calculates subdomain count by inspecting dot-separated components."""
    if not hostname:
        return 0
    clean_host = hostname.split(':')[0]
    if is_valid_ip(clean_host) or clean_host.lower() == "localhost":
        return 0
    parts = [x for x in clean_host.split('.') if x]
    if len(parts) > 2:
        return len(parts) - 2
    return 0


def extract_apex_domain(hostname: str) -> str:
    """
    Extracts effective registered apex domain (e.g., 'console.cloud.google.com' -> 'google.com').
    Correctly accounts for standard two-part ccTLDs.
    """
    if not hostname:
        return ""
    clean = hostname.split(':')[0].strip('[]').lower()
    if is_valid_ip(clean) or clean == "localhost":
        return clean
    parts = [p for p in clean.split('.') if p]
    if len(parts) <= 2:
        return clean
    two_part_tlds = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "edu.au",
        "gov.in", "co.in", "ac.in", "res.in", "com.br", "co.jp", "com.sg"
    }
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in two_part_tlds and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}"
    return f"{parts[-2]}.{parts[-1]}"


def is_high_reputation_domain(hostname: str) -> Tuple[bool, str]:
    """
    Checks if hostname belongs to an authentic, high-reputation domain.
    Returns (is_high_reputation, apex_domain).
    """
    apex = extract_apex_domain(hostname)
    if not apex:
        return False, ""
    if apex in HIGH_REPUTATION_DOMAINS:
        return True, apex
    if apex.endswith((".gov", ".gov.in", ".gov.uk", ".edu", ".edu.in", ".ac.uk", ".mil")):
        return True, apex
    return False, apex


def extract_url_features(raw_url: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    Extracts the 16 exact model features matching train_fulldata.py.
    Returns:
        features: Dictionary mapping feature names to numerical values.
        suspicious_reasons: Human-readable list of detected anomaly descriptions.
    """
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
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
    specials = sum(not c.isalnum() and c not in "/:." for c in normalized)
    
    subdomains = count_subdomains(hostname)
    ip_flag = is_valid_ip(hostname)
    https_flag = 1 if scheme == "https" else 0
    
    # Check for sensitive phishing keywords
    url_lower = normalized.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    keyword_flag = 1 if len(found_keywords) > 0 else 0
    
    digit_ratio = round(digits / max(url_length, 1), 6)
    special_char_ratio = round(specials / max(url_length, 1), 6)
    
    features: Dict[str, Any] = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_at": count_at,
        "count_question": count_question,
        "count_equal": count_equal,
        "count_slash": count_slash,
        "count_digits": digits,
        "count_subdomains": subdomains,
        "has_ip": ip_flag,
        "is_https": https_flag,
        "has_suspicious_keywords": keyword_flag,
        "digit_ratio": digit_ratio,
        "special_char_ratio": special_char_ratio,
    }
    
    # Explainable heuristics for analyst interpretation
    suspicious_reasons: List[str] = []
    if ip_flag == 1:
        suspicious_reasons.append("Raw IP address used as destination hostname.")
    if count_at > 0:
        suspicious_reasons.append("Contains '@' delimiter, which can mask the true destination.")
    if subdomains >= 3:
        suspicious_reasons.append(f"Excessive subdomain nesting ({subdomains} subdomains detected).")
    if count_hyphens >= 3:
        suspicious_reasons.append(f"High number of hyphens ({count_hyphens}), often used in typosquatting.")
    if count_dots >= 4:
        suspicious_reasons.append(f"High dot count ({count_dots}) in URL structure.")
    if https_flag == 0:
        suspicious_reasons.append("Uses unencrypted HTTP protocol instead of HTTPS.")
    if found_keywords:
        suspicious_reasons.append(f"Contains sensitive keywords: {', '.join(found_keywords[:3])}.")
    if any(shortener in hostname.lower() for shortener in KNOWN_SHORTENERS):
        suspicious_reasons.append("Uses a known URL shortening service concealing the destination.")
    if special_char_ratio > 0.08:
        suspicious_reasons.append("Elevated proportion of non-alphanumeric special characters.")
    if url_length > 100:
        suspicious_reasons.append(f"Long URL length ({url_length} characters).")
        
    return features, suspicious_reasons


def features_to_vector(features: Dict[str, Any]) -> List[float]:
    """Converts a feature dictionary to an ordered numerical vector matching FEATURE_NAMES."""
    return [float(features[name]) for name in FEATURE_NAMES]
