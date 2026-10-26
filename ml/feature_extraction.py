"""
PhishGuard AI - Feature Extraction Engine
Extracts deterministic lexical, structural, and semantic features from URLs
without any network sockets, DNS queries, or outbound HTTP requests.
"""

import ipaddress
import re
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse, unquote

# High-risk security and authentication keywords commonly abused in phishing paths and subdomains
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

FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "count_dots",
    "count_hyphens",
    "count_subdomains",
    "count_digits",
    "count_special_chars",
    "is_ip_address",
    "is_https",
    "has_at_symbol",
    "has_suspicious_encoding",
    "is_shortened_service",
    "has_unusual_port",
    "has_suspicious_keywords",
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
    # Strip port if present in hostname
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
    # If IP address, subdomains are 0
    if is_valid_ip(clean_host):
        return 0
    parts = clean_host.split('.')
    # e.g., 'sub.example.com' has parts ['sub', 'example', 'com'], len 3 -> 1 subdomain
    # e.g., 'login.verify.paypal.com' -> len 4 -> 2 subdomains
    if len(parts) > 2:
        return len(parts) - 2
    return 0


def extract_url_features(raw_url: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    Extracts all 16 defined features from a given URL string.
    Returns:
        features: Dictionary mapping feature names to numerical values (int/float).
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
    query_length = len(query)
    
    count_dots = normalized.count(".")
    count_hyphens = normalized.count("-")
    subdomains = count_subdomains(hostname)
    count_digits = sum(c.isdigit() for c in normalized)
    
    # Special characters often used for obfuscation and tracking parameters
    special_chars = set("?=&%~+$;_")
    count_special_chars = sum(c in special_chars for c in normalized)
    
    ip_flag = is_valid_ip(hostname)
    https_flag = 1 if scheme == "https" else 0
    at_symbol_flag = 1 if "@" in normalized else 0
    
    # Check for excessive percent-encoding (e.g., %20, %2e, %2f repeated)
    has_encoding = 1 if normalized.count("%") >= 2 else 0
    
    # Check if host matches common URL shorteners
    shortener_flag = 1 if any(shortener in hostname.lower() for shortener in KNOWN_SHORTENERS) else 0
    
    # Check for non-standard ports
    unusual_port = 0
    if parsed.port and parsed.port not in (80, 443):
        unusual_port = 1
        
    # Check for phishing keywords in hostname or path
    url_lower = normalized.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    keyword_flag = 1 if len(found_keywords) > 0 else 0
    
    features: Dict[str, Any] = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_subdomains": subdomains,
        "count_digits": count_digits,
        "count_special_chars": count_special_chars,
        "is_ip_address": ip_flag,
        "is_https": https_flag,
        "has_at_symbol": at_symbol_flag,
        "has_suspicious_encoding": has_encoding,
        "is_shortened_service": shortener_flag,
        "has_unusual_port": unusual_port,
        "has_suspicious_keywords": keyword_flag,
    }
    
    # Derive human-explainable heuristic flags for security analysts
    suspicious_reasons: List[str] = []
    if ip_flag == 1:
        suspicious_reasons.append("Raw IP address used in place of domain name.")
    if at_symbol_flag == 1:
        suspicious_reasons.append("Contains '@' symbol, which can mask the true destination.")
    if subdomains >= 3:
        suspicious_reasons.append(f"Excessive subdomain nesting ({subdomains} subdomains detected).")
    if count_hyphens >= 3:
        suspicious_reasons.append(f"High number of hyphens ({count_hyphens}), often used for typosquatting.")
    if count_dots >= 4:
        suspicious_reasons.append(f"High number of dots ({count_dots}) in URL structure.")
    if shortener_flag == 1:
        suspicious_reasons.append("Uses a known URL shortening service that conceals destination.")
    if unusual_port == 1:
        suspicious_reasons.append(f"Specifies non-standard network port ({parsed.port}).")
    if found_keywords:
        suspicious_reasons.append(f"Contains sensitive keywords: {', '.join(found_keywords[:4])}.")
    if has_encoding == 1:
        suspicious_reasons.append("Contains multiple percent-encoded characters.")
    if https_flag == 0:
        suspicious_reasons.append("Uses unencrypted HTTP protocol instead of HTTPS.")
    if url_length > 100:
        suspicious_reasons.append(f"Unusually long URL length ({url_length} characters).")
        
    return features, suspicious_reasons


def features_to_vector(features: Dict[str, Any]) -> List[float]:
    """Converts a feature dictionary to an ordered numerical vector matching FEATURE_NAMES."""
    return [float(features[name]) for name in FEATURE_NAMES]
