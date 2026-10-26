"""
PhishGuard AI - Enhanced Feature Extraction v2 (Priority 3)
============================================================
New hard-to-fake features added on top of the 16-feature v1 schema:
  - tld_risk_score    : TLD phishing risk tier (0.0-1.0)
  - brand_lookalike   : Edit-distance typosquatting against top brands (0/1)
  - brand_in_subdomain: Brand name appearing in subdomain of non-brand domain (0/1)
  - has_punycode      : xn-- IDN homograph encoding detected (0/1)
  - hostname_entropy  : Shannon entropy of hostname (higher = more random = suspicious)
  - domain_age_days   : Days since domain registration (-1 if unavailable)

Total: 22 features
"""
import re, math, ipaddress
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse

# ──── Top-brand list for typosquatting checks ───────────────────────────
TOP_BRANDS: List[str] = [
    "paypal", "google", "apple", "microsoft", "amazon", "facebook", "instagram",
    "netflix", "twitter", "linkedin", "dropbox", "gmail", "yahoo", "outlook",
    "chase", "wellsfargo", "bankofamerica", "citi", "hsbc", "barclays",
    "dhl", "fedex", "ups", "usps", "ebay", "walmart", "target", "steam",
    "coinbase", "binance", "robinhood", "stripe", "shopify", "wordpress",
    "icloud", "onedrive", "office365", "docusign", "zoom", "webex"
]

# ──── TLD risk tiers ─────────────────────────────────────────────────────
# Scores based on Spamhaus/Netcraft phishing-per-TLD research
HIGH_RISK_TLDS: Dict[str, float] = {
    # Score 1.0: Extremely over-represented in phishing
    ".tk": 1.0, ".ml": 1.0, ".ga": 1.0, ".cf": 1.0, ".gq": 1.0,
    ".xyz": 0.9, ".top": 0.9, ".work": 0.9, ".loan": 0.9, ".click": 0.9,
    ".club": 0.85, ".online": 0.85, ".site": 0.85, ".win": 0.85, ".bid": 0.85,
    ".link": 0.8, ".info": 0.75, ".buzz": 0.8, ".fun": 0.8, ".space": 0.8,
    ".vip": 0.75, ".shop": 0.7, ".store": 0.7, ".live": 0.7, ".life": 0.65,
    ".pro": 0.6, ".pw": 0.9, ".ws": 0.75, ".cc": 0.7, ".su": 0.75,
}
LOW_RISK_TLDS: Dict[str, float] = {
    ".gov": 0.0, ".edu": 0.0, ".mil": 0.0, ".int": 0.0,
    ".com": 0.1, ".org": 0.15, ".net": 0.2, ".co.uk": 0.1,
    ".gov.uk": 0.0, ".ac.uk": 0.0, ".edu.au": 0.0, ".io": 0.3,
}

SUSPICIOUS_KEYWORDS: List[str] = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "wallet", "confirm", "password", "security", "authenticate", "validation",
    "recover", "billing", "portal", "support", "service", "appleid", "paypal"
]
KNOWN_SHORTENERS: set = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink"
}
HIGH_REPUTATION_DOMAINS: set = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "youtube.com", "googlevideo.com", "android.com", "googleblog.com",
    "google.co.in", "google.co.uk", "google.de", "google.fr", "google.ca",
    "microsoft.com", "office.com", "azure.com", "live.com", "microsoftonline.com",
    "visualstudio.com", "windows.net", "bing.com", "linkedin.com", "github.com",
    "amazon.com", "amazonaws.com", "aws.amazon.com", "media-amazon.com",
    "apple.com", "icloud.com",
    "cloudflare.com", "fastly.com", "akamai.com", "digitalocean.com",
    "docker.com", "gitlab.com", "npmjs.com", "pypi.org",
    "mozilla.org", "wikipedia.org", "wikimedia.org", "chatgpt.com", "openai.com",
    "paypal.com", "stripe.com",
}

# v1 16 features (kept for backward compatibility with deployed model)
FEATURE_NAMES: List[str] = [
    "url_length", "hostname_length", "path_length", "count_dots", "count_hyphens",
    "count_at", "count_question", "count_equal", "count_slash", "count_digits",
    "count_subdomains", "has_ip", "is_https", "has_suspicious_keywords",
    "digit_ratio", "special_char_ratio"
]

# v2 22 features (for next-gen model training)
FEATURE_NAMES_V2: List[str] = FEATURE_NAMES + [
    "tld_risk_score",
    "brand_lookalike",
    "brand_in_subdomain",
    "has_punycode",
    "hostname_entropy",
    "domain_age_days",
]


def normalize_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    url = raw_url.strip()
    url = re.sub(r'[\r\n\t]', '', url)
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = "http://" + url
    return url


def is_valid_ip(hostname: str) -> int:
    if not hostname:
        return 0
    host = hostname.split(':')[0].strip('[]')
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def count_subdomains(hostname: str) -> int:
    if not hostname:
        return 0
    clean_host = hostname.split(':')[0]
    if is_valid_ip(clean_host) or clean_host.lower() == "localhost":
        return 0
    parts = [x for x in clean_host.split('.') if x]
    return max(0, len(parts) - 2)


def extract_apex_domain(hostname: str) -> str:
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
    apex = extract_apex_domain(hostname)
    if not apex:
        return False, ""
    if apex in HIGH_REPUTATION_DOMAINS:
        return True, apex
    if apex.endswith((".gov", ".gov.in", ".gov.uk", ".edu", ".edu.in", ".ac.uk", ".mil")):
        return True, apex
    return False, apex


# ──── NEW feature helpers ────────────────────────────────────────────────

def get_tld_risk_score(hostname: str) -> float:
    """
    Returns a TLD phishing risk score between 0.0 (safe) and 1.0 (very risky).
    Based on Spamhaus/Netcraft empirical TLD risk data.
    """
    if not hostname:
        return 0.5
    clean = hostname.lower().strip(".")
    # Check two-part TLDs first (e.g. co.uk)
    parts = clean.split(".")
    if len(parts) >= 2:
        two = f".{parts[-2]}.{parts[-1]}"
        if two in LOW_RISK_TLDS:
            return LOW_RISK_TLDS[two]
        if two in HIGH_RISK_TLDS:
            return HIGH_RISK_TLDS[two]
    tld = f".{parts[-1]}" if parts else ""
    if tld in HIGH_RISK_TLDS:
        return HIGH_RISK_TLDS[tld]
    if tld in LOW_RISK_TLDS:
        return LOW_RISK_TLDS[tld]
    return 0.35  # Unknown TLD: moderate risk


def levenshtein(s1: str, s2: str) -> int:
    """Fast Levenshtein edit distance."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def check_brand_lookalike(hostname: str) -> int:
    """
    Returns 1 if the hostname looks like a typosquatted version of a top brand.
    Uses Levenshtein distance <= 2 on the SLD (second-level domain) portion.
    Excludes exact matches (those are legit or already caught by allowlist).
    """
    if not hostname:
        return 0
    clean = hostname.lower().strip(".")
    parts = clean.split(".")
    if len(parts) < 2:
        return 0
    # Check the SLD (e.g. "paypall" from "paypall.com")
    sld = parts[-2] if len(parts) >= 2 else ""
    # Also check full subdomain chain for embedded brand names
    for brand in TOP_BRANDS:
        if sld == brand:
            continue   # Exact match = likely legit
        # Edit distance check on SLD
        if len(sld) >= 4 and abs(len(sld) - len(brand)) <= 3:
            dist = levenshtein(sld, brand)
            if dist <= 2:
                return 1
    return 0


def check_brand_in_subdomain(hostname: str) -> int:
    """
    Returns 1 if a brand name appears in the subdomain of a NON-brand apex domain.
    Example: paypal.fakefinance.xyz  (brand=paypal, apex=fakefinance.xyz) -> 1
    """
    if not hostname:
        return 0
    apex = extract_apex_domain(hostname)
    clean = hostname.lower().strip(".")
    # Remove the apex domain to get the subdomain portion
    if apex and clean.endswith(apex):
        subdomain = clean[: len(clean) - len(apex)].strip(".")
    else:
        subdomain = clean
    if not subdomain:
        return 0
    # If the apex itself belongs to a brand, it's legitimate
    apex_sld = apex.split(".")[0] if "." in apex else apex
    if any(apex_sld == brand for brand in TOP_BRANDS):
        return 0
    for brand in TOP_BRANDS:
        if brand in subdomain:
            return 1
    return 0


def has_punycode(hostname: str) -> int:
    """Returns 1 if hostname contains punycode (xn--) IDN encoding."""
    if not hostname:
        return 0
    return 1 if "xn--" in hostname.lower() else 0


def hostname_entropy(hostname: str) -> float:
    """
    Shannon entropy of the hostname (excluding TLD).
    High entropy => random-looking hostname => common in DGA/phishing domains.
    """
    if not hostname:
        return 0.0
    clean = hostname.lower().strip(".")
    # Use only the SLD+subdomain portion
    parts = clean.split(".")
    base = ".".join(parts[:-1]) if len(parts) > 1 else clean
    if not base:
        return 0.0
    freq: Dict[str, int] = {}
    for c in base:
        freq[c] = freq.get(c, 0) + 1
    total = len(base)
    entropy = -sum((count / total) * math.log2(count / total)
                   for count in freq.values() if count > 0)
    return round(entropy, 4)


def get_domain_age_days(hostname: str) -> int:
    """
    Attempts WHOIS lookup for domain creation date.
    Returns days since registration, or -1 if unavailable/error.
    New domains (<30 days old) are a very strong phishing signal.
    NOTE: WHOIS is rate-limited; use only at prediction time, not in batch training.
    """
    if not hostname or is_valid_ip(hostname):
        return -1
    try:
        import whois as python_whois
        from datetime import datetime, timezone
        apex = extract_apex_domain(hostname)
        w = python_whois.whois(apex)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return -1
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - creation).days
        return max(0, age)
    except Exception:
        return -1


# ──── Main feature extraction functions ─────────────────────────────────

def extract_url_features(raw_url: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    v1 backward-compatible: extracts 16 features + suspicious_reasons.
    Used by the currently deployed Random Forest model.
    """
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""
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
    https_flag = 1 if scheme == "https" else 0
    url_lower = normalized.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    keyword_flag = 1 if found_keywords else 0
    digit_ratio = round(digits / max(url_length, 1), 6)
    special_char_ratio = round(specials / max(url_length, 1), 6)

    features: Dict[str, Any] = {
        "url_length": url_length, "hostname_length": hostname_length,
        "path_length": path_length, "count_dots": count_dots,
        "count_hyphens": count_hyphens, "count_at": count_at,
        "count_question": count_question, "count_equal": count_equal,
        "count_slash": count_slash, "count_digits": digits,
        "count_subdomains": subdomains, "has_ip": ip_flag,
        "is_https": https_flag, "has_suspicious_keywords": keyword_flag,
        "digit_ratio": digit_ratio, "special_char_ratio": special_char_ratio,
        "apex_domain": extract_apex_domain(hostname),
        "raw_ml_score": None,
        "is_verified_domain": is_high_reputation_domain(hostname)[0],
    }

    # Suspicious reasons (human-readable explanations)
    suspicious_reasons: List[str] = []
    if ip_flag:
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

    # ── P3: New feature signals appended to suspicious_reasons ──
    tld_risk = get_tld_risk_score(hostname)
    if tld_risk >= 0.8:
        suspicious_reasons.append(f"High-risk TLD detected (risk score: {tld_risk:.1f}/1.0). TLDs like .xyz, .top, .tk are heavily abused for phishing.")
    if check_brand_lookalike(hostname):
        suspicious_reasons.append("Hostname resembles a well-known brand name with slight misspelling (possible typosquatting).")
    if check_brand_in_subdomain(hostname):
        suspicious_reasons.append("A trusted brand name appears in the subdomain of an unrelated domain. Deceptive framing tactic.")
    if has_punycode(hostname):
        suspicious_reasons.append("Hostname contains Punycode (xn--) encoding. Potential homograph/IDN spoofing attack.")
    entropy = hostname_entropy(hostname)
    if entropy > 3.8:
        suspicious_reasons.append(f"High hostname entropy ({entropy:.2f} bits) indicates algorithmically generated or randomized domain name.")

    return features, suspicious_reasons


def extract_url_features_v2(raw_url: str, include_whois: bool = False) -> Tuple[Dict[str, Any], List[str]]:
    """
    v2: extracts all 22 features including new P3 signals.
    Used for next-gen model training. include_whois=True only at inference time.
    """
    features, suspicious_reasons = extract_url_features(raw_url)
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""

    # New v2 features
    features["tld_risk_score"]    = get_tld_risk_score(hostname)
    features["brand_lookalike"]   = check_brand_lookalike(hostname)
    features["brand_in_subdomain"]= check_brand_in_subdomain(hostname)
    features["has_punycode"]      = has_punycode(hostname)
    features["hostname_entropy"]  = hostname_entropy(hostname)
    features["domain_age_days"]   = get_domain_age_days(hostname) if include_whois else -1

    return features, suspicious_reasons


def features_to_vector(features: Dict[str, Any], version: int = 1) -> List[float]:
    """Converts feature dict to ordered vector. version=1 -> 16-D, version=2 -> 22-D."""
    schema = FEATURE_NAMES if version == 1 else FEATURE_NAMES_V2
    return [float(features.get(name, 0.0)) for name in schema]
