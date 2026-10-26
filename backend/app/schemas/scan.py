import re, ipaddress
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator


APP_PORTS = {5173, 3000, 8000, 8080}
LOCAL_DOMAIN_SUFFIXES = (
    ".localhost", ".local", ".internal", ".lan", ".home", ".test", ".example", ".invalid"
)
FORBIDDEN_SCHEMES = (
    "javascript:", "data:", "file:", "vbscript:", "about:", "blob:",
    "ws:", "wss:", "ftp:", "ftps:", "gopher:", "mailto:", "tel:"
)


def validate_scan_url_string(v: str) -> str:
    """
    Enforces strict URL validation before ingestion:
    - Rejects empty, whitespace, and oversized inputs
    - Rejects internal route paths (e.g., /scanner, /dashboard)
    - Rejects non-HTTP/HTTPS schemes (e.g. javascript:, file:, data:)
    - Rejects localhost and loopback hostnames
    - Rejects private, internal, link-local, and reserved IP addresses (RFC 1918, RFC 3927)
    - Rejects own application ports
    - Permits valid external public IP addresses (e.g., raw IPv4 hosts in threats)
    - Enforces valid domain syntax with recognized TLDs for non-IP hosts
    """
    trimmed = v.strip()
    if not trimmed:
        raise ValueError("URL cannot be empty or pure whitespace.")
    if len(trimmed) > 2048:
        raise ValueError("URL length exceeds maximum permitted threshold of 2,048 characters.")
    if any(c in trimmed for c in " \t\r\n"):
        raise ValueError("Web addresses cannot contain spaces or whitespace characters.")

    # 1. Reject relative internal routes
    if trimmed.startswith("/"):
        raise ValueError("Cannot scan internal application routes (e.g. '/scanner'). Please provide a full external URL.")

    lower = trimmed.lower()

    # 2. Reject non-HTTP/HTTPS schemes
    if lower.startswith(FORBIDDEN_SCHEMES):
        raise ValueError("Only external HTTP and HTTPS web addresses are supported for security scanning.")

    # Prefix http:// if missing scheme for parsing
    test_url = trimmed
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', test_url):
        test_url = "http://" + test_url

    try:
        parsed = urlparse(test_url)
    except Exception as e:
        raise ValueError(f"Malformed URL structure: {str(e)}")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme '{scheme}://'. Only 'http://' and 'https://' are supported.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"'{trimmed}' is not a valid web address (no destination hostname detected).")

    clean_host = hostname.lower().strip('.')

    # 3. Reject localhost and local development domains
    if clean_host == "localhost" or clean_host.endswith(LOCAL_DOMAIN_SUFFIXES):
        raise ValueError(
            f"Scanning local development destinations ('{clean_host}') is prohibited for security isolation."
        )

    # 4. Reject loopback and internal addresses
    if clean_host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        raise ValueError(
            "Scanning localhost, loopback, or internal host addresses is disallowed."
        )

    # 5. Check if host is an IP address
    is_ip = False
    try:
        ip = ipaddress.ip_address(clean_host)
        is_ip = True
        if (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_multicast or
            ip.is_unspecified
        ):
            raise ValueError(
                f"Scanning private or internal network IP addresses ('{clean_host}') is prohibited to protect internal networks."
            )
    except ValueError as ve:
        if is_ip:
            raise ve

    # 6. Reject our own active application ports on loopback/localhost
    port = parsed.port
    if port in APP_PORTS and clean_host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        raise ValueError(
            f"Scanning PhishGuard's own active application port ({port}) is prohibited."
        )

    # 7. Validate domain structure (only when host is NOT a raw IP address)
    if not is_ip:
        parts = [p for p in clean_host.split('.') if p]
        if len(parts) < 2:
            raise ValueError(
                f"'{trimmed}' is not a valid web address. A valid external URL must include a registered domain extension (e.g., .com, .org, or .net)."
            )

        tld = parts[-1]
        if not re.match(r'^[a-zA-Z]{2,}$', tld):
            raise ValueError(f"'{trimmed}' contains an invalid domain extension ('.{tld}').")

        for part in parts:
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', part):
                raise ValueError(f"'{trimmed}' contains an invalid domain component ('{part}').")

    return trimmed


class ScanRequest(BaseModel):
    url: str = Field(..., description="The URL string to analyze (untrusted input)")

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, v: str) -> str:
        return validate_scan_url_string(v)


class ThreatProviderResult(BaseModel):
    status: str = Field(..., description="'Not Configured' | 'No Match Reported' | 'Threat Reported' | 'Unavailable' | 'Inconclusive'")
    threat_found: bool = False
    category: Optional[str] = None
    details: Optional[str] = None


class ThreatIntelligenceSummary(BaseModel):
    google_safe_browsing: ThreatProviderResult
    urlhaus: ThreatProviderResult


class ScanResultResponse(BaseModel):
    scan_id: str
    submitted_url: str
    normalized_url: str
    predicted_class: str      # Legitimate / Suspicious / Phishing
    risk_level: str           # Low Risk / Suspicious / High Risk
    ml_probability: float     # Explicit ML probability (0.0 to 1.0)
    model_score: Optional[float] = None
    raw_ml_score: Optional[float] = None
    is_verified_domain: bool = False
    apex_domain: Optional[str] = None
    threat_intel_match: bool = False
    extracted_features: Dict[str, Any]
    suspicious_reasons: List[str]
    threat_intelligence: ThreatIntelligenceSummary
    combined_interpretation: str
    recommended_precautions: List[str]
    model_version: str
    created_at: datetime


class ScanListItem(BaseModel):
    scan_id: str
    submitted_url: str
    predicted_class: str
    risk_level: str
    model_score: Optional[float]
    created_at: datetime
    threat_intel_match: bool = False


class ScanListResponse(BaseModel):
    total_records: int
    page: int
    page_size: int
    total_pages: int
    items: List[ScanListItem]


class DistributionSlice(BaseModel):
    name: str
    value: int
    color: str


class TemporalDataPoint(BaseModel):
    date: str
    scans: int
    phishing: int


class AnalyticsResponse(BaseModel):
    total_scans: int
    phishing_count: int
    legitimate_count: int
    high_risk_count: int
    threat_intel_matches: int
    threat_intel_failures: int
    classification_distribution: List[DistributionSlice]
    risk_distribution: List[DistributionSlice]
    scans_over_time: List[TemporalDataPoint]
    model_status: Dict[str, Any]
    threat_provider_status: Dict[str, str]

class ModelInfoResponse(BaseModel):
    model_version: str
    algorithm: str
    dataset_name: str
    training_date: str
    total_samples: int
    train_samples: int
    test_samples: int
    evaluation_metrics: Dict[str, float]
    confusion_matrix: Dict[str, int]
    feature_schema: List[str]
    feature_importances: Dict[str, float]
