from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, HttpUrl, field_validator


class ScanRequest(BaseModel):
    url: str = Field(..., description="The URL string to analyze (untrusted input)")

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("URL cannot be empty or pure whitespace.")
        if len(trimmed) > 2048:
            raise ValueError("URL length exceeds maximum permitted threshold of 2048 characters.")
        lower = trimmed.lower()
        if lower.startswith(("javascript:", "data:", "file:", "vbscript:")):
            raise ValueError("Dangerous or unsupported URL scheme detected.")
        return trimmed


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
    predicted_class: str  # Legitimate / Phishing
    risk_level: str       # Low Risk / Suspicious / High Risk
    model_score: Optional[float] = None
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
