import os
import pytest
from app.ml.feature_extraction import (
    extract_url_features,
    features_to_vector,
    normalize_url,
    FEATURE_NAMES,
    is_valid_ip,
    count_subdomains
)
from app.services.ml_inference import MLInferenceService


def test_normalize_url():
    assert normalize_url("google.com") == "http://google.com"
    assert normalize_url("https://secure.bank.com/login") == "https://secure.bank.com/login"
    assert normalize_url("   http://test.com\r\n  ") == "http://test.com"


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1") == 1
    assert is_valid_ip("10.0.0.1:8080") == 1
    assert is_valid_ip("google.com") == 0
    assert is_valid_ip("") == 0


def test_count_subdomains():
    assert count_subdomains("example.com") == 0
    assert count_subdomains("sub.example.com") == 1
    assert count_subdomains("a.b.c.example.com") == 3
    assert count_subdomains("192.168.1.1") == 0


def test_feature_extraction_schema():
    url = "http://login.paypal.com.account-verify.xyz/signin?token=123"
    features, reasons = extract_url_features(url)
    
    assert len(features) == len(FEATURE_NAMES)
    for name in FEATURE_NAMES:
        assert name in features
        assert isinstance(features[name], (int, float))
        
    assert features["count_dots"] >= 4
    assert features["has_suspicious_keywords"] == 1
    assert len(reasons) > 0


def test_features_to_vector_order():
    url = "https://example.edu/research"
    features, _ = extract_url_features(url)
    vector = features_to_vector(features)
    
    assert len(vector) == len(FEATURE_NAMES)
    assert vector[FEATURE_NAMES.index("is_https")] == 1.0


def test_ml_model_prediction():
    MLInferenceService.load()
    assert MLInferenceService.is_loaded() is True
    
    # Test high-risk phishing URL
    phish_res = MLInferenceService.predict("http://login.paypal.com.account-verify.xyz/signin")
    assert phish_res["predicted_class"] == "Phishing"
    assert phish_res["risk_level"] in ("High Risk", "Suspicious")
    assert phish_res["model_score"] is not None
    assert len(phish_res["suspicious_reasons"]) > 0
    
    # Test legitimate URL
    legit_res = MLInferenceService.predict("https://wikipedia.org/wiki/Computer_science")
    assert legit_res["predicted_class"] == "Legitimate"
    assert legit_res["risk_level"] == "Low Risk"
    assert legit_res["model_score"] < 0.40
