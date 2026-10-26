"""
Unit tests verifying Prompt 7:
1. Exact brand domains are allowed, while shared hosting / platform domains are strictly blocked.
2. Threat intelligence match (GSB / URLhaus) ALWAYS overrides allowlist & ML verdict.
3. Phishing URLs on hosting platforms (firebaseapp, github.io, s3.amazonaws.com) are not whitelisted.
"""

import pytest
from unittest.mock import patch, AsyncMock
from app.ml.feature_extraction import is_high_reputation_domain
from app.services.threat_intel import ThreatProviderResult
from app.services.ml_inference import MLInferenceService


def test_allowlist_exact_brands_allowed():
    """Exact brand-owned domains and authoritative government/academic roots must be allowed."""
    allowed_samples = [
        "google.com",
        "accounts.google.com",
        "microsoft.com",
        "login.microsoftonline.com",
        "apple.com",
        "paypal.com",
        "stripe.com",
        "whitehouse.gov",
        "mit.edu",
        "cam.ac.uk"
    ]
    for host in allowed_samples:
        is_trusted, apex = is_high_reputation_domain(host)
        assert is_trusted is True, f"Expected {host} to be recognized as high-reputation."


def test_allowlist_shared_hosting_and_platforms_strictly_disallowed():
    """Shared-hosting, PaaS, and user-content domains must NEVER be marked high-reputation."""
    disallowed_samples = [
        "amazonaws.com",
        "s3.amazonaws.com",
        "my-bucket.s3.amazonaws.com",
        "windows.net",
        "blob.core.windows.net",
        "phish.blob.core.windows.net",
        "googleusercontent.com",
        "lh3.googleusercontent.com",
        "github.io",
        "attacker.github.io",
        "firebaseapp.com",
        "secure-login.firebaseapp.com",
        "web.app",
        "verify-account.web.app",
        "azurewebsites.net",
        "portal-login.azurewebsites.net",
        "pages.dev",
        "vercel.app",
        "netlify.app",
        "digitalocean.com"
    ]
    for host in disallowed_samples:
        is_trusted, apex = is_high_reputation_domain(host)
        assert is_trusted is False, f"Critical security issue: {host} was improperly whitelisted as high-reputation!"


def test_ml_inference_hosting_domain_not_protected():
    """Phishing URL hosted on a cloud platform must not receive allowlist protection."""
    test_url = "https://phish-secure-verify.firebaseapp.com/login"
    result = MLInferenceService.predict(test_url)
    assert result["is_verified_domain"] is False
    assert result["apex_domain"] == "firebaseapp.com"


def test_threat_intel_overrides_high_reputation_allowlist(client):
    """
    Even if a URL belongs to a high-reputation domain (e.g. compromised or open redirect),
    a positive hit from Google Safe Browsing or URLhaus MUST override the allowlist
    and classify the URL as Phishing / High Risk.
    """
    fake_gsb_hit = ThreatProviderResult(
        status="Threat Reported",
        threat_found=True,
        category="SOCIAL_ENGINEERING",
        details="Compromised credential harvester detected on Google Safe Browsing."
    )
    fake_urlhaus_clean = ThreatProviderResult(
        status="No Match Reported",
        threat_found=False,
        details="No match."
    )

    with patch("app.services.threat_intel.GoogleSafeBrowsingAdapter.check_url", new=AsyncMock(return_value=fake_gsb_hit)), \
         patch("app.services.threat_intel.URLhausAdapter.check_url", new=AsyncMock(return_value=fake_urlhaus_clean)):

        response = client.post(
            "/api/v1/scan",
            json={"url": "https://accounts.google.com/malicious/redirect"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["predicted_class"] == "Phishing", "Threat intelligence hit failed to override allowlist!"
        assert data["risk_level"] == "High Risk"
        assert data["threat_intel_match"] is True
        assert data["model_score"] == 1.0
        assert "Confirmed Threat" in data["combined_interpretation"]
