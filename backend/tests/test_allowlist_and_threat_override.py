"""
Unit tests verifying Prompt 7:
1. Exact brand domains are allowed, while shared hosting / platform domains are strictly blocked.
2. Any threat-intelligence match ALWAYS overrides the allowlist & ML verdict.
3. Phishing URLs on hosting platforms (firebaseapp, github.io, s3.amazonaws.com) are not whitelisted.
"""

from contextlib import ExitStack, contextmanager
from unittest.mock import AsyncMock, patch
import pytest
from app.ml.feature_extraction import is_high_reputation_domain
from app.services.threat_intel import ThreatProviderResult
from app.services.ml_inference import MLInferenceService


@contextmanager
def mock_threat_intel(**overrides):
    clean_result = ThreatProviderResult(
        status="No Match Reported",
        threat_found=False,
        details="No match.",
    )
    providers = {
        "openphish": "app.services.threat_intel.check_openphish",
        "phishing_database": "app.services.threat_intel.check_phishing_database",
        "phish_destroy": "app.services.threat_intel.PhishDestroyAdapter.check_url",
        "cert_pl": "app.services.threat_intel.check_cert_pl",
        "google_safe_browsing": "app.services.threat_intel.GoogleSafeBrowsingAdapter.check_url",
    }
    with ExitStack() as stack:
        for key, target in providers.items():
            result = overrides.get(key, clean_result)
            stack.enter_context(
                patch(target, new=AsyncMock(return_value=result))
            )
        yield


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


@pytest.mark.requires_ml_model
def test_ml_inference_hosting_domain_not_protected():
    """Phishing URL hosted on a cloud platform must not receive allowlist protection."""
    test_url = "https://phish-secure-verify.firebaseapp.com/login"
    result = MLInferenceService.predict(test_url)
    assert result["is_verified_domain"] is False
    assert result["apex_domain"] == "firebaseapp.com"


@pytest.mark.requires_ml_model
def test_threat_intel_overrides_high_reputation_allowlist(client):
    """
    Even if a URL belongs to a high-reputation domain (e.g. compromised or open redirect),
    a positive hit from any configured threat provider MUST override the allowlist
    and classify the URL as Phishing / High Risk.
    """
    fake_gsb_hit = ThreatProviderResult(
        status="Threat Reported",
        threat_found=True,
        category="SOCIAL_ENGINEERING",
        details="Compromised credential harvester detected on Google Safe Browsing."
    )
    with mock_threat_intel(google_safe_browsing=fake_gsb_hit):
        response = client.post(
            "/api/v1/scan",
            json={"url": "https://accounts.google.com/malicious/redirect"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["predicted_class"] == "Confirmed Phishing (known blocklist)", "Threat intelligence hit failed to override allowlist!"
        assert data["risk_level"] == "High Risk"
        assert data["threat_intel_match"] is True
        assert data["model_score"] == data["ml_probability"]
        assert "Confirmed Phishing (known blocklist)" in data["combined_interpretation"]


@pytest.mark.requires_ml_model
def test_openphish_match_is_treated_as_harmful(client):
    openphish_match = ThreatProviderResult(
        status="Threat Reported",
        threat_found=True,
        category="PHISHING",
        details="Exact URL match in OpenPhish.",
    )

    with mock_threat_intel(openphish=openphish_match):
        response = client.post(
            "/api/v1/scan",
            json={"url": "https://accounts.google.com/community-reported"}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["predicted_class"] == "Confirmed Phishing (known blocklist)"
    assert data["risk_level"] == "High Risk"
    assert data["threat_intel_match"] is True
    assert data["model_score"] == data["ml_probability"]
    assert data["threat_intelligence"]["openphish"]["threat_found"] is True
    assert "OpenPhish" in data["combined_interpretation"]


@pytest.mark.requires_ml_model
def test_user_content_hosts_and_repos_not_verified():
    """
    User-content hosts (Google Forms, Google Sites, Google Drive, user GitHub repos)
    must NOT receive verified allowlist status, while authentic core portals (accounts.google.com,
    www.paypal.com, and github.com root) MUST remain verified.
    """
    unverified_urls = [
        "https://docs.google.com/forms/d/e/1FAIpQLSc_phish/viewform",
        "https://sites.google.com/view/fake-login-update",
        "https://drive.google.com/file/d/1A2B3C_malware/view",
        "https://forms.google.com/d/e/12345/viewform",
        "https://forms.gle/xyzPhish",
        "https://github.com/phish-actor/credential-harvester",
        "https://github.com/someuser/repo/archive/main.zip",
    ]
    for url in unverified_urls:
        result = MLInferenceService.predict(url)
        assert result["is_verified_domain"] is False, f"Expected {url} to NOT be verified!"

    verified_urls = [
        "https://accounts.google.com/signin/v2/identifier",
        "https://www.paypal.com/signin",
        "https://github.com",
        "https://github.com/",
        "https://whitehouse.gov",
    ]
    for url in verified_urls:
        result = MLInferenceService.predict(url)
        assert result["is_verified_domain"] is True, f"Expected {url} to be verified!"
