import pytest
from app.services.threat_intel import (
    GoogleSafeBrowsingAdapter,
    URLhausAdapter,
    ThreatIntelAggregator
)
from app.core.config import settings


@pytest.mark.anyio
async def test_google_safe_browsing_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", "")
    res = await GoogleSafeBrowsingAdapter.check_url("https://example.com")
    assert res.status == "Not Configured"
    assert res.threat_found is False
    assert "not provided" in res.details


@pytest.mark.anyio
async def test_urlhaus_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "URLHAUS_AUTH_KEY", "")
    res = await URLhausAdapter.check_url("https://example.com")
    assert res.status == "Not Configured"
    assert res.threat_found is False


@pytest.mark.anyio
async def test_threat_aggregator_safe_fallback():
    # Verify aggregator evaluates cleanly without raising exceptions
    results = await ThreatIntelAggregator.evaluate_url("https://example.com/test")
    assert "google_safe_browsing" in results
    assert "urlhaus" in results
    assert results["google_safe_browsing"].threat_found is False
    assert results["urlhaus"].threat_found is False


def test_provider_status_reporting():
    status = ThreatIntelAggregator.get_provider_status()
    assert "google_safe_browsing" in status
    assert "urlhaus" in status