import pytest
from app.services.threat_intel import (
    GoogleSafeBrowsingAdapter,
    URLhausAdapter,
    ThreatIntelAggregator
)


@pytest.mark.asyncio
async def test_google_safe_browsing_not_configured():
    # When GOOGLE_SAFE_BROWSING_API_KEY is not set or empty
    res = await GoogleSafeBrowsingAdapter.check_url("https://example.com")
    assert res.status == "Not Configured"
    assert res.threat_found is False
    assert "not provided" in res.details


@pytest.mark.asyncio
async def test_urlhaus_not_configured():
    # When URLHAUS_AUTH_KEY is empty
    res = await URLhausAdapter.check_url("https://example.com")
    assert res.status == "Not Configured"
    assert res.threat_found is False


@pytest.mark.asyncio
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
