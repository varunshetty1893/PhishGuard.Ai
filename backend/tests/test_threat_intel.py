import time
from unittest.mock import AsyncMock, patch

import pytest

from app.core.config import settings
from app.services import local_threat_feeds
from app.services.threat_intel import (
    GoogleSafeBrowsingAdapter,
    PhishDestroyAdapter,
    ThreatIntelAggregator,
)


@pytest.mark.anyio
async def test_google_safe_browsing_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", "")
    result = await GoogleSafeBrowsingAdapter.check_url("https://example.com")
    assert result.status == "Not Configured"
    assert result.threat_found is False
    assert "not provided" in result.details


def _insert_cached_feed(monkeypatch, tmp_path, feed_key, value):
    monkeypatch.setattr(local_threat_feeds, "_DB_PATH", tmp_path / "feeds.sqlite3")
    with local_threat_feeds._connect() as connection:
        connection.execute(
            "INSERT INTO feed_entries (feed_key, value) VALUES (?, ?)",
            (feed_key, value),
        )
        connection.execute(
            "INSERT INTO feed_metadata (feed_key, etag, refreshed_at, entry_count) VALUES (?, NULL, ?, 1)",
            (feed_key, time.time()),
        )
    monkeypatch.setattr(local_threat_feeds, "_schedule_refresh", lambda: None)


@pytest.mark.anyio
async def test_openphish_matches_exact_full_url(monkeypatch, tmp_path):
    url = "https://reported.example/login?campaign=1"
    _insert_cached_feed(monkeypatch, tmp_path, "openphish_urls", url)

    result = await local_threat_feeds.check_openphish(url)

    assert result.status == "Threat Reported"
    assert result.threat_found is True
    assert result.category == "PHISHING"


@pytest.mark.anyio
async def test_phishing_database_matches_subdomains(monkeypatch, tmp_path):
    _insert_cached_feed(monkeypatch, tmp_path, "phishing_database_domains", "reported.example")
    with local_threat_feeds._connect() as connection:
        connection.execute(
            "INSERT INTO feed_metadata (feed_key, etag, refreshed_at, entry_count) VALUES (?, NULL, ?, 1)",
            ("phishing_database_urls", time.time()),
        )

    result = await local_threat_feeds.check_phishing_database(
        "https://login.reported.example/auth"
    )

    assert result.status == "Threat Reported"
    assert result.threat_found is True
    assert "reported.example" in result.details


@pytest.mark.anyio
async def test_phishing_database_unavailable_cache_is_not_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(local_threat_feeds, "_DB_PATH", tmp_path / "empty.sqlite3")
    monkeypatch.setattr(local_threat_feeds, "_schedule_refresh", lambda: None)

    result = await local_threat_feeds.check_phishing_database("https://example.com")

    assert result.status == "Unavailable"
    assert result.threat_found is False
    assert "still downloading or unavailable" in result.details


@pytest.mark.anyio
async def test_phishdestroy_reports_domain_threat(monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"domain": "reported.example", "threat": True, "message": "Known scam"}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, endpoint, **kwargs):
            assert endpoint == PhishDestroyAdapter.ENDPOINT
            assert kwargs["params"] == {"domain": "https://reported.example/login"}
            return FakeResponse()

    monkeypatch.setattr(
        "app.services.threat_intel.httpx.AsyncClient", lambda **_: FakeClient()
    )
    result = await PhishDestroyAdapter.check_url("https://reported.example/login")

    assert result.status == "Threat Reported"
    assert result.threat_found is True
    assert result.details == "Known scam"


@pytest.mark.anyio
async def test_cert_pl_warning_list_matches_subdomains(monkeypatch, tmp_path):
    _insert_cached_feed(monkeypatch, tmp_path, "cert_pl_domains", "reported.example")

    result = await local_threat_feeds.check_cert_pl(
        "https://login.reported.example/auth"
    )

    assert result.status == "Threat Reported"
    assert result.threat_found is True
    assert "CERT-PL" in result.details


@pytest.mark.anyio
async def test_cert_pl_unavailable_cache_is_not_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(local_threat_feeds, "_DB_PATH", tmp_path / "empty.sqlite3")
    monkeypatch.setattr(local_threat_feeds, "_schedule_refresh", lambda: None)

    result = await local_threat_feeds.check_cert_pl("https://example.com")

    assert result.status == "Unavailable"
    assert result.threat_found is False
    assert "still downloading or unavailable" in result.details


@pytest.mark.anyio
async def test_threat_aggregator_returns_sources_in_priority_order():
    clean_result = type(
        "CleanResult",
        (),
        {"status": "No Match Reported", "threat_found": False, "details": "No match"},
    )()
    with (
        patch("app.services.threat_intel.check_openphish", new=AsyncMock(return_value=clean_result)),
        patch("app.services.threat_intel.check_phishing_database", new=AsyncMock(return_value=clean_result)),
        patch("app.services.threat_intel.PhishDestroyAdapter.check_url", new=AsyncMock(return_value=clean_result)),
        patch("app.services.threat_intel.check_cert_pl", new=AsyncMock(return_value=clean_result)),
        patch("app.services.threat_intel.GoogleSafeBrowsingAdapter.check_url", new=AsyncMock(return_value=clean_result)),
    ):
        results = await ThreatIntelAggregator.evaluate_url("https://example.com/test")

    assert list(results) == [
        "openphish",
        "phishing_database",
        "phish_destroy",
        "cert_pl",
        "google_safe_browsing",
    ]
    assert all(not result.threat_found for result in results.values())


def test_provider_status_reporting():
    with (
        patch(
            "app.services.threat_intel.get_feed_status",
            return_value={
                "openphish_urls": "Ready",
                "phishing_database_urls": "Ready",
                "phishing_database_domains": "Ready",
                "cert_pl_domains": "Ready",
            },
        ),
        patch.object(PhishDestroyAdapter, "probe_sync", return_value="Active"),
        patch.object(GoogleSafeBrowsingAdapter, "probe_sync", return_value="Not Configured"),
    ):
        status = ThreatIntelAggregator.get_provider_status(force_probe=True)

    assert status["openphish"] == "Ready"
    assert status["phishing_database_domains"] == "Ready"
    assert status["phish_destroy"] == "Active"
    assert status["cert_pl_domains"] == "Ready"
    assert status["google_safe_browsing"] == "Not Configured"


def test_provider_status_refreshes_feed_status_without_waiting_for_probe_cache(monkeypatch):
    monkeypatch.setattr(
        ThreatIntelAggregator,
        "_cached_status",
        {
            "openphish": "Not Loaded",
            "phishing_database_urls": "Not Loaded",
            "phishing_database_domains": "Not Loaded",
            "cert_pl_domains": "Not Loaded",
            "phish_destroy": "Active",
            "google_safe_browsing": "Not Configured",
        },
    )
    monkeypatch.setattr(ThreatIntelAggregator, "_last_probe_time", time.time())
    monkeypatch.setattr(
        "app.services.threat_intel.get_feed_status",
        lambda: {
            "openphish_urls": "Ready (299 entries)",
            "phishing_database_urls": "Ready (788,969 entries)",
            "phishing_database_domains": "Ready (392,083 entries)",
            "cert_pl_domains": "Ready (10,000 entries)",
        },
    )

    status = ThreatIntelAggregator.get_provider_status()

    assert status["openphish"] == "Ready (299 entries)"
    assert status["phishing_database_urls"] == "Ready (788,969 entries)"
    assert status["phishing_database_domains"] == "Ready (392,083 entries)"
    assert status["cert_pl_domains"] == "Ready (10,000 entries)"
