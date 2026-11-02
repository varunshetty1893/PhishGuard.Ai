import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.scan import DomainAgeCache
from app.services.domain_age import DomainAgeService


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_parse_registration_date():
    # Registration action
    data1 = {
        "events": [
            {"eventAction": "registration", "eventDate": "2024-01-15T12:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2025-01-15T12:00:00Z"}
        ]
    }
    dt1 = DomainAgeService._parse_registration_date(data1)
    assert dt1 is not None
    assert dt1.year == 2024
    assert dt1.month == 1
    assert dt1.day == 15

    # Created action
    data2 = {
        "events": [
            {"eventAction": "created", "eventDate": "2020-05-20T00:00:00+00:00"}
        ]
    }
    dt2 = DomainAgeService._parse_registration_date(data2)
    assert dt2 is not None
    assert dt2.year == 2020

    # No registration action
    data3 = {
        "events": [
            {"eventAction": "last changed", "eventDate": "2023-01-01T00:00:00Z"}
        ]
    }
    assert DomainAgeService._parse_registration_date(data3) is None

    # Empty / malformed
    assert DomainAgeService._parse_registration_date({}) is None
    assert DomainAgeService._parse_registration_date({"events": "invalid"}) is None


def test_evaluate_age_fail_open():
    """Fail open: unknown age MUST NOT raise the score or add suspicion."""
    eval_none = DomainAgeService.evaluate_age(None)
    assert eval_none["age_days"] is None
    assert eval_none["is_new"] is False
    assert eval_none["is_established"] is False
    assert eval_none["score_modifier"] == 0.0
    assert eval_none["reason"] is None
    assert eval_none["status"] == "unknown"


def test_evaluate_age_new_domain():
    """Under 30 days old adds a strong suspicious signal."""
    eval_new = DomainAgeService.evaluate_age(12)
    assert eval_new["is_new"] is True
    assert eval_new["is_established"] is False
    assert eval_new["score_modifier"] == 0.25
    assert "Newly registered domain (12 days old" in eval_new["reason"]


def test_evaluate_age_established_domain():
    """Over 2 years old (730 days) reduces suspicion."""
    eval_est = DomainAgeService.evaluate_age(1200)
    assert eval_est["is_new"] is False
    assert eval_est["is_established"] is True
    assert eval_est["score_modifier"] == -0.10
    assert "Established domain (1200 days old" in eval_est["reason"]


def test_evaluate_age_neutral():
    """Between 30 and 730 days is neutral."""
    eval_neutral = DomainAgeService.evaluate_age(180)
    assert eval_neutral["is_new"] is False
    assert eval_neutral["is_established"] is False
    assert eval_neutral["score_modifier"] == 0.0
    assert eval_neutral["reason"] is None


@pytest.mark.asyncio
async def test_get_domain_age_mocked_success(in_memory_db):
    reg_date_str = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "events": [
            {"eventAction": "registration", "eventDate": reg_date_str}
        ]
    }

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)

    age_days, status = await DomainAgeService.get_domain_age(
        "brand-new-phish-domain.com",
        db=in_memory_db,
        client=mock_client
    )
    assert age_days == 15
    assert status == "live_lookup"

    # Verify cached in SQLite
    cached_entry = in_memory_db.query(DomainAgeCache).filter_by(domain="brand-new-phish-domain.com").first()
    assert cached_entry is not None
    assert cached_entry.age_days == 15

    # Second call uses cache with NO http request made
    mock_client.get.reset_mock()
    cached_age, cached_status = await DomainAgeService.get_domain_age(
        "brand-new-phish-domain.com",
        db=in_memory_db,
        client=mock_client
    )
    assert cached_age == 15
    assert cached_status == "cache_hit"
    mock_client.get.assert_not_called()


@pytest.mark.asyncio
async def test_get_domain_age_timeout_fail_open(in_memory_db):
    """3-second timeout fails open and returns None without raising exceptions."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("RDAP timeout"))

    age_days, status = await DomainAgeService.get_domain_age(
        "slow-lookup.org",
        db=in_memory_db,
        client=mock_client
    )
    assert age_days is None
    assert status == "timeout"


@pytest.mark.asyncio
async def test_get_domain_age_http_404_fail_open(in_memory_db):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)

    age_days, status = await DomainAgeService.get_domain_age(
        "not-in-rdap.xyz",
        db=in_memory_db,
        client=mock_client
    )
    assert age_days is None
    assert status == "not_found"
