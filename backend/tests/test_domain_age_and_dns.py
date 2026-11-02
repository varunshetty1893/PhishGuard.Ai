"""
Phase 9 – Domain Age & DNS Rebinding Tests
==========================================
Tests:
1. DomainAgeService.evaluate_age() branching logic (new / neutral / established / unknown)
2. SSRF rejection paths in get_domain_age() (IPs, loopback, internal suffixes)
3. Mocked RDAP live lookup – success path and timeout path (fail-open)
4. check_domain_dns() rebinding rejection (resolved IP is private RFC1918)
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.domain_age import DomainAgeService


# ─── evaluate_age() unit tests ──────────────────────────────────────────────

class TestEvaluateAge:
    """Tests for the pure evaluate_age() scoring logic."""

    def test_none_fails_open(self):
        r = DomainAgeService.evaluate_age(None)
        assert r["score_modifier"] == 0.0
        assert r["is_new"] is False
        assert r["is_established"] is False
        assert r["status"] == "unknown"

    def test_new_domain_raises_score(self):
        r = DomainAgeService.evaluate_age(5)
        assert r["score_modifier"] == 0.25
        assert r["is_new"] is True
        assert r["status"] == "new"

    def test_boundary_29_days_is_new(self):
        r = DomainAgeService.evaluate_age(29)
        assert r["is_new"] is True
        assert r["score_modifier"] == 0.25

    def test_boundary_30_days_is_neutral(self):
        r = DomainAgeService.evaluate_age(30)
        assert r["is_new"] is False
        assert r["score_modifier"] == 0.0
        assert r["status"] == "neutral"

    def test_neutral_domain(self):
        r = DomainAgeService.evaluate_age(365)
        assert r["score_modifier"] == 0.0
        assert r["is_new"] is False
        assert r["is_established"] is False

    def test_boundary_730_days_is_neutral(self):
        r = DomainAgeService.evaluate_age(730)
        assert r["is_established"] is False
        assert r["score_modifier"] == 0.0

    def test_established_domain_reduces_score(self):
        r = DomainAgeService.evaluate_age(731)
        assert r["is_established"] is True
        assert r["score_modifier"] == -0.10
        assert r["status"] == "established"

    def test_very_old_domain(self):
        r = DomainAgeService.evaluate_age(5000)
        assert r["is_established"] is True
        assert r["score_modifier"] == -0.10


# ─── SSRF rejection paths ───────────────────────────────────────────────────

@pytest.mark.asyncio
class TestDomainAgeSSRFRejection:
    """SSRF / invalid domain rejection must not query RDAP."""

    async def test_ip_address_rejected(self):
        age, status = await DomainAgeService.get_domain_age("192.168.1.1")
        assert age is None
        assert status == "invalid_domain"

    async def test_ipv6_rejected(self):
        age, status = await DomainAgeService.get_domain_age("::1")
        assert age is None
        assert status == "invalid_domain"

    async def test_localhost_rejected(self):
        age, status = await DomainAgeService.get_domain_age("localhost")
        assert age is None
        assert status == "invalid_domain"

    async def test_internal_suffix_rejected(self):
        age, status = await DomainAgeService.get_domain_age("myservice.internal")
        assert age is None
        assert status == "invalid_domain"

    async def test_local_suffix_rejected(self):
        age, status = await DomainAgeService.get_domain_age("printer.local")
        assert age is None
        assert status == "invalid_domain"

    async def test_no_dot_rejected(self):
        age, status = await DomainAgeService.get_domain_age("notadomain")
        assert age is None
        assert status == "invalid_domain"


# ─── Mocked RDAP live lookup ─────────────────────────────────────────────────

@pytest.mark.asyncio
class TestDomainAgeLiveLookup:
    """Live RDAP lookup with mocked httpx.AsyncClient."""

    async def test_successful_rdap_response(self):
        """A 200 RDAP response with a registration event parses age correctly."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration",   "eventDate": "2030-01-01T00:00:00Z"},
            ]
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        age, status = await DomainAgeService.get_domain_age(
            "example.com", db=None, client=mock_client
        )
        assert status == "live_lookup"
        assert age is not None
        assert age > 365 * 4  # registered Jan 2020 → >4 years old

    async def test_rdap_timeout_fails_open(self):
        """Timeout must return (None, 'timeout') — never raise."""
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))

        age, status = await DomainAgeService.get_domain_age(
            "example.com", db=None, client=mock_client
        )
        assert age is None
        assert status == "timeout"

    async def test_rdap_404_returns_not_found(self):
        """404 from RDAP returns 'not_found', not an error."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        age, status = await DomainAgeService.get_domain_age(
            "newdomain.example", db=None, client=mock_client
        )
        assert age is None
        assert status == "not_found"

    async def test_rdap_exception_fails_open(self):
        """Any unexpected exception must not bubble up — fail open."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=RuntimeError("unexpected network error"))

        age, status = await DomainAgeService.get_domain_age(
            "example.com", db=None, client=mock_client
        )
        assert age is None
        assert status == "error"


# ─── DNS rebinding protection ────────────────────────────────────────────────

class TestDNSRebindingProtection:
    """
    check_domain_dns() in scan.py rejects resolved IPs that are RFC1918/loopback.
    We test the underlying is_prohibited_ip() validation logic from security_validation.
    """

    def test_rfc1918_10_is_prohibited(self):
        from app.core.security_validation import is_prohibited_ip
        assert is_prohibited_ip("10.0.0.1") is True

    def test_rfc1918_172_16_is_prohibited(self):
        from app.core.security_validation import is_prohibited_ip
        assert is_prohibited_ip("172.16.100.50") is True

    def test_rfc1918_192_168_is_prohibited(self):
        from app.core.security_validation import is_prohibited_ip
        assert is_prohibited_ip("192.168.1.254") is True

    def test_loopback_is_prohibited(self):
        from app.core.security_validation import is_prohibited_ip
        assert is_prohibited_ip("127.0.0.1") is True

    def test_link_local_metadata_is_prohibited(self):
        from app.core.security_validation import is_prohibited_ip
        assert is_prohibited_ip("169.254.169.254") is True

    def test_public_ip_is_not_prohibited(self):
        from app.core.security_validation import is_prohibited_ip
        assert is_prohibited_ip("8.8.8.8") is False

    def test_public_ip_cloudflare_is_not_prohibited(self):
        from app.core.security_validation import is_prohibited_ip
        assert is_prohibited_ip("1.1.1.1") is False

