import time
import pytest
from fastapi import HTTPException

from app.core.security_validation import validate_url_security, is_prohibited_ip
from app.core.rate_limit import ScanRateLimiter
from app.services.threat_intel import CircuitBreaker


def test_is_prohibited_ip():
    # Loopback
    assert is_prohibited_ip("127.0.0.1") is True
    assert is_prohibited_ip("127.0.0.254") is True
    assert is_prohibited_ip("::1") is True

    # Private RFC 1918
    assert is_prohibited_ip("10.0.0.1") is True
    assert is_prohibited_ip("172.16.5.4") is True
    assert is_prohibited_ip("192.168.1.1") is True

    # Cloud Metadata (AWS/GCP/Azure)
    assert is_prohibited_ip("169.254.169.254") is True

    # Public IPs
    assert is_prohibited_ip("8.8.8.8") is False
    assert is_prohibited_ip("1.1.1.1") is False
    assert is_prohibited_ip("142.250.190.46") is False

    # Invalid / empty
    assert is_prohibited_ip("") is False
    assert is_prohibited_ip("not-an-ip") is False


def test_validate_url_security_prohibits_internal_targets():
    # Prohibit localhost
    safe, reason = validate_url_security("http://localhost:8000/secret")
    assert safe is False
    assert "internal/local" in reason

    # Prohibit loopback IP
    safe, reason = validate_url_security("http://127.0.0.1/admin")
    assert safe is False
    assert "internal/private" in reason

    # Prohibit AWS metadata
    safe, reason = validate_url_security("http://169.254.169.254/latest/meta-data")
    assert safe is False
    assert "internal/private" in reason

    # Prohibit LAN IP
    safe, reason = validate_url_security("https://10.0.1.5/dashboard")
    assert safe is False
    assert "internal/private" in reason

    # Prohibit .local / .internal
    safe, reason = validate_url_security("http://service.internal/api")
    assert safe is False
    assert "internal/local" in reason

    # Prohibit non-HTTP/HTTPS schemes
    safe, reason = validate_url_security("ftp://example.com/file")
    assert safe is False
    assert "scheme" in reason

    safe, reason = validate_url_security("javascript:alert(1)")
    assert safe is False

    # Allow valid public URLs
    safe, reason = validate_url_security("https://google.com/search?q=test")
    assert safe is True
    assert reason is None

    safe, reason = validate_url_security("https://8.8.8.8/dns-query")
    assert safe is True
    assert reason is None


def test_scan_rate_limiter():
    limiter = ScanRateLimiter(max_requests=3, window_seconds=60)
    key = "test_user_1"

    # 3 requests allowed
    limiter.check_scan_rate_limit(key, current_time=100.0)
    limiter.check_scan_rate_limit(key, current_time=101.0)
    limiter.check_scan_rate_limit(key, current_time=102.0)

    # 4th request must be throttled with HTTP 429
    with pytest.raises(HTTPException) as exc_info:
        limiter.check_scan_rate_limit(key, current_time=103.0)

    assert exc_info.value.status_code == 429
    assert "Scan rate limit exceeded" in exc_info.value.detail
    assert "Retry-After" in exc_info.value.headers

    # After window passes, request succeeds
    limiter.check_scan_rate_limit(key, current_time=165.0)


def test_circuit_breaker_lifecycle():
    breaker = CircuitBreaker("mock_provider", failure_threshold=2, recovery_timeout=10.0)

    # Initial: CLOSED
    assert breaker.state == "CLOSED"
    assert breaker.can_execute() is True

    # 1 failure
    breaker.record_failure()
    assert breaker.state == "CLOSED"
    assert breaker.can_execute() is True

    # 2nd failure -> Trips to OPEN
    breaker.record_failure()
    assert breaker.state == "OPEN"
    assert breaker.can_execute() is False

    # Cooldown not elapsed
    breaker.last_state_change = time.time()
    assert breaker.can_execute() is False

    # Simulate cooldown elapsed -> Enters HALF_OPEN
    breaker.last_state_change = time.time() - 15.0
    assert breaker.can_execute() is True
    assert breaker.state == "HALF_OPEN"

    # Successful probe restores to CLOSED
    breaker.record_success()
    assert breaker.state == "CLOSED"
    assert breaker.failure_count == 0

