import asyncio
import concurrent.futures
import httpx
import logging
import threading
import time
from typing import Dict, Optional, Any
from urllib.parse import urlsplit

from app.core.config import settings
from app.services.local_threat_feeds import (
    check_openphish,
    check_phishing_database,
    check_cert_pl,
    get_feed_status,
)
from app.services.threat_types import ThreatProviderResult

logger = logging.getLogger("phishguard.threat_intel")
# Suppress noisy HTTP request INFO logging from httpx in background workers
logging.getLogger("httpx").setLevel(logging.WARNING)


class CircuitBreaker:
    """
    In-memory Circuit Breaker with 3 states: CLOSED, OPEN, HALF_OPEN.
    Protects latency and system stability when external threat providers degrade or fail.
    """
    def __init__(self, name: str, failure_threshold: int = 3, recovery_timeout: float = 60.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.last_state_change = time.time()
        self._lock = threading.Lock()

    def can_execute(self) -> bool:
        with self._lock:
            now = time.time()
            if self.state == "CLOSED":
                return True
            if self.state == "OPEN":
                if now - self.last_state_change >= self.recovery_timeout:
                    self.state = "HALF_OPEN"
                    self.last_state_change = now
                    logger.info(f"CircuitBreaker [{self.name}] entered HALF_OPEN state (probing test request)")
                    return True
                return False
            if self.state == "HALF_OPEN":
                return True
            return True

    def record_success(self):
        with self._lock:
            if self.state in ("HALF_OPEN", "OPEN"):
                logger.info(f"CircuitBreaker [{self.name}] recovered to CLOSED state")
            self.state = "CLOSED"
            self.failure_count = 0

    def record_failure(self):
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.state == "HALF_OPEN" or self.failure_count >= self.failure_threshold:
                if self.state != "OPEN":
                    logger.warning(
                        f"CircuitBreaker [{self.name}] TRIPPED to OPEN state "
                        f"(failures: {self.failure_count}/{self.failure_threshold}, cooldown: {self.recovery_timeout}s)"
                    )
                self.state = "OPEN"
                self.last_state_change = time.time()

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            remaining = max(0.0, self.recovery_timeout - (now - self.last_state_change)) if self.state == "OPEN" else 0.0
            return {
                "state": self.state,
                "failure_count": self.failure_count,
                "remaining_cooldown_seconds": round(remaining, 1)
            }


class GoogleSafeBrowsingAdapter:
    """Adapter for Google Safe Browsing Lookup API v4 with Circuit Breaker."""
    NAME = "Google Safe Browsing"
    _breaker = CircuitBreaker("google_safe_browsing", failure_threshold=3, recovery_timeout=60.0)

    @classmethod
    async def check_url(cls, url: str) -> ThreatProviderResult:
        if not settings.ENABLE_THIRD_PARTY_LOOKUPS:
            return ThreatProviderResult(
                status="Disabled by Policy",
                threat_found=False,
                details="Third-party external threat intelligence lookups disabled by configuration."
            )

        api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY.strip()
        if not api_key:
            return ThreatProviderResult(
                status="Not Configured",
                threat_found=False,
                details="API key not provided in environment configuration."
            )

        # Circuit breaker check: bypass upstream if repeatedly failing
        if not cls._breaker.can_execute():
            remaining = cls._breaker.get_status()["remaining_cooldown_seconds"]
            return ThreatProviderResult(
                status="Unavailable",
                threat_found=False,
                details=f"Provider temporarily bypassed (Circuit Breaker OPEN, {remaining}s cooldown).",
                error_message="CircuitBreakerOpen"
            )

        # URL minimization: strip sensitive query strings and fragments to protect privacy
        parsed = urlsplit(url)
        clean_path = parsed.path if parsed.path else "/"
        minimized_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{clean_path}"

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {
                "clientId": "phishguard-ai",
                "clientVersion": settings.VERSION
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": minimized_url}]
            }
        }

        try:
            async with httpx.AsyncClient(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    cls._breaker.record_success()
                    data = resp.json()
                    matches = data.get("matches", [])
                    if matches:
                        first_match = matches[0]
                        threat_type = first_match.get("threatType", "THREAT_DETECTED")
                        return ThreatProviderResult(
                            status="Threat Reported",
                            threat_found=True,
                            category=threat_type,
                            details=f"Match identified in Google Safe Browsing database: {threat_type}",
                            raw_response=str(data)
                        )
                    else:
                        return ThreatProviderResult(
                            status="No Match Reported",
                            threat_found=False,
                            details="No malicious records returned by Google Safe Browsing.",
                            raw_response=str(data)
                        )
                elif resp.status_code in (400, 403):
                    # Configuration or credential error
                    return ThreatProviderResult(
                        status="Unavailable",
                        threat_found=False,
                        details="Invalid or restricted Google Safe Browsing API credentials.",
                        error_message=f"HTTP {resp.status_code}"
                    )
                else:
                    cls._breaker.record_failure()
                    return ThreatProviderResult(
                        status="Unavailable",
                        threat_found=False,
                        details=f"Upstream provider responded with status {resp.status_code}.",
                        error_message=f"HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            cls._breaker.record_failure()
            logger.warning("Google Safe Browsing request timed out.")
            return ThreatProviderResult(
                status="Unavailable",
                threat_found=False,
                details=f"Request timed out after {settings.THREAT_INTEL_TIMEOUT_SECONDS} seconds.",
                error_message="TimeoutException"
            )
        except Exception as e:
            cls._breaker.record_failure()
            logger.error(f"Google Safe Browsing lookup error: {e}")
            return ThreatProviderResult(
                status="Unavailable",
                threat_found=False,
                details="External threat lookup unavailable.",
                error_message=str(e)
            )

    @classmethod
    def probe_sync(cls) -> str:
        """Verifies API key validity with a synchronous test query."""
        api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY.strip()
        if not api_key:
            return "Not Configured"

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "phishguard-ai", "clientVersion": settings.VERSION},
            "threatInfo": {
                "threatTypes": ["MALWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": "https://testsafebrowsing.appspot.com/s/malware.html"}]
            }
        }
        try:
            with httpx.Client(timeout=3.0) as client:
                r = client.post(endpoint, json=payload)
                if r.status_code == 200:
                    cls._breaker.record_success()
                    return "Active"
                elif r.status_code in (400, 403):
                    return "Invalid API Key"
                cls._breaker.record_failure()
                return f"Unavailable (HTTP {r.status_code})"
        except Exception:
            cls._breaker.record_failure()
            return "Unavailable"


class PhishDestroyAdapter:
    """Adapter for PhishDestroy's public domain and URL reputation API with Circuit Breaker."""
    ENDPOINT = "https://api.destroy.tools/v1/check"
    _breaker = CircuitBreaker("phish_destroy", failure_threshold=3, recovery_timeout=60.0)

    @classmethod
    async def check_url(cls, url: str) -> ThreatProviderResult:
        if not settings.ENABLE_THIRD_PARTY_LOOKUPS:
            return ThreatProviderResult(
                status="Disabled by Policy",
                threat_found=False,
                details="Third-party external threat intelligence lookups disabled by configuration."
            )

        if not cls._breaker.can_execute():
            remaining = cls._breaker.get_status()["remaining_cooldown_seconds"]
            return ThreatProviderResult(
                status="Unavailable",
                threat_found=False,
                details=f"PhishDestroy temporarily bypassed (Circuit Breaker OPEN, {remaining}s cooldown).",
                error_message="CircuitBreakerOpen"
            )

        try:
            parsed = urlsplit(url)
            host_only = (parsed.hostname or url).lower().strip(".")
            async with httpx.AsyncClient(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as client:
                response = await client.get(cls.ENDPOINT, params={"domain": host_only})
            if response.status_code == 200:
                cls._breaker.record_success()
                data = response.json()
                threat_found = data.get("threat") is True
                return ThreatProviderResult(
                    status="Threat Reported" if threat_found else "No Match Reported",
                    threat_found=threat_found,
                    category="PHISHING_OR_SCAM" if threat_found else None,
                    details=data.get("message") or (
                        "PhishDestroy reports a threat for this domain."
                        if threat_found
                        else "PhishDestroy reports no threat for this domain."
                    ),
                    raw_response=str(data),
                )
            cls._breaker.record_failure()
            return ThreatProviderResult(
                status="Unavailable",
                details=f"PhishDestroy responded with HTTP {response.status_code}.",
                error_message=f"HTTP {response.status_code}",
            )
        except httpx.TimeoutException:
            cls._breaker.record_failure()
            logger.warning("PhishDestroy request timed out.")
            return ThreatProviderResult(
                status="Unavailable",
                details="PhishDestroy lookup timed out.",
                error_message="TimeoutException",
            )
        except Exception as error:
            cls._breaker.record_failure()
            logger.error("PhishDestroy lookup error: %s", error)
            return ThreatProviderResult(
                status="Unavailable",
                details="PhishDestroy lookup is unavailable.",
                error_message=str(error),
            )

    @classmethod
    def probe_sync(cls) -> str:
        try:
            with httpx.Client(timeout=3.0) as client:
                response = client.get(
                    cls.ENDPOINT, params={"domain": "example.com"}
                )
            if response.status_code == 200:
                cls._breaker.record_success()
                return "Active"
            cls._breaker.record_failure()
            return f"Unavailable (HTTP {response.status_code})"
        except Exception:
            cls._breaker.record_failure()
            return "Unavailable"


class ThreatIntelAggregator:
    """Dispatches checks in priority order and returns every provider result."""

    _cached_status: Optional[Dict[str, str]] = None
    _last_probe_time: float = 0.0
    _is_probing: bool = False
    _probe_lock = threading.Lock()
    _probe_thread: Optional[threading.Thread] = None
    PROBE_TTL_SECONDS: float = 300.0  # 5 minutes

    @classmethod
    async def evaluate_url(cls, url: str) -> Dict[str, ThreatProviderResult]:
        providers = (
            ("openphish", check_openphish),
            ("phishing_database", check_phishing_database),
            ("phish_destroy", PhishDestroyAdapter.check_url),
            ("cert_pl", check_cert_pl),
            ("google_safe_browsing", GoogleSafeBrowsingAdapter.check_url),
        )
        results = await asyncio.gather(*(check(url) for _, check in providers))
        return {key: result for (key, _), result in zip(providers, results)}

    @classmethod
    def get_circuit_status(cls) -> Dict[str, Any]:
        """Returns live circuit breaker diagnostics for health and monitoring."""
        return {
            "google_safe_browsing": GoogleSafeBrowsingAdapter._breaker.get_status(),
            "phish_destroy": PhishDestroyAdapter._breaker.get_status(),
        }

    @classmethod
    def _run_concurrent_probes(cls) -> Dict[str, str]:
        """Probes external threat providers in parallel."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut_destroy = executor.submit(PhishDestroyAdapter.probe_sync)
            fut_gsb = executor.submit(GoogleSafeBrowsingAdapter.probe_sync)
            pd_status = fut_destroy.result()
            gsb_status = fut_gsb.result()

        feed_status = get_feed_status()
        return {
            "openphish": feed_status.get("openphish_urls", "Ready"),
            "phishing_database_urls": feed_status.get("phishing_database_urls", "Ready"),
            "phishing_database_domains": feed_status.get("phishing_database_domains", "Ready"),
            "cert_pl_domains": feed_status.get("cert_pl_domains", "Ready"),
            "phish_destroy": pd_status,
            "google_safe_browsing": gsb_status,
        }

    @classmethod
    def _background_probe_worker(cls) -> None:
        try:
            new_status = cls._run_concurrent_probes()
            with cls._probe_lock:
                cls._cached_status = new_status
                cls._last_probe_time = time.time()
        except Exception as err:
            logger.warning(f"Error in background threat intel probe: {err}")
        finally:
            with cls._probe_lock:
                cls._is_probing = False

    @classmethod
    def refresh_probes_background(cls) -> None:
        """Kicks off a background probe thread if not already running."""
        with cls._probe_lock:
            if cls._is_probing:
                return
            cls._is_probing = True
            t = threading.Thread(target=cls._background_probe_worker, daemon=True)
            cls._probe_thread = t
            t.start()

    @classmethod
    def shutdown(cls, timeout: float = 1.0) -> None:
        """Gracefully waits for active background probe threads before termination."""
        with cls._probe_lock:
            t = cls._probe_thread
        if t and t.is_alive():
            t.join(timeout=timeout)

    @classmethod
    def get_provider_status(cls, force_probe: bool = False) -> Dict[str, str]:
        """
        Returns provider status instantly without blocking HTTP requests.
        Uses stale-while-revalidate pattern with parallel background probing.
        """
        now = time.time()
        feed_status = get_feed_status()

        if force_probe:
            cls._cached_status = cls._run_concurrent_probes()
            cls._last_probe_time = now
            return dict(cls._cached_status)

        # If cache expired or not present, start background refresh
        if cls._cached_status is None or (now - cls._last_probe_time) >= cls.PROBE_TTL_SECONDS:
            cls.refresh_probes_background()

        # If cache is populated, return immediately with current feed entries merged
        if cls._cached_status is not None:
            status_map = dict(cls._cached_status)
            status_map.update({
                "openphish": feed_status.get("openphish_urls", "Ready"),
                "phishing_database_urls": feed_status.get("phishing_database_urls", "Ready"),
                "phishing_database_domains": feed_status.get("phishing_database_domains", "Ready"),
                "cert_pl_domains": feed_status.get("cert_pl_domains", "Ready"),
            })
            return status_map

        # Initial fast fallback before first background probe completes
        gsb_initial = "Active" if settings.GOOGLE_SAFE_BROWSING_API_KEY.strip() else "Not Configured"
        return {
            "openphish": feed_status.get("openphish_urls", "Ready"),
            "phishing_database_urls": feed_status.get("phishing_database_urls", "Ready"),
            "phishing_database_domains": feed_status.get("phishing_database_domains", "Ready"),
            "cert_pl_domains": feed_status.get("cert_pl_domains", "Ready"),
            "phish_destroy": "Active",
            "google_safe_browsing": gsb_initial,
        }
