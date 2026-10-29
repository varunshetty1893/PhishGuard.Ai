import asyncio
import time
import httpx
import logging
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlsplit

from app.core.config import settings
from app.services.local_threat_feeds import (
    check_openphish,
    check_phishing_database,
    get_feed_status,
)
from app.services.threat_types import ThreatProviderResult

logger = logging.getLogger("phishguard.threat_intel")

class GoogleSafeBrowsingAdapter:
    """Adapter for Google Safe Browsing Lookup API v4."""
    NAME = "Google Safe Browsing"

    @classmethod
    async def check_url(cls, url: str) -> ThreatProviderResult:
        api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY.strip()
        if not api_key:
            return ThreatProviderResult(
                status="Not Configured",
                threat_found=False,
                details="API key not provided in environment configuration."
            )

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
                "threatEntries": [{"url": url}]
            }
        }

        try:
            async with httpx.AsyncClient(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 200:
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
                    return ThreatProviderResult(
                        status="Unavailable",
                        threat_found=False,
                        details="Invalid or restricted Google Safe Browsing API credentials.",
                        error_message=f"HTTP {resp.status_code}"
                    )
                else:
                    return ThreatProviderResult(
                        status="Unavailable",
                        threat_found=False,
                        details=f"Upstream provider responded with status {resp.status_code}.",
                        error_message=f"HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            logger.warning("Google Safe Browsing request timed out.")
            return ThreatProviderResult(
                status="Unavailable",
                threat_found=False,
                details="Request timed out after 4 seconds.",
                error_message="TimeoutException"
            )
        except Exception as e:
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
            with httpx.Client(timeout=4.0) as client:
                r = client.post(endpoint, json=payload)
                if r.status_code == 200:
                    return "Active"
                elif r.status_code in (400, 403):
                    return "Invalid API Key"
                return f"Unavailable (HTTP {r.status_code})"
        except Exception:
            return "Unavailable"


class PhishDestroyAdapter:
    """Adapter for PhishDestroy's public domain and URL reputation API."""
    ENDPOINT = "https://api.destroy.tools/v1/check"

    @classmethod
    async def check_url(cls, url: str) -> ThreatProviderResult:
        try:
            async with httpx.AsyncClient(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as client:
                response = await client.get(cls.ENDPOINT, params={"domain": url})
            if response.status_code == 200:
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
            return ThreatProviderResult(
                status="Unavailable",
                details=f"PhishDestroy responded with HTTP {response.status_code}.",
                error_message=f"HTTP {response.status_code}",
            )
        except httpx.TimeoutException:
            logger.warning("PhishDestroy request timed out.")
            return ThreatProviderResult(
                status="Unavailable",
                details="PhishDestroy lookup timed out.",
                error_message="TimeoutException",
            )
        except Exception as error:
            logger.error("PhishDestroy lookup error: %s", error)
            return ThreatProviderResult(
                status="Unavailable",
                details="PhishDestroy lookup is unavailable.",
                error_message=str(error),
            )

    @classmethod
    def probe_sync(cls) -> str:
        try:
            response = httpx.get(
                cls.ENDPOINT, params={"domain": "example.com"}, timeout=4.0
            )
            return "Active" if response.status_code == 200 else f"Unavailable (HTTP {response.status_code})"
        except httpx.HTTPError:
            return "Unavailable"


class PhishStatsAdapter:
    """Adapter for PhishStats' anonymous-capable phishing lookup API."""
    ENDPOINT = "https://api.phishstats.info/api/phishing"
    CACHE_TTL_SECONDS = 90 * 60
    _cache: Dict[str, Tuple[float, ThreatProviderResult]] = {}

    @classmethod
    async def check_url(cls, url: str) -> ThreatProviderResult:
        cached = cls._cache.get(url)
        if cached and time.time() - cached[0] < cls.CACHE_TTL_SECONDS:
            return cached[1]

        headers = {}
        api_key = settings.PHISHSTATS_API_KEY.strip()
        if api_key:
            headers["X-API-Key"] = api_key
        try:
            async with httpx.AsyncClient(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as client:
                response = await client.get(
                    cls.ENDPOINT,
                    params={"_where": f"(url,eq,{url})", "_size": 20},
                    headers=headers,
                )
            if response.status_code == 200:
                data = response.json()
                records = data if isinstance(data, list) else data.get("data", [])
                matches = [
                    record for record in records
                    if isinstance(record, dict)
                    and isinstance(record.get("url"), str)
                    and record["url"].rstrip("/").casefold() == url.rstrip("/").casefold()
                ]
                if matches:
                    first_match = matches[0]
                    result = ThreatProviderResult(
                        status="Threat Reported",
                        threat_found=True,
                        category="PHISHING",
                        details=(
                            "PhishStats lists this exact URL as a phishing record."
                            + (f" Reported score: {first_match['score']}." if first_match.get("score") is not None else "")
                        ),
                        raw_response=str(first_match),
                    )
                else:
                    result = ThreatProviderResult(
                        status="No Match Reported",
                        details="PhishStats returned no exact full-URL match.",
                        raw_response=str(data),
                    )
                if len(cls._cache) >= 5000:
                    cls._cache.clear()
                cls._cache[url] = (time.time(), result)
                return result
            details = (
                "PhishStats daily or burst quota was reached; configure PHISHSTATS_API_KEY "
                "or wait for the quota to reset."
                if response.status_code == 429
                else f"PhishStats responded with HTTP {response.status_code}."
            )
            return ThreatProviderResult(
                status="Unavailable",
                details=details,
                error_message=f"HTTP {response.status_code}",
            )
        except httpx.TimeoutException:
            logger.warning("PhishStats request timed out.")
            return ThreatProviderResult(
                status="Unavailable",
                details="PhishStats lookup timed out.",
                error_message="TimeoutException",
            )
        except Exception as error:
            logger.error("PhishStats lookup error: %s", error)
            return ThreatProviderResult(
                status="Unavailable",
                details="PhishStats lookup is unavailable.",
                error_message=str(error),
            )

    @classmethod
    def probe_sync(cls) -> str:
        headers = {}
        api_key = settings.PHISHSTATS_API_KEY.strip()
        if api_key:
            headers["X-API-Key"] = api_key
        try:
            response = httpx.get(
                cls.ENDPOINT,
                params={"_size": 1, "_p": 1},
                headers=headers,
                timeout=4.0,
            )
            return "Active" if response.status_code == 200 else f"Unavailable (HTTP {response.status_code})"
        except httpx.HTTPError:
            return "Unavailable"


class ThreatIntelAggregator:
    """Dispatches checks in priority order and returns every provider result."""

    _cached_status: Optional[Dict[str, str]] = None
    _last_probe_time: float = 0.0
    PROBE_TTL_SECONDS: float = 300.0  # 5 minutes

    @classmethod
    async def evaluate_url(cls, url: str) -> Dict[str, ThreatProviderResult]:
        providers = (
            ("openphish", check_openphish),
            ("phishing_database", check_phishing_database),
            ("phish_destroy", PhishDestroyAdapter.check_url),
            ("phishstats", PhishStatsAdapter.check_url),
            ("google_safe_browsing", GoogleSafeBrowsingAdapter.check_url),
        )
        results = await asyncio.gather(*(check(url) for _, check in providers))
        return {key: result for (key, _), result in zip(providers, results)}

    @classmethod
    def get_provider_status(cls, force_probe: bool = False) -> Dict[str, str]:
        """
        Returns accurate provider status.
        Does NOT report 'Active' merely because a key is present.
        Runs live validation probes with TTL caching.
        """
        now = time.time()
        if (
            not force_probe
            and cls._cached_status is not None
            and (now - cls._last_probe_time) < cls.PROBE_TTL_SECONDS
        ):
            return dict(cls._cached_status)

        feed_status = get_feed_status()
        status_map = {
            "openphish": feed_status["openphish_urls"],
            "phishing_database_urls": feed_status["phishing_database_urls"],
            "phishing_database_domains": feed_status["phishing_database_domains"],
            "phish_destroy": PhishDestroyAdapter.probe_sync(),
            "phishstats": PhishStatsAdapter.probe_sync(),
            "google_safe_browsing": GoogleSafeBrowsingAdapter.probe_sync(),
        }
        cls._cached_status = status_map
        cls._last_probe_time = now
        return dict(status_map)
