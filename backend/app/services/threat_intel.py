import time
import httpx
import logging
from typing import Dict, Any, Optional
from app.core.config import settings

logger = logging.getLogger("phishguard.threat_intel")


class ThreatProviderResult:
    """Standardized representation of external threat feed response."""
    def __init__(
        self,
        status: str,  # 'Threat Reported', 'No Match Reported', 'Not Configured', 'Unavailable', 'Inconclusive'
        threat_found: bool = False,
        category: Optional[str] = None,
        details: Optional[str] = None,
        raw_response: Optional[str] = None,
        error_message: Optional[str] = None
    ):
        self.status = status
        self.threat_found = threat_found
        self.category = category
        self.details = details
        self.raw_response = raw_response
        self.error_message = error_message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "threat_found": self.threat_found,
            "category": self.category,
            "details": self.details
        }


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


class URLhausAdapter:
    """Adapter for abuse.ch URLhaus API."""
    NAME = "URLhaus"
    ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

    @classmethod
    async def check_url(cls, url: str) -> ThreatProviderResult:
        auth_key = settings.URLHAUS_AUTH_KEY.strip()
        if not auth_key:
            return ThreatProviderResult(
                status="Not Configured",
                threat_found=False,
                details="Auth-Key not provided in environment configuration."
            )

        headers = {"Auth-Key": auth_key}

        try:
            async with httpx.AsyncClient(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as client:
                resp = await client.post(cls.ENDPOINT, data={"url": url}, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    query_status = data.get("query_status")
                    if query_status == "ok":
                        url_status = data.get("url_status", "active")
                        threat = data.get("threat", "malware_download")
                        tags = data.get("tags") or []
                        tag_str = f" (tags: {', '.join(tags)})" if tags else ""
                        return ThreatProviderResult(
                            status="Threat Reported",
                            threat_found=True,
                            category=threat.upper(),
                            details=f"Malicious payload recorded on URLhaus ({url_status}){tag_str}.",
                            raw_response=str(data)
                        )
                    elif query_status == "no_results":
                        return ThreatProviderResult(
                            status="No Match Reported",
                            threat_found=False,
                            details="No malware or payload distribution record found in URLhaus.",
                            raw_response=str(data)
                        )
                    else:
                        return ThreatProviderResult(
                            status="Inconclusive",
                            threat_found=False,
                            details=f"URLhaus reported status: {query_status}",
                            raw_response=str(data)
                        )
                elif resp.status_code == 403:
                    try:
                        err_data = resp.json()
                        if err_data.get("query_status") == "unknown_auth_key":
                            return ThreatProviderResult(
                                status="Unavailable",
                                threat_found=False,
                                details="Invalid URLhaus Auth-Key: abuse.ch returned 'unknown_auth_key'. Verify your Auth-Key at https://urlhaus.abuse.ch/api/.",
                                error_message="HTTP 403: unknown_auth_key"
                            )
                    except Exception:
                        pass
                    return ThreatProviderResult(
                        status="Unavailable",
                        threat_found=False,
                        details="Access forbidden by URLhaus (HTTP 403). Check your Auth-Key credentials.",
                        error_message="HTTP 403"
                    )
                else:
                    return ThreatProviderResult(
                        status="Unavailable",
                        threat_found=False,
                        details=f"URLhaus endpoint responded with HTTP {resp.status_code}.",
                        error_message=f"HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            logger.warning("URLhaus request timed out.")
            return ThreatProviderResult(
                status="Unavailable",
                threat_found=False,
                details="Request timed out after 4 seconds.",
                error_message="TimeoutException"
            )
        except Exception as e:
            logger.error(f"URLhaus lookup error: {e}")
            return ThreatProviderResult(
                status="Unavailable",
                threat_found=False,
                details="External threat lookup unavailable.",
                error_message=str(e)
            )

    @classmethod
    def probe_sync(cls) -> str:
        """Verifies Auth-Key validity with a synchronous test query."""
        auth_key = settings.URLHAUS_AUTH_KEY.strip()
        if not auth_key:
            return "Not Configured"

        try:
            with httpx.Client(timeout=4.0) as client:
                r = client.post(cls.ENDPOINT, data={"url": "https://google.com"}, headers={"Auth-Key": auth_key})
                if r.status_code == 200:
                    data = r.json()
                    if data.get("query_status") in ("ok", "no_results"):
                        return "Active"
                    return f"Inconclusive ({data.get('query_status')})"
                elif r.status_code == 403:
                    try:
                        err_data = r.json()
                        if err_data.get("query_status") == "unknown_auth_key":
                            return "Invalid Auth Key"
                    except Exception:
                        pass
                    return "Forbidden (403)"
                return f"Unavailable (HTTP {r.status_code})"
        except Exception:
            return "Unavailable"


class ThreatIntelAggregator:
    """Dispatches independent lookups across all configured threat providers."""

    _cached_status: Optional[Dict[str, str]] = None
    _last_probe_time: float = 0.0
    PROBE_TTL_SECONDS: float = 300.0  # 5 minutes

    @classmethod
    async def evaluate_url(cls, url: str) -> Dict[str, ThreatProviderResult]:
        # Execute lookups concurrently/safely
        gsb_result = await GoogleSafeBrowsingAdapter.check_url(url)
        urlhaus_result = await URLhausAdapter.check_url(url)

        # Dynamically refresh cached status based on live lookups
        if cls._cached_status is None:
            cls._cached_status = {}

        if gsb_result.status == "Not Configured":
            cls._cached_status["google_safe_browsing"] = "Not Configured"
        elif gsb_result.status in ("Threat Reported", "No Match Reported"):
            cls._cached_status["google_safe_browsing"] = "Active"
        elif "Invalid" in (gsb_result.details or ""):
            cls._cached_status["google_safe_browsing"] = "Invalid API Key"

        if urlhaus_result.status == "Not Configured":
            cls._cached_status["urlhaus"] = "Not Configured"
        elif urlhaus_result.status in ("Threat Reported", "No Match Reported"):
            cls._cached_status["urlhaus"] = "Active"
        elif "unknown_auth_key" in (urlhaus_result.error_message or ""):
            cls._cached_status["urlhaus"] = "Invalid Auth Key"

        return {
            "google_safe_browsing": gsb_result,
            "urlhaus": urlhaus_result
        }

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

        # Run live synchronous probe
        status_map = {
            "google_safe_browsing": GoogleSafeBrowsingAdapter.probe_sync(),
            "urlhaus": URLhausAdapter.probe_sync()
        }
        cls._cached_status = status_map
        cls._last_probe_time = now
        return dict(status_map)