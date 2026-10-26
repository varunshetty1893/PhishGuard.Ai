"""
PhishGuard AI - Threat Intelligence Integration Services
Independent adapters for Google Safe Browsing v4 and abuse.ch URLhaus.
Provides graceful fallbacks (Not Configured, No Match Reported, Threat Reported, Unavailable).
"""

import logging
from typing import Dict, Any, Optional
import httpx
from app.core.config import settings

logger = logging.getLogger("phishguard.threat_intel")


class ThreatProviderResult:
    def __init__(
        self,
        status: str,
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


class ThreatIntelAggregator:
    """Dispatches independent lookups across all configured threat providers."""

    @classmethod
    async def evaluate_url(cls, url: str) -> Dict[str, ThreatProviderResult]:
        # Execute lookups concurrently/safely
        gsb_result = await GoogleSafeBrowsingAdapter.check_url(url)
        urlhaus_result = await URLhausAdapter.check_url(url)

        return {
            "google_safe_browsing": gsb_result,
            "urlhaus": urlhaus_result
        }

    @classmethod
    def get_provider_status(cls) -> Dict[str, str]:
        gsb_status = "Active" if settings.GOOGLE_SAFE_BROWSING_API_KEY else "Not Configured"
        urlhaus_status = "Active" if settings.URLHAUS_AUTH_KEY else "Not Configured"
        return {
            "google_safe_browsing": gsb_status,
            "urlhaus": urlhaus_status
        }
