import logging
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any
import httpx
from sqlalchemy.orm import Session

from app.models.scan import DomainAgeCache, utc_now

logger = logging.getLogger(__name__)

RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"
RDAP_TIMEOUT_SECONDS = 3.0
CACHE_EXPIRY_DAYS = 7


class DomainAgeService:
    """
    Asynchronous RDAP-based domain age verification service with SQLite caching.

    Adheres strictly to the fail-open security principle:
    - Failures, timeouts, or unknown domains return age_days = None.
    - Unknown age NEVER raises the risk score or flags the URL as suspicious.
    - Domains < 30 days old provide a strong suspicious signal.
    - Domains > 730 days (2 years) old provide reputation dampening (reduces suspicion).
    """

    @staticmethod
    def _parse_registration_date(data: dict) -> Optional[datetime]:
        """Extracts registration or creation datetime from RDAP events array."""
        events = data.get("events", [])
        if not isinstance(events, list):
            return None

        for event in events:
            if not isinstance(event, dict):
                continue
            action = event.get("eventAction", "").lower()
            if action in ("registration", "created"):
                date_str = event.get("eventDate")
                if date_str and isinstance(date_str, str):
                    try:
                        clean_str = date_str.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(clean_str)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        return dt
                    except (ValueError, TypeError):
                        pass
        return None

    @classmethod
    async def get_domain_age(
        cls,
        domain: str,
        db: Optional[Session] = None,
        client: Optional[httpx.AsyncClient] = None
    ) -> Tuple[Optional[int], str]:
        """
        Retrieves domain age in days.
        Returns: (age_days: Optional[int], status: str)
        status: "cache_hit" | "live_lookup" | "not_found" | "timeout" | "error"
        """
        clean_domain = domain.strip().lower().rstrip(".")
        if not clean_domain or "." not in clean_domain:
            return None, "invalid_domain"

        # 1. Check SQLite 7-day cache
        if db is not None:
            try:
                cached = db.query(DomainAgeCache).filter(DomainAgeCache.domain == clean_domain).first()
                if cached:
                    now = datetime.now(timezone.utc)
                    checked_at = cached.checked_at
                    if checked_at.tzinfo is None:
                        checked_at = checked_at.replace(tzinfo=timezone.utc)

                    if (now - checked_at).days < CACHE_EXPIRY_DAYS:
                        return cached.age_days, "cache_hit"
            except Exception as e:
                logger.warning(f"Error querying DomainAgeCache: {e}")

        # 2. Live RDAP lookup (3-second timeout, fail open)
        url = RDAP_BOOTSTRAP_URL.format(domain=clean_domain)
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "PhishGuard-AI/2.1 (Domain-Age-Checker)"
        }

        age_days: Optional[int] = None
        status = "error"
        reg_dt: Optional[datetime] = None

        try:
            if client is not None:
                resp = await client.get(url, headers=headers, timeout=RDAP_TIMEOUT_SECONDS, follow_redirects=True)
            else:
                async with httpx.AsyncClient(timeout=RDAP_TIMEOUT_SECONDS) as new_client:
                    resp = await new_client.get(url, headers=headers, follow_redirects=True)

            if resp.status_code == 200:
                data = resp.json()
                reg_dt = cls._parse_registration_date(data)
                if reg_dt:
                    now = datetime.now(timezone.utc)
                    age_days = max(0, (now - reg_dt).days)
                    status = "live_lookup"
                else:
                    status = "not_found"
            elif resp.status_code == 404:
                status = "not_found"
            else:
                status = f"http_{resp.status_code}"
        except httpx.TimeoutException:
            logger.info(f"RDAP lookup timed out (> {RDAP_TIMEOUT_SECONDS}s) for {clean_domain} - failing open")
            status = "timeout"
        except Exception as e:
            logger.warning(f"RDAP lookup failed for {clean_domain}: {e} - failing open")
            status = "error"

        # 3. Cache result in SQLite if DB session is available
        if db is not None and status in ("live_lookup", "not_found"):
            try:
                cached_entry = db.query(DomainAgeCache).filter(DomainAgeCache.domain == clean_domain).first()
                if cached_entry:
                    cached_entry.age_days = age_days
                    cached_entry.registration_date = reg_dt
                    cached_entry.checked_at = utc_now()
                else:
                    new_entry = DomainAgeCache(
                        domain=clean_domain,
                        age_days=age_days,
                        registration_date=reg_dt,
                        checked_at=utc_now()
                    )
                    db.add(new_entry)
                db.commit()
            except Exception as e:
                db.rollback()
                logger.warning(f"Error persisting DomainAgeCache: {e}")

        return age_days, status

    @staticmethod
    def evaluate_age(age_days: Optional[int]) -> Dict[str, Any]:
        """
        Evaluates domain age according to policy:
        - None (unknown): fail open (score_modifier=0.0, no warning)
        - < 30 days: strong suspicious signal (+0.25 modifier, suspicious=True)
        - > 730 days (2 years): reduced suspicion (-0.10 modifier, established=True)
        - 30-730 days: neutral (score_modifier=0.0)
        """
        if age_days is None:
            return {
                "age_days": None,
                "is_new": False,
                "is_established": False,
                "score_modifier": 0.0,
                "reason": None,
                "status": "unknown"
            }

        if age_days < 30:
            return {
                "age_days": age_days,
                "is_new": True,
                "is_established": False,
                "score_modifier": 0.25,
                "reason": f"Newly registered domain ({age_days} days old, created within the past 30 days). Recent domain registrations are strongly associated with disposable phishing infrastructure.",
                "status": "new"
            }
        elif age_days > 730:
            return {
                "age_days": age_days,
                "is_new": False,
                "is_established": True,
                "score_modifier": -0.10,
                "reason": f"Established domain ({age_days} days old, >2 years). Mature domain registration history reduces risk of disposable phishing.",
                "status": "established"
            }
        else:
            return {
                "age_days": age_days,
                "is_new": False,
                "is_established": False,
                "score_modifier": 0.0,
                "reason": None,
                "status": "neutral"
            }
