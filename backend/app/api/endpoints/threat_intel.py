from fastapi import APIRouter
from app.services.threat_intel import ThreatIntelAggregator

router = APIRouter()


@router.get("/threat-intelligence/status", summary="Check Threat Intelligence Providers Status")
def get_threat_intel_status():
    """
    Returns current runtime configuration and accessibility of external threat feeds.
    """
    status_map = ThreatIntelAggregator.get_provider_status()
    return {
        "providers": status_map,
        "mode": "Hybrid (Machine Learning + Multi-Source Threat Intelligence)"
    }
