from typing import Any, Dict, Optional


class ThreatProviderResult:
    """Standardized representation of an external threat-feed response."""

    def __init__(
        self,
        status: str,
        threat_found: bool = False,
        category: Optional[str] = None,
        details: Optional[str] = None,
        raw_response: Optional[str] = None,
        error_message: Optional[str] = None,
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
            "details": self.details,
        }
