import ipaddress
from typing import Tuple, Optional
from urllib.parse import urlsplit

INTERNAL_DOMAIN_SUFFIXES = (
    ".local", ".internal", ".localhost", ".lan", ".corp", ".home.arpa"
)


def is_prohibited_ip(ip_str: str) -> bool:
    """
    Checks if an IP address string is private, loopback, link-local,
    multicast, reserved, or cloud metadata (e.g. 169.254.169.254).
    """
    if not ip_str:
        return False
    clean_ip = ip_str.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(clean_ip)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def validate_url_security(raw_url: str) -> Tuple[bool, Optional[str]]:
    """
    Validates that a URL does not target localhost, private IPs, or internal network services.
    Enforces SSRF prevention before any outbound network or DNS requests occur.
    Returns (is_safe, error_reason).
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "URL string is empty or invalid."

    try:
        parsed = urlsplit(raw_url.strip())
    except Exception as e:
        return False, f"Malformed URL syntax: {e}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS protocols are accepted."

    netloc = parsed.netloc.strip()
    if not netloc:
        return False, "URL destination network location is empty."

    hostname = (parsed.hostname or "").lower().strip(".")
    if not hostname:
        return False, "URL destination hostname is empty."

    if hostname == "localhost" or any(hostname.endswith(s) for s in INTERNAL_DOMAIN_SUFFIXES):
        return False, f"Destination '{hostname}' targets internal/local infrastructure and is prohibited."

    if is_prohibited_ip(hostname):
        return False, f"Destination IP '{hostname}' is an internal/private address and is prohibited."

    return True, None

