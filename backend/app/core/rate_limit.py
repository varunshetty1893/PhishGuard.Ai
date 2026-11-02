import threading
import time
from typing import Dict, List
from fastapi import HTTPException, status


class AuthRateLimiter:
    """
    In-memory, thread-safe sliding window rate limiter for authentication endpoints.
    Protects /auth/login (per-IP and per-email) and /auth/register (per-IP).
    Default policy: 5 failed attempts per 15-minute window (900s).
    """

    def __init__(
        self,
        max_login_failures: int = 5,
        login_window_seconds: int = 900,
        max_register_per_ip: int = 10,
        register_window_seconds: int = 900
    ):
        self.max_login_failures = max_login_failures
        self.login_window_seconds = login_window_seconds
        self.max_register_per_ip = max_register_per_ip
        self.register_window_seconds = register_window_seconds

        self._lock = threading.Lock()
        # Key -> list of failure timestamps
        self._ip_login_failures: Dict[str, List[float]] = {}
        self._email_login_failures: Dict[str, List[float]] = {}
        # IP -> list of registration attempt timestamps
        self._ip_registrations: Dict[str, List[float]] = {}

    def _cleanup_window(self, timestamps: List[float], window: int, now: float) -> List[float]:
        cutoff = now - window
        return [ts for ts in timestamps if ts > cutoff]

    def check_login_rate_limit(self, ip: str, email: str, current_time: float = None) -> None:
        """
        Validates whether either IP or email has reached failure limits.
        Raises HTTP 429 with Retry-After header if throttled.
        """
        now = current_time if current_time is not None else time.time()
        ip_clean = (ip or "unknown").strip().lower()
        email_clean = (email or "unknown").strip().lower()

        with self._lock:
            # Check IP
            ip_history = self._cleanup_window(
                self._ip_login_failures.get(ip_clean, []),
                self.login_window_seconds,
                now
            )
            self._ip_login_failures[ip_clean] = ip_history

            # Check Email
            email_history = self._cleanup_window(
                self._email_login_failures.get(email_clean, []),
                self.login_window_seconds,
                now
            )
            self._email_login_failures[email_clean] = email_history

            # If either exceeds threshold:
            ip_limited = len(ip_history) >= self.max_login_failures
            email_limited = len(email_history) >= self.max_login_failures

            if ip_limited or email_limited:
                # Calculate remaining cooldown from the oldest failure within the active window
                oldest_ts = now
                if ip_limited and ip_history:
                    oldest_ts = min(oldest_ts, ip_history[0])
                if email_limited and email_history:
                    oldest_ts = min(oldest_ts, email_history[0])

                retry_after = max(1, int(self.login_window_seconds - (now - oldest_ts)))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many failed login attempts. Access temporarily locked. Retry after {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)}
                )

    def record_login_failure(self, ip: str, email: str, current_time: float = None) -> None:
        """Records a failed authentication attempt against both IP and email buckets."""
        now = current_time if current_time is not None else time.time()
        ip_clean = (ip or "unknown").strip().lower()
        email_clean = (email or "unknown").strip().lower()

        with self._lock:
            ip_history = self._cleanup_window(
                self._ip_login_failures.get(ip_clean, []),
                self.login_window_seconds,
                now
            )
            ip_history.append(now)
            self._ip_login_failures[ip_clean] = ip_history

            email_history = self._cleanup_window(
                self._email_login_failures.get(email_clean, []),
                self.login_window_seconds,
                now
            )
            email_history.append(now)
            self._email_login_failures[email_clean] = email_history

    def record_login_success(self, ip: str, email: str) -> None:
        """Clears failure counters for IP and email upon successful authentication."""
        ip_clean = (ip or "unknown").strip().lower()
        email_clean = (email or "unknown").strip().lower()

        with self._lock:
            self._ip_login_failures.pop(ip_clean, None)
            self._email_login_failures.pop(email_clean, None)

    def check_register_rate_limit(self, ip: str, current_time: float = None) -> None:
        """Throttles account registration attempts per client IP."""
        now = current_time if current_time is not None else time.time()
        ip_clean = (ip or "unknown").strip().lower()

        with self._lock:
            reg_history = self._cleanup_window(
                self._ip_registrations.get(ip_clean, []),
                self.register_window_seconds,
                now
            )
            self._ip_registrations[ip_clean] = reg_history

            if len(reg_history) >= self.max_register_per_ip:
                oldest_ts = reg_history[0] if reg_history else now
                retry_after = max(1, int(self.register_window_seconds - (now - oldest_ts)))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many registration requests from this IP. Retry after {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)}
                )

    def record_register_attempt(self, ip: str, current_time: float = None) -> None:
        """Records an account registration attempt."""
        now = current_time if current_time is not None else time.time()
        ip_clean = (ip or "unknown").strip().lower()

        with self._lock:
            reg_history = self._cleanup_window(
                self._ip_registrations.get(ip_clean, []),
                self.register_window_seconds,
                now
            )
            reg_history.append(now)
            self._ip_registrations[ip_clean] = reg_history

    def reset(self) -> None:
        """Clears all rate limit state (used in test fixtures)."""
        with self._lock:
            self._ip_login_failures.clear()
            self._email_login_failures.clear()
            self._ip_registrations.clear()


auth_rate_limiter = AuthRateLimiter()

