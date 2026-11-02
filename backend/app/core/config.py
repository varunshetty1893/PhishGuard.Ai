import os
import secrets
from pathlib import Path
from typing import List

# ─── Load .env BEFORE any os.getenv() calls ──────────────────────────────────
# Resolves the .env relative to this file's location: backend/app/core/../../../.env
# i.e. backend/.env  (correct regardless of cwd when uvicorn is started)
_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent   # backend/
_ENV_FILE    = _BACKEND_DIR / ".env"

try:
    from dotenv import load_dotenv
    _loaded = load_dotenv(_ENV_FILE, override=False)   # override=False: OS env vars win
    if not _loaded:
        # .env not found at expected path - log clearly so the operator notices
        import warnings
        warnings.warn(
            f"[PhishGuard] .env file not found at {_ENV_FILE}. "
            "Threat-intel API keys and other settings will use defaults.",
            stacklevel=2
        )
except ImportError:
    pass   # python-dotenv not installed; rely on shell-exported env vars only
# ─────────────────────────────────────────────────────────────────────────────


class Settings:
    PROJECT_NAME: str = "PhishGuard AI"
    VERSION: str      = "2.1.0"
    API_V1_STR: str   = "/api/v1"

    def __init__(self):
        # All os.getenv() calls happen HERE, after load_dotenv() above has run.
        self.ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()

        # Database
        self._RAW_DB_URL: str = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")

        # Security & SECRET_KEY hardening
        secret_env = os.getenv("SECRET_KEY", "").strip()
        if self.ENVIRONMENT == "production":
            if not secret_env:
                raise RuntimeError(
                    "FATAL: SECRET_KEY environment variable is mandatory when ENVIRONMENT=production."
                )
            self.SECRET_KEY: str = secret_env
            # Default COOKIE_SECURE to True in production unless explicitly overridden
            cookie_sec_env = os.getenv("COOKIE_SECURE")
            self.COOKIE_SECURE: bool = (
                cookie_sec_env.lower() == "true" if cookie_sec_env is not None else True
            )
        else:
            self.SECRET_KEY: str = (
                secret_env if secret_env else "phishguard-dev-secret-key-32bytes-min"
            )
            self.COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"

        self.SESSION_COOKIE_NAME: str   = "phishguard_session"
        self.CSRF_COOKIE_NAME: str      = "phishguard_csrf"
        self.SESSION_MAX_AGE_SECONDS: int  = 86400        # 24 h
        self.REMEMBER_MAX_AGE_SECONDS: int = 86400 * 14   # 14 days
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
            os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10080")
        )

        # ── Threat Intelligence & Privacy Controls ───────────────────────────
        self.ENABLE_THIRD_PARTY_LOOKUPS: bool = (
            os.getenv("ENABLE_THIRD_PARTY_LOOKUPS", "true").lower() == "true"
        )
        self.GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv(
            "GOOGLE_SAFE_BROWSING_API_KEY", ""
        ).strip()
        self.THREAT_INTEL_TIMEOUT_SECONDS: float = 8.0

        # CORS
        raw_origins = os.getenv("ALLOWED_ORIGINS", "")
        if raw_origins.strip():
            self.ALLOWED_ORIGINS: List[str] = [
                o.strip() for o in raw_origins.split(",") if o.strip()
            ]
        else:
            self.ALLOWED_ORIGINS: List[str] = [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            ]

    @property
    def DATABASE_URL(self) -> str:
        url = self._RAW_DB_URL
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+psycopg2://", 1)
        elif url.startswith("postgresql://") and not url.startswith("postgresql+"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return url

    @property
    def IS_POSTGRES(self) -> bool:
        return self.DATABASE_URL.startswith("postgresql")

    def has_gsb(self) -> bool:
        """True only when a non-empty GSB key is configured and third-party lookups are enabled."""
        return bool(self.GOOGLE_SAFE_BROWSING_API_KEY) and self.ENABLE_THIRD_PARTY_LOOKUPS


settings = Settings()
