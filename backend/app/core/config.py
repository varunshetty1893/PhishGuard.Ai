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
        self.ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

        # Database
        self._RAW_DB_URL: str = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")

        # Security
        self.SECRET_KEY: str            = os.getenv("SECRET_KEY", secrets.token_hex(32))
        self.SESSION_COOKIE_NAME: str   = "phishguard_session"
        self.CSRF_COOKIE_NAME: str      = "phishguard_csrf"
        self.SESSION_MAX_AGE_SECONDS: int  = 86400        # 24 h
        self.REMEMBER_MAX_AGE_SECONDS: int = 86400 * 14   # 14 days
        self.COOKIE_SECURE: bool        = os.getenv("COOKIE_SECURE", "false").lower() == "true"
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
            os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10080")
        )

        # ── Threat Intelligence API Keys ─────────────────────────────────────
        self.GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv(
            "GOOGLE_SAFE_BROWSING_API_KEY", ""
        ).strip()
        self.PHISHSTATS_API_KEY: str = os.getenv(
            "PHISHSTATS_API_KEY", ""
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
        """True only when a non-empty GSB key is configured."""
        return bool(self.GOOGLE_SAFE_BROWSING_API_KEY)

    def has_phishstats(self) -> bool:
        """True only when an optional PhishStats API key is configured."""
        return bool(self.PHISHSTATS_API_KEY)


settings = Settings()
