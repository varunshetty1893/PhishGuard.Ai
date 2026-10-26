import os
import secrets
from typing import List

class Settings:
    PROJECT_NAME: str = "PhishGuard AI"
    VERSION: str = "2.1.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Database Configuration (Neon PostgreSQL with SQLite fallback)
    # Accepts postgresql://, postgres://, or sqlite:///
    _RAW_DB_URL: str = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")
    
    @property
    def DATABASE_URL(self) -> str:
        url = self._RAW_DB_URL
        # SQLAlchemy requires postgresql:// instead of postgres://
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        return url

    @property
    def IS_POSTGRES(self) -> bool:
        return self.DATABASE_URL.startswith("postgresql")

    # Security & Session Secrets
    SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_hex(32))
    SESSION_COOKIE_NAME: str = "phishguard_session"
    CSRF_COOKIE_NAME: str = "phishguard_csrf"
    SESSION_MAX_AGE_SECONDS: int = 86400           # 24 hours
    REMEMBER_MAX_AGE_SECONDS: int = 86400 * 14     # 14 days
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    
    # Threat Intelligence Keys (Optional)
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    URLHAUS_AUTH_KEY: str = os.getenv("URLHAUS_AUTH_KEY", "")
    THREAT_INTEL_TIMEOUT_SECONDS: float = 4.0
    
    # CORS Configuration
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]

settings = Settings()
