import os
from typing import List

class Settings:
    PROJECT_NAME: str = "PhishGuard AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")
    
    # Threat Intelligence Keys (Optional)
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    URLHAUS_AUTH_KEY: str = os.getenv("URLHAUS_AUTH_KEY", "")
    
    # Timeouts
    THREAT_INTEL_TIMEOUT_SECONDS: float = 4.0
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ]

settings = Settings()
