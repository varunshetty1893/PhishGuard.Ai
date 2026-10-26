import os
os.environ["COOKIE_SECURE"] = "false"
import pytest
from app.core.config import settings
settings.COOKIE_SECURE = False