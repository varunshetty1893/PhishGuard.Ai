"""
Pytest configuration for PhishGuard AI backend tests.

Key responsibilities:
1. Force SQLite (in-memory/file) before importing the app, so tests never
   hit the Neon Postgres connection specified in .env.
2. Auto-reset the in-memory rate limiter between tests so failures don't bleed.
3. Provide a shared `client` fixture that registers + logs in a fresh test user.
"""

import os
import uuid
import tempfile

# ── Override DATABASE_URL to local SQLite BEFORE any app module is imported ──
# This must happen at module level (before imports) so SQLAlchemy engine is
# created with the test database, not the Neon Postgres URL.
_TEST_DB_FILE = os.path.join(tempfile.gettempdir(), f"phishguard_test_{os.getpid()}.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_FILE}"
os.environ["COOKIE_SECURE"] = "false"
os.environ["ENVIRONMENT"] = "development"   # disable production-only guards

import pytest
from fastapi.testclient import TestClient
from app.core.config import settings
from app.main import app
from app.core.rate_limit import auth_rate_limiter

# Apply settings overrides after import (belt-and-suspenders)
settings.COOKIE_SECURE = False


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """
    Auto-used: wipes in-memory rate-limiter state before AND after every test,
    preventing failures accumulated in one test from blocking registration/login
    in the next test.
    """
    auth_rate_limiter.reset()
    yield
    auth_rate_limiter.reset()


@pytest.fixture
def client():
    """
    Shared authenticated test client.  Creates a unique user per invocation so
    tests are isolated from each other's data.
    """
    with TestClient(app) as c:
        email = f"shared_test_{uuid.uuid4().hex[:8]}@example.com"
        pwd = "TestPassword123!"
        c.post("/api/v1/auth/register", json={
            "full_name": "Shared Tester",
            "email": email,
            "password": pwd,
            "confirm_password": pwd
        })
        login_res = c.post("/api/v1/auth/login", json={"email": email, "password": pwd})
        if login_res.status_code == 200:
            csrf_token = login_res.json().get("csrf_token", "")
            c.headers.update({"X-CSRF-Token": csrf_token})
        yield c
