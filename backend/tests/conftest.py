"""
Pytest configuration for PhishGuard AI backend tests.

Key responsibilities:
1. Force SQLite (in-memory/file) before importing the app, so tests never
   hit the Neon Postgres connection specified in .env.
2. Auto-reset the in-memory rate limiter between tests so failures don't bleed.
3. Provide a shared `client` fixture that registers + logs in a fresh test user.
4. Detect Git LFS pointer stubs for the ML model artifact and cleanly skip ML-dependent
   tests when the real binary has not been pulled.
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

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.core.rate_limit import auth_rate_limiter  # noqa: E402

# Apply settings overrides after import (belt-and-suspenders)
settings.COOKIE_SECURE = False


# ── Git LFS Model Pointer Detection ──────────────────────────────────────────

def is_model_lfs_pointer() -> bool:
    """Return True if phishguard_rf_model.joblib is missing or is a Git LFS pointer stub."""
    if os.environ.get("PHISHGUARD_MOCK_LFS_POINTER") == "1":
        return True
    model_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "app", "ml", "artifacts", "phishguard_rf_model.joblib")
    )
    if not os.path.exists(model_path):
        return True
    try:
        with open(model_path, "rb") as fh:
            header = fh.read(30)
            return header.startswith(b"version https://git-lfs")
    except Exception:
        return True


IS_LFS_POINTER = is_model_lfs_pointer()


@pytest.fixture
def requires_ml_model():
    """Conftest fixture: skips test when phishguard_rf_model.joblib is an un-pulled Git LFS pointer."""
    if is_model_lfs_pointer():
        pytest.skip("phishguard_rf_model.joblib is a Git LFS pointer. Run `git lfs pull` to download real model.")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "requires_ml_model: mark test as requiring the real ML model binary (skips if LFS pointer)"
    )


def pytest_collection_modifyitems(config, items):
    if is_model_lfs_pointer():
        skip_lfs = pytest.mark.skip(
            reason="phishguard_rf_model.joblib is a Git LFS pointer (not downloaded). Run `git lfs pull` to download."
        )
        for item in items:
            if "requires_ml_model" in item.keywords:
                item.add_marker(skip_lfs)


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
    Shared authenticated test client. Creates a unique user per invocation so
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
