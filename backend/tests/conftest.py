import os
import uuid
os.environ["COOKIE_SECURE"] = "false"
import pytest
from fastapi.testclient import TestClient
from app.core.config import settings
from app.main import app

settings.COOKIE_SECURE = False

@pytest.fixture
def client():
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
