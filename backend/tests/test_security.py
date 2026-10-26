import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings


@pytest.fixture
def client():
    with TestClient(app) as c:
        email = f"sec_test_{uuid.uuid4().hex[:8]}@example.com"
        pwd = "SecPassword123!"
        c.post("/api/v1/auth/register", json={
            "full_name": "Security Tester",
            "email": email,
            "password": pwd,
            "confirm_password": pwd
        })
        login_res = c.post("/api/v1/auth/login", json={"email": email, "password": pwd})
        csrf_token = login_res.json()["csrf_token"]
        c.headers.update({"X-CSRF-Token": csrf_token})
        yield c


def test_reject_dangerous_schemes(client):
    dangerous_urls = [
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "file:///etc/passwd",
        "vbscript:msgbox(1)"
    ]
    for url in dangerous_urls:
        res = client.post("/api/v1/scan", json={"url": url})
        assert res.status_code == 422, f"Failed for {url}: status was {res.status_code}"


def test_reject_empty_or_whitespace_url(client):
    res1 = client.post("/api/v1/scan", json={"url": ""})
    assert res1.status_code == 422

    res2 = client.post("/api/v1/scan", json={"url": "   "})
    assert res2.status_code == 422


def test_reject_excessively_long_url(client):
    huge_url = "https://example.com/" + ("a" * 2050)
    res = client.post("/api/v1/scan", json={"url": huge_url})
    assert res.status_code == 422
    assert "exceeds maximum permitted threshold" in res.text


def test_sql_injection_resilience_in_search(client):
    # Pass SQL injection strings into search parameter
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE scan_history; --",
        "UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12"
    ]
    for payload in sqli_payloads:
        res = client.get(f"/api/v1/scans?search={payload}")
        assert res.status_code == 200, f"SQL injection caused error for {payload}"
        assert isinstance(res.json()["items"], list)


def test_no_secrets_leaked_in_public_endpoints(client):
    res_health = client.get("/api/v1/health")
    assert "api_key" not in res_health.text.lower()

    res_model = client.get("/api/v1/model/info")
    assert "api_key" not in res_model.text.lower()

    res_analytics = client.get("/api/v1/analytics")
    assert settings.GOOGLE_SAFE_BROWSING_API_KEY == "" or settings.GOOGLE_SAFE_BROWSING_API_KEY not in res_analytics.text
