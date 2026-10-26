import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        # Register and login test user for authenticated API operations
        email = f"api_test_{uuid.uuid4().hex[:8]}@example.com"
        pwd = "TestPassword123!"
        c.post("/api/v1/auth/register", json={
            "full_name": "API Tester",
            "email": email,
            "password": pwd,
            "confirm_password": pwd
        })
        login_res = c.post("/api/v1/auth/login", json={"email": email, "password": pwd})
        csrf_token = login_res.json()["csrf_token"]
        c.headers.update({"X-CSRF-Token": csrf_token})
        yield c


def test_health_endpoint(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["ml_model_loaded"] is True
    assert "model_version" in data


def test_model_info_endpoint(client):
    res = client.get("/api/v1/model/info")
    assert res.status_code == 200
    data = res.json()
    assert "Random Forest" in data["algorithm"]
    assert data["total_samples"] >= 5000
    assert "evaluation_metrics" in data
    assert "confusion_matrix" in data
    assert "feature_importances" in data


def test_scan_url_endpoint(client):
    target = "http://login.paypal.com.verify-account.security-update.xyz/signin"
    res = client.post("/api/v1/scan", json={"url": target})
    assert res.status_code == 200
    data = res.json()
    assert "scan_id" in data
    assert data["predicted_class"] == "Phishing"
    assert data["risk_level"] in ("High Risk", "Suspicious")
    assert "threat_intelligence" in data
    assert "extracted_features" in data
    assert "combined_interpretation" in data

    # Verify scan can be retrieved by ID
    scan_id = data["scan_id"]
    detail_res = client.get(f"/api/v1/scans/{scan_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["scan_id"] == scan_id


def test_scan_list_and_filters(client):
    # Perform two scans with distinct classes
    client.post("/api/v1/scan", json={"url": "http://paypal.verify-login.xyz/test"})
    client.post("/api/v1/scan", json={"url": "https://python.org/docs"})

    # Test list endpoint
    list_res = client.get("/api/v1/scans?page=1&page_size=10")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total_records"] >= 2
    assert len(list_data["items"]) >= 2

    # Test class filter
    phish_filter = client.get("/api/v1/scans?predicted_class=Phishing")
    assert phish_filter.status_code == 200
    for item in phish_filter.json()["items"]:
        assert item["predicted_class"] == "Phishing"


def test_analytics_endpoint(client):
    client.post("/api/v1/scan", json={"url": "https://example.com/analyticstest"})
    res = client.get("/api/v1/analytics")
    assert res.status_code == 200
    data = res.json()
    assert data["total_scans"] >= 1
    assert "classification_distribution" in data
    assert "risk_distribution" in data
    assert "scans_over_time" in data
    assert len(data["classification_distribution"]) == 2


def test_export_csv_endpoint(client):
    client.post("/api/v1/scan", json={"url": "https://example.com/exporttest"})
    res = client.get("/api/v1/scans/export")
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    assert "Scan ID,Submitted URL" in res.text


def test_delete_individual_and_clear_scans(client):
    # Scan a URL to delete
    res = client.post("/api/v1/scan", json={"url": "https://delete-me-test.org"})
    scan_id = res.json()["scan_id"]

    # Delete individual scan
    del_res = client.delete(f"/api/v1/scans/{scan_id}")
    assert del_res.status_code == 200

    # Ensure 404 upon subsequent retrieval
    get_res = client.get(f"/api/v1/scans/{scan_id}")
    assert get_res.status_code == 404

    # Clear entire user history
    clear_res = client.delete("/api/v1/scans")
    assert clear_res.status_code == 200
    assert clear_res.json()["deleted_count"] >= 0
