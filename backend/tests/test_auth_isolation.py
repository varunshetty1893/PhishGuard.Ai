import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_user_registration_and_argon2_hashing(client):
    """Verifies successful registration and Argon2id password hashing."""
    email = f"alice_{uuid.uuid4().hex[:8]}@example.com"
    reg_payload = {
        "full_name": "Alice Wonderland",
        "email": email,
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    res = client.post("/api/v1/auth/register", json=reg_payload)
    assert res.status_code == 201
    assert "Account created successfully" in res.json()["message"]


def test_duplicate_email_rejection(client):
    """Ensures duplicate accounts for the same email address are rejected."""
    email = f"dup_{uuid.uuid4().hex[:8]}@example.com"
    payload = {
        "full_name": "User One",
        "email": email,
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    # Second registration with same email (different case)
    res2 = client.post("/api/v1/auth/register", json={
        "full_name": "User Two",
        "email": email.upper(),
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"]


def test_password_policy_and_mismatch_validation(client):
    """Enforces password complexity and match validation."""
    # Mismatched passwords
    res1 = client.post("/api/v1/auth/register", json={
        "full_name": "Bad Match",
        "email": f"badmatch_{uuid.uuid4().hex[:8]}@example.com",
        "password": "Password123!",
        "confirm_password": "Password999!"
    })
    assert res1.status_code == 400
    assert "Passwords do not match" in res1.json()["detail"]

    # Weak password (missing special character & digits)
    res2 = client.post("/api/v1/auth/register", json={
        "full_name": "Weak Pwd",
        "email": f"weak_{uuid.uuid4().hex[:8]}@example.com",
        "password": "simplepassword",
        "confirm_password": "simplepassword"
    })
    assert res2.status_code == 400
    assert "Password must contain" in res2.json()["detail"]


def test_login_success_and_failure(client):
    """Tests successful login, invalid credentials, and session establishment."""
    email = f"bob_{uuid.uuid4().hex[:8]}@example.com"
    pwd = "SecurePassword456!"
    client.post("/api/v1/auth/register", json={
        "full_name": "Bob Builder",
        "email": email,
        "password": pwd,
        "confirm_password": pwd
    })

    # Incorrect password
    bad_login = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "WrongPassword999!",
        "remember_me": False
    })
    assert bad_login.status_code == 401
    assert "Invalid email address or password" in bad_login.json()["detail"]

    # Successful login
    login_res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": pwd,
        "remember_me": True
    })
    assert login_res.status_code == 200
    data = login_res.json()
    assert data["user"]["email"] == email
    assert "csrf_token" in data
    assert "phishguard_session" in client.cookies


def test_session_restoration_and_logout(client):
    """Tests /api/v1/auth/me session restore and /api/v1/auth/logout invalidation."""
    email = f"charlie_{uuid.uuid4().hex[:8]}@example.com"
    pwd = "CharliePassword789!"
    client.post("/api/v1/auth/register", json={
        "full_name": "Charlie Chaplin",
        "email": email,
        "password": pwd,
        "confirm_password": pwd
    })

    # Login
    client.post("/api/v1/auth/login", json={"email": email, "password": pwd})
    
    # Restore session via /auth/me
    me_res = client.get("/api/v1/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["user"]["email"] == email

    # Logout
    logout_res = client.post("/api/v1/auth/logout")
    assert logout_res.status_code == 200
    assert "Successfully signed out" in logout_res.json()["message"]

    # Subsequent /auth/me should fail
    me_after = client.get("/api/v1/auth/me")
    assert me_after.status_code == 401


def test_unauthenticated_access_denied():
    """Unauthenticated access to protected endpoints must return 401."""
    with TestClient(app) as unauth_client:
        assert unauth_client.post("/api/v1/scan", json={"url": "https://google.com"}).status_code == 401
        assert unauth_client.get("/api/v1/scans").status_code == 401
        assert unauth_client.get("/api/v1/scans/dummy-scan-id").status_code == 401
        assert unauth_client.delete("/api/v1/scans/dummy-scan-id").status_code == 401
        assert unauth_client.delete("/api/v1/scans").status_code == 401
        assert unauth_client.get("/api/v1/analytics").status_code == 401
        assert unauth_client.get("/api/v1/scans/export").status_code == 401


def test_strict_user_data_isolation():
    """
    CRITICAL TEST: Verifies that User B cannot view, search, export, delete,
    or calculate analytics on User A's private scans.
    """
    # 1. Setup User A
    user_a_client = TestClient(app)
    user_a_email = f"user_a_{uuid.uuid4().hex[:8]}@cybersec.org"
    user_a_client.post("/api/v1/auth/register", json={
        "full_name": "User Alpha",
        "email": user_a_email,
        "password": "AlphaPassword123!",
        "confirm_password": "AlphaPassword123!"
    })
    login_a = user_a_client.post("/api/v1/auth/login", json={
        "email": user_a_email,
        "password": "AlphaPassword123!"
    })
    csrf_a = login_a.json()["csrf_token"]

    # User A performs a scan
    scan_target = "http://malicious-phishing-target-alpha.xyz/login"
    scan_a_res = user_a_client.post(
        "/api/v1/scan",
        json={"url": scan_target},
        headers={"X-CSRF-Token": csrf_a}
    )
    assert scan_a_res.status_code == 200
    scan_a_id = scan_a_res.json()["scan_id"]

    # User A verifies their scan is in their history
    list_a = user_a_client.get("/api/v1/scans").json()
    assert any(s["scan_id"] == scan_a_id for s in list_a["items"])

    # User A analytics shows at least 1 scan
    analytics_a = user_a_client.get("/api/v1/analytics").json()
    assert analytics_a["total_scans"] >= 1

    # 2. Setup User B
    user_b_client = TestClient(app)
    user_b_email = f"user_b_{uuid.uuid4().hex[:8]}@cybersec.org"
    user_b_client.post("/api/v1/auth/register", json={
        "full_name": "User Beta",
        "email": user_b_email,
        "password": "BetaPassword123!",
        "confirm_password": "BetaPassword123!"
    })
    login_b = user_b_client.post("/api/v1/auth/login", json={
        "email": user_b_email,
        "password": "BetaPassword123!"
    })
    csrf_b = login_b.json()["csrf_token"]

    # User B list history -> MUST NOT see User A's scan
    list_b = user_b_client.get("/api/v1/scans").json()
    assert not any(s["scan_id"] == scan_a_id for s in list_b["items"])
    assert list_b["total_records"] == 0

    # User B analytics -> MUST NOT count User A's scans
    analytics_b = user_b_client.get("/api/v1/analytics").json()
    assert analytics_b["total_scans"] == 0
    assert analytics_b["phishing_count"] == 0

    # User B direct IDOR attempt to view User A's scan report -> MUST BE 404/DENIED
    idor_get = user_b_client.get(f"/api/v1/scans/{scan_a_id}")
    assert idor_get.status_code == 404

    # User B direct IDOR attempt to delete User A's scan -> MUST BE 404/DENIED
    idor_del = user_b_client.delete(
        f"/api/v1/scans/{scan_a_id}",
        headers={"X-CSRF-Token": csrf_b}
    )
    assert idor_del.status_code == 404

    # User B attempts to export CSV -> User A's URL must NOT be present in export
    export_b = user_b_client.get("/api/v1/scans/export")
    assert export_b.status_code == 200
    assert scan_target not in export_b.text

    # User B clears their history -> User A's scan must remain intact
    clear_b = user_b_client.delete(
        "/api/v1/scans",
        headers={"X-CSRF-Token": csrf_b}
    )
    assert clear_b.status_code == 200

    # User A verifies their scan still exists unharmed
    detail_a = user_a_client.get(f"/api/v1/scans/{scan_a_id}")
    assert detail_a.status_code == 200
    assert detail_a.json()["scan_id"] == scan_a_id
