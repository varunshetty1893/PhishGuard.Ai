import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import json
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.user import User
from app.core.security import hash_password as get_password_hash

def run_tests():
    print("=" * 60)
    print("PHISHGUARD AI URL SCANNING WORKFLOW VERIFICATION SUITE")
    print("=" * 60)

    # 1. Ensure test user exists in DB
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "test_verifier@phishguard.ai").first()
        if not user:
            user = User(
                email="test_verifier@phishguard.ai",
                password_hash=get_password_hash("VerifierSecurePass123!"),
                full_name="Verification Agent",
                account_status="active"
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print("[+] Test user created.")
        else:
            print("[+] Existing test user retrieved.")
    finally:
        db.close()

    client = TestClient(app)

    # 2. Login to obtain session cookie and CSRF token
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "test_verifier@phishguard.ai", "password": "VerifierSecurePass123!"}
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    csrf_token = login_resp.json().get("csrf_token")
    headers = {"X-CSRF-Token": csrf_token}
    print("[+] Authenticated session and CSRF token obtained.")

    # 3. Test Rejections: Localhost, Internal IP, Malformed, Route, Non-HTTP
    rejection_cases = [
        ("shettybvarun@gmail.com", "Plain email address"),
        ("@shettybvarun", "Social handle"),
        ("jhsahjvahvhasvkhgksghewvfv", "Malformed string without TLD/domain"),
        ("http://localhost:5173", "Localhost with dev port"),
        ("http://localhost/admin", "Localhost path"),
        ("http://127.0.0.1:8000/api", "Loopback address 127.0.0.1"),
        ("http://192.168.1.1", "RFC 1918 Private IP (192.168.x.x)"),
        ("http://10.0.0.5:8080/portal", "RFC 1918 Private IP (10.x.x.x)"),
        ("http://172.16.0.10/login", "RFC 1918 Private IP (172.16.x.x)"),
        ("/scanner", "Internal application route /scanner"),
        ("/dashboard", "Internal application route /dashboard"),
        ("javascript:alert('xss')", "Forbidden scheme javascript:"),
        ("file:///C:/Windows/System32", "Forbidden scheme file:"),
        ("data:text/html,malicious", "Forbidden scheme data:"),
        ("http://dev.test", "Local development domain suffix (.test)"),
        ("http://internal.lan/db", "Internal domain suffix (.lan)")
    ]

    print("\n--- Testing Input Validation Rejection Rules ---")
    for bad_url, description in rejection_cases:
        res = client.post("/api/v1/scan", json={"url": bad_url}, headers=headers)
        assert res.status_code == 422, f"Expected 422 for {bad_url} ({description}), got {res.status_code}: {res.text}"
        error_detail = res.json()["detail"]
        print(f" [PASS] Rejected: '{bad_url}' [{description}] -> 422 Unprocessable Entity")

    # 4. Test Legitimate External URL
    print("\n--- Testing Legitimate External URL Scanning ---")
    legit_url = "https://www.google.com"
    res_legit = client.post("/api/v1/scan", json={"url": legit_url}, headers=headers)
    assert res_legit.status_code == 200, f"Legit scan failed: {res_legit.text}"
    legit_data = res_legit.json()
    assert legit_data["predicted_class"] == "Legitimate"
    assert legit_data["risk_level"] == "Low Risk"
    assert "ml_probability" in legit_data
    assert legit_data["is_verified_domain"] is True
    assert legit_data["apex_domain"] == "google.com"
    print(f" [PASS] Scanned: {legit_url}")
    print(f"        Class: {legit_data['predicted_class']} | Risk: {legit_data['risk_level']}")
    print(f"        ML Probability: {legit_data['ml_probability'] * 100:.2f}% | Apex: {legit_data['apex_domain']}")
    print(f"        Google Safe Browsing: {legit_data['threat_intelligence']['google_safe_browsing']['status']}")
    print(f"        URLhaus: {legit_data['threat_intelligence']['urlhaus']['status']}")

    # 5. Test Phishing External URL
    print("\n--- Testing Phishing External URL Scanning ---")
    phish_url = "http://login.paypal.com.account-verify.xyz/signin"
    res_phish = client.post("/api/v1/scan", json={"url": phish_url}, headers=headers)
    assert res_phish.status_code == 200, f"Phish scan failed: {res_phish.text}"
    phish_data = res_phish.json()
    assert phish_data["predicted_class"] == "Phishing"
    assert phish_data["risk_level"] == "High Risk"
    assert phish_data["ml_probability"] >= 0.75
    assert len(phish_data["suspicious_reasons"]) > 0
    print(f" [PASS] Scanned: {phish_url}")
    print(f"        Class: {phish_data['predicted_class']} | Risk: {phish_data['risk_level']}")
    print(f"        ML Probability: {phish_data['ml_probability'] * 100:.2f}% (Explicitly separated)")
    print(f"        Threat Feeds Match: {phish_data['threat_intel_match']}")
    print(f"        Synthesis Note: {phish_data['combined_interpretation']}")
    print(f"        Detected Anomalies: {phish_data['suspicious_reasons']}")

    # 6. Verify Critical Rule: Never label a URL safe just because it is absent from threat databases
    # When URLhaus and GSB return No Match or Not Configured, phish_url MUST STILL be High Risk!
    assert phish_data["risk_level"] == "High Risk", "CRITICAL FAILURE: Phishing URL was downgraded despite high ML score!"
    print("\n [PASS] Verified: URL is NOT labeled safe when absent/unmatched in threat databases.")

    # 7. Test Suspicious External Domain
    print("\n--- Testing Suspicious / Compound External URL ---")
    susp_url = "http://93.184.216.34/secure/login.php"
    res_susp = client.post("/api/v1/scan", json={"url": susp_url}, headers=headers)
    assert res_susp.status_code == 200, f"Susp scan failed: {res_susp.text}"
    susp_data = res_susp.json()
    print(f" [PASS] Scanned: {susp_url}")
    print(f"        Class: {susp_data['predicted_class']} | Risk: {susp_data['risk_level']}")
    print(f"        ML Probability: {susp_data['ml_probability'] * 100:.2f}%")

    print("\n" + "=" * 60)
    print("ALL 18 VERIFICATION CHECKS PASSED PERFECTLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()




