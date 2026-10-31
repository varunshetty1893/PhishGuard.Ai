# PhishGuard AI — REST API Documentation

## 1. Base URL
All API endpoints are versioned under:
```
http://localhost:8000/api/v1
```
Interactive OpenAPI documentation is automatically served at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## 2. Standardized Response Formats

### 2.1 Success Response Wrapper
Most standard operations return JSON payloads conforming to strict Pydantic schemas.

### 2.2 Error Response Schema
```json
{
  "detail": "Error description message",
  "error_code": "INVALID_URL | RATE_LIMIT_EXCEEDED | NOT_FOUND | SERVER_ERROR",
  "timestamp": "2026-10-26T09:50:00Z"
}
```

---

## 3. Endpoints Specification

### 3.1 System Health
- **Endpoint:** `GET /api/v1/health`
- **Description:** Verifies service health, database connectivity, and ML model availability.
- **Response `200 OK`:**
```json
{
  "status": "healthy",
  "database": "connected",
  "ml_model_loaded": true,
  "model_version": "1.0.0",
  "timestamp": "2026-10-26T09:50:00Z"
}
```

---

### 3.2 Model Metadata & Transparency
- **Endpoint:** `GET /api/v1/model/info`
- **Description:** Retrieves the active ML model metadata, benchmark provenance, and evaluation metrics for the ML Lab.
- **Response `200 OK`:**
```json
{
  "model_version": "1.0.0",
  "algorithm": "Random Forest Classifier",
  "dataset_name": "PhishGuard Academic Benchmark (Curated PhishTank & Tranco)",
  "training_date": "2026-10-26T09:50:00Z",
  "total_samples": 10000,
  "train_samples": 8000,
  "test_samples": 2000,
  "evaluation_metrics": {
    "accuracy": 0.965,
    "precision": 0.958,
    "recall": 0.972,
    "f1": 0.965,
    "roc_auc": 0.991
  },
  "confusion_matrix": {
    "tn": 958,
    "fp": 42,
    "fn": 28,
    "tp": 972
  },
  "feature_schema": ["url_length", "hostname_length", "..."],
  "feature_importances": {
    "count_dots": 0.185,
    "url_length": 0.142,
    "has_suspicious_keywords": 0.134
  }
}
```

---

### 3.3 Execute URL Scan
- **Endpoint:** `POST /api/v1/scan`
- **Description:** Ingests untrusted URL, extracts 16 features, runs ML inference, and triggers optional threat-intel lookups.
- **Request Body:**
```json
{
  "url": "http://paypal.com.verify-login.security-account.xyz/update"
}
```
- **Response `200 OK`:**
```json
{
  "scan_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "submitted_url": "http://paypal.com.verify-login.security-account.xyz/update",
  "normalized_url": "http://paypal.com.verify-login.security-account.xyz/update",
  "predicted_class": "Phishing",
  "risk_level": "High Risk",
  "model_score": 0.942,
  "extracted_features": {
    "url_length": 58,
    "hostname_length": 49,
    "path_length": 7,
    "query_length": 0,
    "count_dots": 4,
    "count_hyphens": 2,
    "count_subdomains": 4,
    "count_digits": 0,
    "count_special_chars": 0,
    "is_ip_address": 0,
    "is_https": 0,
    "has_at_symbol": 0,
    "has_suspicious_encoding": 0,
    "is_shortened_service": 0,
    "has_unusual_port": 0,
    "has_suspicious_keywords": 1
  },
  "suspicious_reasons": [
    "High number of subdomain components (4 subdomains detected)",
    "Presence of high-risk authentication keywords ('verify', 'login', 'security', 'account')",
    "Insecure HTTP protocol used for sensitive security context",
    "Excessive dot count indicative of brand impersonation nesting"
  ],
  "threat_intelligence": {
    "google_safe_browsing": {
      "status": "Not Configured",
      "threat_found": false,
      "category": null,
      "details": "API key not provided in environment"
    },
    "openphish": {
      "status": "No Match Reported",
      "threat_found": false,
      "category": null,
      "details": "No exact URL match found in the local feed"
    },
    "phishing_database": {
      "status": "No Match Reported",
      "threat_found": false,
      "category": null,
      "details": "No URL or domain match found in the local feeds"
    },
    "phish_destroy": {
      "status": "No Match Reported",
      "threat_found": false,
      "category": null,
      "details": "No threat reported"
    },
    "cert_pl": {
      "status": "No Match Reported",
      "threat_found": false,
      "category": null,
      "details": "No domain match in CERT-PL Warning List. Its coverage focuses on dangerous sites targeting Polish users."
    }
  },
  "combined_interpretation": "High probability phishing attempt detected by Machine Learning model. Do not enter credentials or download files from this destination.",
  "recommended_precautions": [
    "Do not provide credentials, personal information, or financial details.",
    "Do not download or execute attachments from this link.",
    "Verify the destination domain directly via official bookmarks."
  ],
  "model_version": "1.0.0",
  "created_at": "2026-10-26T09:50:00Z"
}
```

---

### 3.4 Scan History & Querying
- **Endpoint:** `GET /api/v1/scans`
- **Query Parameters:**
  - `page` (default 1)
  - `page_size` (default 10, max 100)
  - `search` (URL substring query)
  - `predicted_class` (`Legitimate` or `Phishing`)
  - `risk_level` (`Low Risk`, `Suspicious`, `High Risk`)
  - `threat_status` (`Threat Reported`, `No Match Reported`, `All`)
- **Response `200 OK`:**
```json
{
  "total_records": 128,
  "page": 1,
  "page_size": 10,
  "total_pages": 13,
  "items": [ ... ]
}
```

---

### 3.5 Single Scan Detail
- **Endpoint:** `GET /api/v1/scans/{scan_id}`
- **Response `200 OK`:** Full scan record matching scan creation schema.
- **Response `404 Not Found`:** If `scan_id` does not exist.

---

### 3.6 Delete Records
- **Endpoint:** `DELETE /api/v1/scans/{scan_id}` (Delete single scan).
- **Endpoint:** `DELETE /api/v1/scans` (Clear entire history).

---

### 3.7 Analytics Aggregate
- **Endpoint:** `GET /api/v1/analytics`
- **Description:** Returns live aggregate metrics calculated directly from database records.
- **Response `200 OK`:**
```json
{
  "total_scans": 128,
  "phishing_count": 52,
  "legitimate_count": 76,
  "high_risk_count": 48,
  "threat_intel_matches": 14,
  "threat_intel_failures": 3,
  "classification_distribution": [
    {"name": "Legitimate", "value": 76, "color": "#39FF88"},
    {"name": "Phishing", "value": 52, "color": "#FF525C"}
  ],
  "risk_distribution": [
    {"name": "Low Risk", "value": 70, "color": "#39FF88"},
    {"name": "Suspicious", "value": 10, "color": "#FFD54A"},
    {"name": "High Risk", "value": 48, "color": "#FF525C"}
  ],
  "scans_over_time": [
    {"date": "2026-10-24", "scans": 34, "phishing": 12},
    {"date": "2026-10-25", "scans": 51, "phishing": 21},
    {"date": "2026-10-26", "scans": 43, "phishing": 19}
  ],
  "model_status": {
    "version": "1.0.0",
    "status": "Active"
  },
  "threat_provider_status": {
    "openphish": "Ready",
    "phishing_database_urls": "Ready",
    "phishing_database_domains": "Ready",
    "cert_pl_domains": "Ready",
    "phish_destroy": "Active",
    "google_safe_browsing": "Not Configured"
  }
}
```

---

### 3.8 CSV Export
- **Endpoint:** `GET /api/v1/scans/export`
- **Description:** Streams a RFC 4180 compliant CSV file of all scan history records.
- **Headers:** `Content-Disposition: attachment; filename="phishguard_scan_history.csv"`
