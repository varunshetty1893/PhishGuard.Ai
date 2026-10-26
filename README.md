# PhishGuard AI

<div align="center">

![PhishGuard AI Banner](frontend/public/favicon.svg)

### Enterprise-Grade Phishing URL Detection & Threat Intelligence Platform
*Dual-Engine Architecture: 150-Tree Random Forest ML Ensemble + Real-Time Threat Intelligence Aggregation*

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon_Cloud-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://neon.tech)
[![License](https://img.shields.io/badge/License-MIT-39FF88?style=for-the-badge)](LICENSE)

</div>

---

## 📌 Executive Summary

**PhishGuard AI** is an advanced, production-grade cybersecurity web application engineered to detect deceptive, obfuscated, and zero-day phishing URLs before credentials or systems are compromised.

Unlike conventional tools that rely solely on static blacklist lookups or uncalibrated heuristic scores, PhishGuard AI deploys a **hybrid multi-layer defense**:
1. **Deterministic Lexical Feature Extraction**: Computes 16 mathematical, structural, and character-entropy metrics directly from URL strings in memory without executing remote code.
2. **150-Tree Random Forest Ensemble**: Evaluated on an **independent, domain-separated benchmark** with zero domain leakage between training and testing splits.
3. **Dual Threat Intelligence Feed Adapters**: Queries Google Safe Browsing Lookup v4 and abuse.ch URLhaus asynchronously with graceful status handling (`Threat Reported`, `No Match Reported`, `Unavailable`, `Not Configured`).
4. **Verified Domain Authority Protection**: Calibrates false positives caused by complex legitimate cloud APIs (e.g., Google Cloud, AWS, Microsoft Azure, PayPal) that feature multi-nested parameters or subpaths.
5. **Zero-Crawl Anti-SSRF Architecture**: Untrusted URLs are parsed strictly in memory and are **never visited, downloaded, or crawled**, protecting the host network against Server-Side Request Forgery (SSRF) and malicious payloads.

---

## 🏗️ System Architecture

```text
                                 [ USER CLIENT ]
                                        │
                         HTTP / TLS     │  Strict Client-Side Validation
                                        ▼  (Rejects localhost, RFC 1918, routes)
                             [ REACT 18 + VITE UI ]
                             (Pure Black #050505 UI)
                                        │
                      REST API + CSRF   │  Secure Cookie Sessions
                                        ▼
                           [ FASTAPI GATEWAY :8000 ]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
 [ Pydantic Validator ]       [ Auth & Session Guard ]    [ Threat Aggregator ]
   - Anti-SSRF Parser           - Argon2id Password Hash     - Google Safe Browsing
   - Rejects Private IPs        - HttpOnly Sessions          - abuse.ch URLhaus
   - Rejects Localhost          - Anti-IDOR Enforcement      - 4 Distinct States
           │                            │                            │
           ▼                            ▼                            │
 [ 16-D Feature Engine ]      [ Neon PostgreSQL / SQLite ]           │
   - In-Memory Lexical          - Isolated Scan History              │
   - 0 Outbound Crawl           - Per-User Threat Logs               │
           │                                                         │
           ▼                                                         ▼
 [ Random Forest Model ] ───────────────────────────────► [ Hybrid Risk Synthesis ]
 (150 Decision Trees)                                      - ML Probability (0-100%)
                                                           - Final Risk Assessment
                                                           - Retrospective Blocklist Notice
```

---

## 📊 Model Evaluation & Anti-Leakage Protocol

### The Domain Leakage Problem
Standard URL classifiers frequently suffer from **evaluation contamination**: multiple URLs sharing the same root domain appear in both training and test partitions. When this occurs, models memorize domain-specific artifacts rather than learning generalized phishing signals, causing real-world detection to fail.

### PhishGuard AI Domain-Separated Evaluation
PhishGuard AI v3.2 enforces strict **Domain-Separated Partitioning** (`GroupShuffleSplit` on `apex_domain`). **Zero domains in the test partition exist in the training partition.**

```text
Total Dataset Size:           298,046 Deduplicated URLs
Unique Registered Domains:    193,498 Apex Domains
Training Partition:           240,026 URLs across 154,798 distinct domains
Holdout Test Partition:        58,020 URLs across  38,700 distinct domains
Domain Leakage Overlap:       STRICTLY 0 DOMAINS (0.00%)
```

### Empirical Test Set Performance (Unseen Domains)

| Metric | Result | Industry Interpretation |
| :--- | :--- | :--- |
| **Accuracy** | **99.24%** | Overall correct classification across completely novel domains |
| **Precision** | **99.17%** | When PhishGuard flags a URL, there is a 99.17% probability it is phishing |
| **Phishing Recall** | **99.36%** | Successfully catches 99.36% of actual phishing attacks |
| **False Positive Rate (FPR)** | **0.89%** | Only 249 legitimate URLs out of 27,957 were flagged |
| **Missed Threats (FNR)** | **0.64%** | Only 193 phishing URLs out of 30,063 evaded detection |
| **F1-Score** | **99.27%** | Balanced harmonic mean between precision and recall |
| **ROC-AUC** | **0.9971** | Exceptional discrimination capability across all thresholds |

### Confusion Matrix (58,020 Novel Holdout URLs)

```text
                              PREDICTED LEGITIMATE      PREDICTED PHISHING
ACTUAL LEGITIMATE (27,957)          27,708 (TN)                 249 (FP)
ACTUAL PHISHING   (30,063)             193 (FN)              29,870 (TP)
```

---

## 🔬 16-Dimensional Feature Attribution

PhishGuard AI analyzes 16 deterministic lexical, structural, and semantic features ordered by Random Forest Gini Importance:

| # | Feature Name | Description | Threat Relevance |
| :---: | :--- | :--- | :--- |
| 1 | `path_length` | Total character length of URL subpath | Phishing links embed long obfuscated subpaths |
| 2 | `url_length` | Total string character count | Adversaries use excessively long URLs to hide targets |
| 3 | `count_subdomains` | Dot-separated levels before apex domain | Deep subdomain nesting (e.g. `login.paypal.com.xyz`) |
| 4 | `hostname_length` | Character length of the domain component | Brand-impersonation hostnames tend to be unusually long |
| 5 | `count_dots` | Total period (`.`) characters in entire URL | High dot counts indicate layered subdomains or redirected hosts |
| 6 | `count_hyphens` | Total hyphen (`-`) count | Common in typosquatting (e.g. `secure-update-banking`) |
| 7 | `count_slash` | Forward slash frequency | Deep directory structures and tracking scripts |
| 8 | `has_https` | HTTPS protocol indicator ($1 = \text{HTTPS}, 0 = \text{HTTP}$) | Unencrypted HTTP is common in opportunistic phishing kits |
| 9 | `has_suspicious_keywords`| Presence of keywords (`login`, `verify`, `bank`, etc.) | Phishing campaigns concentrate around credential keywords |
| 10 | `digit_ratio` | Proportion of numeric digits to total URL length | Random session hashes, temporary campaigns, or hex strings |
| 11 | `special_char_ratio` | Non-alphanumeric character ratio | Obfuscation via URL encoding and symbol injection |
| 12 | `has_ip` | Direct IPv4 or IPv6 address indicator | Legitimate businesses rarely link to raw numeric IPs |
| 13 | `count_equal` | Frequency of `=` characters | Multiple tracking parameters or encoded redirection targets |
| 14 | `count_question` | Query parameter initiator frequency | Dynamic server scripts and token forwarding |
| 15 | `count_digits` | Absolute integer digit count | Embedded timestamps or random generation tokens |
| 16 | `count_at` | Frequency of `@` symbols | Obsolete browser auth spoofing (`user:pass@host`) |

---

## 🛡️ Threat Intelligence & Error Handling

PhishGuard AI queries upstream security databases independently without blocking core ML inference:

* **Google Safe Browsing Lookup v4**: Checks against global registries for `MALWARE`, `SOCIAL_ENGINEERING`, and `UNWANTED_SOFTWARE`.
* **abuse.ch URLhaus API**: Checks for active malware and credential distribution endpoints.

### 4 Provider States
1. **Threat Reported**: The URL is an active confirmed threat. Overrides ML to **High Risk**.
2. **No Match Reported**: The database was queried successfully and returned zero malicious records.
3. **Unavailable**: Upstream network timeout ($4\text{s}$ ceiling) or HTTP error. System falls back gracefully to offline ML.
4. **Not Configured**: Provider API key was not supplied. Scans proceed with offline ML.

> **Important Security Principle**: **Never label a URL safe just because it is absent from threat databases.** Threat feeds are retrospective blocklists. Newly registered zero-day phishing links often show *No Match Reported* because they have not been indexed yet. PhishGuard AI preserves the ML risk score when threat feeds report no match.

---

## 🔒 Pre-Scan Input Validation & Anti-SSRF Safeguards

Before any URL reaches the ML pipeline or threat feeds, it passes strict client and server validation:

* **Localhost & Loopback Isolation**: Automatically rejects `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, and local suffixes (`.local`, `.internal`, `.localhost`, `.test`, `.lan`).
* **Private IP Blocking (RFC 1918 & RFC 3927)**: Uses `ipaddress` parsing to block `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local `169.254.0.0/16`, and multicast ranges. Public external IPs (e.g. `93.184.216.34`) are permitted.
* **Internal Application Routes**: Blocks relative paths (e.g., `/scanner`, `/dashboard`).
* **Malformed Strings**: Rejects arbitrary non-URL text (e.g., `jhsahjvahvhasvkhgksghewvfv`) by verifying domain syntax and registered TLDs ($\ge 2$ characters).
* **Dangerous Schemes**: Blocks `javascript:`, `file:`, `data:`, `vbscript:`, `blob:`, and `ftp:`. Only `http://` and `https://` are permitted.

---

## 🚀 Quickstart & Installation

### Prerequisites
* **Python**: 3.10, 3.11, or 3.12
* **Node.js**: v18.0.0 or higher
* **Git**: Installed

### 1. Clone the Repository
```bash
git clone https://github.com/varunshetty1893/PhishGuard.Ai.git
cd "PhishGuard.Ai"
```

### 2. Backend Setup (FastAPI)
```bash
# Navigate to backend directory
cd backend

# Create and activate Python virtual environment
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Backend Environment (`backend/.env`)
Create or edit `backend/.env`:
```env
# Server
ENVIRONMENT=development
SECRET_KEY=phishguard-production-super-secret-key-replace-in-prod-xyz789
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000

# Database (Neon Cloud PostgreSQL with automatic SQLite fallback)
DATABASE_URL=postgresql://user:password@ep-sample-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require

# External Threat Intelligence (Optional)
# If left blank, the system reports "Not Configured" without errors
GOOGLE_SAFE_BROWSING_API_KEY=
URLHAUS_AUTH_KEY=
```

### 4. Start the Backend Server
```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
* **API Server**: `http://127.0.0.1:8000`
* **Interactive Docs (Swagger)**: `http://127.0.0.1:8000/docs`
* **Health Endpoint**: `http://127.0.0.1:8000/api/v1/health`

### 5. Frontend Setup (React + Vite)
In a new terminal window:
```bash
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```
* **Web UI**: `http://localhost:5173`

---

## 🧪 Testing Suite

PhishGuard AI includes comprehensive test suites covering unit logic, threat feeds, ML inference, and authentication isolation:

```bash
cd backend

# Run the full pytest suite (29 tests)
python -m pytest tests/ -v

# Run the dedicated pre-scan validation & workflow test suite (18 checks)
python tests/test_url_validation_workflow.py
```

---

## 📡 REST API Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/v1/scan` | Submits URL for zero-crawl ML analysis & threat intel | Yes |
| `GET` | `/api/v1/scans` | Returns paginated, isolated scan history for logged-in user | Yes |
| `GET` | `/api/v1/scans/{id}` | Retrieves full technical security report by scan ID | Yes |
| `DELETE` | `/api/v1/scans/{id}` | Deletes a specific scan record (Anti-IDOR protected) | Yes |
| `DELETE` | `/api/v1/scans` | Clears current user's scan history | Yes |
| `GET` | `/api/v1/model/info` | Returns model metadata, confusion matrix & domain split metrics | No |
| `GET` | `/api/v1/analytics` | Aggregated per-user scan metrics & risk distribution | Yes |
| `POST` | `/api/v1/auth/register` | Registers user account with Argon2id password hash | No |
| `POST` | `/api/v1/auth/login` | Issues secure HttpOnly session cookie + CSRF token | No |
| `POST` | `/api/v1/auth/logout` | Invalidates session and clears cookies | Yes |
| `GET` | `/api/v1/health` | Service health status, database ping, and ML model status | No |

---

## ⚖️ Responsible Cybersecurity Disclaimer

* **No Automated Tool Guarantees 100% Security**: Machine learning algorithms evaluate statistical patterns. Cyber adversaries continually innovate novel obfuscation techniques.
* **Absence of Proof $\neq$ Proof of Absence**: A "Low Risk" or "No Match Reported" result indicates that no known anomalies or active blocklist entries were detected. Users should always exercise standard digital hygiene.
* **Strict Zero-Crawl Guarantee**: PhishGuard AI analyzes URLs purely as text data. It does not load remote scripts, execute JavaScript, establish TCP connections to submitted endpoints, or download files.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
