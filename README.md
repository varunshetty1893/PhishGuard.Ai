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
3. **Multi-Source Threat Intelligence**: Checks cached OpenPhish, Phishing.Database, and CERT-PL Warning List feeds, the PhishDestroy API, and Google Safe Browsing when configured, with explicit provider status handling.
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
   - Rejects Private IPs        - HttpOnly Sessions             - OpenPhish, Phishing.Database, CERT-PL, and PhishDestroy
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

### Empirical Test Set Performance (Domain-Isolated 3-Split, Threshold 0.640)

| Metric | Result | Industry Interpretation |
| :--- | :---: | :--- |
| **Accuracy** | **96.82%** | Overall correct classification across completely novel held-out domains |
| **Precision** | **97.61%** | Fraction of true threats among all flagged URLs |
| **Phishing Recall** | **95.38%** | Successfully catches 95.38% of actual phishing attacks |
| **False Positive Rate (FPR)** | **1.96%** | Low false alarm rate on novel held-out domains |
| **Missed Threats (FNR)** | **4.62%** | Missed phishing rate under domain isolation |
| **F1-Score** | **96.48%** | Balanced harmonic mean between precision and recall |
| **ROC-AUC** | **0.9928** | Discrimination capability across all thresholds |

### Confusion Matrix (7,118 Novel Held-Out URLs)

```text
                              PREDICTED LEGITIMATE      PREDICTED PHISHING
ACTUAL LEGITIMATE (3,869)           3,793 (TN)                  76 (FP)
ACTUAL PHISHING   (3,249)             150 (FN)               3,099 (TP)
```

### Out-of-Distribution Stress Test Performance
- **Long-Tail Legitimate FPR (1,080 URLs from Tranco ranks 200k-1M & SSO Portals):** **13.06%** [95% CI: 11.05% - 15.06%]
- **Hard Phishing Recall (600 live 2026 OpenPhish & held-out targeted samples):** **96.67%** (580 / 600 caught)

See [ML_METHODOLOGY.md](ML_METHODOLOGY.md) for full empirical audit trail and known limitations.

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

PhishGuard AI always runs its local ML model and independently checks the following sources in priority order:

1. **OpenPhish public feed**: Exact full-URL matches against a periodically refreshed local feed.
2. **Phishing.Database**: Exact URL and domain/subdomain matches against periodically refreshed local lists.
3. **PhishDestroy API**: Public no-key phishing and scam domain-reputation check.
4. **CERT-PL Warning List**: Cached domain matches from the Polish national cybersecurity team's public phishing and dangerous-site list; its coverage focuses on sites targeting Polish users.
5. **Google Safe Browsing Lookup v4**: Checks global malware and social-engineering lists when configured.

Feed misses do not override the ML result. A positive feed match raises the verdict to **High Risk**, while the reported probability remains the ML model's probability. Provider errors, stale local data, and rate limits are reported as **Unavailable**, never as a clean result. The local feed cache is stored in an ignored SQLite database and refreshed in the background.

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

# Optional API key; public feeds and PhishDestroy work without a key.
GOOGLE_SAFE_BROWSING_API_KEY=
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
