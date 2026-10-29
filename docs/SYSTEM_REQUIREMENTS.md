# PhishGuard AI — System Requirements Specification

## 1. Introduction
**PhishGuard AI** is an academic cybersecurity web application that detects phishing URLs using a trained machine-learning classifier and multiple threat-intelligence sources: cached OpenPhish and Phishing.Database feeds, PhishDestroy and PhishStats lookups, and optional Google Safe Browsing.

Designed as an MCA individual capstone project, the system provides transparent, explainable URL risk assessments without crawling, executing, or navigating to untrusted external URLs.

---

## 2. Product Identity & Scope
- **Product Name:** PhishGuard AI
- **Tagline:** *"Detect the Threat. Protect Your Digital World."*
- **Target Audience:** Cybersecurity researchers, IT security teams, academic evaluators, and everyday Internet users seeking transparent link verification.
- **Academic Standard:** Master of Computer Applications (MCA) Project Standard.

---

## 3. Functional Requirements (FR)

### FR-1: URL Scanning & Input Ingestion
- **FR-1.1:** Accept URLs via a high-visibility scanner input field with client-side and server-side validation.
- **FR-1.2:** Sanitize and normalize input strings safely (trim whitespace, handle URI encoding, scheme validation for `http` and `https`).
- **FR-1.3:** Reject empty strings, invalid schemes (`javascript:`, `file:`, `data:`), and strings exceeding 2,048 characters.
- **FR-1.4:** **Zero-Execution Rule:** Under no circumstances shall the application visit, crawl, render, execute, or perform backend DNS lookups against the submitted URL.

### FR-2: Machine Learning Inference Engine
- **FR-2.1:** Extract consistent, deterministic lexical and structural features from the submitted URL.
- **FR-2.2:** Load a serialized, genuinely trained ML classification model (e.g., Random Forest Classifier).
- **FR-2.3:** Calculate predicted classification label (`Legitimate` vs. `Phishing`).
- **FR-2.4:** Produce calibrated model confidence score (probabilities) and map to a standardized risk category (`Low Risk`, `Suspicious`, `High Risk`).
- **FR-2.5:** Return structured, human-readable explanations of extracted suspicious characteristics (e.g., presence of IP address, excessive subdomains, suspicious keywords, @ symbol).

### FR-3: Multi-Source Threat Intelligence
- **FR-3.1:** Check local OpenPhish and Phishing.Database feeds and query PhishDestroy and PhishStats.
- **FR-3.2:** Query Google Safe Browsing API v4 when `GOOGLE_SAFE_BROWSING_API_KEY` is present in the environment.
- **FR-3.3:** Maintain independent fallback states:
  - `Not Configured`: API credentials missing.
  - `No Match Reported`: Service queried successfully; no malicious threat record reported.
  - `Threat Reported`: Service confirms URL is associated with known threats (phishing/malware).
  - `Unavailable`: Network timeout, rate limit, or external provider downtime.
  - `Inconclusive`: Ambiguous or unparseable upstream response.
- **FR-3.4:** Display ML classification and threat-intel findings separately. Never merge them into an ungrounded combined percentage.

### FR-4: Analytics & Real-Time Dashboard
- **FR-4.1:** Compute real-time analytics from SQLite database records:
  - Total URLs scanned.
  - URLs classified as likely phishing vs. likely legitimate.
  - High-risk scan volume.
  - External threat intelligence matches & check failures.
  - Temporal scan distribution (scans over time).
- **FR-4.2:** Display genuine empty states when no scan records exist.

### FR-5: Scan History & Data Portability
- **FR-5.1:** Persist each scan event in SQLite with timestamps, extracted features, classification, risk level, model score, and threat-check logs.
- **FR-5.2:** Provide paginated scan history with search by URL and multi-criteria filters (classification, risk level, threat-intel status).
- **FR-5.3:** Allow viewing individual scan reports via persistent URL `/history/:scanId`.
- **FR-5.4:** Provide one-click CSV export of historical scans.
- **FR-5.5:** Support individual scan deletion and complete history clearance with modal confirmation.

### FR-6: Machine Learning Laboratory (ML Lab)
- **FR-6.1:** Present genuine training and evaluation metadata (Dataset name, version, training date, sample counts).
- **FR-6.2:** Display empirical evaluation metrics: Accuracy, Precision, Recall, F1-Score, and ROC-AUC.
- **FR-6.3:** Render the confusion matrix and feature importance rankings derived from the trained model.
- **FR-6.4:** Document model limitations and adversarial evasion considerations.

---

## 4. Non-Functional Requirements (NFR)

### NFR-1: Performance & Responsiveness
- Local URL feature extraction and ML inference latency must be under 150ms.
- External threat-intelligence lookups must have a strict timeout of 4.0 seconds per provider so as never to block the user.
- Frontend initial page load under 1.5 seconds on local host.

### NFR-2: Security & Privacy
- **Untrusted Input Guarantee:** The backend treats all input as untrusted strings.
- **SSRF Protection:** No HTTP/HTTPS connections are made to the target URL itself. Outbound calls are restricted to the configured threat-feed and provider endpoints.
- **Secret Protection:** API keys and environment variables are strictly encapsulated in the backend environment. No keys are exposed in client bundles or public API responses.
- **XSS & Injection Prevention:** User inputs and URL text are safely sanitized and escaped in React DOM rendering.

### NFR-3: Visual Aesthetics & Strict Palette Constraint
- **Pure Black Foundation:** Primary background `#050505`, secondary background `#0A0A0A`, cards `#111111`, elevated surfaces `#181818`, borders `#292929`.
- **Accents:** Neon Green (`#39FF88`, `#16C96A`), Warning Yellow (`#FFD54A`, `#EABF32`), Danger Red (`#FF525C`, `#D93645`).
- **STRICT PROHIBITION:** ZERO BLUE OR PURPLE anywhere in CSS, SVGs, icons, charts, loading spinners, or hover effects.

### NFR-4: Portability & Academic Demonstration
- Runs natively on Windows 11 with Python 3.12+ and Node.js 20+.
- Zero mandatory paid API subscriptions; operates fully offline/locally using the trained ML model.
- Uses SQLite with zero configuration required.
