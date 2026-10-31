# PhishGuard AI — Master Viva Questions & Answers (Academic Evaluation)

This document contains 25 comprehensive technical viva questions and detailed answers prepared for MCA capstone evaluation, external examiners, and technical project reviews.

---

### Q1: What is the core problem that PhishGuard AI solves?
**Answer:**
PhishGuard AI addresses the vulnerability of users and organizations to phishing and credential harvesting attacks delivered via malicious URLs. Traditional defense mechanisms rely almost exclusively on static blacklists (such as Google Safe Browsing or commercial feeds). However, blacklists fail to detect zero-day phishing campaigns during the critical window between attack launch and public indexing. PhishGuard AI provides an immediate, offline lexical and structural Machine Learning assessment that inspects the URL's inherent characteristics, complemented by multi-source threat intelligence when available.

---

### Q2: Why did you choose lexical and structural feature extraction over fetching webpage content?
**Answer:**
1. **Security (SSRF & Malware Protection):** Fetching page content requires opening network sockets and downloading arbitrary HTML/JavaScript from untrusted, potentially malicious hosts. This exposes the scanner server to Server-Side Request Forgery (SSRF), remote code execution, or drive-by payload downloads.
2. **Performance & Latency:** Offline lexical parsing executes in under 5 milliseconds using standard string algorithms, whereas fetching web content takes several seconds and depends on remote server uptime.
3. **Evasion Resistance:** Many modern phishing kits actively cloaking against crawlers (detecting headless browsers or cloud IP ranges) will serve benign 404 pages to scanners while serving phishing forms to genuine targets. URL lexical features cannot be cloaked this way.

---

### Q3: What Machine Learning algorithms did you evaluate, and which one did you select as primary?
**Answer:**
We evaluated two complementary supervised classification algorithms:
1. **Random Forest Classifier (Primary):** An ensemble of decision trees using bootstrap aggregating (bagging) and random feature subspace sampling. It excels at capturing non-linear relationships, threshold cutoffs (e.g., number of dots or subdomains), and feature interactions without requiring continuous normalization. It is robust against overfitting and offers Mean Decrease in Impurity (MDI) feature importances.
2. **Logistic Regression (Baseline):** A linear classifier with L2 regularization used as a benchmark to determine whether the feature space is linearly separable.
The Random Forest model outperformed Logistic Regression in both Recall (critical to minimize false negatives in security) and ROC-AUC, making it the chosen production model.

---

### Q4: Which specific features are extracted from each URL?
**Answer:**
We extract 16 distinct lexical, structural, and semantic features:
1. `url_length`: Total character length.
2. `hostname_length`: Character length of the host component.
3. `path_length`: Length of the path component.
4. `query_length`: Length of parameters query string.
5. `count_dots`: Total dot occurrences (indicates subdomain nesting).
6. `count_hyphens`: Hyphen occurrences (commonly used in typosquatting).
7. `count_subdomains`: Number of subdomain levels.
8. `count_digits`: Total numerical digits across the URL.
9. `count_special_chars`: Special symbols (`_`, `?`, `=`, `&`, `%`, `~`).
10. `is_ip_address`: Binary flag indicating if the hostname is a raw IPv4/IPv6 address.
11. `is_https`: Protocol flag (HTTP vs HTTPS).
12. `has_at_symbol`: Binary flag for `@` (used to obfuscate host destinations).
13. `has_suspicious_encoding`: Presence of percent-encoded sequences (`%20`, `%2e`).
14. `is_shortened_service`: Binary flag for known shortening services (`bit.ly`, `tinyurl.com`, etc.).
15. `has_unusual_port`: Binary flag for non-standard ports (e.g., `:8080`, `:8443`).
16. `has_suspicious_keywords`: Binary flag for sensitive credential keywords (`login`, `verify`, `banking`, `secure`, `update`, `account`, `signin`, `wallet`, `confirm`).

---

### Q5: Does the presence of HTTPS mean a URL is legitimate?
**Answer:**
No. Historically, SSL certificates were costly and required business identity verification, so phishing sites ran over unencrypted HTTP. Today, automated free certificate authorities (such as Let's Encrypt) allow threat actors to generate valid SSL/TLS certificates in seconds. Over 70% of modern phishing sites utilize HTTPS. PhishGuard AI treats HTTPS as one feature among 16, never assuming safety based on encryption alone.

---

### Q6: Does an IP address in the hostname automatically indicate malicious intent?
**Answer:**
No. While legitimate consumer websites rarely use direct IP addresses (they rely on DNS domain names), certain local intranet routers (`192.168.1.1`), corporate developer previews, or IoT device dashboards legitimately expose IP addresses. Thus, `is_ip_address` is a weighted signal within the ensemble rather than a hard deterministic block.

---

### Q7: How does PhishGuard AI prevent data leakage between training and testing splits?
**Answer:**
We apply strict isolation:
1. The dataset is deduplicated prior to splitting.
2. A stratified 80/20 train/test split is applied using a fixed random seed (`random_state=42`) to maintain consistent class proportions.
3. Feature transformers and preprocessing statistics are calculated strictly on the training partition and applied to the test partition.
4. Test records are evaluated only after model training is completely finalized.

---

### Q8: What evaluation metrics did you use to assess model quality?
**Answer:**
- **Accuracy:** Overall proportion of correct predictions across both classes.
- **Precision:** $\frac{TP}{TP + FP}$ — Measures how many flagged URLs were truly phishing. High precision prevents false alarms that degrade user trust.
- **Recall (Sensitivity):** $\frac{TP}{TP + FN}$ — Measures the proportion of actual phishing URLs successfully caught. In cybersecurity, recall is of paramount importance because a false negative means a user visits a malicious site and risks credential compromise.
- **F1-Score:** The harmonic mean balancing precision and recall.
- **Confusion Matrix:** Explicitly reports True Negatives, False Positives, False Negatives, and True Positives.
- **ROC-AUC:** Area under the ROC curve indicating discriminatory power across all probability thresholds.

---

### Q9: How does PhishGuard AI integrate with external Threat Intelligence feeds?
**Answer:**
PhishGuard AI implements an asynchronous Adapter Pattern supporting:
- **OpenPhish, Phishing.Database, and CERT-PL Warning List:** Public feeds cached locally for URL/domain lookups. CERT-PL focuses on threats targeting Polish users.
- **PhishDestroy:** Server-side reputation lookup.
- **Google Safe Browsing API v4:** Optional Google threat database lookup.
The integrations are independent. Each check reports its own state, and a provider failure does not turn a URL into a clean result.

---

### Q10: Why do you keep the ML model prediction separate from threat-intelligence findings?
**Answer:**
Combining ML output probabilities and external threat-intel responses into a single combined percentage (e.g., "78% Malicious") is mathematically ungrounded and misleading. A machine learning model outputs a statistical classification probability based on structural patterns, whereas a threat-intelligence feed provides an empirical database lookup. If Safe Browsing returns "No Match", it does not decrease the probability that a zero-day structure is phishing. Keeping them distinct allows security analysts to see both the algorithmic risk and authoritative database hits side-by-side.

---

### Q11: How do you prevent Server-Side Request Forgery (SSRF)?
**Answer:**
1. The backend application strictly forbids making HTTP/HTTPS connections to the user-submitted URL.
2. Input URLs are passed exclusively to the in-memory lexical parser and regex feature extractor.
3. External network requests are restricted to configured feed sources and hardcoded threat-provider endpoints; no request is made to the submitted URL itself.
4. Schemes such as `file://`, `gopher://`, `dict://`, and internal private IP requests (`localhost`, `127.0.0.1`, `169.254.169.254`) are safely parsed as strings or rejected without network resolution.

---

### Q12: How are API keys protected in PhishGuard AI?
**Answer:**
API keys are stored exclusively as server-side environment variables loaded by FastAPI from `.env`. They are never injected into the client bundle, never transmitted to the browser, and never exposed in error responses or logs.

---

### Q13: What happens if an external threat provider is down or rate-limited?
**Answer:**
The threat intelligence service executes external calls with a strict 4.0-second timeout inside non-blocking `try...except` blocks. If an endpoint times out, returns HTTP 429 (rate limited), or experiences a 500 error, its status is logged as `Unavailable`. The user receives their full ML prediction and feature breakdown without interruption.

---

### Q14: Describe the database schema and storage strategy.
**Answer:**
We use SQLite managed through SQLAlchemy ORM with three core tables:
1. `scan_history`: Records scan ID (UUIDv4), submitted URL, normalized URL, predicted class, risk level, model probability score, extracted 16 features (JSON), heuristic explanations, combined interpretation, and timestamp.
2. `threat_check_logs`: Linked one-to-many to `scan_history`, storing provider name, check status, threat category, and checked timestamp.
3. `model_metadata`: Stores the audit log of model training, algorithm name, sample counts, evaluation metrics, confusion matrix, and feature importances.

---

### Q15: How does the analytics dashboard compute statistics?
**Answer:**
The `/api/v1/analytics` endpoint executes live SQL aggregation queries against the SQLite database using SQLAlchemy functions (`func.count`, `func.date`, group by filters). It calculates total scans, legitimate vs. phishing breakdowns, high-risk counts, external threat matches, and temporal scan distribution dynamically. There is zero hardcoding of analytics metrics.

---

### Q16: How does the URL Scanner handle empty states and input errors?
**Answer:**
- Frontend validation uses React Hook Form and Zod to enforce valid URL format before dispatch.
- Server-side Pydantic models validate URL syntax and enforce a 2,048-character length limit.
- If no scans exist, the Dashboard and History pages render dedicated, styled empty states guiding the user to run their first scan.

---

### Q17: Why is there a strict color restriction prohibiting blue and purple?
**Answer:**
In cybersecurity operations centers (SOC) and incident response tools, color conveys critical operational meaning:
- **Green (`#39FF88`):** Safe, active, legitimate, passed checks.
- **Yellow (`#FFD54A`):** Caution, suspicious, unconfigured provider, warning.
- **Red (`#FF525C`):** High risk, confirmed phishing attack, critical alert.
- **Black/Charcoal (`#050505` to `#181818`):** Clean, distraction-free operations foundation.
Blue and purple dilute this semantic hierarchy, introducing visual noise. Enforcing a strict palette creates an authentic, high-contrast security dashboard aesthetic.

---

### Q18: What is the purpose of the ML Lab page?
**Answer:**
Academic evaluation requires algorithmic transparency. The ML Lab provides a transparent window into model performance:
- Source dataset provenance and sample counts.
- Selected algorithm (Random Forest) and hyperparameters.
- Empirical evaluation metrics (Accuracy, Precision, Recall, F1, ROC-AUC).
- The exact confusion matrix from held-out testing.
- Feature importance rankings (MDI) revealing which lexical properties most strongly indicate phishing.
- Documented model limitations and evasion strategies.

---

### Q19: What are the main limitations of purely lexical URL classification?
**Answer:**
1. **Adversarial URL Crafting:** Attackers who understand the model's feature weights can register brand-new single-word domains without hyphens or subdomains to evade purely lexical filters.
2. **URL Shorteners:** A shortened link (`bit.ly/xyz`) masks destination features until redirected.
3. **Compromised Reputable Sites:** If a trusted university (`.edu`) or government (`.gov`) site is compromised and hosts a phishing path, high-reputation domain features may initially bias predictions towards legitimate.
These limitations highlight why defense-in-depth (pairing ML with threat-intelligence and browser protections) is essential.

---

### Q20: How does CSV export work and how is data integrity maintained?
**Answer:**
The `/api/v1/scans/export` endpoint queries the SQLite database, serializes records into RFC 4180 compliant CSV format using Python's `csv.writer`, and streams it with `Content-Type: text/csv`. User-submitted URLs containing commas or quotation marks are properly escaped to prevent CSV injection.

---

### Q21: How is the frontend decoupled from the backend?
**Answer:**
The frontend is a single-page application (SPA) built with React and Vite. It communicates with the backend exclusively via asynchronous REST API calls over HTTP using JSON payloads. This decoupling allows the backend to be replaced, scaled, or containerized independently without modifying frontend presentation logic.

---

### Q22: What role does Cross-Origin Resource Sharing (CORS) play?
**Answer:**
FastAPI utilizes `CORSMiddleware` configured to allow authorized frontend origins (e.g., `http://localhost:5173`) to make API requests while restricting unauthorized cross-origin requests.

---

### Q23: How do you handle Internationalized Domain Names (IDNs) and Punycode?
**Answer:**
Attackers often use homograph attacks (substituting Cyrillic letters for Latin letters, e.g., `pаypаl.com`). During URL normalization, our feature engine utilizes Python's `urllib.parse` and encodes domain hostnames using IDNA (Punycode `xn--`), allowing suspicious character counts and encoding flags to capture homoglyph obfuscation.

---

### Q24: Can PhishGuard AI guarantee that a URL is 100% safe?
**Answer:**
No security system can guarantee 100% safety. A "Legitimate" classification indicates that the URL does not display typical phishing patterns and has no matches on active threat feeds. We explicitly display a responsible-use disclaimer stating that users should remain vigilant, verify credentials, and practice safe browsing.

---

### Q25: What are future research and engineering enhancements for PhishGuard AI?
**Answer:**
1. **Deep Learning Sequence Models:** Incorporating Character-level CNNs or Transformer-based tokenizers (BERT/RoBERTa) to capture subtle semantic patterns in hostnames.
2. **Passive DNS & Whois Age Integration:** Enriching feature vectors with domain registration age (newly registered domains are far more likely to be phishing) via passive DNS lookups.
3. **Browser Extension:** Developing a lightweight Chrome/Firefox extension that intercepts navigation events and queries PhishGuard AI in real-time.
4. **Sandboxed Headless Screenshot Preview:** Safe server-side headless browser capture inside an isolated Docker container with zero network interaction to target local subnets.
