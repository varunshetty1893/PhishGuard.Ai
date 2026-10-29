# PhishGuard AI — Machine Learning Methodology & Architecture

## 1. Executive Summary
PhishGuard AI employs a supervised machine learning classification pipeline to identify malicious phishing URLs based strictly on lexical, structural, and syntactic properties of the URL string.

To ensure safety, performance, and resistance to Server-Side Request Forgery (SSRF), the feature extraction operates **completely offline** without executing DNS queries, opening TCP sockets, or rendering web content.

---

## 2. Dataset Provenance & Selection

### 2.1 Benchmark Selection
For academic transparency and reproducibility, PhishGuard AI utilizes a curated, verified benchmark of legitimate and phishing URLs derived from widely cited open cybersecurity repositories:
- **Phishing Distribution:** Sourced from verified active and historical community feeds (PhishTank archive and open research repositories).
- **Legitimate Distribution:** Sourced from top high-reputation domains (Tranco / Alexa Top 1M reputable domains) across diverse TLDs (`.com`, `.org`, `.edu`, `.gov`, `.io`).
- **Data Integrity:** Strict deduplication, target label normalization (0 = Legitimate, 1 = Phishing), and scheme normalization to prevent training bias.

---

## 3. Feature Engineering

The feature vector consists of 16 carefully engineered structural, lexical, and statistical dimensions:

| # | Feature Name | Data Type | Cybersecurity Rationale |
|---|---|---|---|
| 1 | `url_length` | Integer | Phishing URLs are frequently longer to conceal destination domains or embed redirect payloads. |
| 2 | `hostname_length` | Integer | Attackers frequently chain subdomains or use randomly generated hostnames. |
| 3 | `path_length` | Integer | Deep paths are often used to mirror legitimate banking or authentication directories. |
| 4 | `query_length` | Integer | Phishing campaigns often append tracking tokens, session IDs, or base64 redirects in query strings. |
| 5 | `count_dots` | Integer | Excessive dots indicate deep subdomain nesting (`login.paypal.com.account-verify.xyz`). |
| 6 | `count_hyphens` | Integer | Hyphens are widely used in typosquatting and brand impersonation (`security-update-apple.com`). |
| 7 | `count_subdomains` | Integer | More than 2 subdomains strongly correlates with malicious hosting environments. |
| 8 | `count_digits` | Integer | Phishers incorporate random digits to evade static domain blacklists. |
| 9 | `count_special_chars` | Integer | Special characters (`_`, `?`, `=`, `&`, `%`, `~`) indicate complex parameter spoofing. |
| 10 | `is_ip_address` | Binary (0/1) | Legitimate sites rarely use raw IPv4/IPv6 addresses directly in links. |
| 11 | `is_https` | Binary (0/1) | Captures protocol. Note: Modern phishers also use free SSL certificates (Let's Encrypt), making HTTPS alone insufficient for legitimacy. |
| 12 | `has_at_symbol` | Binary (0/1) | In standard URLs, everything before `@` is treated as user authentication and ignored by the browser, a classic obfuscation trick (`legitimate.com@evil.com`). |
| 13 | `has_suspicious_encoding` | Binary (0/1) | Repeated `%` or double URL-encoding used to bypass signature scanners. |
| 14 | `is_shortened_service` | Binary (0/1) | Uses recognized shortening services (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, `ow.ly`) to mask destinations. |
| 15 | `has_unusual_port` | Binary (0/1) | Non-standard ports (e.g., `:8080`, `:8443`, `:8888`, `:81`) outside port 80/443. |
| 16 | `has_suspicious_keywords` | Binary (0/1) | Presence of high-risk terms (`login`, `verify`, `banking`, `secure`, `update`, `account`, `signin`, `wallet`, `confirm`). |

---

## 4. Model Training & Comparison Protocol

### 4.1 Candidate Algorithms
1. **Random Forest Classifier:**
   - Ensemble of decision trees using bagging and feature subspace sampling.
   - Handles non-linear feature interactions, resistant to overfitting, provides feature importances via Gini impurity reduction.
2. **Logistic Regression (Baseline):**
   - Linear baseline classifier with L2 regularization.
   - Evaluates whether linear boundaries are sufficient or non-linear ensembles are required.

### 4.2 Data Partitioning & Leakage Prevention
- **Split Ratio:** 80% Training partition, 20% Held-out Test partition.
- **Stratification:** Stratified sampling preserving identical class ratios in both splits.
- **Random Seed:** Fixed seed `random_state=42` across all preprocessing and fitting for exact reproducibility.
- **No Data Leakage:** Preprocessors and feature extractors are fit strictly on training splits.

---

## 5. Evaluation Metrics & Decision Rules

### 5.1 Metrics
- **Accuracy:** Overall proportion of correct classifications.
- **Precision:** $\frac{TP}{TP + FP}$ — Critical to avoid falsely blocking legitimate business sites.
- **Recall (Sensitivity):** $\frac{TP}{TP + FN}$ — Critical to catch malicious phishing attacks.
- **F1-Score:** Harmonic mean of precision and recall.
- **ROC-AUC:** Area under receiver operating characteristic curve assessing discrimination threshold.

### 5.2 Calibrated Risk Tiers
- **Low Risk (Green):** ML probability $< 0.40$ AND no suspicious indicators.
- **Suspicious (Yellow):** ML probability between $0.40$ and $0.69$ OR multiple heuristic flags present.
- **High Risk (Red):** ML probability $\ge 0.70$ OR any confirmed malicious threat match.

---

## 6. Model Limitations & Adversarial Defenses
1. **Zero-Day Obfuscation:** A novel phishing URL with zero heuristic flags on a clean brand-new domain may evade pure lexical analysis.
2. **Shortener Masking:** URL shorteners hide true destinations; PhishGuard AI flags shorteners as a distinct suspicious feature.
3. **Defense-in-Depth:** Combining the trained ML model with OpenPhish and Phishing.Database feeds, PhishDestroy and PhishStats, and optional Google Safe Browsing yields layered coverage without a single-provider dependency.
