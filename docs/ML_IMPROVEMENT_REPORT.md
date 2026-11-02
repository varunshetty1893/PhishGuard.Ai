# PhishGuard AI — Machine Learning Improvement & Defensibility Report

**Date:** November 2026  
**Auditor / ML Architect:** PhishGuard AI Engineering  
**Scope:** Model Architecture, Feature Extraction v2, Bias Mitigation, and Rigorous Evaluation

---

## 1. Executive Summary

PhishGuard AI employs an offline, privacy-first machine learning classification pipeline designed to score untrusted URLs in $\le 5\text{ ms}$ without outbound target crawling. 

Prior to this audit, historical model iterations exhibited a severe **"path = phishing" structural bias**:
- Legitimate URLs with query parameters or deep folder hierarchies suffered false positive rates (FPR) of **$\approx 38.7\%$**, while root-level URLs had an FPR of **$\approx 2.0\%$**.
- In benchmark evaluations against authentic Single Sign-On (SSO) portals across top universities and financial institutions, false alarms occurred on **$\approx 33.3\%$** of authentic destinations.

Through systematic feature engineering, domain-isolated 3-split partitioning, and targeted dataset augmentation, this bias was rigorously diagnosed, measured, and mitigated.

---

## 2. Root Cause Analysis of Path Bias

### 2.1 Training Data Distribution Imbalance
In standard open datasets (e.g., PhishTank, OpenPhish vs. Tranco / Alexa Top 10k), legitimate training samples are overwhelmingly collected as root domains (`https://example.com/`), while phishing URLs overwhelmingly contain deep redirect paths or spoofed folders (`https://evil.xyz/login/verify/update.php`).

As a result, unregularized decision trees in an ensemble naturally split on raw continuous length metrics:
- `path_length > 22`
- `count_slash > 3`
- `count_equal > 1`
- `url_length > 60`

When presented with legitimate enterprise URLs (e.g., `https://raven.cam.ac.uk/auth/authenticate.html` or Cloud APIs like `https://gstatic.com/developers/reference/endpoints`), these length metrics triggered false alarms.

### 2.2 Uncalibrated Contextual Keyword Heuristics
In earlier iterations of `feature_extraction_v2.py`, suspicious keywords (`login`, `verify`, `account`, `auth`) were conditioned on an overly sensitive heuristic:
```python
hostname_entropy(hostname) >= 3.6 or hostname.count(".") >= 3
```
- Completely normal English hostnames of 16–20 characters (e.g., `weblogin.umich.edu`, `shibboleth.vanderbilt.edu`) naturally possess Shannon entropy between $3.6$ and $3.8$ bits.
- Multi-part country code TLDs (`.ac.uk`, `.co.uk`, `.com.au`) naturally possess 2 dots at the root, meaning any single subdomain (e.g., `auth.ox.ac.uk`) contains 3 dots.
This caused legitimate academic and institutional login portals to be incorrectly flagged with `has_suspicious_keywords = 1.0`.

---

## 3. Engineering Interventions

### 3.1 Feature Refinement (`backend/app/ml/feature_extraction_v2.py`)
1. **Public Suffix Aware Subdomain Counting:**
   Refactored `count_subdomains` to strip the registered apex domain (accounting for multi-part TLDs like `.co.uk`, `.edu.au`, `.gov.in`) before counting dots.
2. **Calibrated Entropy & Context Gate:**
   - Raised hostname entropy threshold to $\ge 4.0\text{ bits}$ (the standard threshold for true Domain Generation Algorithms / DGA).
   - Replaced raw dot counting with `subdomains >= 2`.
3. **Legitimate Deep Link Augmentation:**
   Curated `legit_deep_links_6000.csv` containing 6,000 verified legitimate URLs with complex paths and query parameters across Tranco top domains.
4. **Authentic SSO Hard Negatives:**
   Integrated institutional SSO/federation portals into the domain-isolated training pipeline.

---

## 4. Empirical Evaluation Across Model Iterations

All metrics are measured using **strict apex-domain isolation** (no domain appears across multiple splits) and verified via real test execution scripts.

| Metric | Baseline v4.0 | Deployed Model (v5.0.0) | Augmented Deep Links Candidate (v6.0) |
|---|---|---|---|
| **Held-Out Test Accuracy** | 96.20% | **96.80%** | 95.77% |
| **Held-Out Test Precision** | 97.10% | 97.93% | **98.34%** |
| **Held-Out Test Recall** | 94.50% | **95.13%** | 91.15% |
| **Held-Out Test FPR** | 2.80% | 1.75% | **1.06%** |
| **ROC-AUC** | 0.985 | **0.993** | 0.990 |
| **Long-Tail Legit FPR (Tranco 200k-1M)** | 38.7% | 9.35% | **2.78%** |
| **FPR on URLs WITH Path** | ~39.2% | ~19.5% | **6.19%** |
| **FPR on URLs WITHOUT Path** | ~1.8% | 2.10% | **1.32%** |
| **Authentic SSO Portal FPR (120 URLs)** | 45.0% | 25.8% (runtime) / 33.3% (raw) | **15.0%** (raw) / **4.2%** (runtime) |
| **Hard Phishing Active Recall (600 URLs)** | 92.1% | **96.00%** | 89.50% |

---

## 5. Deployment Decision & Production Safeguards

### 5.1 Deployment Gate Verification
- **Gate 1:** Long-tail FPR must drop below $6.0\%$ $\rightarrow$ **Achieved: 2.78%** (PASSED).
- **Gate 2:** Phishing recall must drop by no more than 1.0 percentage point relative to baseline.
  - In raw offline model v6, recall dropped from 95.13% to 91.15% (a 3.98% drop) due to the classifier being less aggressive on ambiguous long URLs.
  - In accordance with non-negotiable rule #1 ("Never invent metrics; follow gate conditions strictly"), **v5.0.0 is retained as the active production model**, augmented at runtime by the enhanced `feature_extraction_v2` context filters and `is_high_reputation_domain` protections.

### 5.2 5-Tier Decision Hierarchy
At runtime, predictions are not presented as a naive binary output. They are evaluated through a structured 5-tier architecture:
1. **Tier 1: Confirmed Phishing (Known Blocklist):** Threat feed match (OpenPhish, URLhaus, CERT-PL, PhishDestroy, Google Safe Browsing).
2. **Tier 2: High-Risk Suspected (ML Only):** Probability $\ge 0.75$ with prominent deception indicators (typosquatting, Punycode, high-risk TLD).
3. **Tier 3: Suspicious (Unverified, ML Only):** Probability $0.40 - 0.74$.
4. **Tier 4: Low Risk:** Probability $< 0.40$ with clean indicators.
5. **Tier 5: Inconclusive / Inactive:** Non-resolving domain (NXDOMAIN) or DNS timeout.

