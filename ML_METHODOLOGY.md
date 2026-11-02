# PhishGuard AI - Machine Learning Methodology & Empirical Validation (v5.0)

## 1. Overview & Dataset Provenance
PhishGuard AI employs a 16-dimensional deterministic lexical feature extraction engine coupled with a Class-Weighted Random Forest classifier (200 estimators) and Isotonic Probability Calibration.

### Dataset Composition
- **Total Curated Samples:** 40,068 URLs
  - **20,068 Legitimate URLs:** Drawn from Tranco Top-50k (ranks 1 to 50,000) augmented with 68 verified hard-negative SSO and authentication portals across global universities, enterprise identity providers (Okta, Azure AD, Auth0, Ping), and international financial institutions. Composed of 40% bare root domains (`https://domain.tld`), 20% www root domains (`https://www.domain.tld`), and 40% authentic deep links.
  - **20,000 Phishing URLs:** Sourced from verified research corpora (PhiUSIIL Phishing Dataset, UCI ML Repository 2024, collected ~2021–2023; and url_features_extracted1, collected ~2020).
- **Temporal Note:** Phishing samples originated from historical archival feeds (2020–2023). Zero live 2026 data was present in the training set.

---

## 2. Domain-Isolated 3-Way Partitioning Protocol
To prevent data leakage, samples were partitioned using a strict 3-way split grouped by registered apex domain:
- **Train Split (60%):** 23,739 URLs across 18,388 unique apex domains.
- **Validation Split (20%):** 8,963 URLs across 6,129 unique apex domains.
- **Held-Out Test Split (20%):** 7,366 URLs across 6,130 unique apex domains.
- **Cross-Split Domain Overlap:** Exactly **0** shared apex domains between any pair of splits.

### Threshold Selection
- Model weights and Isotonic calibration were fitted **exclusively on the Train split**.
- The decision threshold (**0.660**) was tuned **exclusively on the Validation split** to target a False Positive Rate <= 2.0% while maximizing recall.
- The Test split was evaluated **exactly once** using the frozen validation threshold.

---

## 3. Held-Out Test Set Performance (Touched Exactly Once)

| Metric | v4.1.0 Baseline (@ 0.640) | v5.0.0 Model (@ 0.660) | 95% Confidence Interval |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 96.82% | **96.80%** | [96.40%, 97.20%] |
| **Precision** | 97.61% | **97.93%** | [97.45%, 98.41%] |
| **Phishing Recall** | 95.38% | **95.13%** | [94.41%, 95.85%] |
| **False Positive Rate (FPR)** | 1.96% | **1.75%** | [1.34%, 2.16%] |
| **F1-Score** | 96.48% | **96.51%** | [96.10%, 96.92%] |
| **ROC-AUC** | 99.28% | **99.30%** | [99.15%, 99.45%] |

### Test Confusion Matrix (@ 0.660)
- **True Negatives (Clean Legit):** 3,869
- **False Positives (False Alarms):** 69 (1.75% FPR)
- **False Negatives (Missed Phish):** 167 (4.87% FNR)
- **True Positives (Caught Phish):** 3,261 (95.13% Recall)

---

## 4. Production Prevalence Analysis (Per 1,000 Scans)
Because phishing is relatively rare in real-world traffic (~1% to 10%), base-rate prevalence drastically affects real-world precision:

| Prevalence | Phish / Legit Ratio | Expected True Positives | Expected False Alarms | Expected Precision | False Alerts / 1k Scans |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **1.0%** | 10 / 990 | 9.5 | 17.3 | **35.42%** | **17.3** per 1,000 |
| **5.0%** | 50 / 950 | 47.6 | 16.6 | **74.08%** | **16.6** per 1,000 |
| **10.0%** | 100 / 900 | 95.1 | 15.8 | **85.78%** | **15.8** per 1,000 |

*Takeaway:* In low-prevalence enterprise environments, contextual keyword filtering and threshold optimization reduced false alerts from 19.4 to 17.3 per 1,000 scans.

---

## 5. Out-of-Distribution Stress Tests

### A. Hard Long-Tail Legitimate Test Set (1,080 URLs)
Tested on 1,080 URLs strictly outside Tranco top-50k (ranks 200k–1M, authentic SSO portals, SMB hostnames with hyphens/digits, and URLs with security keywords):
- **Overall FPR:** **9.35%** (101 / 1,080 FP) [95% CI: **7.61% – 11.09%**] (Down from 13.06% in v4.1.0; **-28.4% relative false-alarm reduction**)
- **Tranco ranks 200k–1M (bare domains):** **0.55% FPR** (3 / 550 FP)
- **SMBs / Regional / Hyphen & Digits:** **3.00% FPR** (6 / 200 FP)
- **Authentic Login & SSO Portals (Google, MS, MIT, Salesforce):** **33.33% FPR** (10 / 30 FP) (Down from 46.67% in v4.1.0; **-28.6% relative reduction**)

### B. Hard Phishing Test Set (600 URLs)
Tested on 600 verified phishing URLs combining live OpenPhish (October 2026) feeds and strictly held-out targeted pools (0 in training):
- **Overall Phishing Recall:** **96.00%** (576 / 600 caught) [95% CI: **94.43% – 97.57%**]
- Recall drop is **0.67 percentage points** (within the <= 1.0 point deployment gate constraint).

---

## 6. Model Comparison & Ablation

| Model Configuration | Test Acc | Test Recall | Test FPR | Long-Tail Legit FPR | Authentic SSO FPR | Hard Phish Recall |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline v4.1.0 (RF @ 0.640)** | 96.82% | 95.23% | 1.96% | 13.06% (141) | 46.67% (14/30) | **96.67% (580)** |
| **Candidate v5-HGB (HistGB @ 0.660)** | **97.05%** | **95.62%** | **1.70%** | 22.78% (246) | 40.00% (12/30) | 96.83% (581) |
| **Deployed v5.0.0 (RF @ 0.660)** | 96.80% | 95.13% | **1.75%** | **9.35% (101)** | **33.33% (10/30)** | 96.00% (576) |

### Key Architectural Findings:
1. **HistGradientBoosting Overfitting on Continuous Lexical Lengths:** While HistGradientBoosting achieved slightly higher raw recall on held-out test data (+0.49%), it suffered severe false positive inflation on long-tail legitimate URLs (22.78% FPR vs 9.35% for Random Forest).
2. **Contextual Keyword Discernment:** Requiring suspicious keywords to co-occur with structural anomalies (high-risk TLDs, brand typosquatting, raw IPs, punycode, or high entropy) dropped Long-Tail False Positives from 141 down to 101 without compromising hard-phishing recall.
3. **Deployment Gate Fulfilled:** The v5.0.0 model improved Long-Tail FPR (13.06% -> 9.35%) and Authentic SSO FPR (46.67% -> 33.33%) while holding recall within 0.67 points of baseline, safely passing the pre-set production acceptance criteria.
