# PhishGuard AI — 30-URL Ground-Truth Security Benchmark

This document provides a curated benchmark suite of **30 real-world web addresses** across three distinct risk tiers:
1. **10 Confirmed Malicious / Phishing Links (Real-World Attack Patterns)**
2. **10 Authenticated Legitimate Links (Real-World Clean Websites & Portals)**
3. **10 Borderline / "50-50" Ambiguous Edge-Cases (Shorteners, Cloud Buckets, Legacy HTTP, Complex Paths)**

Each entry documents the URL destination, structural characteristics, risk rationale, and verified PhishGuard AI detection output.

---

## 1. Ten (10) Confirmed Malicious & Phishing Links (Attack Patterns)

These URLs exhibit hallmark indicators of credential harvesting, brand impersonation, typosquatting, deceptive subdomains, or high-risk TLD abuse.

| # | Analyzed Address (Untrusted Destination) | Target Impersonated | Attack Mechanism / Threat Indicators | PhishGuard AI Verdict | Risk Score |
| :-: | :--- | :--- | :--- | :--- | :-: |
| **1** | `http://login.paypal.com.account-verify.xyz/signin` | **PayPal** | Chained deceptive subdomains, sensitive keywords (`login`, `signin`, `verify`), high-risk `.xyz` TLD, unencrypted HTTP. | **Phishing (High Risk)** | **98.1 / 100** |
| **2** | `https://chase-security-login-update.com/auth/verify` | **Chase Bank** | Compound hyphenated keywords, deceptive credentials harvesting path, high hostname entropy (3.96 bits). | **Phishing (High Risk)** | **86.8 / 100** |
| **3** | `http://bankofamerica.com.account-protection.info/sign-in` | **Bank of America** | Brand name embedded inside subdomain of an unauthorized apex domain, insecure HTTP protocol. | **Phishing (High Risk)** | **96.6 / 100** |
| **4** | `https://appleid-apple-support-verify.com/security/login` | **Apple ID** | Hyphenated multi-token typosquatting, credential harvesting keywords (`appleid`, `support`, `verify`, `login`). | **Phishing (High Risk)** | **90.1 / 100** |
| **5** | `http://secure-wellsfargo-banking.net/update/credentials` | **Wells Fargo** | Unauthorized financial brand imitation, unencrypted connection, sensitive banking keywords. | **Phishing (High Risk)** | **96.6 / 100** |
| **6** | `https://metamask-wallet-connect-auth.xyz/sync` | **MetaMask** | Web3 wallet drainer lure, high-risk `.xyz` registry abuse, deceptive `wallet-connect` hyphenated prefix. | **Phishing (High Risk)** | **82.3 / 100** |
| **7** | `http://netflix-billing-update-account.cc/login` | **Netflix** | Streaming credential phishing, billing payment capture lure, unencrypted transmission. | **Phishing (High Risk)** | **85.9 / 100** |
| **8** | `https://accounts-google-security-review.top/signin` | **Google Accounts** | High-risk `.top` TLD, unauthorized authentication lure mimicking Google Account recovery. | **Phishing (High Risk)** | **82.3 / 100** |
| **9** | `https://www.1ogle.com/search` | **Google Search** | Classic single-character substitution typosquatting (`1` replacing `g` / `l`), unregistered or deceptive mimic. | **Phishing (High Risk)** | **78.0 / 100** |
| **10** | `https://paypal-verify.vercel.app` | **PayPal on Vercel** | Phishing kit hosted on shared PaaS hosting (`vercel.app`), leveraging authentic cloud domain to bypass filters. | **Phishing (High Risk)** | **78.0 / 100** |

---

## 2. Ten (10) Confirmed Legitimate Links (Authentic Portals)

These destinations represent authoritative, verified, high-reputation domains, major public institutions, and verified legitimate developer project deployments.

| # | Analyzed Address (Verified Destination) | Entity / Service | Structural Posture & Reputation Indicators | PhishGuard AI Verdict | Risk Score |
| :-: | :--- | :--- | :--- | :--- | :-: |
| **1** | `https://www.google.com` | **Google Search** | Verified authoritative apex domain, clean lexical structure, official HTTPS encryption. | **Legitimate (Low Risk)** | **0.0 / 100** |
| **2** | `https://github.com` | **GitHub** | Verified software development platform, trusted infrastructure authority. | **Legitimate (Low Risk)** | **0.0 / 100** |
| **3** | `https://wikipedia.org` | **Wikimedia Foundation** | Non-profit global encyclopedia, clean URL hierarchy, verified authentic apex. | **Legitimate (Low Risk)** | **0.0 / 100** |
| **4** | `https://www.microsoft.com` | **Microsoft Corporation** | Verified enterprise enterprise infrastructure, trusted domain authority. | **Legitimate (Low Risk)** | **0.0 / 100** |
| **5** | `https://apple.com` | **Apple Inc.** | Official hardware and software ecosystem portal, verified root infrastructure. | **Legitimate (Low Risk)** | **0.0 / 100** |
| **6** | `https://www.amazon.com` | **Amazon Web Services / Retail** | Verified global e-commerce and cloud platform, high-authority domain. | **Legitimate (Low Risk)** | **0.0 / 100** |
| **7** | `https://softshowcase.vercel.app` | **User Portfolio (SoftShowcase)** | Real developer project deployed on Vercel; zero brand lookalikes, zero sensitive keywords, HSTS-enforced TLS. | **Legitimate (Low Risk)** | **2.8 / 100** |
| **8** | `https://www.linkedin.com` | **LinkedIn (Microsoft)** | Global professional networking service, verified apex domain authority. | **Legitimate (Low Risk)** | **0.0 / 100** |
| **9** | `https://cloudflare.com` | **Cloudflare Inc.** | Global CDN & DNS authority, verified security infrastructure. | **Legitimate (Low Risk)** | **0.0 / 100** |
| **10** | `https://stackoverflow.com` | **Stack Overflow** | Global developer knowledgebase, clean lexical structure, low anomaly metrics. | **Legitimate (Low Risk)** | **1.1 / 100** |

---

## 3. Ten (10) Borderline / 50-50 Ambiguous Edge-Cases

These URLs fall into the "50-50" grey zone: they are real web links that exhibit elevated structural complexity, URL shorteners, unencrypted HTTP protocols, deep cloud asset paths, or multi-hyphenated developer staging environments.

| # | Analyzed Address (Edge-Case Destination) | Ambiguity Type | Rationale (Why it is Borderline) | PhishGuard AI Decision | Risk Score |
| :-: | :--- | :--- | :--- | :--- | :-: |
| **1** | `https://bit.ly/3uL8qZ1` | **URL Shortener** | Bitly hides the actual destination endpoint. Could redirect to a benign blog or a malicious site. Model scores elevated caution (61.3%), below phishing cutoff. | **Legitimate (Low Risk / Caution)** | **61.3 / 100** |
| **2** | `https://tinyurl.com/developer-tools` | **URL Shortener** | Masked destination. Benign utility masking an address; triggers shortening service warning but remains unblocked without threat feed matches. | **Legitimate (Low Risk / Caution)** | **58.3 / 100** |
| **3** | `http://info.cern.ch` | **Legacy Insecure HTTP** | World's first website (CERN, 1991). Operates strictly over unencrypted HTTP without TLS, but has zero phishing deception. System caps score and warns about unencrypted transport. | **Legitimate (Suspicious Protocol)** | **35.0 / 100** |
| **4** | `http://neverssl.com` | **Intentional HTTP Test Site** | Legitimate utility created to trigger captive portal Wi-Fi logins without SSL. Clean domain, but entirely plaintext. Flagged for transport caution. | **Legitimate (Low Risk / Caution)** | **9.8 / 100** |
| **5** | `http://speedtest.tele2.net` | **Public ISP Speedtest Utility** | Public bandwidth test server provided by Tele2. Plain HTTP protocol triggers transport caution, but no brand spoofing is detected. | **Legitimate (Suspicious Protocol)** | **35.0 / 100** |
| **6** | `https://api-sandbox.developer-portal.dev/v1/auth/token` | **Complex API Endpoint** | Legitimate API staging URL, but contains tokens (`portal`, `auth`, `token`) that resemble phishing login forms. Elevated risk due to lexical keywords. | **Phishing (Suspicious API Form)** | **96.6 / 100** |
| **7** | `https://s3.us-west-2.amazonaws.com/public-assets-archive/data.zip` | **Multi-Token Cloud Storage** | Real Amazon S3 bucket path. High dot count, region prefixes, and archive file extension make it structurally indistinguishable from phishing payload droppers. | **Phishing (High Complexity)** | **95.6 / 100** |
| **8** | `https://my-testing-project.pages.dev/preview/build-42` | **PaaS Staging Subdomain** | Cloudflare Pages staging build. Multi-hyphenated subdomain and build versioning elevate hostname entropy (3.86 bits). | **Phishing (Elevated Entropy)** | **95.3 / 100** |
| **9** | `https://news-tech-digest.blogspot.com/2026/10/article.html` | **Free Shared Blog Platform** | Authentic Google Blogger link, but on shared platform (`blogspot.com`) with high entropy and dates in path. | **Phishing (Shared Subdomain Bias)** | **99.3 / 100** |
| **10** | `https://raw.githubusercontent.com/torvalds/linux/master/README` | **Deep CDN Asset Path** | Authentic Linus Torvalds Linux repository README, but deep multi-slash CDN structure on shared GitHub domain triggers lexical anomaly alerts. | **Phishing (Path Depth Bias)** | **91.8 / 100** |

---

## 4. Machine Learning Engine Accuracy & Confusion Matrix

Based on evaluation against **7,118 ground-truth test URLs** (isolated 3-split holdout set):

```
                       CONFUSION MATRIX (7,118 SAMPLES)
                       ┌──────────────────────┬──────────────────────┐
                       │   ACTUAL NEGATIVE    │   ACTUAL POSITIVE    │
                       │     (Legitimate)     │      (Phishing)      │
┌──────────────────────┼──────────────────────┼──────────────────────┤
│ PREDICTED NEGATIVE   │     TN = 3,793       │      FN = 150        │
│ (Classified Clean)   │  (Correctly Clean)   │ (Missed by Raw ML)   │
├──────────────────────┼──────────────────────┼──────────────────────┤
│ PREDICTED POSITIVE   │      FP = 76         │      TP = 3,099       │
│ (Classified Phish)   │   (False Alarms)     │  (Caught Phishing)   │
└──────────────────────┴──────────────────────┴──────────────────────┘
```

### Statistical Performance Metrics

- **Test Accuracy:** **96.82%**
- **Precision:** **97.61%** (When PhishGuard AI predicts Phishing, it is correct 97.6% of the time)
- **Recall (Sensitivity):** **95.38%** (Catches over 95 out of every 100 phishing attacks via ML alone)
- **F1 Score:** **96.48%**
- **Area Under ROC Curve (ROC-AUC):** **99.28%**
- **False Positive Rate (FPR):** **1.96%** (Only 76 false alarms across 3,869 legitimate websites)
- **Hybrid Threat-Intel Recall:** **~98.5%** (With Google Safe Browsing, PhishDestroy, OpenPhish, Phishing.Database, and CERT-PL active overrides)
