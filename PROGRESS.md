# PhishGuard AI - Implementation Progress Tracker

## Project Overview
- **Project Name:** PhishGuard AI
- **Tagline:** Detect the Threat. Protect Your Digital World.
- **Academic Context:** MCA Individual Capstone / Academic Project
- **Technology Stack:**
  - Backend: Python 3.12, FastAPI, SQLite, SQLAlchemy, Scikit-learn, Pandas, NumPy, Joblib
  - Frontend: React 18 / Vite, TypeScript, Tailwind CSS, Lucide React, Recharts
  - Testing: Pytest, Vitest / React Testing Library
- **UI Aesthetic:** Pure black/charcoal foundation (#050505, #0A0A0A, #111111) with vibrant green (#39FF88), yellow (#FFD54A), and red (#FF525C) accents. ZERO blue or purple allowed.

---

## Phases & Status

| Phase | Description | Status | Test Result / Verification |
|-------|-------------|--------|----------------------------|
| **Phase 1** | Repository Inspection & Complete Documentation First | **COMPLETED** | Environment verified. Created full `docs/` suite (Requirements, Architecture, Database, ML, API, Threat Intel, Viva Q&A). |
| **Phase 2** | Public Dataset Verification & Feature Extraction Engine | **COMPLETED** | 16-feature deterministic lexical extractor. Zero network sockets opened. Tested on sample URLs. |
| **Phase 3** | Genuine ML Model Training, Evaluation & Benchmarking | **COMPLETED** | 5,000 URLs benchmark dataset. Random Forest vs Logistic Regression. Serialized `phishguard_rf_model.joblib` and `model_metadata.json`. |
| **Phase 4** | FastAPI Backend & SQLite Database Layer | **COMPLETED** | SQLAlchemy models, Pydantic schemas, versioned REST endpoints (`/api/v1/health`, `/scan`, `/scans`, `/analytics`, `/scans/export`). |
| **Phase 5** | Multi-Source Threat Intelligence | **COMPLETED** | Cached OpenPhish and Phishing.Database feeds, PhishDestroy and PhishStats lookups, and optional Google Safe Browsing. |
| **Phase 6** | Black-Themed Frontend Implementation (Strict Palette) | **COMPLETED** | Pure black foundation (#050505), neon green (#39FF88), yellow (#FFD54A), and red (#FF525C). Zero blue or purple anywhere. |
| **Phase 7** | Frontend-Backend API Integration | **COMPLETED** | React Router SPA with real-time scanning, probability meters, and live model transparency. |
| **Phase 8** | Scan History, Analytics, and CSV Export | **COMPLETED** | Dynamic SQLite aggregation, paginated audit table, search, filters, and RFC 4180 streaming CSV export. |
| **Phase 9** | End-to-End Automated Testing & Security Hardening | **COMPLETED** | 22/22 Pytest tests passing. Verified SSRF immunity, XSS sanitization, 2,048 char limit, and secret isolation. |
| **Phase 10** | Academic Viva Prep & Final Acceptance Verification | **COMPLETED** | 25 detailed MCA viva questions & answers in `docs/VIVA_QUESTIONS.md`. Browser verified. |

---

## Log of Executed Phases
- **Phase 1:** Initialized Git repository on `main`. Created comprehensive documentation suite in `docs/`.
- **Phase 2:** Implemented `ml/feature_extraction.py` and `backend/app/ml/feature_extraction.py` with 16 lexical and structural features.
- **Phase 3:** Built `ml/prepare_dataset.py` pulling 2,500 active phishing URLs from Mitchell Krogza Phishing.Database and 2,500 legitimate URLs. Trained Random Forest (150 estimators) and serialized artifacts.
- **Phase 4 & 5:** Built FastAPI application with SQLite database persistence, Pydantic validation, and threat intelligence adapters.
- **Phase 6 & 7:** Developed React + Vite + TypeScript frontend with Tailwind CSS and Recharts. Strict pure-black cyber SaaS theme with green, yellow, and red accents.
- **Phase 8:** Implemented full paginated history with multi-attribute filtering and CSV export.
- **Phase 9:** Executed Pytest test suite (22/22 tests passing) and ran automated color audits (0 blue/purple).
- **Phase 10:** Prepared 25 comprehensive viva questions and verified local Windows 11 execution.

## v4.1 Empirical Validation & Hardening Update (October 2026)
- **Data Leakage & Overlap Audit (Prompt 1):** Verified provenance of 16,245 training phishing URLs (PhiUSIIL 61.5%, Kaggle 38.5%). Discovered and documented previous fresh Tranco test leakage (79.2% domain overlap). Disclosed smoke test exact matches and threshold selection directly on test set.
- **Domain-Isolated 3-Split Retraining (Prompt 2):** Partitioned into 60% Train, 20% Val, 20% Test by registered apex domain. Fit model & calibration on train only, tuned threshold (0.640) on validation only, evaluated on test exactly once: Accuracy 96.82%, Precision 97.61%, Recall 95.38%, FPR 1.96%, ROC-AUC 99.28%.
- **Long-Tail Legitimate Test Set (Prompt 3):** Evaluated 1,080 URLs outside Tranco top-50k. Achieved 0.55% FPR on ranks 200k-1M, 3.00% on SMBs/regional, and documented 46.67% FPR on authentic SSO login portals (overall FPR 13.06% [95% CI: 11.05% - 15.06%]).
- **Hard Phishing Test Set (Prompt 4):** Evaluated 600 verified phishing URLs across HTTPS (95.34%), bare domains (98.70%), compromised CMS sites (99.33%), and platform-hosted sites (98.02%). Overall recall: 96.67%.
- **Time-Based Evaluation (Prompt 5):** Created continuous OpenPhish daily collector (`openphish_timeseries.csv`). Measured temporal recall vs random split on 7-day chronological cohorts.
- **Ablation Study (Prompt 6):** Benchmarked feature subsets and model architectures (Random Forest vs Logistic Regression vs Gradient Boosting). Found keywords drive 40% of false positives on legitimate login portals, and tree ensembles vastly outperform linear models.
- **Allowlist Hardening (Prompt 7):** Stripped shared-hosting and cloud platforms (`amazonaws.com`, `windows.net`, `googleusercontent.com`, `github.io`, `firebaseapp.com`, `web.app`, `azurewebsites.net`) from `HIGH_REPUTATION_DOMAINS`. Added unit tests proving threat intelligence feeds always override allowlists.
- **Honest UI & Documentation (Prompt 8):** Updated `/api/v1/model/info`, ML Lab page, `ResultsPage.tsx`, `ML_METHODOLOGY.md`, and archived v3 reports.
