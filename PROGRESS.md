# PhishGuard AI - Implementation Progress Tracker

## Project Overview
- **Project Name:** PhishGuard AI
- **Tagline:** Detect the Threat. Protect Your Digital World.
- **Academic Context:** MCA Individual Capstone / Academic Project
- **Technology Stack:**
  - Backend: Python 3.12, FastAPI, SQLite, SQLAlchemy, Scikit-learn, Pandas, NumPy, Joblib
  - Frontend: React 18 / Vite, TypeScript, Tailwind CSS, Lucide React, Recharts
  - Testing: Pytest 8.3.5 (47 backend tests), Vitest + React Testing Library (33 frontend tests)
- **UI Aesthetic:** Pure black/charcoal foundation (#050505, #0A0A0A, #111111) with vibrant green (#39FF88), yellow (#FFD54A), and red (#FF525C) accents. ZERO blue or purple allowed.

---

## Phases & Status

| Phase | Description | Status | Test Result / Verification |
|-------|-------------|--------|----------------------------|
| **Phase 1** | Repository Inspection & Complete Documentation First | **COMPLETED** | Environment verified. Created full `docs/` suite (Requirements, Architecture, Database, ML, API, Threat Intel, Viva Q&A). |
| **Phase 2** | Public Dataset Verification & Feature Extraction Engine | **COMPLETED** | 16-feature deterministic lexical extractor. Zero network sockets opened. Tested on sample URLs. |
| **Phase 3** | Genuine ML Model Training, Evaluation & Benchmarking | **COMPLETED** | 5,000 URLs benchmark dataset. Random Forest vs Logistic Regression. Serialized `phishguard_rf_model.joblib` and `model_metadata.json`. |
| **Phase 4** | FastAPI Backend & SQLite Database Layer | **COMPLETED** | SQLAlchemy models, Pydantic schemas, versioned REST endpoints (`/api/v1/health`, `/scan`, `/scans`, `/analytics`, `/scans/export`). |
| **Phase 5** | Multi-Source Threat Intelligence | **COMPLETED** | Cached OpenPhish, Phishing.Database, and CERT-PL feeds, PhishDestroy lookups, and optional Google Safe Browsing. |
| **Phase 6** | Black-Themed Frontend Implementation (Strict Palette) | **COMPLETED** | Pure black foundation (#050505), neon green (#39FF88), yellow (#FFD54A), and red (#FF525C). Zero blue or purple anywhere. |
| **Phase 7** | Frontend-Backend API Integration | **COMPLETED** | React Router SPA with real-time scanning, probability meters, and live model transparency. |
| **Phase 8** | Scan History, Analytics, and CSV Export | **COMPLETED** | Dynamic SQLite aggregation, paginated audit table, search, filters, and RFC 4180 streaming CSV export. |
| **Phase 9** | End-to-End Automated Testing & Security Hardening | **COMPLETED** | 22/22 Pytest tests passing. Verified SSRF immunity, XSS sanitization, 2,048 char limit, and secret isolation. |
| **Phase 10** | Academic Viva Prep & Final Acceptance Verification | **COMPLETED** | 25 detailed MCA viva questions & answers in `docs/VIVA_QUESTIONS.md`. Browser verified. |
| **Hardening Phase 1** | Security Hardening | **COMPLETED** | Host-level allowlist, login rate limiting (5 fail/15m -> 429), session-token hashing at rest (HMAC-SHA256), SECRET_KEY enforcement, security headers middleware, production hardening (/docs disabled, COOKIE_SECURE, CSRF on logout), error leakage fix, privacy controls. **47 backend tests passing.** |
| **Hardening Phase 2** | DevOps & Reproducibility | **COMPLETED** | LFS guard, Docker named volume + healthchecks + non-root user, metadata key fixes, CI workflow (`.github/workflows/ci.yml`), `React.lazy` route code splitting, Vitest + RTL frontend tests. **47 backend tests + 33 frontend tests passing.** |
| **Hardening Phase 3** | Detection Quality | **COMPLETED** | Hard-negative SSO dataset augmentation, contextual keyword discernment, systematic RF vs HistGB benchmark, deployment gate validation. Deployed v5.0.0 RF model: **Long-tail FPR 13.06% -> 9.35% (-28.4%), SSO FPR 46.67% -> 33.33% (-28.6%), Hard Phishing Recall 96.00% (within 0.67% of baseline).** |

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

## Hardening Phase 1 — Security (November 2026)
- **Host-level allowlist:** Replaced apex-domain trust (`google.com`, `github.com`) with host-level exact match (`accounts.google.com`, `www.google.com`, `www.paypal.com`, etc.). User-content hosts (`docs.google.com/forms`, `sites.google.com`, `*.github.io`) get no automatic trust and are fully ML-scored.
- **Login rate limiting:** `AuthRateLimiter` class with 5-failure / 15-minute sliding window per IP+email. HTTP 429 with `Retry-After` header on breach.
- **Session token hashing at rest:** SHA-256 (HMAC with SECRET_KEY) of raw token stored in `user_sessions` table. Raw token only in cookie. Alembic migration included.
- **SECRET_KEY enforcement:** Startup raises `ValueError` in production if `SECRET_KEY` is missing.
- **Security headers middleware:** CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, HSTS (when `COOKIE_SECURE=true`). Also added to nginx config in `frontend/Dockerfile`.
- **Production hardening:** `/docs` and `/redoc` disabled when `ENVIRONMENT=production`. `COOKIE_SECURE` defaults to `true` in production. CSRF token required on `/auth/logout`.
- **Error leakage fix:** `scan.py` no longer returns `str(e)` to clients. Server logs the full error with a UUID request ID; client receives only the request ID and a generic message.
- **Privacy controls:** PhishDestroy receives only the hostname (not full URL). Google Safe Browsing strips query string and fragment. `ENABLE_THIRD_PARTY_LOOKUPS=false` disables all external feeds. `docs/PRIVACY.md` documents exactly what is sent to each service.
- **Test count:** 42 → 47 backend tests (5 new tests for Phase 1 behaviors).

## Hardening Phase 2 — DevOps & Reproducibility (November 2026)
- **LFS guard:** `MLInferenceService.load()` detects Git LFS pointer stub and raises `RuntimeError("Model is a Git LFS pointer — run git lfs pull")`. `/api/v1/health` reports `model_loaded: false` with the reason.
- **Docker:** Named volume `phishguard-db-data` replaces file bind-mount. Healthcheck on backend (10s interval). `depends_on: condition: service_healthy`. Non-root user `phishguard:phishguard` (uid 1001). `.dockerignore` excludes `*.db`, `.env`, `node_modules/`, `.git/`, test artifacts. All secrets env-driven (`SECRET_KEY`, `ENVIRONMENT`, `COOKIE_SECURE`, `ALLOWED_ORIGINS`, `DATABASE_URL`).
- **Metadata bug fixes:** `ml_inference.py` now reads `decision_threshold` (falls back to `optimal_threshold`; raises `RuntimeError` if neither is present — no more hard-coded 0.64). `main.py` metadata sync uses real keys (`training_samples`, `validation_samples`, `test_samples`, `test_accuracy`, `test_f1`, `decision_threshold`, `confusion_matrix`).
- **CI:** `.github/workflows/ci.yml` runs backend `ruff` lint + `pytest` (SQLite env override) and frontend `tsc` + `npm build` on every push/PR.
- **Dataset docs:** `ml/data/PROVENANCE.md` updated to reflect that `dataset.csv` IS committed in LFS (consistent with `.gitattributes`).
- **Frontend code splitting:** `App.tsx` uses `React.lazy()` + `<Suspense>` for all 9 page routes, eliminating the ~790 KB monolithic bundle warning.
- **Frontend tests:** Vitest + React Testing Library added. Tests: `urlValidator.test.ts` (21 cases), `AuthContext.test.tsx` (5 cases), `ScannerPage.test.tsx` (7 cases) = 33 tests passing.
- **Backend test count:** 47 tests, all passing.

## Hardening Phase 3 — Detection Quality (November 2026)
- **Hard-negative dataset:** Added 68 verified authentic login/SSO/portal URLs (global universities, enterprise IdPs: Okta, Azure AD, Auth0, Ping; international banks) with strict domain-isolated 3-split partitioning (Train: 23,739 across 18,388 domains, Val: 8,963 across 6,129 domains, Test: 7,366 across 6,130 domains, 0 domain leakage).
- **Contextual keyword discernment:** `has_suspicious_keywords` is now conditioned on structural risk indicators (high-risk TLDs, brand typosquatting, raw IP, punycode, unencrypted HTTP, or anomalous hyphens/dots). Prevents clean HTTPS authentic portals (`portal.chase.com`, `accounts.google.com`) from false-alarming.
- **Model evaluation & comparison:**
  - Evaluated Random Forest (RF) vs HistGradientBoosting (HGB) with isotonic calibration.
  - HGB achieved slightly higher validation recall (+0.49%) but suffered severe false positive inflation on long-tail legitimate URLs (22.78% FPR).
  - Random Forest demonstrated superior resistance to long-tail false positives (9.35% FPR).
- **Deployment gate passed:**
  - Long-Tail Legit FPR: 13.06% (141/1,080) -> **9.35% (101/1,080)** (-28.4% relative false-alarm reduction)
  - Authentic SSO FPR: 46.67% (14/30) -> **33.33% (10/30)** (-28.6% relative false-alarm reduction)
  - Hard Phishing Recall: 96.67% (580/600) -> **96.00% (576/600)** (drop of 0.67% <= 1.0 point limit)
  - Held-out Test FPR: 1.96% -> **1.75%**
  - Held-out Test Recall: 95.23% -> **95.13%**
- **Deployed v5.0.0 model:** Serialized `phishguard_rf_model.joblib` and `model_metadata.json` across `ml/artifacts` and `backend/app/ml/artifacts`. Updated `ML_METHODOLOGY.md`, `/model/info` endpoint, and MLLabPage.
