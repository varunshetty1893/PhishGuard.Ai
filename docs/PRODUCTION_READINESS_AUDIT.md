# PhishGuard AI — Production Readiness & Architecture Audit

**Document Version:** 1.0.0  
**Audit Date:** 2026-11-02  
**Auditor:** Senior Cybersecurity Product Architect & QA Lead  
**Scope:** Complete repository audit across Backend, Frontend, Machine Learning, Threat Intelligence, Database, Security, DevOps, and Testing.

---

## Executive Summary

PhishGuard AI has demonstrated foundational capabilities: a dual-engine architecture combining lexical machine learning inference with multi-source threat intelligence aggregation, an authenticated user system, and an interactive pure-black cyber web interface.

However, to transition from a capstone/academic demonstration into an **enterprise-grade, production-ready cybersecurity SaaS product (targeting $\ge$ 8/10 product maturity)**, significant architectural weaknesses, false-positive biases, security vulnerabilities, and operational gaps must be resolved.

This audit details **16 specific technical findings** categorized by severity, component, real-world impact, recommended remediation, and empirical verification criteria.

---

## Audit Findings Matrix

| ID | Component | Severity | Description | Status |
|:---|:---|:---:|:---|:---:|
| **SEC-01** | Security / SSRF | **Critical** | Unrestricted DNS & RDAP queries vulnerable to SSRF / Rebinding | Planned Phase 4 |
| **SEC-02** | Security / Rate Limiting | **High** | No rate limiting on `/api/v1/scan` allows DoS and feed quota drainage | Planned Phase 4 |
| **ML-01** | ML Pipeline | **High** | Severe Path & Query false-positive bias on authentic deep links | Planned Phase 2 |
| **ML-02** | ML Architecture | **High** | Feature extraction discrepancy (16-D model vs 22-D extraction engine) | Planned Phase 2 |
| **ML-03** | Decision Engine | **Medium** | Lack of 5-tier transparent risk decision architecture | Planned Phase 2 |
| **TI-01** | Threat Intel | **High** | Lack of circuit breakers and adaptive timeouts for external APIs | Planned Phase 3 |
| **TI-02** | Threat Intel | **Medium** | Deprecated / 410 URLhaus endpoint and unmonitored feed staleness | Planned Phase 3 |
| **DB-01** | Database | **High** | Incomplete Alembic migrations & missing table definitions | Planned Phase 5 |
| **DB-02** | Database / Concurrency | **Medium** | SQLite file lock contention under concurrent scan workloads | Planned Phase 5 |
| **API-01** | Backend / Reliability | **Medium** | Background worker threads leak errors on application shutdown | Planned Phase 5 |
| **API-02** | Backend / Configuration | **Low** | Inconsistent versioning across config, models, and metadata | Planned Phase 5 |
| **UX-01** | Frontend / UX | **Medium** | Technical jargon in scan results confuses ordinary users | Planned Phase 6 |
| **UX-02** | Frontend / Accessibility | **Low** | React state update `act(...)` warnings in Vitest test runs | Planned Phase 6 |
| **PERF-01** | Performance | **Medium** | Uncached network hops in scanning critical path degrade p95 latency | Planned Phase 7 |
| **OPS-01** | Operations | **Medium** | Public `/health` endpoint lacks granular component metrics | Planned Phase 8 |
| **TEST-01** | Quality Assurance | **Medium** | Test suite lacks automated load, SSRF, and edge-case benchmark suites | Planned Phase 9 |

---

## Detailed Technical Findings

### 1. Security & Protection (SEC)

#### Finding SEC-01: SSRF & DNS Rebinding Vulnerability in External Resolution
- **Component:** `backend/app/api/endpoints/scan.py` (`check_domain_dns`) & `backend/app/services/domain_age.py` (`DomainAgeService`)
- **Severity:** **Critical**
- **Description:** 
  The backend performs outbound DNS queries (`socket.gethostbyname`) and HTTP RDAP queries with `follow_redirects=True`. Input domains are not validated against private IP spaces (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), multicast, or cloud metadata endpoints (`169.254.169.254`). An attacker submitting a domain that resolves to internal services can probe infrastructure or trigger Server-Side Request Forgery.
- **Real-World Consequences:**
  Internal service discovery, cloud instance metadata theft (AWS/GCP/Azure credentials), and potential lateral network traversal.
- **Recommended Solution:**
  1. Implement a strict IP blacklist using Python's standard `ipaddress` module.
  2. Reject or isolate any URL resolving to loopback, link-local, private, or multicast ranges before initiating network calls.
  3. Set `follow_redirects=False` or implement a safe redirect validator for RDAP/HTTP calls that enforces public-only HTTPS destinations.
- **Verification Method:**
  Automated tests attempting scans on `http://169.254.169.254/latest/meta-data`, `http://127.0.0.1:8000`, `http://[::1]`, and domains with DNS rebinding records resolving to `127.0.0.1`. Must all be rejected cleanly with HTTP 422 or safe rejection.

#### Finding SEC-02: Missing Rate Limiting on Primary Scan Endpoint
- **Component:** `backend/app/api/endpoints/scan.py` (`/api/v1/scan`)
- **Severity:** **High**
- **Description:**
  `AuthRateLimiter` is only enforced on `/auth/login` and `/auth/register`. The resource-intensive `/api/v1/scan` endpoint (which triggers DNS lookups, RDAP queries, external Safe Browsing checks, and database writes) has no rate limit.
- **Real-World Consequences:**
  An authenticated account or compromised credential can issue thousands of automated requests per minute, exhausting third-party API quotas, locking SQLite databases, and degrading server responsiveness.
- **Recommended Solution:**
  Implement a sliding-window rate limiter on `/api/v1/scan` (e.g., 30 scans/minute per user/IP) returning HTTP 429 with `Retry-After`.
- **Verification Method:**
  Test issuing 35 concurrent scan requests from a single user session; verify requests 31-35 receive HTTP 429.

---

### 2. Machine Learning & Detection Quality (ML)

#### Finding ML-01: Severe Path & Query False-Positive Bias
- **Component:** `backend/app/ml/feature_extraction_v2.py` & Model Artifacts
- **Severity:** **High**
- **Description:**
  The current 16-feature schema includes `path_length`, `count_slash`, `url_length`, `count_equal`, and `count_question`. Because training corpora historically paired simple root domains (`https://google.com`) with clean labels and deep path URLs (`http://attacker/login/verify/step1`) with phishing, the model penalizes deep legitimate URLs. Real-world benchmark: live synthetic deep-link FPR is **19.5%**, and authentic SSO portal FPR is **33.3%**.
- **Real-World Consequences:**
  False alarms on authentic enterprise links: Google Drive shared links, Jira issue URLs, AWS documentation, university portals, password reset links, and SaaS dashboards.
- **Recommended Solution:**
  1. Decouple path length from domain structure: compute path metrics normalized to total URL length or segment ratios.
  2. Integrate domain reputation features (e.g. Tranco rank tier indicator) and TLD risk indicators.
  3. Augment training with 3,500+ legitimate deep-links under strict domain-isolated 3-split partitioning.
  4. Optimize probability calibration using Isotonic regression with an empirical threshold targeting $\le 2\%$ natural FPR and $\le 5\%$ long-tail FPR.
- **Verification Method:**
  Run evaluation across:
  - 1,000+ unseen Tranco deep-link URLs (target FPR $\le 5\%$).
  - 100+ authentic enterprise SSO portals (target FPR $\le 10\%$).
  - 600+ hard phishing URLs (target recall $\ge 95\%$).

#### Finding ML-02: Feature Extraction Discrepancy (16-D vs 22-D)
- **Component:** `backend/app/ml/feature_extraction_v2.py` & `backend/app/services/ml_inference.py`
- **Severity:** **High**
- **Description:**
  `feature_extraction_v2.py` extracts 22 features, including hard-to-fake lexical signals (`tld_risk_score`, `brand_lookalike`, `brand_in_subdomain`, `has_punycode`, `hostname_entropy`). However, the production model `phishguard_rf_model.joblib` only receives the first 16 features. Brand typosquatting is handled via post-hoc Python `elif` branches in `ml_inference.py` rather than within the ML probability estimation.
- **Real-World Consequences:**
  The ML model is blind to critical signals like Punycode homographs and brand typosquatting, forcing reliance on manual rules.
- **Recommended Solution:**
  Train, calibrate, and deploy a unified model natively consuming the complete enhanced feature space, aligning inference and training.
- **Verification Method:**
  Model metadata validation confirming feature dimension matches vector extraction at runtime.

#### Finding ML-03: Lack of Formal 5-Tier Decision Architecture
- **Component:** `backend/app/api/endpoints/scan.py` & `frontend/src/pages/ResultsPage.tsx`
- **Severity:** **Medium**
- **Description:**
  Results are currently bucketed into "Confirmed Phishing (known blocklist)", "Suspicious (unverified, ML only)", or "Legitimate". There is no explicit "Unknown / Inconclusive" state or distinction between "High-Risk Suspected Phishing" and "Low-Confidence Suspicious".
- **Real-World Consequences:**
  Ambiguous URLs (e.g., brand-new domains with clean names, or unreachable hosts) are either forced into binary verdicts or misleadingly portrayed.
- **Recommended Solution:**
  Implement a 5-tier decision architecture:
  1. *Confirmed Malicious*: Validated threat intelligence feed match.
  2. *High-Risk Suspected*: Strong ML score ($\ge 0.75$) + structural anomalies.
  3. *Suspicious*: Moderate ML probability ($0.40 - 0.74$) or elevated structural deviations.
  4. *Low-Risk*: Clean structural indicators and low ML score ($< 0.40$).
  5. *Inconclusive / Unknown*: Incomplete data, unresolvable domain, or timeout.
- **Verification Method:**
  Verify unit tests mapping all score combinations to appropriate tiers.

---

### 3. Threat Intelligence & External Resiliency (TI)

#### Finding TI-01: Absence of Circuit Breakers & Adaptive Timeouts
- **Component:** `backend/app/services/threat_intel.py`
- **Severity:** **High**
- **Description:**
  `GoogleSafeBrowsingAdapter` and `PhishDestroyAdapter` make network HTTP calls during scans. While bounded by an 8-second timeout, if upstream providers experience sustained outage or latency, every scan request blocks for 8 seconds.
- **Real-World Consequences:**
  Cascading backend latency, request backlog, and poor user response times during third-party incidents.
- **Recommended Solution:**
  1. Implement an in-memory Circuit Breaker pattern (state: Closed $\rightarrow$ Open $\rightarrow$ Half-Open) with a 60-second cooldown after 3 consecutive failures.
  2. Tighten external API per-call timeouts from 8.0s to 3.0s.
  3. Return "Unavailable (Circuit Open)" immediately without network latency when open.
- **Verification Method:**
  Mock upstream 500/timeout errors; verify consecutive failures trip the circuit breaker and subsequent queries return in $< 1$ms.

#### Finding TI-02: Deprecated URLhaus Feed Endpoint & Feed Freshness Visibility
- **Component:** `backend/app/services/local_threat_feeds.py` & `ml/live_eval.py`
- **Severity:** **Medium**
- **Description:**
  URLhaus CSV recent endpoint returned HTTP 410 (Gone). Local feeds (`openphish_urls`, `phishing_database_urls`, `cert_pl_domains`) lack explicit freshness metrics exposed to administrators or health endpoints.
- **Real-World Consequences:**
  Silently degraded blocklist coverage if a feed source changes format or authentication requirements.
- **Recommended Solution:**
  1. Update URL sources to active endpoints and add validation on downloaded feed formats.
  2. Expose feed age, entry count, and last refresh timestamp via `/api/v1/health` and threat intelligence status endpoints.
- **Verification Method:**
  Verify health endpoint reports feed entry counts and timestamps.

---

### 4. Database Reliability & Migrations (DB)

#### Finding DB-01: Incomplete Alembic Migration Chain
- **Component:** `backend/alembic/versions/`
- **Severity:** **High**
- **Description:**
  Alembic version `9ddc59dc1b66` only creates a foreign key between `scan_history` and `users`. It assumes tables already exist. Initial table generation depends on runtime `Base.metadata.create_all()` in `init_db()`. New tables such as `domain_age_cache` and column size updates have no migration files.
- **Real-World Consequences:**
  Enterprise deployments using automated CI/CD migration scripts (`alembic upgrade head`) will fail on clean Postgres instances.
- **Recommended Solution:**
  Author a consolidated baseline migration script providing idempotent `CREATE TABLE` and `INDEX` definitions for all models (`users`, `user_sessions`, `scan_history`, `threat_check_logs`, `domain_age_cache`, `model_metadata`).
- **Verification Method:**
  Run `alembic upgrade head` on an empty temporary database; confirm all tables and relationships instantiate without errors.

#### Finding DB-02: SQLite Concurrency Locking under Load
- **Component:** `backend/app/db/session.py`
- **Severity:** **Medium**
- **Description:**
  Default SQLite configuration runs in `DELETE` journal mode without WAL (Write-Ahead Logging). Under multi-threaded concurrent scans, concurrent transactions attempting to insert scans or cache RDAP results hit `sqlite3.OperationalError: database is locked`.
- **Real-World Consequences:**
  Failed scan queries during concurrent user traffic.
- **Recommended Solution:**
  Execute `PRAGMA journal_mode=WAL;` and `PRAGMA busy_timeout=5000;` on SQLite connections to support concurrent readers and writers.
- **Verification Method:**
  Run 50 concurrent simulated scan requests; confirm 0 database lock errors.

---

### 5. Backend Architecture & Error Handling (API)

#### Finding API-01: Ungraceful Thread Shutdown in Threat Intel Probes
- **Component:** `backend/app/services/threat_intel.py`
- **Severity:** **Medium**
- **Description:**
  Background probe threads execute synchronous HTTP calls without listening to application shutdown signals, causing `ValueError: I/O operation on closed file` when pytest or uvicorn tears down stdout/stderr handlers.
- **Recommended Solution:**
  Track background threads with a cancellation event or thread pool managed inside FastAPI's `lifespan` context manager.
- **Verification Method:**
  Execute `pytest -q`; verify 0 `ValueError: I/O operation on closed file` errors in logs.

#### Finding API-02: Inconsistent Product & Model Version Identifiers
- **Component:** `backend/app/core/config.py`, `models/scan.py`, `model_metadata.json`
- **Severity:** **Low**
- **Description:**
  `config.py` specifies version `"2.1.0"`, `model_metadata.json` reports `"5.0.0"`, and legacy database default was `"1.0.0"`.
- **Recommended Solution:**
  Centralize platform version (`v5.1.0`) across all backend, frontend, and API metadata responses.
- **Verification Method:**
  Assert `/api/v1/health` and `/` return consistent version identifiers.

---

### 6. Frontend Experience & Product Polish (UX)

#### Finding UX-01: Raw Technical Jargon in Verdict Explanations
- **Component:** `frontend/src/pages/ResultsPage.tsx`
- **Severity:** **Medium**
- **Description:**
  Scan results occasionally present internal technical flags like "Shannon entropy 3.96 bits" or "NXDOMAIN" directly to users without plain-language context.
- **Recommended Solution:**
  Enhance UI cards with clear explanations:
  - "What does this mean?"
  - "Why is this flagged?"
  - "Recommended Action"
- **Verification Method:**
  Review UI renderings for phishing, suspicious, and legitimate scan outputs.

#### Finding UX-02: React Testing State Warnings
- **Component:** `frontend/src/__tests__/ScannerPage.test.tsx`
- **Severity:** **Low**
- **Description:**
  Vitest reports `An update to ScannerPage inside a test was not wrapped in act(...)` during simulated URL pre-fill tests.
- **Recommended Solution:**
  Refactor test assertions using `await waitFor(...)` to eliminate warnings.
- **Verification Method:**
  Run `npm run test:run`; confirm 0 stderr warnings.

---

### 7. Performance & Operations (PERF & OPS)

#### Finding PERF-01: Critical-Path Latency on Domain Lookups
- **Component:** `backend/app/api/endpoints/scan.py`
- **Severity:** **Medium**
- **Description:**
  Scanning an uncached URL takes 1.5–3.0 seconds due to DNS and RDAP network latency.
- **Recommended Solution:**
  Cache DNS and RDAP results aggressively (TTL 7 days for domain age, 1 hour for DNS); enforce 1.5s timeout on DNS and 2.5s on RDAP.
- **Verification Method:**
  Measure response latency on repeated vs fresh domain scans.

#### Finding OPS-01: Minimal Health Endpoint Telemetry
- **Component:** `backend/app/api/endpoints/health.py`
- **Severity:** **Medium**
- **Description:**
  `/api/v1/health` reports basic database status and model presence, but lacks threat feed entry counts, circuit breaker states, and uptime metrics.
- **Recommended Solution:**
  Enrich health endpoint with structured status: database latency, model version, active threat feed entry counts, and circuit breaker health.
- **Verification Method:**
  Query `/api/v1/health`; verify structured health payload without secret leakage.

---

## Conclusion & Action Plan

To advance PhishGuard AI to a verified **8/10+ production maturity rating**, execution will proceed through the remaining 9 planned phases:

1. **Phase 2:** ML Detection Improvement (path-bias elimination, 22-D model training, 5-tier decision engine).
2. **Phase 3:** Threat Intelligence Hardening (circuit breakers, feed monitoring, adaptive timeouts).
3. **Phase 4:** Application Security Hardening (SSRF boundary protection, scan rate limiting).
4. **Phase 5:** Backend & Database Reliability (SQLite WAL mode, clean Alembic migration, thread lifecycle).
5. **Phase 6:** Frontend Experience (plain-language explanations, 5-tier badge rendering, test cleanups).
6. **Phase 7:** Performance & Load Benchmarking (Locust/k6 load testing, p95 optimization).
7. **Phase 8:** Monitoring & Operations (enriched telemetry, structured logging).
8. **Phase 9:** Automated Testing (comprehensive test suite expansion).
9. **Phase 10:** Final Professional Review & Production Readiness Report.

