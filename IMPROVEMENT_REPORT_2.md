# PhishGuard AI -- Improvement Report 2

**Generated:** 2026-11-02  
**Author:** Automated improvement pipeline  
**Model in production:** v5.0.0 (unchanged)

---

## Summary

Four improvement steps were executed against the PhishGuard AI codebase.
Steps 1, 3, and 4 were completed and committed. Step 2 (path-bias retraining)
was evaluated but deployment was blocked by the quality gates.

---

## Step 1: Domain Age Feature (RDAP + SQLite Cache)

**Status:** Committed (`bf3926f`)

Added a domain-age lookup service using RDAP with:
- 7-day SQLite cache to avoid redundant network calls
- 3-second timeout with fail-open (unknown age never raises the score)
- Domains < 30 days old: +0.25 suspicion modifier
- Domains > 2 years old: -0.10 suspicion dampening
- 8 new unit tests (parse, fail-open, age evaluation, timeout, cache hit)

| Metric | Before | After |
| :--- | :---: | :---: |
| Backend tests | 47 passed | 55 passed |
| Domain age integration | None | Async RDAP + SQLite cache |

---

## Step 2: Remove Path = Phishing Bias (Retraining)

**Status:** Evaluated but NOT deployed (gates failed)

### What was done
- Generated 3,500 legitimate deep-link URLs from Tranco top-50k with realistic paths
- Generated 120 authentic SSO evaluation URLs
- Retrained v6 candidate with domain-isolated splits
- Swept thresholds 0.50-0.70 and tested class weights 1.0-1.4
- Also tested HistGradientBoosting as alternative architecture

### Gate check results (threshold = 0.580)

| Metric | Gate | Candidate v6 | Pass? |
| :--- | :---: | :---: | :---: |
| Long-tail FPR | < 6.0% | 7.31% | FAIL |
| Recall drop | <= 1.0 pt | 2.04 pt (96.0% -> 94.04%) | FAIL |
| Path FPR | (info) | 19.81% (was 38.7%) | Improved |
| SSO FPR | (info) | 33.33% | Unchanged |

### Best threshold explored (t = 0.60, 3500 deep links)

| Metric | Value |
| :--- | :---: |
| Long-tail FPR | 5.83% (below gate) |
| Recall | 91.83% (drop = 3.3 pt > 1 pt gate) |

**Conclusion:** No threshold/deep-link/class-weight combination simultaneously
satisfied both gates. The path bias is structural in the 16-feature schema.
v5.0.0 model preserved as production model.

### Blocked
Fixing the path bias requires deeper feature engineering (e.g., domain
reputation features, path n-gram features, or a two-stage classifier).
This is beyond the scope of a threshold-tuning pass.

---

## Step 3: Honest Result Labels

**Status:** Committed (`401d198`)

### Changes
- **Threat feed match:** `"Confirmed Phishing (known blocklist)"`
- **ML-only detection (incl. typosquatting):** `"Suspicious (unverified, ML only)"`
- **Never** show bare `"Phishing"` for ML-only results

### Files changed
- `backend/app/services/ml_inference.py` -- typosquat branch now returns "Suspicious"
- `backend/app/api/endpoints/scan.py` -- feed/ML/DNS label logic updated
- `backend/app/api/endpoints/analytics.py` -- phishing count catches all label variants
- `backend/app/models/scan.py` -- `predicted_class` column widened to 60 chars
- `frontend/src/types/index.ts` -- type union updated
- `frontend/src/components/StatusBadge.tsx` -- red for confirmed, yellow for ML-only
- `frontend/src/pages/ResultsPage.tsx` -- verdict headline updated
- `frontend/src/pages/HistoryPage.tsx` -- filter dropdown updated
- All relevant backend and frontend tests updated

| Metric | Before | After |
| :--- | :---: | :---: |
| Backend tests | 55 passed | 55 passed |
| Frontend tests | 33 passed | 33 passed |
| ML-only label | "Phishing" | "Suspicious (unverified, ML only)" |
| Blocklist label | "Phishing" | "Confirmed Phishing (known blocklist)" |

---

## Step 4: Live Evaluation Script

**Status:** Committed (this commit)

Created `ml/live_eval.py` that:
1. Fetches phishing URLs from OpenPhish feed (URLhaus returned HTTP 410 Gone)
2. Builds legitimate deep-link URLs from Tranco top-50k with realistic paths
3. Runs ML inference only (no threat feeds, no RDAP)
4. Computes recall, FPR, and 95% Wilson confidence intervals
5. Writes `ml/reports/live_eval_YYYY-MM-DD.json`

### Live evaluation results (2026-11-02)

| Metric | Value | 95% CI |
| :--- | :---: | :---: |
| **Recall** | 97.0% | 93.7% - 100.0% |
| **FPR** | 19.5% | 14.0% - 25.0% |
| Phishing URLs evaluated | 100 | (OpenPhish only) |
| Legit URLs evaluated | 200 | (Tranco + paths) |
| Model version | v5.0.0 | threshold = 0.660 |

> **Note on FPR:** The 19.5% FPR is measured on synthetic deep-link URLs where
> every legitimate URL has a path/query component. This stresses the model's
> known path-bias weakness. The held-out test FPR on a natural URL mix is 1.96%.

### Data source notes
- **OpenPhish:** 100 URLs fetched successfully
- **URLhaus:** HTTP 410 Gone (API deprecated or requires auth as of 2026-11-02)

---

## Before / After Summary

All numbers below are from scripts actually run during this improvement cycle.

| Metric | Before (v5.0.0 baseline) | After improvements |
| :--- | :---: | :---: |
| Backend tests | 47 passed | 55 passed (+8 domain age) |
| Frontend tests | 33 passed | 33 passed |
| Domain age check | None | RDAP + 7-day SQLite cache |
| ML-only label | "Phishing" | "Suspicious (unverified, ML only)" |
| Blocklist label | "Phishing" | "Confirmed Phishing (known blocklist)" |
| Live eval script | None | ml/live_eval.py |
| Live recall | N/A | 97.0% (CI: 93.7%-100.0%) |
| Live FPR (deep links) | N/A | 19.5% (CI: 14.0%-25.0%) |
| Path FPR (v6 candidate) | 38.7% | 19.8% (candidate, not deployed) |
| Production model | v5.0.0 | v5.0.0 (unchanged) |

---

## What Is Blocked

1. **Path-bias gate failure:** The v6 retraining improved path FPR from 38.7% to
   19.8% but could not satisfy both gates (long-tail FPR < 6% AND recall drop
   <= 1 pt) simultaneously. The bias is structural in the 16-feature schema.

2. **URLhaus API:** Returns HTTP 410 Gone. Live eval currently relies on
   OpenPhish only. A replacement feed (e.g., PhishTank) could be added.

3. **Deeper feature engineering:** Fixing path bias likely requires domain
   reputation features, path token analysis, or a two-stage classifier
   architecture. This is out of scope for this improvement cycle.

---

## Git History

```
401d198 step-3: honest result labels
b4c316d step-2: path-bias evaluation (gate failed, v5 preserved)
bf3926f step-1: domain age feature
```

