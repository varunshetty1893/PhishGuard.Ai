# Testing & Quality Report

## Overview

This document records the test coverage improvements made during the PhishGuard AI Professional Product Strengthening project. All numbers come from `python -m pytest -q` runs on the local development machine.

---

## Test Count Progression

| Milestone | Passing Tests | Notes |
|---|---|---|
| CI baseline (before project) | 55 | Original suite |
| After Phase 4 (security hardening) | 59 | +4 security tests |
| After Phase 7 (performance tests) | 64 | +5 performance tests |
| After Phase 9 (domain age + DNS) | **89** | +25 domain age / rebinding tests |

---

## Test Suites Added

### `tests/test_security_hardening.py` (Phase 4)

Tests the SSRF / rate-limiting / circuit-breaker infrastructure added in Phase 4.

| Test | What it verifies |
|---|---|
| `test_ssrf_url_validation_loopback` | `validate_url_security()` rejects `http://127.0.0.1/admin` |
| `test_ssrf_url_validation_rfc1918` | `validate_url_security()` rejects `http://192.168.1.1/` |
| `test_scan_rate_limiter_allows_within_limit` | 60 requests/60 s window succeeds |
| `test_scan_rate_limiter_blocks_excess` | 61st request within window is rejected |

---

### `tests/test_performance.py` (Phase 7)

Measures real wall-clock latency of the ML inference pipeline under concurrent load.

| Test | Concurrency | Limit | Actual p95 (dev box) |
|---|---|---|---|
| `test_single_inference_under_200ms` | 1 | 200 ms | ~106 ms |
| `test_p95_within_limit[1-200]` | 1 | 200 ms | 105.6 ms |
| `test_p95_within_limit[10-2000]` | 10 | 2000 ms | 950.5 ms |
| `test_p95_within_limit[25-8000]` | 25 | 8000 ms | 3795.4 ms |
| `test_feature_extraction_under_20ms` | 1 (×100) | 20 ms avg | **0.64 ms** avg |

> [!NOTE]
> The 25-worker p95 of ~3.8 s reflects Python's GIL serialising Random Forest prediction across threads on a Windows dev machine. Production deployment behind a WSGI process manager (Gunicorn with multiple workers) would not exhibit this bottleneck because each worker is a separate process.

> [!TIP]
> Replacing Random Forest with `HistGradientBoostingClassifier` (which releases the GIL during predict) would substantially reduce concurrent latency. This is tracked as a future ML improvement.

---

### `tests/test_domain_age_and_dns.py` (Phase 9)

25 tests across 4 test classes.

#### `TestEvaluateAge` (8 tests)

| Test | What it verifies |
|---|---|
| `test_none_fails_open` | `age=None` → `score_modifier=0.0`, no warning |
| `test_new_domain_raises_score` | `age=5` → `score_modifier=+0.25`, `is_new=True` |
| `test_boundary_29_days_is_new` | `age=29` → still "new" |
| `test_boundary_30_days_is_neutral` | `age=30` → "neutral" (30-day boundary is exclusive) |
| `test_neutral_domain` | `age=365` → `score_modifier=0.0` |
| `test_boundary_730_days_is_neutral` | `age=730` → still "neutral" |
| `test_established_domain_reduces_score` | `age=731` → `score_modifier=-0.10`, `is_established=True` |
| `test_very_old_domain` | `age=5000` → `score_modifier=-0.10` |

#### `TestDomainAgeSSRFRejection` (6 tests)

Verifies that `get_domain_age()` never queries RDAP for prohibited inputs:

| Input | Expected status |
|---|---|
| `"192.168.1.1"` | `invalid_domain` |
| `"::1"` | `invalid_domain` |
| `"localhost"` | `invalid_domain` |
| `"myservice.internal"` | `invalid_domain` |
| `"printer.local"` | `invalid_domain` |
| `"notadomain"` | `invalid_domain` |

#### `TestDomainAgeLiveLookup` (4 tests — mocked RDAP)

| Test | Scenario |
|---|---|
| `test_successful_rdap_response` | 200 with `registration` event → `age_days > 365*4` |
| `test_rdap_timeout_fails_open` | `httpx.TimeoutException` → `(None, "timeout")` — never raises |
| `test_rdap_404_returns_not_found` | 404 → `(None, "not_found")` |
| `test_rdap_exception_fails_open` | `RuntimeError` → `(None, "error")` — never raises |

#### `TestDNSRebindingProtection` (7 tests)

Validates `is_prohibited_ip()` from `security_validation.py`:

| IP | Expected |
|---|---|
| `10.0.0.1` | prohibited ✅ |
| `172.16.100.50` | prohibited ✅ |
| `192.168.1.254` | prohibited ✅ |
| `127.0.0.1` | prohibited ✅ |
| `169.254.169.254` | prohibited ✅ |
| `8.8.8.8` | allowed ✅ |
| `1.1.1.1` | allowed ✅ |

---

## Remaining Coverage Gaps (acknowledged)

| Area | Gap | Priority |
|---|---|---|
| `scan.py` `/scan` endpoint | No integration test for the SSRF+rate-limit combined flow via TestClient | Medium |
| `analytics.py` | Temporal data point calculation not unit-tested in isolation | Low |
| `threat_intel.py` CircuitBreaker | State transition OPEN→HALF_OPEN→CLOSED not tested with real timer | Low |
| ML training pipeline | `train_v6_deep_links.py` is not under pytest | Deferred (gates not met) |

---

## Test Execution Time

Full suite on Windows dev machine (Python 3.12, PostgreSQL DATABASE_URL):

```
89 passed, 3215 warnings in 51.72s
```

The 3,215 warnings are all `DeprecationWarning` from `joblib` (NumPy 2.5 shape assignment) in the model-loading tests — they are noise from a third-party library and do not indicate any project code issue.
