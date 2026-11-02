# Performance & Load Test Report

## Methodology

Tests were executed on the local Windows development machine using `pytest` with real in-process ML inference calls (no network, no real DB). This isolates the CPU-bound ML inference and feature extraction pipeline from network or database variability.

**Machine:** Windows 11, Python 3.12.x, 12-core CPU  
**Model:** Random Forest (`phishguard_rf_model.joblib`, v5.0.0, 31 features)  
**Test file:** `backend/tests/test_performance.py`  
**Run command:** `cd backend && python -m pytest tests/test_performance.py -v -s`

---

## Results

### Feature Extraction Latency

| Metric | Value |
|---|---|
| 100-iteration average | **0.64 ms** |
| Limit | 20 ms |
| Pass | ✅ |

Feature extraction (URL parsing, entropy calculation, regex matching, TLD stripping) is extremely fast — averaging under 1 ms per URL.

---

### Single-Worker Inference Latency

| Metric | Value |
|---|---|
| p50 | ~98 ms |
| p95 | **105.6 ms** |
| p99 | 106.7 ms |
| Limit | 200 ms |
| Pass | ✅ |

A single sequential inference (feature extraction + Random Forest `.predict_proba()`) runs in ~100 ms on this hardware. This dominates response time at low concurrency.

---

### Concurrent Inference Latency (Thread Pool)

| Concurrency | Calls | p50 | p95 | p99 | Max | Limit | Pass |
|---|---|---|---|---|---|---|---|
| 1 worker | 5 | 98.1 ms | 105.6 ms | 106.7 ms | 106.9 ms | 200 ms | ✅ |
| 10 workers | 50 | 599.9 ms | 950.5 ms | 1455.9 ms | 1887.4 ms | 2000 ms | ✅ |
| 25 workers | 125 | 1508.1 ms | 3795.4 ms | 4909.5 ms | 5368.5 ms | 8000 ms | ✅ |

---

## Analysis

### GIL Bottleneck at High Concurrency

The Random Forest `predict_proba()` call in scikit-learn holds Python's Global Interpreter Lock (GIL) for the duration of prediction. This means that with many threads, inference is serialised in practice — increasing concurrency increases latency linearly rather than providing throughput gains from parallelism.

**Production mitigation (already applicable):**  
FastAPI/Uvicorn is typically deployed behind multiple Gunicorn workers (`--workers 4`), each in a separate OS process. Since the GIL is per-process, 4 Gunicorn workers provide genuine parallelism and would serve ~4× the concurrency without per-request latency increase. Thread-level concurrency is not the correct model for CPU-bound scikit-learn inference.

### Recommended Production Tuning

| Setting | Recommendation |
|---|---|
| Gunicorn workers | `2 × CPU_cores + 1` (e.g. 9 workers on 4-core) |
| Uvicorn worker class | `uvicorn.workers.UvicornWorker` |
| ML model loading | Load once at startup (`MLInferenceService.load()` in lifespan); do not reload per-request |
| Response caching | Cache scan results for identical URLs for 5 minutes (Redis or in-memory LRU) — not yet implemented |

### Future ML Improvement

Replacing Random Forest with `sklearn.ensemble.HistGradientBoostingClassifier` would release the GIL during predict, enabling genuine thread-level parallelism. This is tracked as a future ML improvement alongside the v6 recall-gate issue.
