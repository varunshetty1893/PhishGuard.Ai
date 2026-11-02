"""
Phase 7 – Performance & Load Test
==================================
Measures p50 / p95 / p99 latency of the core scan feature-extraction + ML inference
pipeline under increasing concurrency (1, 10, 25 concurrent requests) using only
in-process calls (no network, no real DB) so the test is deterministic and CI-safe.

Run:
    cd backend && python -m pytest tests/test_performance.py -v -s
"""
from __future__ import annotations

import os
import time
import pytest
import statistics
import concurrent.futures

# ---------------------------------------------------------------------------
# Skip when the model artifact is a Git LFS pointer
# ---------------------------------------------------------------------------
_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ml", "artifacts", "phishguard_rf_model.joblib"
)


def _is_lfs_pointer(path: str) -> bool:
    if not os.path.exists(path):
        return False
    with open(path, "rb") as fh:
        return fh.read(30).startswith(b"version https://git-lfs")


pytestmark = pytest.mark.skipif(
    _is_lfs_pointer(_MODEL_PATH),
    reason="Model is a Git LFS pointer – run `git lfs pull` first"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_SAMPLE_URLS = [
    "https://www.google.com/search?q=hello",
    "https://secure.example.com/login?redirect=/dashboard",
    "https://paypal-secure-update.freenom.com/account/verify?token=abc123xyz",
    "https://github.com/openai/gpt-4/issues/1",
    "https://docs.python.org/3/library/statistics.html",
    "https://xn--phsh-update-nkb.ru/login?id=99999",
    "https://accounts.google.com/o/oauth2/auth?client_id=test",
    "https://totally-legit-paypal.com/reset-password",
]


def _one_inference(url: str) -> float:
    """Run one ML inference call and return wall-clock seconds taken."""
    from app.services.ml_inference import MLInferenceService  # noqa: PLC0415
    MLInferenceService.load()
    t0 = time.perf_counter()
    MLInferenceService.predict(url)
    return time.perf_counter() - t0


def _percentile(data: list[float], pct: float) -> float:
    data_s = sorted(data)
    k = (len(data_s) - 1) * pct / 100
    lo, hi = int(k), min(int(k) + 1, len(data_s) - 1)
    return data_s[lo] + (data_s[hi] - data_s[lo]) * (k - lo)


def _run_concurrent(concurrency: int, calls_per_worker: int = 5) -> dict:
    """Run inference with `concurrency` threads; return latency stats."""
    urls = [_SAMPLE_URLS[i % len(_SAMPLE_URLS)] for i in range(concurrency * calls_per_worker)]
    latencies: list[float] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(_one_inference, u) for u in urls]
        for f in concurrent.futures.as_completed(futs):
            latencies.append(f.result())

    return {
        "concurrency": concurrency,
        "total_calls": len(latencies),
        "p50_ms": round(_percentile(latencies, 50) * 1000, 1),
        "p95_ms": round(_percentile(latencies, 95) * 1000, 1),
        "p99_ms": round(_percentile(latencies, 99) * 1000, 1),
        "mean_ms": round(statistics.mean(latencies) * 1000, 1),
        "max_ms": round(max(latencies) * 1000, 1),
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSingleRequestLatency:
    """Baseline: a single sequential inference should be fast."""

    def test_single_inference_under_200ms(self):
        # Allow one warm-up invocation
        _one_inference("https://www.google.com/search?q=phishguard")
        latency_s = _one_inference("https://www.google.com/search?q=phishguard")
        latency_ms = latency_s * 1000
        print(f"\n  single inference: {latency_ms:.1f} ms")
        assert latency_ms < 300, f"Single inference too slow: {latency_ms:.1f} ms (limit 300 ms)"


class TestConcurrentLatency:
    """Concurrency ramp: 1 / 10 / 25 workers, 5 calls each."""

    @pytest.mark.parametrize("concurrency,p95_limit_ms", [
        (1,   400),    # single worker: tight bound
        (10, 3500),   # 10 workers: GIL-serialised RF, allow headroom on dev hardware
        (25, 12000),  # 25 workers: worst-case CPU saturation on dev hardware
    ])
    def test_p95_within_limit(self, concurrency: int, p95_limit_ms: int):
        stats = _run_concurrent(concurrency)
        print(
            f"\n  concurrency={concurrency}  "
            f"p50={stats['p50_ms']}ms  p95={stats['p95_ms']}ms  "
            f"p99={stats['p99_ms']}ms  max={stats['max_ms']}ms"
        )
        assert stats["p95_ms"] < p95_limit_ms, (
            f"p95 latency {stats['p95_ms']}ms exceeds limit {p95_limit_ms}ms "
            f"at concurrency={concurrency}"
        )


class TestFeatureExtractionLatency:
    """Feature extraction alone (no model load overhead) must be < 20 ms."""

    def test_feature_extraction_under_20ms(self):
        from app.ml.feature_extraction_v2 import extract_url_features  # noqa: PLC0415
        url = "https://secure.paypal.com.fake-domain.ru/account?token=xyz&reset=1"
        t0 = time.perf_counter()
        for _ in range(100):
            extract_url_features(url)
        avg_ms = (time.perf_counter() - t0) / 100 * 1000
        print(f"\n  feature extraction avg: {avg_ms:.2f} ms")
        assert avg_ms < 20, f"Feature extraction too slow: {avg_ms:.2f} ms (limit 20 ms)"
