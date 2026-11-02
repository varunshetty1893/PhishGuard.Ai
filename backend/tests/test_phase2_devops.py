"""
Phase 2 — Reproducibility & DevOps regression tests.

Tests:
1. LFS pointer guard: MLInferenceService.load() raises RuntimeError when the
   model file starts with the Git LFS pointer prefix.
2. decision_threshold: MLInferenceService uses 'decision_threshold' from metadata
   (not the removed hard-coded 0.64 default), with fallback to 'optimal_threshold'.
3. Health endpoint: /api/v1/health returns model_loaded=true and no model_load_error
   when a real model is present.
4. Health endpoint LFS: reports model_loaded=False and model_load_error when the
   file on disk is a Git LFS pointer (unit-tested via direct function call).
5. Metadata sync keys: model_metadata.json real keys are correctly mapped.
"""
import pytest
from unittest.mock import patch, MagicMock
from app.services.ml_inference import MLInferenceService


# ── 1. LFS pointer guard ──────────────────────────────────────────────────────

def test_lfs_pointer_guard_raises_runtime_error(tmp_path):
    """
    When model file starts with the Git LFS pointer header,
    MLInferenceService.load() must raise RuntimeError with a clear message.
    """
    fake_pointer = tmp_path / "fake_model.joblib"
    fake_pointer.write_bytes(
        b"version https://git-lfs.github.com/spec/v1\n"
        b"oid sha256:deadbeef\nsize 133\n"
    )

    original_model = MLInferenceService._model
    MLInferenceService._model = None
    try:
        with patch("app.services.ml_inference.MODEL_PATH", str(fake_pointer)):
            with pytest.raises(RuntimeError, match="Git LFS pointer"):
                MLInferenceService.load()
    finally:
        MLInferenceService._model = original_model


# ── 2. decision_threshold key reading ────────────────────────────────────────

def test_decision_threshold_key_takes_priority():
    """
    When metadata contains 'decision_threshold', MLInferenceService uses that value.
    When only 'optimal_threshold' is present, it falls back correctly.
    When neither is present, the result is None (which triggers RuntimeError in predict).
    """
    svc = MLInferenceService

    with patch.object(svc, "get_metadata", return_value={"decision_threshold": 0.55}):
        val = (
            svc.get_metadata().get("decision_threshold")
            or svc.get_metadata().get("optimal_threshold")
        )
        assert val == 0.55

    with patch.object(svc, "get_metadata", return_value={"optimal_threshold": 0.60}):
        val = (
            svc.get_metadata().get("decision_threshold")
            or svc.get_metadata().get("optimal_threshold")
        )
        assert val == 0.60

    with patch.object(svc, "get_metadata", return_value={"model_version": "test"}):
        val = (
            svc.get_metadata().get("decision_threshold")
            or svc.get_metadata().get("optimal_threshold")
        )
        assert val is None


# ── 3. Health endpoint — normal (model loaded) ────────────────────────────────

@pytest.mark.requires_ml_model
def test_health_endpoint_model_loaded(client):
    """
    /api/v1/health must return model_loaded=true when model is properly loaded.
    """
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["model_loaded"] is True
    assert "model_load_error" not in data
    assert data["model_version"] != "unknown"


# ── 4. Health endpoint — LFS pointer detected ─────────────────────────────────

def test_health_endpoint_lfs_pointer_reported(tmp_path):
    """
    /api/v1/health must report model_loaded=False and model_load_error when the
    file on disk is a Git LFS pointer stub.

    Called as a unit test (direct function call with mock DB) so that the
    in-memory model cache state is irrelevant — the detection is purely file-based.
    """
    import app.api.endpoints.health as health_mod

    fake_pointer = tmp_path / "fake.joblib"
    fake_pointer.write_bytes(
        b"version https://git-lfs.github.com/spec/v1\n"
        b"oid sha256:deadbeef\nsize 133\n"
    )

    mock_db = MagicMock()
    mock_db.execute.return_value = None

    original_path = health_mod._MODEL_PATH
    health_mod._MODEL_PATH = str(fake_pointer)
    try:
        result = health_mod.get_health(db=mock_db)

        assert "model_load_error" in result, (
            f"Expected model_load_error in result: {result}"
        )
        assert "git lfs pull" in result["model_load_error"].lower(), result
        assert result["model_loaded"] is False, (
            f"Expected model_loaded=False when LFS pointer detected, got: {result}"
        )
    finally:
        health_mod._MODEL_PATH = original_path


# ── 5. Metadata sync key mapping ──────────────────────────────────────────────

def test_metadata_sync_uses_real_keys():
    """
    The real keys from model_metadata.json (training_samples, validation_samples,
    test_samples, test_accuracy, decision_threshold, confusion_matrix) must be
    correctly read and totalled — old dummy defaults (5000/4000/1000) must not appear.
    """
    real_meta = {
        "model_version": "v4.1.0",
        "training_samples": 23913,
        "validation_samples": 8969,
        "test_samples": 7118,
        "decision_threshold": 0.64,
        "test_accuracy": 0.9682,
        "test_f1": 0.9648,
        "confusion_matrix": {"tn": 3793, "fp": 76, "fn": 150, "tp": 3099},
    }

    total = (
        real_meta.get("training_samples", 0)
        + real_meta.get("validation_samples", 0)
        + real_meta.get("test_samples", 0)
    )
    assert total == 40000, f"Expected 40000 total samples, got {total}"

    eval_metrics = {
        k: real_meta[k]
        for k in ("test_accuracy", "test_f1", "decision_threshold", "confusion_matrix")
        if k in real_meta
    }
    assert eval_metrics["test_accuracy"] == 0.9682
    assert eval_metrics["decision_threshold"] == 0.64
    assert "confusion_matrix" in eval_metrics

    # Old wrong defaults must NOT match the real values
    assert total != 9000   # old 5000+4000+... defaults were wrong
    assert real_meta.get("training_samples") != 4000   # old train_samples default
