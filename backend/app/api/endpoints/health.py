from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.db.session import get_db
from app.services.ml_inference import MLInferenceService
from app.services.threat_intel import ThreatIntelAggregator
import os
import time

router = APIRouter()

_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "ml", "artifacts", "phishguard_rf_model.joblib"
)

# Module-level startup timestamp for uptime calculation
_START_TIME = time.monotonic()


@router.get("/health", summary="System Health Check")
def get_health(db: Session = Depends(get_db)):
    """
    Enriched health endpoint returning component telemetry:
    - Database connectivity
    - ML model version and load status
    - Circuit breaker states for each threat intel provider
    - Feed freshness timestamps
    - System uptime
    """
    # ── Database ──────────────────────────────────────────────────────────────
    db_status = "connected"
    db_latency_ms: float | None = None
    try:
        t0 = time.perf_counter()
        db.execute(text("SELECT 1"))
        db_latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    # ── ML Model ──────────────────────────────────────────────────────────────
    ml_loaded = False
    model_version = "unknown"
    model_load_error = None
    model_algorithm = "unknown"
    model_threshold: float | None = None
    model_features: int | None = None

    # Check for Git LFS pointer BEFORE attempting to load (avoids joblib crash)
    if os.path.exists(_MODEL_PATH):
        with open(_MODEL_PATH, "rb") as fh:
            header = fh.read(30)
        if header.startswith(b"version https://git-lfs"):
            model_load_error = (
                "Model is a Git LFS pointer — run `git lfs pull` to download "
                "the actual model artifact."
            )
    try:
        if model_load_error:
            ml_loaded = False
        else:
            MLInferenceService.load()
            ml_loaded = MLInferenceService.is_loaded()
            meta = MLInferenceService.get_metadata()
            model_version = meta.get("model_version", "unknown")
            model_algorithm = meta.get("algorithm", "Random Forest")
            model_threshold = meta.get("decision_threshold") or meta.get("optimal_threshold")
            feature_schema = meta.get("feature_schema", [])
            model_features = len(feature_schema) if feature_schema else None
    except Exception as exc:
        ml_loaded = False
        if model_load_error is None:
            model_load_error = str(exc)

    # ── Threat Intelligence (provider status + circuit breaker states) ────────
    threat_providers = ThreatIntelAggregator.get_provider_status()
    try:
        circuit_status = ThreatIntelAggregator.get_circuit_status()
    except Exception:
        circuit_status = {}

    # ── Uptime ────────────────────────────────────────────────────────────────
    uptime_seconds = round(time.monotonic() - _START_TIME, 1)

    # ── Assemble response ─────────────────────────────────────────────────────
    result = {
        "status": "healthy" if db_status == "connected" and ml_loaded else "degraded",
        "uptime_seconds": uptime_seconds,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": {
            "status": db_status,
            "latency_ms": db_latency_ms,
        },
        "ml_model": {
            "loaded": ml_loaded,
            # backward-compat legacy keys
            "model_loaded": ml_loaded,
            "ml_model_loaded": ml_loaded,
            "model_version": model_version,
            "algorithm": model_algorithm,
            "decision_threshold": model_threshold,
            "feature_count": model_features,
        },
        "threat_intel": {
            "providers": threat_providers,
            "circuit_breakers": circuit_status,
        },
    }
    if model_load_error:
        result["ml_model"]["load_error"] = model_load_error

    return result
