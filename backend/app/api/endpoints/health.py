from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.db.session import get_db
from app.services.ml_inference import MLInferenceService
from app.services.threat_intel import ThreatIntelAggregator
import os

router = APIRouter()

_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "ml", "artifacts", "phishguard_rf_model.joblib"
)


@router.get("/health", summary="System Health Check")
def get_health(db: Session = Depends(get_db)):
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    ml_loaded = False
    model_version = "unknown"
    model_load_error = None

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
            # LFS pointer detected on disk — the file is unusable regardless of
            # what may be cached in memory from a previous (valid) load.
            ml_loaded = False
        else:
            MLInferenceService.load()
            ml_loaded = MLInferenceService.is_loaded()
            meta = MLInferenceService.get_metadata()
            model_version = meta.get("model_version", "2.1.0")
    except Exception as exc:
        ml_loaded = False
        if model_load_error is None:
            model_load_error = str(exc)

    threat_providers = ThreatIntelAggregator.get_provider_status()

    result = {
        "status": "healthy" if db_status == "connected" and ml_loaded else "degraded",
        "database": db_status,
        "model_loaded": ml_loaded,
        # keep legacy key for backward compatibility
        "ml_model_loaded": ml_loaded,
        "model_version": model_version,
        "threat_providers": threat_providers,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    if model_load_error:
        result["model_load_error"] = model_load_error
    return result
