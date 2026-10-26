from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.db.session import get_db
from app.services.ml_inference import MLInferenceService

router = APIRouter()

@router.get("/health", summary="System Health Check")
def get_health(db: Session = Depends(get_db)):
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    ml_loaded = False
    model_version = "unknown"
    try:
        MLInferenceService.load()
        ml_loaded = MLInferenceService.is_loaded()
        meta = MLInferenceService.get_metadata()
        model_version = meta.get("model_version", "1.0.0")
    except Exception:
        ml_loaded = False

    return {
        "status": "healthy" if db_status == "connected" and ml_loaded else "degraded",
        "database": db_status,
        "ml_model_loaded": ml_loaded,
        "model_version": model_version,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
