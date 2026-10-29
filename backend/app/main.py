import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.db.session import engine, Base, SessionLocal, init_db
from app.api.api import api_router
from app.services.ml_inference import MLInferenceService
from app.services.local_threat_feeds import start_feed_refresh
from app.models.scan import ModelMetadata

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishguard.main")

# Auto-initialize DB schema immediately
init_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup sequence
    logger.info("Initializing PhishGuard AI database tables...")
    init_db()

    logger.info("Starting background refresh of local phishing feeds...")
    start_feed_refresh()

    logger.info("Pre-loading machine learning model artifact...")
    try:
        MLInferenceService.load()
        meta = MLInferenceService.get_metadata()
        logger.info(f"ML Model loaded: {meta.get('algorithm', 'Random Forest')} (v{meta.get('model_version')})")

        # Sync metadata into SQLite database if not present
        db = SessionLocal()
        try:
            existing = db.query(ModelMetadata).filter(ModelMetadata.model_version == meta.get("model_version", "1.0.0")).first()
            if not existing and meta:
                record = ModelMetadata(
                    model_version=meta.get("model_version", "1.0.0"),
                    algorithm=meta.get("algorithm", "Random Forest Classifier"),
                    dataset_name=meta.get("dataset_name", "PhishGuard Threat Intelligence Benchmark"),
                    total_samples=meta.get("total_samples", 5000),
                    train_samples=meta.get("train_samples", 4000),
                    test_samples=meta.get("test_samples", 1000)
                )
                record.evaluation_metrics = meta.get("evaluation_metrics", {})
                record.confusion_matrix = meta.get("confusion_matrix", {})
                record.feature_schema = meta.get("feature_schema", [])
                record.feature_importances = meta.get("feature_importances", {})
                db.add(record)
                db.commit()
                logger.info("Model metadata synchronized with database.")
        finally:
            db.close()

    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")

    yield

    # Shutdown sequence
    logger.info("PhishGuard AI application shutting down.")


app = FastAPI(
    title="PhishGuard AI API",
    description="Professional ML-Based Phishing URL Detection & Threat Intelligence Platform",
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API v1 router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", summary="Root Index")
def root_info():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "tagline": "Detect the Threat. Protect Your Digital World.",
        "documentation": "/docs",
        "api_v1": settings.API_V1_STR
    }
