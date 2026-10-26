from fastapi import APIRouter, HTTPException
from app.services.ml_inference import MLInferenceService
from app.schemas.scan import ModelInfoResponse

router = APIRouter()

@router.get("/model/info", response_model=ModelInfoResponse, summary="Retrieve Trained Model Transparency Details")
def get_model_info():
    try:
        meta = MLInferenceService.get_metadata()
        if not meta:
            raise HTTPException(status_code=404, detail="Model metadata is unavailable.")
        
        return {
            "model_version": meta.get("model_version", "1.0.0"),
            "algorithm": meta.get("algorithm", "Random Forest Classifier"),
            "dataset_name": meta.get("dataset_name", "PhishGuard Academic Benchmark"),
            "training_date": meta.get("training_date", ""),
            "total_samples": meta.get("total_samples", 5000),
            "train_samples": meta.get("train_samples", 4000),
            "test_samples": meta.get("test_samples", 1000),
            "evaluation_metrics": meta.get("evaluation_metrics", {}),
            "confusion_matrix": meta.get("confusion_matrix", {}),
            "feature_schema": meta.get("feature_schema", []),
            "feature_importances": meta.get("feature_importances", {})
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load model info: {str(e)}")
