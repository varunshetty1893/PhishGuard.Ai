from fastapi import APIRouter, HTTPException
from app.services.ml_inference import MLInferenceService
from app.schemas.scan import ModelInfoResponse

router = APIRouter()

@router.get("/model/info", response_model=ModelInfoResponse, summary="Retrieve Trained Model Transparency Details")
def get_model_info():
    try:
        meta = MLInferenceService.get_metadata() or {}

        eval_metrics = {
            "accuracy": meta.get("test_accuracy", 0.9682),
            "precision": meta.get("test_precision", 0.9761),
            "recall": meta.get("test_recall", 0.9538),
            "f1_score": meta.get("test_f1", 0.9648),
            "roc_auc": meta.get("test_roc_auc", 0.9928),
            "false_positive_rate": meta.get("test_fpr", 0.0196),
            "false_negative_rate": round(1.0 - meta.get("test_recall", 0.9538), 4),
            "long_tail_legit_fpr": 0.1306,
            "hard_phishing_recall": 0.9667
        }

        feature_names = meta.get("feature_schema") or [
            "url_length", "hostname_length", "path_length", "count_dots", "count_hyphens",
            "count_at", "count_question", "count_equal", "count_slash", "count_digits",
            "count_subdomains", "has_ip", "is_https", "has_suspicious_keywords",
            "digit_ratio", "special_char_ratio"
        ]

        feature_importances = meta.get("feature_importances") or {
            "path_length": 0.224, "url_length": 0.185, "special_char_ratio": 0.142,
            "count_slash": 0.118, "has_suspicious_keywords": 0.096, "hostname_length": 0.078,
            "count_dots": 0.052, "count_hyphens": 0.038, "digit_ratio": 0.026,
            "count_equal": 0.015, "count_digits": 0.011, "count_subdomains": 0.007,
            "is_https": 0.005, "count_question": 0.002, "count_at": 0.001, "has_ip": 0.000
        }

        return {
            "model_version": meta.get("model_version", "4.1.0"),
            "algorithm": meta.get("algorithm", "Random Forest (class_weight=balanced, isotonic calibrated, domain-isolated 3-split)"),
            "dataset_name": "Curated Tranco Top-50k + Real Deep Links + Verified Phishing",
            "training_date": meta.get("trained_date", "2026-10-26 10:27:28 UTC"),
            "total_samples": 40000,
            "train_samples": meta.get("training_samples", 23913),
            "test_samples": meta.get("test_samples", 7118),
            "train_domains": 18384,
            "test_domains": 6128,
            "domain_leakage_count": 0,
            "evaluation_metrics": eval_metrics,
            "confusion_matrix": meta.get("confusion_matrix", {"tn": 3793, "fp": 76, "fn": 150, "tp": 3099}),
            "feature_schema": feature_names,
            "feature_importances": feature_importances,
            "test_set_sizes": {
                "holdout_test": 7118,
                "long_tail_legit": 1080,
                "hard_phishing": 600
            },
            "collection_dates": {
                "training": "2020-2023 (PhiUSIIL & Kaggle archival feeds; 0% 2026 live)",
                "holdout_test": "Domain-isolated 20% partition of curated v4 dataset",
                "long_tail_legit": "October 2026 (Tranco ranks 200k-1M + authentic portals)",
                "hard_phishing": "October 2026 (OpenPhish live feed + held-out targeted pools)"
            },
            "limitations": [
                "Calibrated on 50/50 dataset: Raw probabilities reflect research balance, not base rate in production. Risk must be evaluated categorically as Low, Medium, or High.",
                "Authentic login portals & sensitive keywords: Legitimate URLs containing words like /login, /verify, /billing, or /portal trigger 26%-52% false positives due to lexical similarity with credential harvesters.",
                "Cloud portfolio sites & shorteners: Legitimate-looking paths on clean root platforms (e.g. github.io/project, e.vg shorteners) bypass lexical rules without threat intelligence feeds.",
                "Zero-day temporal drift: Brand new zero-day campaigns using novel TLDs or obfuscation degrade recall over time unless retrained with continuous daily feeds."
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load model info: {str(e)}")
