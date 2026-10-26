"""
PhishGuard AI - Machine Learning Inference Engine Service
Loads serialized Random Forest model and metadata for runtime URL classification.
"""

import json
import os
from typing import Dict, Any, Tuple, List
import joblib

from app.ml.feature_extraction import (
    FEATURE_NAMES,
    extract_url_features,
    features_to_vector,
    normalize_url
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "ml", "artifacts")
MODEL_PATH = os.path.join(ARTIFACTS_DIR, "phishguard_rf_model.joblib")
METADATA_PATH = os.path.join(ARTIFACTS_DIR, "model_metadata.json")


class MLInferenceService:
    _model = None
    _metadata = None

    @classmethod
    def load(cls):
        """Loads serialized model and metadata into memory."""
        if cls._model is None:
            if not os.path.exists(MODEL_PATH):
                raise FileNotFoundError(
                    f"Machine learning model artifact not found at: {MODEL_PATH}. "
                    "Run 'python ml/train.py' first to train and persist the model."
                )
            cls._model = joblib.load(MODEL_PATH)

        if cls._metadata is None:
            if os.path.exists(METADATA_PATH):
                with open(METADATA_PATH, "r", encoding="utf-8") as f:
                    cls._metadata = json.load(f)
            else:
                cls._metadata = {"model_version": "1.0.0", "algorithm": "Random Forest"}

    @classmethod
    def is_loaded(cls) -> bool:
        return cls._model is not None

    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        cls.load()
        return cls._metadata or {}

    @classmethod
    def predict(cls, raw_url: str) -> Dict[str, Any]:
        """
        Executes complete offline inference on untrusted input string.
        Returns:
            Dictionary containing prediction, probability score, risk tier,
            extracted features, heuristic flags, and recommended precautions.
        """
        cls.load()

        normalized = normalize_url(raw_url)
        features, suspicious_reasons = extract_url_features(normalized)
        vector = features_to_vector(features)

        # Scikit-learn inference (1 sample matrix)
        prediction = int(cls._model.predict([vector])[0])
        probabilities = cls._model.predict_proba([vector])[0]
        # Class 1 is Phishing probability
        phish_prob = float(round(probabilities[1], 4))

        predicted_class = "Phishing" if prediction == 1 else "Legitimate"

        # Calibrated risk level calculation
        # Even if probability is borderline, high heuristic counts elevate risk
        if phish_prob >= 0.70 or len(suspicious_reasons) >= 4:
            risk_level = "High Risk"
        elif phish_prob >= 0.40 or len(suspicious_reasons) >= 2:
            risk_level = "Suspicious"
        else:
            risk_level = "Low Risk"

        # Generate contextual recommendations
        precautions: List[str] = []
        if risk_level == "High Risk":
            precautions.append("DO NOT click this link or submit personal or financial credentials.")
            precautions.append("DO NOT download any software, attachments, or extensions from this domain.")
            precautions.append("If received via email or SMS, report the message as phishing to your security administrator.")
        elif risk_level == "Suspicious":
            precautions.append("Exercise extreme caution. Structural indicators suggest anomalous characteristics.")
            precautions.append("Verify the organization's authentic URL directly via a verified search engine or bookmark.")
            precautions.append("Check the address bar carefully for typosquatting or strange domain suffixes.")
        else:
            precautions.append("Standard browsing precautions apply.")
            precautions.append("While the URL displays legitimate structural patterns, remain alert if prompted for unexpected passwords.")

        # Combined plain-English explanation
        if risk_level == "High Risk":
            interpretation = (
                f"High-risk phishing signature detected ({phish_prob*100:.1f}% model confidence). "
                f"The URL exhibits structural evasion traits commonly associated with credential harvesting."
            )
        elif risk_level == "Suspicious":
            interpretation = (
                f"Suspicious link structure detected ({phish_prob*100:.1f}% risk score). "
                f"Contains anomaly indicators that warrant user verification before proceeding."
            )
        else:
            interpretation = (
                f"Structural patterns conform to legitimate web standards ({phish_prob*100:.1f}% risk score). "
                f"No prominent phishing indicators identified."
            )

        model_version = cls._metadata.get("model_version", "1.0.0") if cls._metadata else "1.0.0"

        return {
            "submitted_url": raw_url,
            "normalized_url": normalized,
            "predicted_class": predicted_class,
            "risk_level": risk_level,
            "model_score": phish_prob,
            "extracted_features": features,
            "suspicious_reasons": suspicious_reasons,
            "combined_interpretation": interpretation,
            "recommended_precautions": precautions,
            "model_version": model_version
        }
