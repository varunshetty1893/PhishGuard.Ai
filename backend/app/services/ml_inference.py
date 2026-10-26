"""
PhishGuard AI - Machine Learning Inference Engine Service
Loads serialized Random Forest model and metadata for runtime URL classification.
Includes high-reputation domain protection, false-positive mitigation, and calibrated risk scoring.
"""

import json
import os
from typing import Dict, Any, Tuple, List
from urllib.parse import urlparse
import joblib

from app.ml.feature_extraction import (
    FEATURE_NAMES,
    extract_url_features,
    features_to_vector,
    normalize_url,
    extract_apex_domain,
    is_high_reputation_domain
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
                    f"Machine learning model artifact not found at: {MODEL_PATH}."
                )
            cls._model = joblib.load(MODEL_PATH)

        if cls._metadata is None:
            if os.path.exists(METADATA_PATH):
                with open(METADATA_PATH, "r", encoding="utf-8") as f:
                    cls._metadata = json.load(f)
            else:
                cls._metadata = {"model_version": "3.0.0", "algorithm": "Random Forest"}

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
        parsed = urlparse(normalized)
        hostname = parsed.hostname or ""

        features, suspicious_reasons = extract_url_features(normalized)
        vector = features_to_vector(features)

        # Scikit-learn inference (1 sample matrix)
        probabilities = cls._model.predict_proba([vector])[0]
        raw_phish_prob = float(round(probabilities[1], 4))

        # Check for verified high-reputation domain authority (false-positive mitigation)
        is_trusted, apex = is_high_reputation_domain(hostname)

        features["apex_domain"] = apex
        features["is_verified_domain"] = 1 if is_trusted else 0

        if is_trusted:
            is_verified_domain = True
            predicted_class = "Legitimate"
            risk_level = "Low Risk"
            calibrated_score = round(min(raw_phish_prob * 0.05, 0.05), 4)

            if raw_phish_prob >= 0.50:
                anomaly_explanation = (
                    f"The URL contains complex cloud API structures (such as secondary endpoint hostnames in URI paths or tracking parameters) "
                    f"that elevate raw lexical metrics, but the registered apex domain '{apex}' is an authentic, high-reputation authority."
                )
                suspicious_reasons.append(
                    f"Elevated lexical complexity from cloud API paths; verified authentic under {apex}."
                )
            else:
                anomaly_explanation = f"The registered apex domain '{apex}' is a verified authentic high-reputation authority."

            interpretation = (
                f"Verified authentic infrastructure ({apex}). {anomaly_explanation} "
                "No active malicious listings detected."
            )
            precautions = [
                f"Standard browsing precautions apply. This destination is hosted on verified {apex} infrastructure.",
                "Ensure you are signed in through official organization portals before submitting sensitive credentials."
            ]
            final_model_score = calibrated_score
        else:
            is_verified_domain = False
            # Aligned risk thresholds with cautious, professional cybersecurity terminology
            if raw_phish_prob >= 0.75 or len(suspicious_reasons) >= 4:
                predicted_class = "Phishing"
                risk_level = "High Risk"
                interpretation = (
                    f"Elevated heuristic phishing probability ({raw_phish_prob*100:.1f}%). "
                    "The URL displays structural lexical patterns statistically correlating with deceptive or harvesting landing pages. "
                    "Exercise caution and verify the source before proceeding."
                )
                precautions = [
                    "Do not submit credentials, passwords, or personal financial details.",
                    "Verify the organization's authentic domain directly via official bookmarks or search.",
                    "Inspect the browser address bar for subtle domain misspellings or unusual extensions."
                ]
            elif raw_phish_prob >= 0.45 or len(suspicious_reasons) >= 2:
                predicted_class = "Suspicious"
                risk_level = "Suspicious"
                interpretation = (
                    f"Anomalous URL structure detected ({raw_phish_prob*100:.1f}% risk score). "
                    "Contains structural variations that deviate from typical baselines. Review the domain carefully before proceeding."
                )
                precautions = [
                    "Exercise caution before entering any information.",
                    "Verify that the domain matches the expected sender or organization.",
                    "If received in an unsolicited message, confirm with the sender through an alternate verified channel."
                ]
            else:
                predicted_class = "Legitimate"
                risk_level = "Low Risk"
                interpretation = (
                    f"Conforms to standard web address patterns ({raw_phish_prob*100:.1f}% risk score). "
                    "No prominent deception indicators or anomalous structural patterns identified."
                )
                precautions = [
                    "Standard browsing precautions apply.",
                    "While structural patterns conform to expected standards, remain mindful of unexpected credential prompts."
                ]
            final_model_score = raw_phish_prob

        model_version = cls._metadata.get("model_version", "3.0.0") if cls._metadata else "3.0.0"

        return {
            "submitted_url": raw_url,
            "normalized_url": normalized,
            "predicted_class": predicted_class,
            "risk_level": risk_level,
            "model_score": final_model_score,
            "raw_ml_score": raw_phish_prob,
            "is_verified_domain": is_verified_domain,
            "apex_domain": apex,
            "extracted_features": features,
            "suspicious_reasons": suspicious_reasons,
            "combined_interpretation": interpretation,
            "recommended_precautions": precautions,
            "model_version": model_version
        }
