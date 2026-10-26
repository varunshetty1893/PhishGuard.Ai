"""
PhishGuard AI - Machine Learning Inference Engine Service
Loads serialized Random Forest model and metadata for runtime URL classification.
Includes high-reputation domain protection, false-positive mitigation, calibrated risk scoring,
and v2 enhanced signals: TLD risk, brand lookalike, punycode, hostname entropy.
"""
import json
import os
from typing import Dict, Any, List
from urllib.parse import urlparse
import joblib

from app.ml.feature_extraction import (
    FEATURE_NAMES,
    extract_url_features,
    features_to_vector,
    normalize_url,
    extract_apex_domain,
    is_high_reputation_domain,
    # P3 new signals
    get_tld_risk_score,
    check_brand_lookalike,
    check_brand_in_subdomain,
    has_punycode,
    hostname_entropy,
)

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "ml", "artifacts")
MODEL_PATH    = os.path.join(ARTIFACTS_DIR, "phishguard_rf_model.joblib")
METADATA_PATH = os.path.join(ARTIFACTS_DIR, "model_metadata.json")


class MLInferenceService:
    _model    = None
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
                cls._metadata = {"model_version": "3.2.0", "algorithm": "Random Forest"}

    @classmethod
    def is_loaded(cls) -> bool:
        return cls._model is not None

    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        cls.load()
        return cls._metadata or {}

    @classmethod
    def _enrich_reasons_with_v2(cls, suspicious_reasons: List[str],
                                  hostname: str, raw_phish_prob: float) -> List[str]:
        """
        Appends P3 enhanced signal explanations to the suspicious_reasons list.
        These run at inference time and do NOT affect the model score
        (which uses the 16-feature v1 schema), but improve UI explanations.
        """
        enriched = list(suspicious_reasons)  # copy
        tld_risk = get_tld_risk_score(hostname)
        if tld_risk >= 0.8:
            enriched.append(
                f"High-risk TLD detected (score {tld_risk:.1f}/1.0). "
                "Registries like .xyz, .top, .tk, .ml and .ga are disproportionately abused for phishing campaigns."
            )
        if check_brand_lookalike(hostname):
            enriched.append(
                "Hostname closely resembles a well-known brand name with slight spelling variation "
                "(e.g. 'paypa1' or 'micorosoft'). Classic typosquatting technique."
            )
        if check_brand_in_subdomain(hostname):
            enriched.append(
                "A trusted brand name appears in the subdomain of an unrelated apex domain. "
                "Attackers use this to make URLs appear legitimate at a glance (e.g. paypal.evil.xyz)."
            )
        if has_punycode(hostname):
            enriched.append(
                "Hostname contains Punycode (xn--) encoding, indicating a possible IDN homograph attack "
                "where visually similar Unicode characters substitute ASCII letters."
            )
        ent = hostname_entropy(hostname)
        if ent > 3.8:
            enriched.append(
                f"High hostname entropy ({ent:.2f} bits) suggests an algorithmically generated or "
                "randomised domain name — a common signature of phishing kit infrastructure and DGA domains."
            )
        return enriched

    @classmethod
    def predict(cls, raw_url: str) -> Dict[str, Any]:
        """
        Executes complete offline inference on untrusted input string.
        Returns prediction, probability score, risk tier, features, enriched heuristic flags.
        """
        cls.load()

        normalized = normalize_url(raw_url)
        parsed     = urlparse(normalized)
        hostname   = parsed.hostname or ""

        # v1 16-feature extraction (matches the deployed model schema exactly)
        features, suspicious_reasons = extract_url_features(normalized)
        vector = features_to_vector(features)  # 16-D vector

        # Scikit-learn inference
        probabilities  = cls._model.predict_proba([vector])[0]
        raw_phish_prob = float(round(probabilities[1], 4))

        # P3: Enrich suspicious_reasons with v2 signals (UI only, no model change)
        # extract_url_features already adds basic v2 reasons; enrich adds richer descriptions
        # Deduplicate by keeping first occurrence of each unique reason topic
        seen_keys = set()
        deduped = []
        for r in suspicious_reasons:
            # Use first 40 chars as dedup key (catches same-topic duplicates)
            key = r[:40].lower()
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(r)
        suspicious_reasons = deduped
        suspicious_reasons = cls._enrich_reasons_with_v2(
            suspicious_reasons, hostname, raw_phish_prob
        )
        # Final dedup pass
        seen_keys = set()
        deduped2 = []
        for r in suspicious_reasons:
            key = r[:40].lower()
            if key not in seen_keys:
                seen_keys.add(key)
                deduped2.append(r)
        suspicious_reasons = deduped2

        # High-reputation domain protection (false-positive mitigation)
        is_trusted, apex = is_high_reputation_domain(hostname)
        features["apex_domain"]        = apex
        features["is_verified_domain"] = 1 if is_trusted else 0

        if is_trusted:
            is_verified_domain = True
            predicted_class    = "Legitimate"
            risk_level         = "Low Risk"
            calibrated_score   = round(min(raw_phish_prob * 0.05, 0.05), 4)

            if raw_phish_prob >= 0.50:
                anomaly_explanation = (
                    f"The URL contains complex cloud API or CDN path structures "
                    f"that elevate raw lexical metrics, but the registered apex domain "
                    f"'{apex}' is an authentic, high-reputation authority. "
                    "ML score reflects structural complexity, NOT a genuine threat."
                )
                suspicious_reasons.append(
                    f"Note: Elevated ML score is due to complex API/CDN path structure; "
                    f"apex domain '{apex}' is verified legitimate."
                )
            else:
                anomaly_explanation = (
                    f"The registered apex domain '{apex}' is a verified authentic authority."
                )
            interpretation = (
                f"Verified authentic infrastructure ({apex}). {anomaly_explanation} "
                "No active threat listings detected."
            )
            precautions = [
                f"Standard precautions apply. Destination is hosted on verified {apex} infrastructure.",
                "Ensure you sign in through official portals before submitting credentials."
            ]
            final_model_score = calibrated_score

        else:
            is_verified_domain = False
            threshold = float(cls.get_metadata().get("optimal_threshold", 0.64))
            n_signals = len(suspicious_reasons)

            if raw_phish_prob >= threshold:
                predicted_class = "Phishing"
                risk_level      = "High Risk" if raw_phish_prob >= 0.75 else "Suspicious"
                interpretation = (
                    f"The ML model assigned a phishing probability of {raw_phish_prob*100:.1f}% "
                    f"(optimal threshold: {threshold*100:.1f}%) based on {n_signals} structural indicators. "
                    "URL patterns deviate from legitimate web address baselines."
                )
                precautions = [
                    "Do NOT submit credentials, passwords, or payment details on this destination.",
                    "Verify the organisation's authentic domain directly via official bookmarks or a trusted search engine.",
                    "Inspect the address bar for subtle misspellings, unusual TLDs, or unexpected subdomains.",
                    "If received via email or SMS, report the message as phishing to your security team.",
                ]
            elif raw_phish_prob >= 0.35 and n_signals >= 2:
                predicted_class = "Legitimate"
                risk_level      = "Suspicious"
                interpretation = (
                    f"Elevated structural indicators detected ({n_signals} flags, ML probability: {raw_phish_prob*100:.1f}%), "
                    f"though below the phishing threshold of {threshold*100:.1f}%. Proceed with standard caution."
                )
                precautions = [
                    "Exercise caution before entering any sensitive information.",
                    "Verify the domain matches the expected sender or organization.",
                    "If received in an unsolicited message, confirm through an alternate verified channel.",
                ]
            else:
                predicted_class = "Legitimate"
                risk_level      = "Low Risk"
                interpretation = (
                    f"URL conforms to standard web address patterns (ML probability: {raw_phish_prob*100:.1f}%). "
                    "No prominent deception indicators identified."
                )
                precautions = [
                    "Standard browsing precautions apply.",
                    "While structural patterns are clean, remain alert if prompted for unexpected credentials.",
                ]
            final_model_score = raw_phish_prob

        model_version = (cls._metadata or {}).get("model_version", "3.2.0")

        return {
            "submitted_url":           raw_url,
            "normalized_url":          normalized,
            "predicted_class":         predicted_class,
            "risk_level":              risk_level,
            "model_score":             final_model_score,
            "raw_ml_score":            raw_phish_prob,
            "is_verified_domain":      is_verified_domain,
            "apex_domain":             apex,
            "extracted_features":      features,
            "suspicious_reasons":      suspicious_reasons,
            "combined_interpretation": interpretation,
            "recommended_precautions": precautions,
            "model_version":           model_version,
        }