from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db
from app.models.scan import ScanHistory, ThreatCheckLog
from app.models.user import User
from app.schemas.scan import AnalyticsResponse, DistributionSlice, TemporalDataPoint
from app.services.ml_inference import MLInferenceService
from app.services.threat_intel import ThreatIntelAggregator
from app.api.deps import get_current_user

router = APIRouter()


@router.get(
    "/analytics",
    response_model=AnalyticsResponse,
    summary="Retrieve Dynamic Analytics from User's Isolated Records"
)
def get_analytics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Computes real-time analytics strictly from the authenticated user's records.
    Never exposes or aggregates another user's private scans.
    """
    user_id = current_user.id

    # User-scoped counts
    total_scans = (
        db.query(func.count(ScanHistory.id))
        .filter(ScanHistory.user_id == user_id)
        .scalar() or 0
    )
    phishing_count = (
        db.query(func.count(ScanHistory.id))
        .filter(ScanHistory.user_id == user_id, ScanHistory.predicted_class == "Phishing")
        .scalar() or 0
    )
    legitimate_count = (
        db.query(func.count(ScanHistory.id))
        .filter(ScanHistory.user_id == user_id, ScanHistory.predicted_class == "Legitimate")
        .scalar() or 0
    )
    high_risk_count = (
        db.query(func.count(ScanHistory.id))
        .filter(ScanHistory.user_id == user_id, ScanHistory.risk_level == "High Risk")
        .scalar() or 0
    )
    suspicious_count = (
        db.query(func.count(ScanHistory.id))
        .filter(ScanHistory.user_id == user_id, ScanHistory.risk_level == "Suspicious")
        .scalar() or 0
    )
    low_risk_count = (
        db.query(func.count(ScanHistory.id))
        .filter(ScanHistory.user_id == user_id, ScanHistory.risk_level == "Low Risk")
        .scalar() or 0
    )

    # Threat intel matches linked to user's scans
    threat_intel_matches = (
        db.query(func.count(ThreatCheckLog.id))
        .join(ScanHistory, ThreatCheckLog.scan_id == ScanHistory.scan_id)
        .filter(ScanHistory.user_id == user_id, ThreatCheckLog.threat_found == True)
        .scalar() or 0
    )
    threat_intel_failures = (
        db.query(func.count(ThreatCheckLog.id))
        .join(ScanHistory, ThreatCheckLog.scan_id == ScanHistory.scan_id)
        .filter(ScanHistory.user_id == user_id, ThreatCheckLog.check_status == "Unavailable")
        .scalar() or 0
    )

    # Color Palette: Green (#39FF88), Yellow (#FFD54A), Red (#FF525C)
    classification_distribution = [
        DistributionSlice(name="Legitimate", value=legitimate_count, color="#39FF88"),
        DistributionSlice(name="Phishing", value=phishing_count, color="#FF525C")
    ]

    risk_distribution = [
        DistributionSlice(name="Low Risk", value=low_risk_count, color="#39FF88"),
        DistributionSlice(name="Suspicious", value=suspicious_count, color="#FFD54A"),
        DistributionSlice(name="High Risk", value=high_risk_count, color="#FF525C")
    ]

    # Calculate temporal activity for past 7 days for current user only
    now = datetime.now(timezone.utc)
    scans_over_time = []
    for i in range(6, -1, -1):
        target_day = (now - timedelta(days=i)).date()
        day_start = datetime(target_day.year, target_day.month, target_day.day, 0, 0, 0, tzinfo=timezone.utc)
        day_end = datetime(target_day.year, target_day.month, target_day.day, 23, 59, 59, tzinfo=timezone.utc)

        day_total = (
            db.query(func.count(ScanHistory.id))
            .filter(
                ScanHistory.user_id == user_id,
                ScanHistory.created_at >= day_start,
                ScanHistory.created_at <= day_end
            )
            .scalar() or 0
        )
        day_phish = (
            db.query(func.count(ScanHistory.id))
            .filter(
                ScanHistory.user_id == user_id,
                ScanHistory.predicted_class == "Phishing",
                ScanHistory.created_at >= day_start,
                ScanHistory.created_at <= day_end
            )
            .scalar() or 0
        )
        scans_over_time.append(
            TemporalDataPoint(
                date=target_day.strftime("%b %d"),
                scans=day_total,
                phishing=day_phish
            )
        )

    model_meta = MLInferenceService.get_metadata() or {}
    model_status = {
        "is_loaded": MLInferenceService.is_loaded(),
        "model_version": model_meta.get("model_version", "2.1.0"),
        "algorithm": model_meta.get("algorithm", "Random Forest Classifier"),
        "features_tracked": len(model_meta.get("feature_schema", []))
    }

    threat_provider_status = ThreatIntelAggregator.get_provider_status()

    return AnalyticsResponse(
        total_scans=total_scans,
        phishing_count=phishing_count,
        legitimate_count=legitimate_count,
        high_risk_count=high_risk_count,
        threat_intel_matches=threat_intel_matches,
        threat_intel_failures=threat_intel_failures,
        classification_distribution=classification_distribution,
        risk_distribution=risk_distribution,
        scans_over_time=scans_over_time,
        model_status=model_status,
        threat_provider_status=threat_provider_status
    )
