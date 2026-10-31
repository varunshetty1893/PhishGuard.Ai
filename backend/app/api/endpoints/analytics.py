from datetime import datetime, date, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from app.db.session import get_db
from app.models.scan import ScanHistory, ThreatCheckLog
from app.models.user import User
from app.schemas.scan import AnalyticsResponse, DistributionSlice, TemporalDataPoint
from app.services.ml_inference import MLInferenceService
from app.services.threat_intel import ThreatIntelAggregator
from app.ml.feature_extraction import FEATURE_NAMES
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

    # 1. Consolidated count query for user scans (single round-trip)
    stats = (
        db.query(
            func.count(ScanHistory.id).label("total"),
            func.count(case((ScanHistory.predicted_class == "Phishing", 1))).label("phishing"),
            func.count(case((ScanHistory.predicted_class == "Legitimate", 1))).label("legitimate"),
            func.count(case((ScanHistory.risk_level == "High Risk", 1))).label("high_risk"),
            func.count(case((ScanHistory.risk_level == "Suspicious", 1))).label("suspicious"),
            func.count(case((ScanHistory.risk_level == "Low Risk", 1))).label("low_risk"),
        )
        .filter(ScanHistory.user_id == user_id)
        .one()
    )

    total_scans = stats.total or 0
    phishing_count = stats.phishing or 0
    legitimate_count = stats.legitimate or 0
    high_risk_count = stats.high_risk or 0
    suspicious_count = stats.suspicious or 0
    low_risk_count = stats.low_risk or 0

    threat_intel_matches = 0
    threat_intel_failures = 0
    daily_map = {}

    if total_scans > 0:
        # 2. Consolidated threat check query (single round-trip with join)
        threat_stats = (
            db.query(
                func.count(case((ThreatCheckLog.threat_found == True, 1))).label("matches"),
                func.count(case((ThreatCheckLog.check_status == "Unavailable", 1))).label("failures"),
            )
            .join(ScanHistory, ThreatCheckLog.scan_id == ScanHistory.scan_id)
            .filter(ScanHistory.user_id == user_id)
            .one()
        )
        threat_intel_matches = threat_stats.matches or 0
        threat_intel_failures = threat_stats.failures or 0

        # 3. Consolidated 7-day activity query (single round-trip grouped by date)
        now = datetime.now(timezone.utc)
        seven_days_ago = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
        daily_rows = (
            db.query(
                func.date(ScanHistory.created_at).label("day"),
                func.count(ScanHistory.id).label("total"),
                func.count(case((ScanHistory.predicted_class == "Phishing", 1))).label("phishing"),
            )
            .filter(
                ScanHistory.user_id == user_id,
                ScanHistory.created_at >= seven_days_ago,
            )
            .group_by(func.date(ScanHistory.created_at))
            .all()
        )
        for r in daily_rows:
            day_val = r.day
            if isinstance(day_val, str):
                day_key = day_val[:10]
            elif isinstance(day_val, (datetime, date)):
                day_key = day_val.strftime("%Y-%m-%d")
            else:
                day_key = str(day_val)[:10]
            daily_map[day_key] = (r.total or 0, r.phishing or 0)
    else:
        now = datetime.now(timezone.utc)

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

    # Generate 7-day temporal activity points purely in-memory (0ms)
    scans_over_time = []
    for i in range(6, -1, -1):
        target_day = (now - timedelta(days=i)).date()
        day_str = target_day.strftime("%Y-%m-%d")
        day_total, day_phish = daily_map.get(day_str, (0, 0))
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
        "features_tracked": len(model_meta.get("feature_schema", [])) or len(FEATURE_NAMES)
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
