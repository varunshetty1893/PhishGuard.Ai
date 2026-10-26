from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db
from app.models.scan import ScanHistory, ThreatCheckLog
from app.schemas.scan import AnalyticsResponse, DistributionSlice, TemporalDataPoint
from app.services.ml_inference import MLInferenceService
from app.services.threat_intel import ThreatIntelAggregator

router = APIRouter()


@router.get("/analytics", response_model=AnalyticsResponse, summary="Retrieve Dynamic Analytics from SQLite Records")
def get_analytics(db: Session = Depends(get_db)):
    """
    Computes real-time analytics directly from SQLite database records.
    Never returns hardcoded or fabricated statistics.
    """
    total_scans = db.query(func.count(ScanHistory.id)).scalar() or 0
    phishing_count = db.query(func.count(ScanHistory.id)).filter(ScanHistory.predicted_class == "Phishing").scalar() or 0
    legitimate_count = db.query(func.count(ScanHistory.id)).filter(ScanHistory.predicted_class == "Legitimate").scalar() or 0
    high_risk_count = db.query(func.count(ScanHistory.id)).filter(ScanHistory.risk_level == "High Risk").scalar() or 0
    suspicious_count = db.query(func.count(ScanHistory.id)).filter(ScanHistory.risk_level == "Suspicious").scalar() or 0
    low_risk_count = db.query(func.count(ScanHistory.id)).filter(ScanHistory.risk_level == "Low Risk").scalar() or 0

    threat_intel_matches = db.query(func.count(ThreatCheckLog.id)).filter(ThreatCheckLog.threat_found == True).scalar() or 0
    threat_intel_failures = db.query(func.count(ThreatCheckLog.id)).filter(ThreatCheckLog.check_status == "Unavailable").scalar() or 0

    # Colors strictly compliant with the black, green, yellow, and red palette:
    # Legitimate / Low Risk: #39FF88
    # Suspicious: #FFD54A
    # Phishing / High Risk: #FF525C
    classification_distribution = [
        DistributionSlice(name="Legitimate", value=legitimate_count, color="#39FF88"),
        DistributionSlice(name="Phishing", value=phishing_count, color="#FF525C")
    ]

    risk_distribution = [
        DistributionSlice(name="Low Risk", value=low_risk_count, color="#39FF88"),
        DistributionSlice(name="Suspicious", value=suspicious_count, color="#FFD54A"),
        DistributionSlice(name="High Risk", value=high_risk_count, color="#FF525C")
    ]

    # Calculate temporal scan activity for the last 7 days from actual records
    now = datetime.now(timezone.utc)
    scans_over_time = []
    
    # Generate past 7 days buckets
    for i in range(6, -1, -1):
        target_day = (now - timedelta(days=i)).date()
        day_start = datetime(target_day.year, target_day.month, target_day.day, 0, 0, 0, tzinfo=timezone.utc)
        day_end = datetime(target_day.year, target_day.month, target_day.day, 23, 59, 59, tzinfo=timezone.utc)

        day_total = (
            db.query(func.count(ScanHistory.id))
            .filter(ScanHistory.created_at >= day_start, ScanHistory.created_at <= day_end)
            .scalar() or 0
        )
        day_phish = (
            db.query(func.count(ScanHistory.id))
            .filter(
                ScanHistory.created_at >= day_start,
                ScanHistory.created_at <= day_end,
                ScanHistory.predicted_class == "Phishing"
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

    meta = MLInferenceService.get_metadata()
    model_status = {
        "version": meta.get("model_version", "1.0.0"),
        "algorithm": meta.get("algorithm", "Random Forest Classifier"),
        "status": "Active" if MLInferenceService.is_loaded() else "Ready"
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
