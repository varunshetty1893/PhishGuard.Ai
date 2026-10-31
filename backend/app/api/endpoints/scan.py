import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.session import get_db
from app.models.scan import ScanHistory, ThreatCheckLog
from app.models.user import User
from app.schemas.scan import (
    ScanRequest,
    ScanResultResponse,
    ScanListResponse,
    ScanListItem,
    ThreatIntelligenceSummary,
    ThreatProviderResult
)
from app.services.ml_inference import MLInferenceService
from app.services.threat_intel import ThreatIntelAggregator
from app.api.deps import get_current_user, verify_csrf

router = APIRouter()

PROVIDER_LABELS = {
    "openphish": "OpenPhish",
    "phishing_database": "Phishing.Database",
    "phish_destroy": "PhishDestroy",
    "cert_pl": "CERT-PL Warning List",
    "google_safe_browsing": "Google Safe Browsing",
}


@router.post(
    "/scan",
    response_model=ScanResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Untrusted URL"
)
async def scan_url(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db)
):
    """
    Ingests untrusted URL input, performs deterministic offline feature extraction,
    runs ML model inference, dispatches optional threat-intelligence checks,
    persists scan record bound to the authenticated user, and returns comprehensive report.
    Never accepts trusted user_id from frontend.
    """
    raw_url = request.url

    # 1. Run Machine Learning Inference (Offline, in-memory, zero outbound crawl)
    try:
        ml_result = MLInferenceService.predict(raw_url)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Machine learning inference failed: {str(e)}"
        )

    # 2. Run External Threat Intelligence (Independent & Optional)
    normalized_url = ml_result["normalized_url"]
    threat_results = await ThreatIntelAggregator.evaluate_url(normalized_url)

    # 3. Combine Threat Intel and ML Results
    raw_ml_prob = float(ml_result.get("raw_ml_score", ml_result.get("model_score", 0.0)))
    ml_probability = float(ml_result.get("model_score", raw_ml_prob))
    is_verified = bool(ml_result.get("is_verified_domain", False))
    apex = ml_result.get("apex_domain")
    suspicious_reasons = list(ml_result.get("suspicious_reasons", []))
    precautions = list(ml_result.get("recommended_precautions", []))

    matched_providers = [
        (key, result)
        for key, result in threat_results.items()
        if result.threat_found
    ]
    threat_intel_match = bool(matched_providers)

    if threat_intel_match:
        # A positive threat-feed result overrides the model's classification,
        # while the displayed probability remains the model's own score.
        predicted_class = "Phishing"
        risk_level = "High Risk"
        provider_str = ", ".join(
            f"{PROVIDER_LABELS[key]} ({result.category or 'Threat detected'})"
            for key, result in matched_providers
        )
        combined_interpretation = (
            f"Threat Feed Match: This URL or its domain is listed by {provider_str}. "
            "Treat it as harmful. Do not visit this destination."
        )
        suspicious_reasons.insert(0, f"Confirmed threat listed in {provider_str}.")
        precautions = [
            "DO NOT click this link, navigate to this destination, or download any files.",
            "DO NOT submit usernames, passwords, credit card numbers, or personal data.",
            "If received via email, SMS, or chat, report the message to your security team."
        ]
    else:
        # Missing from a threat feed is not proof that a URL is safe.
        predicted_class = ml_result["predicted_class"]
        risk_level = ml_result["risk_level"]

        provider_states = [
            f"{PROVIDER_LABELS[key]}: {result.status}"
            for key, result in threat_results.items()
        ]
        provider_notes = "; ".join(provider_states)

        if is_verified:
            combined_interpretation = (
                f"Verified infrastructure ({apex}). Structural metrics and domain authority indicate legitimate ownership. "
                f"External threat status: {provider_notes}."
            )
        elif risk_level == "High Risk":
            combined_interpretation = (
                f"High Risk (ML Phishing Probability: {raw_ml_prob*100:.1f}%). "
                f"Threat feed status: {provider_notes}. The machine learning engine detected deceptive lexical anomalies. "
                f"Threat databases are retrospective blocklists and often have zero visibility into newly registered or zero-day phishing links. "
                f"Exercise extreme caution."
            )
        elif risk_level == "Suspicious":
            combined_interpretation = (
                f"Suspicious URL (ML Probability: {raw_ml_prob*100:.1f}%). "
                f"External threat status: {provider_notes}. "
                f"The URL exhibits structural variations that deviate from typical legitimate websites. "
                f"Exercise caution and verify the source directly."
            )
        else:
            combined_interpretation = (
                f"Low Risk (ML Probability: {ml_probability*100:.1f}%). "
                f"External threat status: {provider_notes}. Absence from threat databases does not guarantee safety."
            )

    # 4. Create Unique Scan ID
    scan_id = str(uuid.uuid4())

    # 5. Persist Scan Record Strictly Bound to Authenticated User
    scan_record = ScanHistory(
        scan_id=scan_id,
        user_id=current_user.id,
        submitted_url=ml_result["submitted_url"],
        normalized_url=ml_result["normalized_url"],
        predicted_class=predicted_class,
        risk_level=risk_level,
        model_score=ml_probability,
        combined_interpretation=combined_interpretation,
        model_version=ml_result["model_version"]
    )
    scan_record.extracted_features = ml_result["extracted_features"]
    scan_record.suspicious_reasons = suspicious_reasons
    db.add(scan_record)

    # 6. Persist Threat Logs tied to this scan
    for key, result in threat_results.items():
        db.add(
            ThreatCheckLog(
                scan_id=scan_id,
                provider_name=PROVIDER_LABELS[key],
                check_status=result.status,
                threat_found=result.threat_found,
                threat_category=result.category,
                raw_response=result.raw_response,
                error_message=result.error_message,
            )
        )
    db.commit()
    db.refresh(scan_record)

    threat_summary = ThreatIntelligenceSummary(
        **{
            key: ThreatProviderResult(
                status=result.status,
                threat_found=result.threat_found,
                category=result.category,
                details=result.details,
            )
            for key, result in threat_results.items()
        }
    )

    return ScanResultResponse(
        scan_id=scan_record.scan_id,
        submitted_url=scan_record.submitted_url,
        normalized_url=scan_record.normalized_url,
        predicted_class=scan_record.predicted_class,
        risk_level=scan_record.risk_level,
        ml_probability=ml_probability,
        model_score=scan_record.model_score,
        raw_ml_score=raw_ml_prob,
        is_verified_domain=is_verified,
        apex_domain=apex,
        threat_intel_match=threat_intel_match,
        extracted_features=scan_record.extracted_features,
        suspicious_reasons=scan_record.suspicious_reasons,
        threat_intelligence=threat_summary,
        combined_interpretation=scan_record.combined_interpretation,
        recommended_precautions=precautions,
        model_version=scan_record.model_version,
        created_at=scan_record.created_at
    )


@router.get(
    "/scans",
    response_model=ScanListResponse,
    summary="Query User's Paginated Scan History"
)
def list_scans(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search substring in submitted URL"),
    predicted_class: Optional[str] = Query(None, description="Filter by class ('Legitimate' or 'Phishing')"),
    risk_level: Optional[str] = Query(None, description="Filter by risk tier ('Low Risk', 'Suspicious', 'High Risk')"),
    threat_status: Optional[str] = Query(None, description="Filter by threat match ('Threat Found', 'No Match', 'All')"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves paginated scan records strictly isolated to the authenticated user.
    """
    query = db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id)

    if search:
        query = query.filter(ScanHistory.submitted_url.ilike(f"%{search.strip()}%"))
    if predicted_class:
        query = query.filter(ScanHistory.predicted_class == predicted_class)
    if risk_level:
        query = query.filter(ScanHistory.risk_level == risk_level)

    total_records = query.count()
    total_pages = (total_records + page_size - 1) // page_size if total_records > 0 else 1

    records = (
        query.order_by(desc(ScanHistory.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    items = []
    for r in records:
        has_threat_match = any(t.threat_found for t in r.threat_logs)
        if threat_status == "Threat Found" and not has_threat_match:
            continue
        if threat_status == "No Match" and has_threat_match:
            continue

        items.append(
            ScanListItem(
                scan_id=r.scan_id,
                submitted_url=r.submitted_url,
                predicted_class=r.predicted_class,
                risk_level=r.risk_level,
                model_score=r.model_score,
                created_at=r.created_at,
                threat_intel_match=has_threat_match
            )
        )

    return ScanListResponse(
        total_records=total_records,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=items
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResultResponse,
    summary="Retrieve Individual Scan Detail"
)
def get_scan_detail(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves individual scan report.
    Returns 404 if record doesn't exist OR if it belongs to another user (anti-IDOR).
    """
    record = (
        db.query(ScanHistory)
        .filter(ScanHistory.scan_id == scan_id, ScanHistory.user_id == current_user.id)
        .first()
    )
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found or access denied."
        )

    logs_by_provider = {log.provider_name: log for log in record.threat_logs}
    threat_summary_values = {}
    for key, label in PROVIDER_LABELS.items():
        log = logs_by_provider.get(label)
        if log:
            threat_summary_values[key] = ThreatProviderResult(
                status=log.check_status,
                threat_found=log.threat_found,
                category=log.threat_category,
                details=log.raw_response or log.error_message,
            )
    threat_summary = ThreatIntelligenceSummary(**threat_summary_values)

    precautions = []
    if record.risk_level == "High Risk":
        precautions.append("DO NOT click this link or submit personal or financial credentials.")
        precautions.append("DO NOT download any software, attachments, or extensions from this domain.")
        precautions.append("If received via email or SMS, report the message as phishing to your security administrator.")
    elif record.risk_level == "Suspicious":
        precautions.append("Exercise extreme caution. Structural indicators suggest anomalous characteristics.")
        precautions.append("Verify the organization's authentic URL directly via a verified search engine or bookmark.")
        precautions.append("Check the address bar carefully for typosquatting or strange domain suffixes.")
    else:
        precautions.append("Standard browsing precautions apply.")
        precautions.append("While the URL displays legitimate structural patterns, remain alert if prompted for unexpected passwords.")

    feats = record.extracted_features or {}
    apex_dom = feats.get("apex_domain")
    is_ver = bool(feats.get("is_verified_domain", 0))
    raw_val = feats.get("raw_ml_score")
    if raw_val is None:
        raw_val = record.model_score if record.model_score is not None else 0.0
    raw_score = float(raw_val)
    assessed_score = float(record.model_score) if record.model_score is not None else raw_score
    threat_found = any(t.threat_found for t in record.threat_logs)

    return ScanResultResponse(
        scan_id=record.scan_id,
        submitted_url=record.submitted_url,
        normalized_url=record.normalized_url,
        predicted_class=record.predicted_class,
        risk_level=record.risk_level,
        ml_probability=assessed_score,
        model_score=record.model_score,
        raw_ml_score=raw_score,
        is_verified_domain=is_ver,
        apex_domain=apex_dom,
        threat_intel_match=threat_found,
        extracted_features=record.extracted_features,
        suspicious_reasons=record.suspicious_reasons,
        threat_intelligence=threat_summary,
        combined_interpretation=record.combined_interpretation,
        recommended_precautions=precautions,
        model_version=record.model_version,
        created_at=record.created_at
    )


@router.delete(
    "/scans/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Individual Scan Record"
)
def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db)
):
    """
    Deletes individual scan record belonging to current user.
    Rejects access if scan belongs to another user.
    """
    record = (
        db.query(ScanHistory)
        .filter(ScanHistory.scan_id == scan_id, ScanHistory.user_id == current_user.id)
        .first()
    )
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found or access denied."
        )

    db.delete(record)
    db.commit()
    return {"message": "Scan record successfully deleted.", "scan_id": scan_id}


@router.delete(
    "/scans",
    status_code=status.HTTP_200_OK,
    summary="Clear User's Entire Scan History"
)
def clear_all_scans(
    current_user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db)
):
    """
    Clears all scan records belonging strictly to the authenticated user.
    Never deletes other users' scan records.
    """
    deleted_count = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .delete(synchronize_session=False)
    )
    db.commit()
    return {
        "message": "Your scan history was cleared successfully.",
        "deleted_count": deleted_count
    }
