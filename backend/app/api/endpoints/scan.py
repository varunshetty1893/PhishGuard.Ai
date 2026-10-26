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

    # 1. Run Machine Learning Inference
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
    gsb_res = threat_results["google_safe_browsing"]
    urlhaus_res = threat_results["urlhaus"]

    # 3. Create Unique Scan ID
    scan_id = str(uuid.uuid4())

    # 4. Persist Scan Record Strictly Bound to Authenticated User
    scan_record = ScanHistory(
        scan_id=scan_id,
        user_id=current_user.id,
        submitted_url=ml_result["submitted_url"],
        normalized_url=ml_result["normalized_url"],
        predicted_class=ml_result["predicted_class"],
        risk_level=ml_result["risk_level"],
        model_score=ml_result["model_score"],
        combined_interpretation=ml_result["combined_interpretation"],
        model_version=ml_result["model_version"]
    )
    scan_record.extracted_features = ml_result["extracted_features"]
    scan_record.suspicious_reasons = ml_result["suspicious_reasons"]
    db.add(scan_record)

    # 5. Persist Threat Logs tied to this scan
    gsb_log = ThreatCheckLog(
        scan_id=scan_id,
        provider_name="Google Safe Browsing",
        check_status=gsb_res.status,
        threat_found=gsb_res.threat_found,
        threat_category=gsb_res.category,
        raw_response=gsb_res.raw_response,
        error_message=gsb_res.error_message
    )
    urlhaus_log = ThreatCheckLog(
        scan_id=scan_id,
        provider_name="URLhaus",
        check_status=urlhaus_res.status,
        threat_found=urlhaus_res.threat_found,
        threat_category=urlhaus_res.category,
        raw_response=urlhaus_res.raw_response,
        error_message=urlhaus_res.error_message
    )
    db.add(gsb_log)
    db.add(urlhaus_log)
    db.commit()
    db.refresh(scan_record)

    threat_summary = ThreatIntelligenceSummary(
        google_safe_browsing=ThreatProviderResult(
            status=gsb_res.status,
            threat_found=gsb_res.threat_found,
            category=gsb_res.category,
            details=gsb_res.details
        ),
        urlhaus=ThreatProviderResult(
            status=urlhaus_res.status,
            threat_found=urlhaus_res.threat_found,
            category=urlhaus_res.category,
            details=urlhaus_res.details
        )
    )

    return ScanResultResponse(
        scan_id=scan_record.scan_id,
        submitted_url=scan_record.submitted_url,
        normalized_url=scan_record.normalized_url,
        predicted_class=scan_record.predicted_class,
        risk_level=scan_record.risk_level,
        model_score=scan_record.model_score,
        extracted_features=scan_record.extracted_features,
        suspicious_reasons=scan_record.suspicious_reasons,
        threat_intelligence=threat_summary,
        combined_interpretation=scan_record.combined_interpretation,
        recommended_precautions=ml_result["recommended_precautions"],
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

    gsb_log = next((t for t in record.threat_logs if t.provider_name == "Google Safe Browsing"), None)
    urlhaus_log = next((t for t in record.threat_logs if t.provider_name == "URLhaus"), None)

    threat_summary = ThreatIntelligenceSummary(
        google_safe_browsing=ThreatProviderResult(
            status=gsb_log.check_status if gsb_log else "Not Configured",
            threat_found=gsb_log.threat_found if gsb_log else False,
            category=gsb_log.threat_category if gsb_log else None,
            details=gsb_log.raw_response if gsb_log else None
        ),
        urlhaus=ThreatProviderResult(
            status=urlhaus_log.check_status if urlhaus_log else "No Match Reported",
            threat_found=urlhaus_log.threat_found if urlhaus_log else False,
            category=urlhaus_log.threat_category if urlhaus_log else None,
            details=urlhaus_log.raw_response if urlhaus_log else None
        )
    )

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

    return ScanResultResponse(
        scan_id=record.scan_id,
        submitted_url=record.submitted_url,
        normalized_url=record.normalized_url,
        predicted_class=record.predicted_class,
        risk_level=record.risk_level,
        model_score=record.model_score,
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
