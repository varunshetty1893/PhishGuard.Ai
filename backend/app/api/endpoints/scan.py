import asyncio
import logging
import socket
import uuid
from typing import Optional, Tuple
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session, selectinload
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
from app.services.domain_age import DomainAgeService
from app.api.deps import get_current_user, verify_csrf
from app.core.security_validation import validate_url_security, is_prohibited_ip, INTERNAL_DOMAIN_SUFFIXES
from app.core.rate_limit import scan_rate_limiter

logger = logging.getLogger("phishguard.scan")
router = APIRouter()

PROVIDER_LABELS = {
    "openphish": "OpenPhish",
    "phishing_database": "Phishing.Database",
    "phish_destroy": "PhishDestroy",
    "cert_pl": "CERT-PL Warning List",
    "google_safe_browsing": "Google Safe Browsing",
}


async def check_domain_dns(hostname: str) -> Tuple[Optional[bool], Optional[str]]:
    """
    Asynchronously checks whether domain resolves via DNS.
    Enforces SSRF prevention: validates that resolved IP is public.
    Returns (exists, detail).
    True = resolved, False = NXDOMAIN or internal IP (SSRF blocked), None = timeout / inconclusive.
    """
    if not hostname:
        return True, "No hostname"
    clean = hostname.split(":")[0].strip().rstrip(".")

    if clean.lower() == "localhost" or any(clean.lower().endswith(s) for s in INTERNAL_DOMAIN_SUFFIXES):
        return False, "Destination targets internal/local infrastructure (SSRF prohibited)."

    if is_prohibited_ip(clean):
        return False, f"Destination IP '{clean}' is an internal/private address (SSRF prohibited)."

    # If public raw IP address, DNS resolution is not applicable
    try:
        socket.inet_aton(clean)
        return True, "Public IP address destination"
    except socket.error:
        pass

    try:
        resolved_ip = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyname, clean),
            timeout=1.5
        )
        if is_prohibited_ip(resolved_ip):
            logger.warning(f"SSRF Shield: Domain '{clean}' resolved to prohibited IP '{resolved_ip}'.")
            return False, f"Domain resolves to private/internal IP address ({resolved_ip}) - blocked by SSRF policy."
        return True, "Domain resolves in public DNS."
    except socket.gaierror as e:
        return False, f"Domain does not resolve in public DNS (NXDOMAIN): {e}"
    except Exception:
        return None, "DNS verification timed out or was inconclusive."


@router.post(
    "/scan",
    response_model=ScanResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Untrusted URL"
)
async def scan_url(
    request: ScanRequest,
    http_req: Request,
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

    # 0. Enforce SSRF and Scheme Security Validation
    is_safe, error_reason = validate_url_security(raw_url)
    if not is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security Policy Rejection: {error_reason}"
        )

    # 0.1 Enforce Rate Limiting
    client_ip = http_req.client.host if http_req.client else "unknown"
    rate_key = f"user:{current_user.id}" if current_user and hasattr(current_user, "id") else f"ip:{client_ip}"
    scan_rate_limiter.check_scan_rate_limit(rate_key)

    # 1. Run Machine Learning Inference (Offline, in-memory, zero outbound crawl)
    try:
        ml_result = MLInferenceService.predict(raw_url)
    except Exception as e:
        req_id = str(uuid.uuid4())[:8]
        logger.error(f"[Req {req_id}] Machine learning inference failed on URL: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Machine learning inference encountered an error. (Request ID: {req_id})"
        )

    # 2. Run External Threat Intelligence & DNS Domain Check in Parallel
    normalized_url = ml_result["normalized_url"]
    parsed_host = urlparse(normalized_url).hostname or ""

    threat_results, dns_check, (domain_age_days, domain_age_status) = await asyncio.gather(
        ThreatIntelAggregator.evaluate_url(normalized_url),
        check_domain_dns(parsed_host),
        DomainAgeService.get_domain_age(parsed_host, db=db)
    )
    dns_resolves, dns_detail = dns_check
    age_eval = DomainAgeService.evaluate_age(domain_age_days)

    # 3. Combine Threat Intel, DNS and ML Results
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
        # A positive threat-feed result overrides the model's classification
        predicted_class = "Confirmed Phishing (known blocklist)"
        risk_level = "High Risk"
        provider_str = ", ".join(
            f"{PROVIDER_LABELS[key]} ({result.category or 'Threat detected'})"
            for key, result in matched_providers
        )
        combined_interpretation = (
            f"Confirmed Phishing (known blocklist): This URL or its domain is listed by {provider_str}. "
            "Treat it as harmful. Do not visit this destination."
        )
        suspicious_reasons.insert(0, f"Confirmed threat listed in {provider_str}.")
        if age_eval["is_new"]:
            suspicious_reasons.append(age_eval["reason"])
        precautions = [
            "DO NOT click this link, navigate to this destination, or download any files.",
            "DO NOT submit usernames, passwords, credit card numbers, or personal data.",
            "If received via email, SMS, or chat, report the message to your security team."
        ]
    else:
        # Missing from a threat feed: ML-only predictions must NEVER be labeled 'Phishing'
        raw_pred_class = ml_result["predicted_class"]
        risk_level = ml_result["risk_level"]
        predicted_class = "Suspicious (unverified, ML only)" if (raw_pred_class == "Phishing" or "Suspicious" in raw_pred_class) else "Legitimate"

        # Check domain existence via DNS
        if dns_resolves is False and not is_verified:
            dns_reason = "Domain does not exist or has no active DNS records (NXDOMAIN). The destination cannot be reached."
            if not any("NXDOMAIN" in r or "does not exist" in r for r in suspicious_reasons):
                suspicious_reasons.insert(0, dns_reason)

            if raw_pred_class == "Phishing" or risk_level == "High Risk":
                predicted_class = "Suspicious (unverified, ML only)"
                risk_level = "High Risk"
                ml_probability = max(ml_probability, 0.85)
                combined_interpretation = (
                    f"Suspicious (unverified, ML only): Hostname '{parsed_host}' mimics a recognized brand but does not exist in public DNS (NXDOMAIN). "
                    f"Unregistered lookalike addresses are potential phishing indicators. Do not interact with this destination."
                )
            else:
                predicted_class = "Legitimate"
                risk_level = "Suspicious"
                ml_probability = max(ml_probability, 0.50)
                combined_interpretation = (
                    f"Inactive / Non-Existent Domain: The domain '{parsed_host}' does not resolve in public DNS (NXDOMAIN). "
                    f"The website cannot be reached and cannot be confirmed safe."
                )
            if "This website address does not exist or has no active DNS records. Do not rely on it." not in precautions:
                precautions.insert(0, "This website address does not exist or has no active DNS records. Do not rely on it.")
        else:
            # Evaluate Domain Age Impact
            if age_eval["is_new"]:
                # Under 30 days old: strong suspicious signal (+0.25 modifier)
                if age_eval["reason"] not in suspicious_reasons:
                    suspicious_reasons.insert(0, age_eval["reason"])
                ml_probability = min(0.95, ml_probability + age_eval["score_modifier"])
                if ml_probability >= 0.65:
                    predicted_class = "Suspicious (unverified, ML only)"
                    risk_level = "High Risk"
                elif ml_probability >= 0.40:
                    if risk_level == "Low Risk":
                        risk_level = "Suspicious"
            elif age_eval["is_established"] and not is_verified:
                # Over 2 years old: reduce suspicion (-0.10 modifier)
                has_lookalike = any("lookalike" in r.lower() or "typo" in r.lower() for r in suspicious_reasons)
                if not has_lookalike:
                    ml_probability = max(0.01, ml_probability + age_eval["score_modifier"])
                    if ml_probability < 0.40 and risk_level == "Suspicious" and len(suspicious_reasons) <= 1:
                        risk_level = "Low Risk"

            provider_states = [
                f"{PROVIDER_LABELS[key]}: {result.status}"
                for key, result in threat_results.items()
            ]
            provider_notes = "; ".join(provider_states)

            if is_verified:
                combined_interpretation = (
                    f"Verified authentic website ({apex}). This domain is recognized as an official, authentic authority. "
                    f"No active security threat listings were detected."
                )
            elif risk_level == "High Risk":
                predicted_class = "Suspicious (unverified, ML only)"
                if len(suspicious_reasons) == 0:
                    combined_interpretation = (
                        f"Unusual Link Structure: Our AI assigned a high risk score ({ml_probability*100:.1f}/100) due to deep file or directory paths, "
                        f"but all 5 security threat databases report no active phishing records. Verify that you trust the source before interacting."
                    )
                else:
                    combined_interpretation = (
                        f"Potential Phishing: Our AI detected suspicious patterns in this link (Risk Score: {ml_probability*100:.1f}/100). "
                        f"While no security database has confirmed it on a blocklist yet, exercise caution and do not enter passwords or sensitive information."
                    )
            elif risk_level == "Suspicious":
                predicted_class = "Suspicious (unverified, ML only)"
                combined_interpretation = (
                    f"Caution Advised: This link exhibits minor structural warning signs (Risk Score: {ml_probability*100:.1f}/100). "
                    f"Verify the website identity directly before submitting passwords or sensitive information."
                )
            else:
                combined_interpretation = (
                    f"Safe Link: No suspicious patterns or active threat listings were found for this address (Risk Score: {ml_probability*100:.1f}/100)."
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
    feat = dict(ml_result["extracted_features"])
    feat["dns_resolved"] = 1 if dns_resolves is True else (0 if dns_resolves is False else -1)
    feat["dns_status"] = dns_detail or "Unknown"
    feat["domain_age_days"] = domain_age_days if domain_age_days is not None else -1
    scan_record.extracted_features = feat
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
        domain_age_days=domain_age_days,
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
        if predicted_class.lower() == "phishing":
            query = query.filter(
                (ScanHistory.predicted_class == "Confirmed Phishing (known blocklist)") |
                (ScanHistory.predicted_class == "Suspicious (unverified, ML only)") |
                (ScanHistory.predicted_class == "Phishing")
            )
        else:
            query = query.filter(ScanHistory.predicted_class.ilike(f"%{predicted_class}%"))
    if risk_level:
        query = query.filter(ScanHistory.risk_level == risk_level)

    total_records = query.count()
    total_pages = (total_records + page_size - 1) // page_size if total_records > 0 else 1

    records = (
        query.options(selectinload(ScanHistory.threat_logs))
        .order_by(desc(ScanHistory.created_at))
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
