import csv
import io
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.session import get_db
from app.models.scan import ScanHistory
from app.models.user import User
from app.api.deps import get_current_user

router = APIRouter()


@router.get(
    "/scans/export",
    summary="Export Authenticated User's Scan History as CSV"
)
def export_scans_csv(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Streams RFC 4180 compliant CSV export containing historical URL scans
    strictly owned by the authenticated user.
    Never exports another user's scan data.
    """
    records = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .order_by(desc(ScanHistory.created_at))
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output)

    headers = [
        "Scan ID",
        "Submitted URL",
        "Normalized URL",
        "Predicted Class",
        "Risk Level",
        "Model Score",
        "Model Version",
        "Created At (UTC)",
        "URL Length",
        "Hostname Length",
        "Count Dots",
        "Count Hyphens",
        "Subdomains",
        "Is HTTPS",
        "Is IP Address",
        "Suspicious Keywords",
        "Combined Interpretation"
    ]
    writer.writerow(headers)

    for r in records:
        f = r.extracted_features or {}
        writer.writerow([
            r.scan_id,
            r.submitted_url,
            r.normalized_url,
            r.predicted_class,
            r.risk_level,
            f"{r.model_score:.4f}" if r.model_score is not None else "N/A",
            r.model_version,
            r.created_at.isoformat() if r.created_at else "",
            f.get("url_length", ""),
            f.get("hostname_length", ""),
            f.get("count_dots", ""),
            f.get("count_hyphens", ""),
            f.get("count_subdomains", ""),
            f.get("is_https", ""),
            f.get("is_ip_address", ""),
            f.get("has_suspicious_keywords", ""),
            r.combined_interpretation
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard_scan_history.csv"}
    )
