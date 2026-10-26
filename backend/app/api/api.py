from fastapi import APIRouter
from app.api.endpoints import health, model, export, scan, analytics, threat_intel, auth

api_router = APIRouter()

# Authentication & Session Management
api_router.include_router(auth.router, tags=["Authentication"])

# Public Transparency & Health
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(model.router, tags=["Model Transparency"])

# Data Export must be mounted BEFORE scan.router to prevent /scans/{scan_id} shadowing /scans/export
api_router.include_router(export.router, tags=["Data Export"])

# Protected Application Endpoints (User-Isolated)
api_router.include_router(scan.router, tags=["Scanner & History"])
api_router.include_router(analytics.router, tags=["Analytics"])
api_router.include_router(threat_intel.router, tags=["Threat Intelligence"])
