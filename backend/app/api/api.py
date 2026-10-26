from fastapi import APIRouter
from app.api.endpoints import health, model, scan, analytics, export, threat_intel

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(model.router, tags=["Model Transparency"])
api_router.include_router(export.router, tags=["Data Export"])
api_router.include_router(scan.router, tags=["Scanner & History"])
api_router.include_router(analytics.router, tags=["Analytics"])
api_router.include_router(threat_intel.router, tags=["Threat Intelligence"])
