from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.connectors import router as connectors_router
from app.api.audits import router as audits_router
from app.api.rules import router as rules_router
from app.api.webhooks import router as webhooks_router
from app.api.api_keys import router as api_keys_router

router = APIRouter()

# Include all sub-routers
router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
router.include_router(connectors_router, prefix="/connectors", tags=["Connectors"])
router.include_router(audits_router, prefix="/audits", tags=["Audits"])
router.include_router(rules_router, prefix="/rules", tags=["Compliance Rules"])
router.include_router(webhooks_router, prefix="/webhooks", tags=["Webhooks"])
router.include_router(api_keys_router, prefix="/api-keys", tags=["API Keys"])
