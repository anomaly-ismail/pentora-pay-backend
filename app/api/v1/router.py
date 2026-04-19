"""V1 API Router."""
from fastapi import APIRouter
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.accounts import router as accounts_router
from app.api.v1.endpoints.admin import router as admin_router
from app.api.v1.endpoints.notifications import router as notifications_router
from app.api.v1.endpoints.corporate import flutter_router as corporate_flutter_router
from app.api.v1.endpoints.corporate import admin_corp_router
from app.api.v1.endpoints.employees import router as employees_router
from app.api.v1.endpoints.webhooks import router as webhooks_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(accounts_router)
router.include_router(admin_router)
router.include_router(notifications_router)
router.include_router(corporate_flutter_router)
router.include_router(admin_corp_router)
router.include_router(employees_router)
router.include_router(webhooks_router)


@router.get("/ping", tags=["System"])
async def ping():
    return {"message": "pong", "version": "v1"}
