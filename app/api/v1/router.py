"""V1 API Router."""
from fastapi import APIRouter
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.accounts import router as accounts_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(accounts_router)


@router.get("/ping", tags=["System"])
async def ping():
    return {"message": "pong", "version": "v1"}
