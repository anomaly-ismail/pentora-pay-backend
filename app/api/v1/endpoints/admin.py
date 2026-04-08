from fastapi import APIRouter, Depends, HTTPException, status
from app.schemas.admin import AdminLoginRequest, AdminLoginResponse
from app.services.admin_service import login_admin

router = APIRouter(prefix="/admin/sso", tags=["Admin SSO"])

@router.post("/login", response_model=AdminLoginResponse)
async def admin_login(body: AdminLoginRequest):
    """
    Admin SSO Giriş Endpoint'i.
    E-posta ve şifre ile JWT üretir.
    """
    return await login_admin(body)
