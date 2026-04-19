from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.schemas.admin import AdminLoginRequest, AdminLoginResponse, AdminLogoutResponse
from app.services.admin_service import login_admin, logout_admin

router = APIRouter(prefix="/admin/sso", tags=["Admin SSO"])

_bearer = HTTPBearer(auto_error=False)


@router.post("/login", response_model=None)
async def admin_login(body: AdminLoginRequest):
    """
    Admin SSO Giriş Endpoint'i.
    H-3: Argon2id şifre doğrulama.
    H-5: httpOnly cookie + body token (hibrit).
    L-4: ES256 desteği.
    """
    return await login_admin(body)


@router.post("/logout", response_model=AdminLogoutResponse)
async def admin_logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> AdminLogoutResponse:
    """
    H-6: Admin JWT'yi blacklist'e ekler — logout sonrası token geçersiz.
    Authorization header veya admin_token cookie'sinden token alır.
    """
    token = ""
    if credentials:
        token = credentials.credentials
    if not token:
        token = request.cookies.get("admin_token", "")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Oturum token'ı bulunamadı.",
        )

    result = await logout_admin(token)

    from fastapi.responses import JSONResponse
    from app.core.config import get_settings
    settings = get_settings()
    response = JSONResponse(content=result)
    delete_kwargs: dict = {
        "key": "admin_token",
        "path": "/api/v1/admin",
        "secure": settings.is_production,
        "httponly": True,
        "samesite": "lax",
    }
    if settings.is_production:
        delete_kwargs["domain"] = ".pentorasec.com.tr"
    response.delete_cookie(**delete_kwargs)
    return response
