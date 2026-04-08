import jwt
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
from app.core.config import get_settings
from app.core.security import safe_compare
from app.schemas.admin import AdminLoginRequest, AdminLoginResponse

settings = get_settings()

def create_admin_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return encoded_jwt

async def login_admin(request: AdminLoginRequest) -> AdminLoginResponse:
    # OWASP: Timing attack protection using safe_compare
    # We compare both email and password in constant time
    
    email_ok = safe_compare(request.email, settings.admin_mail)
    pass_ok = safe_compare(request.password, settings.admin_pass)
    
    if not email_ok or not pass_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz kimlik bilgileri",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.jwt_access_token_expire_minutes)
    access_token = create_admin_access_token(
        data={"sub": request.email, "role": "admin"},
        expires_delta=access_token_expires
    )
    
    return AdminLoginResponse(
        access_token=access_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60
    )
